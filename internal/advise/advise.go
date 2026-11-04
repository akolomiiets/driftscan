// Package advise asks an AI model for a short triage note per Finding (ADR-0009). It sees only what
// the Report already holds, so no plan value can reach the model (ADR-0002), and it changes nothing.
package advise

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
)

const (
	// BatchSize is the most Findings of one Root sent in one request.
	BatchSize = 15
	// MaxNoteLen caps the stored note, in characters.
	MaxNoteLen   = 400
	maxRuleLen   = 300
	batchTimeout = 2 * time.Minute
)

// Advisor is one model call: system and user text in, the model's text out.
// Bedrock is the only implementation; the seam lets another provider be added later.
type Advisor interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

// Options select which Findings are sent.
type Options struct {
	// MaxFindings caps the Findings sent in one run, highest Severity first.
	MaxFindings         int
	IncludeInfo         bool
	IncludeAcknowledged bool
}

// Result tells the caller what happened; Errors are per-request failures, the Report keeps the rest.
type Result struct {
	Sent, Advised, Dropped, Skipped int
	Errors                          []error
}

// requestFinding is the whole of what leaves the machine for one Finding. Add a field only if the
// Report already holds it and ADR-0002 allows it; a test pins the field set.
type requestFinding struct {
	Address      string   `json:"address"`
	Type         string   `json:"type,omitempty"`
	Kind         string   `json:"kind"`
	Paths        []string `json:"paths,omitempty"`
	Severity     string   `json:"severity"`
	Acknowledged bool     `json:"acknowledged,omitempty"`
	Owner        string   `json:"owner,omitempty"`
}

type request struct {
	Root     string           `json:"root"`
	Findings []requestFinding `json:"findings"`
}

type answer struct {
	Address string `json:"address"`
	Kind    string `json:"kind"`
	Note    string `json:"note"`
	Action  string `json:"action"`
	// RuleRaw is a string or an object depending on the model; IgnoreRule is its text form.
	RuleRaw    json.RawMessage `json:"ignore_rule,omitempty"`
	IgnoreRule string          `json:"-"`
}

const systemPrompt = `You triage Terraform drift findings for an infrastructure team.
Each finding says a resource differs from Terraform state (kind "drift") or that code was merged but not applied (kind "pending"). You get only the resource address, type, changed attribute names, severity and owner. You never see attribute values; do not guess them.
For every finding give: a short note with the likely cause (for example console hotfix, autoscaling, an AWS-managed default, another tool) and the risk; and one action:
- adopt: edit the code to match reality; name the attribute to edit in the note
- revert: restore the declared value by applying the code again
- ignore: the change is expected noise; put a drift.yaml ignore rule snippet in ignore_rule (keys: type, address, attribute, reason)
- investigate: not enough information
Reply with ONLY a JSON array, no prose and no code fences. Each element: {"address": string, "kind": string, "note": string, "action": "adopt"|"revert"|"ignore"|"investigate", "ignore_rule": string (only when action is ignore)}. Copy address and kind exactly from the input. Keep each note under 300 characters.`

// Run adds advice to eligible Findings of r in place and reports what happened.
func Run(ctx context.Context, a Advisor, r *finding.Report, o Options) Result {
	var res Result
	idx := eligible(*r, o, &res)
	if o.MaxFindings > 0 && len(idx) > o.MaxFindings {
		res.Skipped += len(idx) - o.MaxFindings
		idx = idx[:o.MaxFindings]
	}

	byRoot := map[string][]int{}
	var roots []string
	for _, i := range idx {
		root := r.Findings[i].Root
		if _, ok := byRoot[root]; !ok {
			roots = append(roots, root)
		}
		byRoot[root] = append(byRoot[root], i)
	}
	for _, root := range roots {
		all := byRoot[root]
		for len(all) > 0 {
			n := min(BatchSize, len(all))
			adviseBatch(ctx, a, r, root, all[:n], &res)
			all = all[n:]
		}
	}
	return res
}

// eligible returns Finding indexes worth advising, most severe first (stable otherwise).
func eligible(r finding.Report, o Options, res *Result) []int {
	var idx []int
	for i, f := range r.Findings {
		switch {
		case f.Kind == finding.KindScanError || !f.Active():
			continue
		case f.Advice != "", f.Acknowledged && !o.IncludeAcknowledged, f.Severity == finding.SeverityInfo && !o.IncludeInfo:
			res.Skipped++
		default:
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool { return r.Findings[idx[a]].Severity > r.Findings[idx[b]].Severity })
	return idx
}

func adviseBatch(parent context.Context, a Advisor, r *finding.Report, root string, idx []int, res *Result) {
	ctx, cancel := context.WithTimeout(parent, batchTimeout)
	defer cancel()
	body, err := BuildRequest(root, pick(r.Findings, idx))
	if err != nil {
		res.Errors = append(res.Errors, err)
		return
	}
	res.Sent += len(idx)
	text, err := a.Complete(ctx, systemPrompt, string(body))
	if err != nil {
		res.Errors = append(res.Errors, fmt.Errorf("root %s: %w", root, err))
		return
	}
	answers, dropped, err := parse(text)
	if err != nil {
		res.Dropped += len(idx)
		return
	}
	res.Dropped += dropped

	byKey := map[string]int{}
	for _, i := range idx {
		byKey[r.Findings[i].Address+"\x00"+string(r.Findings[i].Kind)] = i
	}
	for _, ans := range answers {
		i, ok := byKey[ans.Address+"\x00"+ans.Kind]
		if !ok || r.Findings[i].Advice != "" {
			res.Dropped++
			continue
		}
		r.Findings[i].Advice = ans.Note
		r.Findings[i].AdviceAction = ans.Action
		r.Findings[i].AdviceIgnoreRule = ans.IgnoreRule
		res.Advised++
	}
}

func pick(fs []finding.Finding, idx []int) []finding.Finding {
	out := make([]finding.Finding, len(idx))
	for i, j := range idx {
		out[i] = fs[j]
	}
	return out
}

// BuildRequest is the only place a Finding is turned into model input.
func BuildRequest(root string, fs []finding.Finding) ([]byte, error) {
	req := request{Root: root}
	for _, f := range fs {
		req.Findings = append(req.Findings, requestFinding{
			Address: f.Address, Type: f.Type, Kind: string(f.Kind), Paths: f.Paths,
			Severity: f.Severity.String(), Acknowledged: f.Acknowledged, Owner: f.Owner,
		})
	}
	return json.Marshal(req)
}

var validActions = map[string]bool{"adopt": true, "revert": true, "ignore": true, "investigate": true}

// parse extracts the JSON array from the model text and keeps only well-formed answers.
// It returns an error when no array can be read at all.
func parse(text string) (ok []answer, dropped int, err error) {
	text = stripFences(text)
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		start, end := strings.Index(text, "["), strings.LastIndex(text, "]")
		if start < 0 || end < start {
			return nil, 0, errors.New("no JSON array in model output")
		}
		if err := json.Unmarshal([]byte(text[start:end+1]), &raw); err != nil {
			return nil, 0, fmt.Errorf("model output is not a JSON array: %w", err)
		}
	}
	for _, m := range raw {
		var a answer
		if err := json.Unmarshal(m, &a); err != nil {
			dropped++
			continue
		}
		a.Note = clean(a.Note, MaxNoteLen)
		a.IgnoreRule = truncate(strings.TrimSpace(strings.ReplaceAll(ruleText(a.RuleRaw), "```", "")), maxRuleLen)
		if a.Address == "" || a.Kind == "" || a.Note == "" || !validActions[a.Action] {
			dropped++
			continue
		}
		if a.Action != "ignore" {
			a.IgnoreRule = ""
		}
		ok = append(ok, a)
	}
	return ok, dropped, nil
}

// stripFences trims the text and removes a surrounding ``` code fence line pair.
func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if nl := strings.Index(s, "\n"); nl >= 0 {
			s = s[nl+1:]
		}
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "```"))
	}
	return s
}

// ruleText turns an ignore_rule that is a JSON string or object into text; anything else is empty.
func ruleText(raw json.RawMessage) string {
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return str
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s: %v", k, obj[k]))
	}
	return strings.Join(lines, "\n")
}

// clean collapses whitespace so a note stays one Markdown line, then caps it.
func clean(s string, n int) string {
	return truncate(strings.Join(strings.Fields(s), " "), n)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}
