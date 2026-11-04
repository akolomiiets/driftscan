package output

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
)

//go:embed report.html.tmpl
var htmlTemplateText string

//go:embed report.js
var htmlScript string

var htmlTemplate = template.Must(template.New("report").Parse(htmlTemplateText))

type htmlRow struct {
	Env, Kind, KindText, Severity, StatusKey, StatusText string
	SevRank                                              int
	Paths, Actions, Loc, LocURL, Message                 string
	AckText, Owner, ChangedBy, Search                    string
	Address, LocParts                                    []string
	ShownPaths, MorePaths                                []string
	MoreLabel                                            string
	Resolved                                             bool
}

// maxShownPaths is how many attribute paths a row lists before folding the rest into a details element.
const maxShownPaths = 6

type htmlTable struct {
	Rows   []htmlRow
	Widths []int
	Detail bool
}

// tableOf builds a table with column widths (percent) computed from which optional columns have content.
func tableOf(rows []htmlRow) htmlTable {
	t := htmlTable{Rows: rows}
	for _, r := range rows {
		if r.Message != "" || r.AckText != "" || r.Owner != "" || r.ChangedBy != "" {
			t.Detail = true
			break
		}
	}
	// Kind, Severity, Status, Resource, Attributes, Location, [Details]
	t.Widths = []int{6, 8, 9, 20, 40, 17}
	if t.Detail {
		t.Widths = []int{6, 8, 9, 18, 26, 17, 16}
	}
	return t
}

// breakSegments splits s so that a line break may be inserted between consecutive segments:
// after each sep byte, and also before "[" when breakBracket is set.
func breakSegments(s, seps string, breakBracket bool) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch {
		case breakBracket && s[i] == '[' && i > start:
			out = append(out, s[start:i])
			start = i
		case strings.IndexByte(seps, s[i]) >= 0 && i+1 < len(s):
			out = append(out, s[start:i+1])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// commaList appends a comma to every item but the last, so a comma never wraps onto its own line.
func commaList(items []string) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it
		if i < len(items)-1 {
			out[i] += ","
		}
	}
	return out
}

type htmlRoot struct {
	Path, Summary, ID, EnvKey, State, Label string
	Open                                    bool
	Rows, AckRows                           htmlTable
	rank                                    int
}

type htmlEnv struct {
	Name, Key, ID string
	Roots         []htmlRoot
	Counts        Counts
	rank          int
}

type htmlEnvOption struct{ Value, Label string }

type htmlPage struct {
	Headline, Meta, Generated string
	Compared, Partial         bool
	Shard                     string
	Counts                    Counts
	Total                     int
	Envs                      []htmlEnvOption
	Groups                    []htmlEnv
	Script                    template.JS
	ScriptHash                string
}

const topLevelKey = "-"

// rootEnv is the Root path without its last segment, "" for a single-segment path.
func rootEnv(root string) string {
	if d := path.Dir(root); d != "." && d != "/" {
		return d
	}
	return ""
}

func envKey(env string) string {
	if env == "" {
		return topLevelKey
	}
	return env
}

func envLabel(env string) string {
	if env == "" {
		return "(top level)"
	}
	return env
}

// anchorID is a stable, collision-free element id for a path.
func anchorID(prefix, p string) string {
	var b strings.Builder
	dash := true
	for _, r := range strings.ToLower(p) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	h := sha256.Sum256([]byte(p))
	return prefix + strings.Trim(b.String(), "-") + "-" + hex.EncodeToString(h[:4])
}

// HTML renders the whole Report as one self-contained page: inline CSS and JS, no external requests.
// The output depends only on the arguments.
func HTML(r finding.Report, src Source, generated time.Time) ([]byte, error) {
	p := htmlPage{
		Generated: generated.UTC().Format(time.RFC3339),
		Shard:     r.Shard,
		Compared:  r.Compared,
		Partial:   r.Partial,
		Counts:    Count(r),
		Total:     len(r.Findings),
		Script:    template.JS(htmlScript),
	}
	sum := sha256.Sum256([]byte(htmlScript))
	p.ScriptHash = base64.StdEncoding.EncodeToString(sum[:])
	p.Groups = htmlGroups(r, src)
	for _, g := range p.Groups {
		p.Envs = append(p.Envs, htmlEnvOption{Value: g.Key, Label: g.Name})
	}
	p.Headline = headline(p.Groups)
	p.Meta = metaLine(r, p.Groups)

	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, p); err != nil {
		return nil, fmt.Errorf("render html: %w", err)
	}
	return buf.Bytes(), nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func headline(groups []htmlEnv) string {
	var drift, driftRoots, errRoots int
	for _, g := range groups {
		drift += g.Counts.Drift
		for _, r := range g.Roots {
			switch r.State {
			case "drift":
				driftRoots++
			case "error":
				errRoots++
			}
		}
	}
	envs := plural(len(groups), "environment", "environments")
	failed := plural(errRoots, "Root", "Roots") + " could not be planned"
	switch {
	case drift > 0 && errRoots > 0:
		return plural(drift, "drifted resource", "drifted resources") + " in " + plural(driftRoots, "Root", "Roots") +
			" across " + envs + ". " + failed + "."
	case drift > 0:
		return plural(drift, "drifted resource", "drifted resources") + " in " + plural(driftRoots, "Root", "Roots") +
			" across " + envs
	case errRoots > 0:
		return failed + ". No drift found in the rest."
	default:
		return "No drift across " + envs
	}
}

func metaLine(r finding.Report, groups []htmlEnv) string {
	tool := "driftscan"
	if r.Tool != "" {
		tool = r.Tool
	}
	dur := r.Duration.Round(100 * time.Millisecond)
	if r.Duration >= time.Minute {
		dur = r.Duration.Round(time.Second)
	}
	n := 0
	for _, g := range groups {
		n += len(g.Roots)
	}
	s := fmt.Sprintf("%s scanned %s on %s in %s.", tool, plural(n, "Root", "Roots"),
		r.StartedAt.UTC().Format("2006-01-02 15:04 UTC"), dur)
	if r.Compared {
		var added, changed int
		for _, f := range r.Findings {
			if !f.Active() {
				continue
			}
			switch f.Status {
			case finding.StatusNew:
				added++
			case finding.StatusChanged:
				changed++
			}
		}
		s += fmt.Sprintf(" Compared with the previous Scan: %d new, %d changed.", added, changed)
	}
	return s
}

func rootState(outcome finding.RootOutcome, c Counts) string {
	switch {
	case c.Errors > 0 || outcome == finding.RootError:
		return "error"
	case c.Drift > 0:
		return "drift"
	case c.Pending > 0:
		return "pending"
	case c.Acknowledged > 0:
		return "ack"
	default:
		return "clean"
	}
}

func htmlGroups(r finding.Report, src Source) []htmlEnv {
	byRoot := map[string][]finding.Finding{}
	outcome := map[string]finding.RootOutcome{}
	seen := map[string]bool{}
	var paths []string
	for _, rr := range r.Roots {
		outcome[rr.Path] = rr.Outcome
		if !seen[rr.Path] {
			seen[rr.Path] = true
			paths = append(paths, rr.Path)
		}
	}
	for _, f := range r.Findings {
		byRoot[f.Root] = append(byRoot[f.Root], f)
		if !seen[f.Root] {
			seen[f.Root] = true
			paths = append(paths, f.Root)
		}
	}

	envRoots := map[string][]htmlRoot{}
	envCounts := map[string]Counts{}
	for _, rp := range paths {
		fs := byRoot[rp]
		sort.SliceStable(fs, func(a, b int) bool {
			if fs[a].Active() != fs[b].Active() {
				return fs[a].Active()
			}
			if fresh(fs[a]) != fresh(fs[b]) {
				return fresh(fs[a])
			}
			if fs[a].Severity != fs[b].Severity {
				return fs[a].Severity > fs[b].Severity
			}
			return fs[a].Address < fs[b].Address
		})
		env := rootEnv(rp)
		c := Count(finding.Report{Findings: fs})
		root := htmlRoot{Path: rp, Summary: rootSummary(outcome[rp], c), ID: anchorID("root-", rp), EnvKey: envKey(env),
			State: rootState(outcome[rp], c)}
		root.Label = rp + ": " + root.Summary
		var rows, ackRows []htmlRow
		for _, f := range fs {
			row := htmlRowOf(f, src)
			if f.Acknowledged && f.Active() {
				ackRows = append(ackRows, row)
				continue
			}
			rows = append(rows, row)
			if f.Active() && (f.Kind == finding.KindScanError || f.Kind == finding.KindDrift) {
				root.Open = true
			}
		}
		root.Rows, root.AckRows = tableOf(rows), tableOf(ackRows)
		switch {
		case root.Open:
			root.rank = 0
		case len(fs) > 0:
			root.rank = 1
		default:
			root.rank = 2
		}
		envRoots[env] = append(envRoots[env], root)
		t := envCounts[env]
		t.Roots++
		t.Drift += c.Drift
		t.Pending += c.Pending
		t.Errors += c.Errors
		t.Acknowledged += c.Acknowledged
		t.Resolved += c.Resolved
		envCounts[env] = t
	}

	groups := make([]htmlEnv, 0, len(envRoots))
	for n, roots := range envRoots {
		sort.SliceStable(roots, func(a, b int) bool {
			if roots[a].rank != roots[b].rank {
				return roots[a].rank < roots[b].rank
			}
			return roots[a].Path < roots[b].Path
		})
		g := htmlEnv{Name: envLabel(n), Key: envKey(n), ID: anchorID("env-", envLabel(n)), Roots: roots, Counts: envCounts[n], rank: 1}
		if g.Counts.Errors > 0 || g.Counts.Drift > 0 {
			g.rank = 0
		}
		groups = append(groups, g)
	}
	sort.Slice(groups, func(a, b int) bool {
		if groups[a].rank != groups[b].rank {
			return groups[a].rank < groups[b].rank
		}
		if (groups[a].Key == topLevelKey) != (groups[b].Key == topLevelKey) {
			return groups[b].Key == topLevelKey
		}
		return groups[a].Name < groups[b].Name
	})
	return groups
}

func rootSummary(outcome finding.RootOutcome, c Counts) string {
	var parts []string
	add := func(n int, label string) {
		if n > 0 {
			parts = append(parts, strconv.Itoa(n)+" "+label)
		}
	}
	add(c.Drift, "drift")
	add(c.Pending, "pending")
	add(c.Errors, "scan errors")
	add(c.Acknowledged, "acknowledged")
	add(c.Resolved, "resolved")
	if len(parts) > 0 {
		return strings.Join(parts, ", ")
	}
	return string(outcome)
}

func htmlRowOf(f finding.Finding, src Source) htmlRow {
	row := htmlRow{
		Env:        envKey(rootEnv(f.Root)),
		Kind:       string(f.Kind),
		KindText:   kindText(f.Kind),
		Severity:   f.Severity.String(),
		SevRank:    int(f.Severity),
		StatusKey:  string(f.Status),
		StatusText: statusText(f),
		Address:    breakSegments(f.Address, ".", true),
		Paths:      strings.Join(f.Paths, ", "),
		Actions:    strings.Join(f.Actions, ", "),
		LocURL:     src.URL(f),
		Message:    f.Message,
		Owner:      f.Owner,
		ChangedBy:  f.ChangedBy,
		Resolved:   f.Status == finding.StatusResolved,
	}
	paths := commaList(f.Paths)
	if len(paths) > maxShownPaths {
		row.ShownPaths, row.MorePaths = paths[:maxShownPaths], paths[maxShownPaths:]
		row.MoreLabel = fmt.Sprintf("+%d more", len(row.MorePaths))
	} else {
		row.ShownPaths = paths
	}
	if row.StatusKey == "" {
		row.StatusKey = "none"
	}
	if p := src.Path(f); p != "" {
		row.Loc = p
		if f.Line > 0 {
			row.Loc += ":" + strconv.Itoa(f.Line)
		}
	}
	row.LocParts = breakSegments(row.Loc, "/", false)
	if f.Acknowledged {
		row.AckText = "acknowledged: " + ackText(f.AckReason)
	}
	row.Search = strings.ToLower(strings.Join([]string{f.Root, f.Address, row.Paths, f.Message, row.Loc, f.Owner}, " "))
	return row
}

func kindText(k finding.Kind) string {
	switch k {
	case finding.KindScanError:
		return "Scan error"
	case finding.KindPending:
		return "Pending"
	default:
		return "Drift"
	}
}
