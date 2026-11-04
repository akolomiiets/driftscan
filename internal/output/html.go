package output

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
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
	Address, Paths, Actions, Loc, LocURL, Message        string
	AckText, Owner, ChangedBy, Search                    string
	Resolved                                             bool
}

type htmlRoot struct {
	Path, Summary string
	Open          bool
	Rows, AckRows []htmlRow
	rank          int
}

type htmlEnv struct {
	Name  string
	Roots []htmlRoot
}

type htmlPage struct {
	Tool, Started, Duration, Generated, Shard string
	Compared, Partial                         bool
	Counts                                    Counts
	Added, Changed, Total                     int
	StatusClass, StatusText                   string
	Envs                                      []string
	Groups                                    []htmlEnv
	Script                                    template.JS
	ScriptHash                                string
}

// rootEnv is the Root path without its last segment, "" for a single-segment path.
func rootEnv(root string) string {
	if d := path.Dir(root); d != "." && d != "/" {
		return d
	}
	return ""
}

// HTML renders the whole Report as one self-contained page: inline CSS and JS, no external requests.
// The output depends only on the arguments.
func HTML(r finding.Report, src Source, generated time.Time) ([]byte, error) {
	c := Count(r)
	p := htmlPage{
		Tool:      r.Tool,
		Started:   r.StartedAt.UTC().Format(time.RFC3339),
		Duration:  r.Duration.Round(100 * time.Millisecond).String(),
		Generated: generated.UTC().Format(time.RFC3339),
		Shard:     r.Shard,
		Compared:  r.Compared,
		Partial:   r.Partial,
		Counts:    c,
		Total:     len(r.Findings),
		Script:    template.JS(htmlScript),
	}
	sum := sha256.Sum256([]byte(htmlScript))
	p.ScriptHash = base64.StdEncoding.EncodeToString(sum[:])
	switch {
	case c.Drift > 0 || c.Errors > 0:
		p.StatusClass, p.StatusText = "bad", "Drift or Scan errors found"
	case c.Pending > 0:
		p.StatusClass, p.StatusText = "warn", "Pending changes only"
	default:
		p.StatusClass, p.StatusText = "ok", "No drift"
	}
	for _, f := range r.Findings {
		if !f.Active() {
			continue
		}
		switch f.Status {
		case finding.StatusNew:
			p.Added++
		case finding.StatusChanged:
			p.Changed++
		}
	}
	p.Groups = htmlGroups(r, src)
	for _, g := range p.Groups {
		if g.Name != "" {
			p.Envs = append(p.Envs, g.Name)
		}
	}

	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, p); err != nil {
		return nil, fmt.Errorf("render html: %w", err)
	}
	return buf.Bytes(), nil
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
		root := htmlRoot{Path: rp, Summary: rootSummary(outcome[rp], fs)}
		for _, f := range fs {
			row := htmlRowOf(f, src)
			if f.Acknowledged && f.Active() {
				root.AckRows = append(root.AckRows, row)
				continue
			}
			root.Rows = append(root.Rows, row)
			if f.Active() && (f.Kind == finding.KindScanError || f.Kind == finding.KindDrift) {
				root.Open = true
			}
		}
		switch {
		case root.Open:
			root.rank = 0
		case len(fs) > 0:
			root.rank = 1
		default:
			root.rank = 2
		}
		env := rootEnv(rp)
		envRoots[env] = append(envRoots[env], root)
	}

	names := make([]string, 0, len(envRoots))
	for n := range envRoots {
		names = append(names, n)
	}
	sort.Slice(names, func(a, b int) bool {
		if (names[a] == "") != (names[b] == "") {
			return names[b] == ""
		}
		return names[a] < names[b]
	})
	groups := make([]htmlEnv, 0, len(names))
	for _, n := range names {
		roots := envRoots[n]
		sort.SliceStable(roots, func(a, b int) bool {
			if roots[a].rank != roots[b].rank {
				return roots[a].rank < roots[b].rank
			}
			return roots[a].Path < roots[b].Path
		})
		groups = append(groups, htmlEnv{Name: n, Roots: roots})
	}
	return groups
}

func rootSummary(outcome finding.RootOutcome, fs []finding.Finding) string {
	c := Count(finding.Report{Findings: fs})
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
	if outcome == "" {
		return "no findings"
	}
	return string(outcome)
}

func htmlRowOf(f finding.Finding, src Source) htmlRow {
	row := htmlRow{
		Env:        rootEnv(f.Root),
		Kind:       string(f.Kind),
		KindText:   kindText(f.Kind),
		Severity:   f.Severity.String(),
		SevRank:    int(f.Severity),
		StatusKey:  string(f.Status),
		StatusText: statusText(f),
		Address:    f.Address,
		Paths:      strings.Join(f.Paths, ", "),
		Actions:    strings.Join(f.Actions, ", "),
		LocURL:     src.URL(f),
		Message:    f.Message,
		Owner:      f.Owner,
		ChangedBy:  f.ChangedBy,
		Resolved:   f.Status == finding.StatusResolved,
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
	if f.Acknowledged {
		row.AckText = "acknowledged: " + ackText(f.AckReason)
	}
	row.Search = strings.ToLower(f.Root + " " + f.Address + " " + row.Paths)
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
