// Package output renders a compared Report for people and tools: Markdown, Slack, SARIF and OTLP metrics.
package output

import (
	"fmt"
	"html"
	"sort"
	"strings"

	"github.com/akolomiiets/driftscan/internal/finding"
)

// Counts summarises active Findings by kind.
type Counts struct {
	Drift, Pending, Errors, Acknowledged, Resolved, Roots, RootsDrifted int
}

func Count(r finding.Report) Counts {
	c := Counts{Roots: len(r.Roots)}
	for _, root := range r.Roots {
		if root.Outcome == finding.RootDrifted {
			c.RootsDrifted++
		}
	}
	for _, f := range r.Findings {
		switch {
		case f.Status == finding.StatusResolved:
			c.Resolved++
		case f.Kind == finding.KindScanError:
			c.Errors++
		case f.Acknowledged:
			c.Acknowledged++
		case f.Kind == finding.KindDrift:
			c.Drift++
		case f.Kind == finding.KindPending:
			c.Pending++
		}
	}
	return c
}

// Markdown renders the whole Report, suitable for $GITHUB_STEP_SUMMARY.
func Markdown(r finding.Report) string {
	var b strings.Builder
	c := Count(r)
	b.WriteString("## driftscan\n\n")
	fmt.Fprintf(&b, "%d Roots scanned, %d with Drift. **%d Drift**, %d Pending changes, %d Scan errors, %d acknowledged, %d resolved.\n\n",
		c.Roots, c.RootsDrifted, c.Drift, c.Pending, c.Errors, c.Acknowledged, c.Resolved)
	if !r.Compared {
		b.WriteString("_No Baseline: this Scan establishes it. Statuses start from the next Scan._\n\n")
	}

	owners, actors := false, false
	for _, f := range r.Findings {
		owners = owners || f.Owner != ""
		actors = actors || f.ChangedBy != ""
	}

	sections := []struct {
		title string
		keep  func(finding.Finding) bool
	}{
		{"Scan errors", func(f finding.Finding) bool { return f.Kind == finding.KindScanError && f.Active() }},
		{"Drift", func(f finding.Finding) bool {
			return f.Kind == finding.KindDrift && f.Active() && !f.Acknowledged
		}},
		{"Pending changes", func(f finding.Finding) bool { return f.Kind == finding.KindPending && f.Active() }},
		{"Acknowledged (lifecycle.ignore_changes)", func(f finding.Finding) bool { return f.Acknowledged && f.Active() }},
		{"Resolved since last Scan", func(f finding.Finding) bool { return f.Status == finding.StatusResolved }},
	}
	for _, s := range sections {
		var rows []finding.Finding
		for _, f := range r.Findings {
			if s.keep(f) {
				rows = append(rows, f)
			}
		}
		if len(rows) == 0 {
			continue
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Severity > rows[j].Severity })
		fmt.Fprintf(&b, "### %s (%d)\n\n", s.title, len(rows))
		head, sep := "| Severity | Status | Root | Resource | Attributes |", "|---|---|---|---|---|"
		if owners {
			head, sep = head+" Owner |", sep+"---|"
		}
		if actors {
			head, sep = head+" Changed by |", sep+"---|"
		}
		b.WriteString(head + "\n" + sep + "\n")
		for _, f := range rows {
			what := code(f.Address)
			detail := code(strings.Join(f.Paths, ", "))
			if f.Kind == finding.KindScanError {
				what, detail = "-", cell(f.Message)
			} else if len(f.Paths) == 0 {
				detail = cell(strings.Join(f.Actions, ", "))
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |", f.Severity, statusText(f), code(f.Root), what, detail)
			if owners {
				fmt.Fprintf(&b, " %s |", cell(orDash(f.Owner)))
			}
			if actors {
				fmt.Fprintf(&b, " %s |", cell(orDash(f.ChangedBy)))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
		writeAdvice(&b, rows)
	}
	return b.String()
}

// writeAdvice renders AI notes below a table, clearly labelled, so a human reviews them before acting.
func writeAdvice(b *strings.Builder, rows []finding.Finding) {
	var advised []finding.Finding
	for _, f := range rows {
		if f.Advice != "" && f.Active() {
			advised = append(advised, f)
		}
	}
	if len(advised) == 0 {
		return
	}
	fmt.Fprintf(b, "<details><summary>AI-generated advice (%d) - unverified, review before acting</summary>\n\n", len(advised))
	for _, f := range advised {
		fmt.Fprintf(b, "- %s **%s**: %s\n", code(f.Address), cell(f.AdviceAction), cell(html.EscapeString(f.Advice)))
		if f.AdviceIgnoreRule != "" {
			b.WriteString("\n  ```yaml\n")
			for _, l := range strings.Split(f.AdviceIgnoreRule, "\n") {
				b.WriteString("  " + html.EscapeString(l) + "\n")
			}
			b.WriteString("  ```\n\n")
		}
	}
	b.WriteString("\n</details>\n\n")
}

func statusText(f finding.Finding) string {
	if f.Status == "" {
		return "-"
	}
	if f.SeenCount > 1 && f.Status != finding.StatusResolved {
		return fmt.Sprintf("%s (%d scans)", f.Status, f.SeenCount)
	}
	return string(f.Status)
}

func code(s string) string {
	if s == "" {
		return "-"
	}
	return "`" + strings.ReplaceAll(s, "`", "'") + "`"
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
