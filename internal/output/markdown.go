// Package output renders a compared Report for people and tools: Markdown, Slack, SARIF and OTLP metrics.
package output

import (
	"fmt"
	"html"
	"sort"
	"strconv"
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

// MarkdownBudget is the largest summary Markdown returns: GitHub rejects a step summary over 1 MiB.
var MarkdownBudget = 1000 * 1024

type mdSection struct {
	title string
	open  bool
	ack   bool
	rows  []finding.Finding
}

// Markdown renders the whole Report, suitable for $GITHUB_STEP_SUMMARY. When the result would exceed
// MarkdownBudget, whole Findings are dropped from the lowest-priority end.
func Markdown(r finding.Report, src Source) string {
	owners, actors := false, false
	for _, f := range r.Findings {
		owners = owners || f.Owner != ""
		actors = actors || f.ChangedBy != ""
	}
	sections := mdSections(r)
	total := 0
	for _, s := range sections {
		total += len(s.rows)
	}
	render := func(n int) string { return renderMarkdown(r, src, sections, owners, actors, n, total) }
	if full := render(total); len(full) <= MarkdownBudget {
		return full
	}
	lo, hi := 0, total-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if len(render(mid)) <= MarkdownBudget {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return render(lo)
}

func mdSections(r finding.Report) []mdSection {
	defs := []mdSection{
		{title: "Scan errors"},
		{title: "Drift", open: true},
		{title: "Pending changes"},
		{title: "Resolved since last Scan"},
		{title: "Acknowledged", ack: true},
	}
	keep := []func(finding.Finding) bool{
		func(f finding.Finding) bool { return f.Kind == finding.KindScanError && f.Active() },
		func(f finding.Finding) bool { return f.Kind == finding.KindDrift && f.Active() && !f.Acknowledged },
		func(f finding.Finding) bool { return f.Kind == finding.KindPending && f.Active() },
		func(f finding.Finding) bool { return f.Status == finding.StatusResolved },
		func(f finding.Finding) bool { return f.Acknowledged && f.Active() },
	}
	for i := range defs {
		for _, f := range r.Findings {
			if keep[i](f) {
				defs[i].rows = append(defs[i].rows, f)
			}
		}
		rows := defs[i].rows
		sort.SliceStable(rows, func(a, b int) bool {
			if fresh(rows[a]) != fresh(rows[b]) {
				return fresh(rows[a])
			}
			return rows[a].Severity > rows[b].Severity
		})
	}
	return defs
}

func fresh(f finding.Finding) bool {
	return f.Status == finding.StatusNew || f.Status == finding.StatusChanged
}

func renderMarkdown(r finding.Report, src Source, sections []mdSection, owners, actors bool, n, total int) string {
	var b strings.Builder
	writeHeader(&b, r)
	kept := n
	for _, s := range sections {
		rows := s.rows
		if len(rows) > n {
			rows = rows[:n]
		}
		n -= len(rows)
		if len(rows) == 0 {
			continue
		}
		if s.ack {
			fmt.Fprintf(&b, "<details>\n<summary><b>%s (%d)</b></summary>\n\n", s.title, len(s.rows))
		} else {
			fmt.Fprintf(&b, "### %s (%d)\n\n", s.title, len(s.rows))
		}
		for _, g := range groupByRoot(rows) {
			open := ""
			if s.open {
				open = " open"
			}
			fmt.Fprintf(&b, "<details%s>\n<summary><b>%s</b> - %d</summary>\n\n", open, esc(g[0].Root), len(g))
			writeTable(&b, g, s.ack, owners, actors, src)
			b.WriteString("</details>\n\n")
		}
		writeAdvice(&b, rows)
		if s.ack {
			b.WriteString("</details>\n\n")
		}
	}
	if kept < total {
		fmt.Fprintf(&b, "_%d more Findings not shown, see the report artifact._\n", total-kept)
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
		fmt.Fprintf(b, "- %s **%s**: %s\n", code(f.Address), esc(f.AdviceAction), esc(f.Advice))
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

func ackText(reason string) string {
	if reason == finding.AckNotReverted {
		return "not reverted by apply"
	}
	return "covered by lifecycle.ignore_changes"
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

var escaper = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "`", "&#96;", "|", "&#124;", `\`, "&#92;",
	"*", "&#42;", "[", "&#91;", "]", "&#93;", "~", "&#126;", "\r\n", " ", "\n", " ", "\r", " ",
)

// esc makes any string safe in a table cell, link text, <summary> or <code>: HTML and Markdown
// metacharacters become entities, which render as the original character.
func esc(s string) string {
	s = escaper.Replace(s)
	// Underscores inside a word never start emphasis; others are encoded.
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '_' && !(i > 0 && i+1 < len(s) && isWordByte(s[i-1]) && isWordByte(s[i+1])) {
			b.WriteString("&#95;")
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isWordByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func code(s string) string {
	if s == "" {
		return "-"
	}
	return "<code>" + esc(s) + "</code>"
}

func writeHeader(b *strings.Builder, r finding.Report) {
	c := Count(r)
	icon := ":green_circle:"
	switch {
	case c.Drift > 0 || c.Errors > 0:
		icon = ":red_circle:"
	case c.Pending > 0:
		icon = ":yellow_circle:"
	}
	b.WriteString("## driftscan\n\n")
	fmt.Fprintf(b, "%s %d Roots scanned, %d with Drift.\n\n", icon, c.Roots, c.RootsDrifted)
	fmt.Fprintf(b, "**%d Drift** | %d Pending changes | %d Scan errors | %d acknowledged | %d resolved\n\n",
		c.Drift, c.Pending, c.Errors, c.Acknowledged, c.Resolved)
	if !r.Compared {
		b.WriteString("_No Baseline: this Scan establishes it. Statuses start from the next Scan._\n\n")
		return
	}
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
	fmt.Fprintf(b, "Active Findings: %d new, %d changed.\n\n", added, changed)
}

// groupByRoot keeps the order of rows and groups them by Root, in order of first appearance.
func groupByRoot(rows []finding.Finding) [][]finding.Finding {
	var groups [][]finding.Finding
	index := map[string]int{}
	for _, f := range rows {
		i, ok := index[f.Root]
		if !ok {
			i = len(groups)
			index[f.Root] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], f)
	}
	return groups
}

func writeTable(b *strings.Builder, rows []finding.Finding, ack, owners, actors bool, src Source) {
	head, sep := "| Severity | Status | Resource | Attributes | Location |", "|---|---|---|---|---|"
	if ack {
		head, sep = head+" Reason |", sep+"---|"
	}
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
			what, detail = "-", esc(f.Message)
		} else if len(f.Paths) == 0 {
			detail = esc(orDash(strings.Join(f.Actions, ", ")))
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |", f.Severity, esc(statusText(f)), what, detail, location(f, src))
		if ack {
			fmt.Fprintf(b, " %s |", esc(ackText(f.AckReason)))
		}
		if owners {
			fmt.Fprintf(b, " %s |", esc(orDash(f.Owner)))
		}
		if actors {
			fmt.Fprintf(b, " %s |", esc(orDash(f.ChangedBy)))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func location(f finding.Finding, src Source) string {
	p := src.Path(f)
	if p == "" {
		return "-"
	}
	text := p
	if f.Line > 0 {
		text += ":" + strconv.Itoa(f.Line)
	}
	if u := src.URL(f); u != "" {
		return "[" + esc(text) + "](" + u + ")"
	}
	return code(text)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
