package output

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/akolomiiets/driftscan/internal/finding"
)

// maxAnnotationsPerLevel is the number GitHub shows per level and step.
const maxAnnotationsPerLevel = 10

var (
	annotationData     = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	annotationProperty = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
)

// Annotations renders new and changed Findings as GitHub Actions workflow commands. Acknowledged
// Findings are skipped; pending changes are included only when pending is true. At most 10 lines
// are returned per level, the last one summarising the rest.
func Annotations(r finding.Report, src Source, pending bool) []string {
	byLevel := map[string][]finding.Finding{}
	for _, f := range r.Findings {
		if !f.Active() || f.Acknowledged || (f.Status != finding.StatusNew && f.Status != finding.StatusChanged) {
			continue
		}
		lvl := annotationLevel(f)
		if lvl == "notice" && !pending {
			continue
		}
		byLevel[lvl] = append(byLevel[lvl], f)
	}

	var out []string
	for _, lvl := range []string{"error", "warning", "notice"} {
		fs := byLevel[lvl]
		sort.SliceStable(fs, func(i, j int) bool {
			if fs[i].Severity != fs[j].Severity {
				return fs[i].Severity > fs[j].Severity
			}
			if fs[i].Root != fs[j].Root {
				return fs[i].Root < fs[j].Root
			}
			return fs[i].Address < fs[j].Address
		})
		shown := fs
		if len(fs) > maxAnnotationsPerLevel {
			shown = fs[:maxAnnotationsPerLevel-1]
		}
		for _, f := range shown {
			out = append(out, annotationLine(lvl, f, src))
		}
		if len(shown) < len(fs) {
			msg := fmt.Sprintf("%d more %s Findings, see the step summary", len(fs)-len(shown), lvl)
			out = append(out, "::"+lvl+" title=driftscan::"+annotationData.Replace(msg))
		}
	}
	return out
}

func annotationLevel(f finding.Finding) string {
	switch {
	case f.Kind == finding.KindPending:
		return "notice"
	case f.Kind == finding.KindDrift && f.Severity >= finding.SeverityHigh:
		return "error"
	default:
		return "warning"
	}
}

func annotationLine(level string, f finding.Finding, src Source) string {
	var props []string
	if p := src.Path(f); p != "" {
		props = append(props, "file="+annotationProperty.Replace(p))
		if f.Line > 0 {
			props = append(props, "line="+strconv.Itoa(f.Line))
		}
	}
	title := "driftscan: " + f.Address
	if f.Kind == finding.KindScanError {
		title = "driftscan: Scan error in " + f.Root
	}
	props = append(props, "title="+annotationProperty.Replace(title))
	return "::" + level + " " + strings.Join(props, ",") + "::" + annotationData.Replace(annotationMessage(f))
}

func annotationMessage(f finding.Finding) string {
	if f.Kind == finding.KindScanError {
		return f.Message
	}
	switch {
	case len(f.Paths) > 0:
		return strings.Join(f.Paths, ", ")
	case len(f.Actions) > 0:
		return strings.Join(f.Actions, ", ")
	case f.Kind == finding.KindPending:
		return "pending change"
	default:
		return "drift"
	}
}
