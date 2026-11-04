// Package compare sets each Finding's status against the Baseline (ADR-0001) and decides which
// Findings deserve an alert.
package compare

import (
	"slices"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/scan"
)

// Compare returns cur with statuses filled in. baseline nil means a first Scan: everything is new
// and Compared stays false so outputs stay quiet. Resolved Findings appear once, in the Report that
// resolves them, and are not carried further.
func Compare(baseline *finding.Report, cur finding.Report, now time.Time) finding.Report {
	out := cur
	out.Findings = nil
	out.Roots = slices.Clone(cur.Roots)

	prev := map[string]finding.Finding{}
	prevFails := map[string]int{}
	if baseline != nil {
		for _, f := range baseline.Findings {
			if f.Active() {
				if f.Acknowledged && f.AckReason == "" {
					f.AckReason = finding.AckIgnoreChanges // v0.1 Baselines had only this reason
				}
				prev[f.Key()] = f
			}
		}
		for _, r := range baseline.Roots {
			prevFails[r.Path] = r.FailCount
		}
	}

	errored := map[string]bool{}
	present := map[string]bool{}
	for i, r := range out.Roots {
		present[r.Path] = true
		if r.Outcome == finding.RootError {
			errored[r.Path] = true
			out.Roots[i].FailCount = prevFails[r.Path] + 1
		}
	}

	seen := map[string]bool{}
	for _, f := range cur.Findings {
		k := f.Key()
		seen[k] = true
		p, ok := prev[k]
		switch {
		case !ok:
			f.Status = finding.StatusNew
			f.SeenCount = 1
			f.FirstSeen = now.UTC()
		default:
			f.Status = finding.StatusPersisting
			if !slices.Equal(f.Paths, p.Paths) || !slices.Equal(f.Actions, p.Actions) ||
				f.Acknowledged != p.Acknowledged || f.AckReason != p.AckReason {
				f.Status = finding.StatusChanged
			}
			f.SeenCount = p.SeenCount + 1
			f.FirstSeen = p.FirstSeen
		}
		out.Findings = append(out.Findings, f)
	}

	for k, p := range prev {
		if seen[k] {
			continue
		}
		switch {
		case !present[p.Root] && cur.Partial:
			// The Root was not scanned (lost shard): nothing is known about it.
			p.Status = finding.StatusUnknown
		case errored[p.Root] && p.Kind != finding.KindScanError:
			p.Status = finding.StatusUnknown
		default:
			p.Status = finding.StatusResolved
		}
		out.Findings = append(out.Findings, p)
	}

	scan.Sort(out.Findings)
	out.Compared = baseline != nil
	return out
}

// Options tune Alerts.
type Options struct {
	// Digest also includes persisting Findings seen at least DigestAfter times (a weekly run).
	Digest      bool
	DigestAfter int
	// BrokenRootAfter alerts once more when a Root has failed this many Scans in a row.
	BrokenRootAfter int
}

// Alerts returns the Findings a notification channel should carry: the delta (new, changed,
// resolved), never unknown, plus digest and broken-Root reminders. Empty for a first Scan.
func Alerts(r finding.Report, o Options) []finding.Finding {
	if !r.Compared {
		return nil
	}
	fails := map[string]int{}
	for _, root := range r.Roots {
		fails[root.Path] = root.FailCount
	}
	var out []finding.Finding
	for _, f := range r.Findings {
		switch f.Status {
		case finding.StatusNew, finding.StatusChanged, finding.StatusResolved:
			out = append(out, f)
		case finding.StatusPersisting:
			if f.Kind == finding.KindScanError && o.BrokenRootAfter > 0 && fails[f.Root] == o.BrokenRootAfter {
				out = append(out, f)
			} else if o.Digest && f.SeenCount >= max(o.DigestAfter, 1) {
				out = append(out, f)
			}
		}
	}
	return out
}

// Failing returns the active Findings at or above threshold; any means the CI job should fail.
func Failing(r finding.Report, threshold finding.Severity) []finding.Finding {
	var out []finding.Finding
	for _, f := range r.Findings {
		if f.Active() && f.Severity >= threshold {
			out = append(out, f)
		}
	}
	return out
}
