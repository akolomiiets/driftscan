// Package scan plans every Root in parallel and produces a raw Report (not yet compared with a Baseline).
package scan

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/akolomiiets/driftscan/internal/config"
	"github.com/akolomiiets/driftscan/internal/discover"
	"github.com/akolomiiets/driftscan/internal/extract"
	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/rules"
	"github.com/akolomiiets/driftscan/internal/runner"
)

// Run never fails as a whole: a Root that cannot be planned or parsed becomes a Scan error Finding.
// Findings are sorted by Root, then address, then kind.
func Run(ctx context.Context, cfg config.Config, roots []discover.Root, r runner.Runner, now time.Time, tool string) finding.Report {
	start := time.Now()
	results := make([]rootResult, len(roots))
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for i, root := range roots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = scanRoot(ctx, cfg, root, r, now)
		}()
	}
	wg.Wait()

	rep := finding.Report{Version: finding.ReportVersion, Tool: tool, StartedAt: now.UTC()}
	for _, res := range results {
		rep.Roots = append(rep.Roots, res.result)
		rep.Findings = append(rep.Findings, res.findings...)
	}
	Sort(rep.Findings)
	rep.Duration = time.Since(start)
	return rep
}

type rootResult struct {
	result   finding.RootResult
	findings []finding.Finding
}

func scanRoot(ctx context.Context, cfg config.Config, root discover.Root, r runner.Runner, now time.Time) rootResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	res := rootResult{result: finding.RootResult{Path: root.Path}}
	fail := func(msg string) rootResult {
		res.result.Outcome = finding.RootError
		res.result.Duration = time.Since(start)
		res.findings = []finding.Finding{{
			Root: root.Path, Kind: finding.KindScanError, Severity: finding.SeverityHigh, Message: msg,
			File: root.Info.BackendFile.File, Line: root.Info.BackendFile.Line,
		}}
		return res
	}

	plans, err := r.Run(ctx, root, cfg.Pending.On())
	if err != nil {
		return fail(err.Error())
	}
	fs, err := extract.Drift(plans.RefreshOnly, root.Path, root.Info)
	if err != nil {
		return fail(err.Error())
	}
	if plans.Pending != nil {
		pending, err := extract.Pending(plans.Pending, root.Path)
		if err != nil {
			return fail(err.Error())
		}
		fs = append(fs, pending...)
	}
	for i := range fs {
		loc, _ := root.Info.Locate(fs[i].Address)
		fs[i].File, fs[i].Line = loc.File, loc.Line
	}
	res.findings = rules.Apply(fs, cfg, now)
	res.result.Outcome = finding.RootClean
	for _, f := range res.findings {
		if f.Kind == finding.KindDrift && !f.Acknowledged {
			res.result.Outcome = finding.RootDrifted
		}
	}
	res.result.Duration = time.Since(start)
	return res
}

func Sort(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Root != b.Root {
			return a.Root < b.Root
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Kind < b.Kind
	})
}
