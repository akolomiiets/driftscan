package scan

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akolomiiets/driftscan/internal/config"
	"github.com/akolomiiets/driftscan/internal/discover"
	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/runner"
)

type fake struct {
	plans    map[string]runner.Plans
	errs     map[string]error
	inFlight atomic.Int32
	peak     atomic.Int32
	sleep    time.Duration
	pending  atomic.Bool
}

func (f *fake) Run(ctx context.Context, root discover.Root, withPending bool) (runner.Plans, error) {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if withPending {
		f.pending.Store(true)
	}
	select {
	case <-time.After(f.sleep):
	case <-ctx.Done():
		return runner.Plans{}, errors.New("timed out")
	}
	if err := f.errs[root.Path]; err != nil {
		return runner.Plans{}, err
	}
	p := f.plans[root.Path]
	if !withPending {
		p.Pending = nil
	}
	return p, nil
}

func fixture(t *testing.T, name string) []byte {
	b, err := os.ReadFile("../extract/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const emptyPlan = `{"format_version":"1.2","terraform_version":"1.16.3"}`

func TestRunCollectsFindingsAndErrors(t *testing.T) {
	f := &fake{
		plans: map[string]runner.Plans{
			"a": {Drift: fixture(t, "drift.json"), Pending: fixture(t, "pending.json")},
			"b": {Drift: []byte(emptyPlan), Pending: []byte(emptyPlan)},
			"d": {Drift: []byte("not json")},
		},
		errs: map[string]error{"c": errors.New("Error: No valid credential sources found")},
	}
	roots := []discover.Root{{Path: "d"}, {Path: "c"}, {Path: "b"}, {Path: "a"}}
	rep := Run(context.Background(), config.Default(), roots, f, time.Now(), "test")

	outcomes := map[string]finding.RootOutcome{}
	for _, r := range rep.Roots {
		outcomes[r.Path] = r.Outcome
	}
	want := map[string]finding.RootOutcome{"a": finding.RootDrifted, "b": finding.RootClean, "c": finding.RootError, "d": finding.RootError}
	for k, v := range want {
		if outcomes[k] != v {
			t.Errorf("root %s outcome = %s, want %s", k, outcomes[k], v)
		}
	}
	var kinds = map[finding.Kind]int{}
	for _, fd := range rep.Findings {
		kinds[fd.Kind]++
	}
	if kinds[finding.KindDrift] != 4 || kinds[finding.KindPending] != 2 || kinds[finding.KindScanError] != 2 {
		t.Errorf("kinds = %v", kinds)
	}
	if rep.Findings[0].Root != "a" || rep.Findings[len(rep.Findings)-1].Root != "d" {
		t.Errorf("not sorted: first %s last %s", rep.Findings[0].Root, rep.Findings[len(rep.Findings)-1].Root)
	}
	if !f.pending.Load() {
		t.Error("pending plan not requested")
	}
}

func TestConcurrencyLimitAndTimeout(t *testing.T) {
	f := &fake{plans: map[string]runner.Plans{}, sleep: 50 * time.Millisecond}
	var roots []discover.Root
	for _, p := range []string{"1", "2", "3", "4", "5", "6"} {
		roots = append(roots, discover.Root{Path: p})
		f.plans[p] = runner.Plans{Drift: []byte(emptyPlan)}
	}
	cfg := config.Default()
	cfg.Concurrency = 2
	Run(context.Background(), cfg, roots, f, time.Now(), "test")
	if f.peak.Load() != 2 {
		t.Errorf("peak concurrency = %d, want 2", f.peak.Load())
	}

	cfg.Timeout = 10 * time.Millisecond
	rep := Run(context.Background(), cfg, roots[:1], f, time.Now(), "test")
	if rep.Roots[0].Outcome != finding.RootError {
		t.Errorf("timeout outcome = %s", rep.Roots[0].Outcome)
	}
}

func TestPendingDisabledSkipsSecondPlan(t *testing.T) {
	f := &fake{plans: map[string]runner.Plans{"a": {Drift: []byte(emptyPlan)}}}
	cfg, _ := config.Parse([]byte("pending:\n  enabled: false\n"))
	Run(context.Background(), cfg, []discover.Root{{Path: "a"}}, f, time.Now(), "test")
	if f.pending.Load() {
		t.Error("pending plan requested while disabled")
	}
}

func TestSummarizeKeepsOnlyHeadlines(t *testing.T) {
	stderr := "╷\n│ Error: Invalid value for variable\n│ \n│   on main.tf line 3: password = \"hunter2\"\n╵\n"
	got := runner.Summarize(stderr)
	if got != "Error: Invalid value for variable" {
		t.Errorf("got %q", got)
	}
	got = runner.Summarize(`Error: reading SSM Parameter "/prod/db/password": AccessDenied` + "\n")
	if got != `Error: reading SSM Parameter "...": AccessDenied` {
		t.Errorf("quoted not stripped: %q", got)
	}
}
