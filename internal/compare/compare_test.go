package compare

import (
	"testing"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
)

var (
	day1 = time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	day2 = day1.AddDate(0, 0, 1)
)

func d(root, addr string, sev finding.Severity, paths ...string) finding.Finding {
	return finding.Finding{Root: root, Address: addr, Type: "t", Kind: finding.KindDrift, Severity: sev, Paths: paths}
}

func errF(root string) finding.Finding {
	return finding.Finding{Root: root, Kind: finding.KindScanError, Severity: finding.SeverityHigh, Message: "Error: x"}
}

func rep(roots map[string]finding.RootOutcome, fs ...finding.Finding) finding.Report {
	r := finding.Report{Version: finding.ReportVersion}
	for p, o := range roots {
		r.Roots = append(r.Roots, finding.RootResult{Path: p, Outcome: o})
	}
	r.Findings = fs
	return r
}

func status(r finding.Report) map[string]finding.Status {
	m := map[string]finding.Status{}
	for _, f := range r.Findings {
		m[f.Root+"|"+f.Address+"|"+string(f.Kind)] = f.Status
	}
	return m
}

func TestFirstScanIsQuiet(t *testing.T) {
	cur := rep(map[string]finding.RootOutcome{"a": finding.RootDrifted}, d("a", "x", finding.SeverityHigh, "ingress"))
	got := Compare(nil, cur, day1)
	if got.Compared || got.Findings[0].Status != finding.StatusNew || got.Findings[0].SeenCount != 1 {
		t.Fatalf("first scan = %+v", got)
	}
	if a := Alerts(got, Options{}); len(a) != 0 {
		t.Errorf("first scan alerts = %v", a)
	}
	if f := Failing(got, finding.SeverityHigh); len(f) != 1 {
		t.Errorf("first scan must still fail CI: %v", f)
	}
}

func TestStatuses(t *testing.T) {
	base := Compare(nil, rep(map[string]finding.RootOutcome{"a": finding.RootDrifted, "b": finding.RootDrifted, "c": finding.RootDrifted},
		d("a", "keep", finding.SeverityMedium, "x"),
		d("a", "more", finding.SeverityMedium, "ingress"),
		d("a", "fixed", finding.SeverityMedium, "x"),
		d("b", "lost", finding.SeverityHigh, "x"),
		d("c", "gone-root", finding.SeverityMedium, "x"),
	), day1)

	cur := rep(map[string]finding.RootOutcome{"a": finding.RootDrifted, "b": finding.RootError},
		d("a", "keep", finding.SeverityMedium, "x"),
		d("a", "more", finding.SeverityMedium, "egress", "ingress"),
		d("a", "fresh", finding.SeverityHigh, "x"),
		errF("b"),
	)
	got := Compare(&base, cur, day2)
	want := map[string]finding.Status{
		"a|keep|drift":      finding.StatusPersisting,
		"a|more|drift":      finding.StatusChanged,
		"a|fresh|drift":     finding.StatusNew,
		"a|fixed|drift":     finding.StatusResolved,
		"b|lost|drift":      finding.StatusUnknown,
		"b||scan_error":     finding.StatusNew,
		"c|gone-root|drift": finding.StatusResolved,
	}
	s := status(got)
	for k, v := range want {
		if s[k] != v {
			t.Errorf("%s = %q, want %q", k, s[k], v)
		}
	}
	if len(s) != len(want) {
		t.Errorf("statuses = %v", s)
	}
	for _, f := range got.Findings {
		if f.Address == "keep" && (f.SeenCount != 2 || !f.FirstSeen.Equal(day1)) {
			t.Errorf("keep seen=%d first=%v", f.SeenCount, f.FirstSeen)
		}
	}

	alerts := map[string]bool{}
	for _, f := range Alerts(got, Options{}) {
		alerts[f.Root+"|"+f.Address+"|"+string(f.Kind)] = true
	}
	for _, k := range []string{"a|more|drift", "a|fresh|drift", "a|fixed|drift", "b||scan_error", "c|gone-root|drift"} {
		if !alerts[k] {
			t.Errorf("missing alert %s", k)
		}
	}
	if alerts["a|keep|drift"] || alerts["b|lost|drift"] {
		t.Errorf("persisting/unknown alerted: %v", alerts)
	}
}

func TestPartialReportKeepsAbsentRootsUnknown(t *testing.T) {
	base := Compare(nil, rep(map[string]finding.RootOutcome{"a": finding.RootDrifted, "b": finding.RootDrifted},
		d("a", "x", finding.SeverityHigh, "p"), d("b", "y", finding.SeverityHigh, "p")), day1)
	cur := rep(map[string]finding.RootOutcome{"a": finding.RootDrifted}, d("a", "x", finding.SeverityHigh, "p"))
	cur.Partial = true
	if s := status(Compare(&base, cur, day2)); s["b|y|drift"] != finding.StatusUnknown {
		t.Errorf("partial: %v", s)
	}
	cur.Partial = false
	if s := status(Compare(&base, cur, day2)); s["b|y|drift"] != finding.StatusResolved {
		t.Errorf("complete: %v", s)
	}
}

func TestUnknownCarriesAndResolvedDrops(t *testing.T) {
	base := Compare(nil, rep(map[string]finding.RootOutcome{"b": finding.RootDrifted}, d("b", "x", finding.SeverityHigh, "p")), day1)
	errScan := rep(map[string]finding.RootOutcome{"b": finding.RootError}, errF("b"))
	r2 := Compare(&base, errScan, day2)
	r3 := Compare(&r2, errScan, day2.AddDate(0, 0, 1))
	if s := status(r3); s["b|x|drift"] != finding.StatusUnknown || s["b||scan_error"] != finding.StatusPersisting {
		t.Fatalf("r3 = %v", s)
	}
	if r3.Roots[0].FailCount != 3-1 {
		t.Errorf("fail count = %d, want 2", r3.Roots[0].FailCount)
	}
	if f := Failing(r3, finding.SeverityHigh); len(f) != 2 {
		t.Errorf("unknown drift and error should keep CI red: %v", f)
	}

	clean := rep(map[string]finding.RootOutcome{"b": finding.RootClean})
	r4 := Compare(&r3, clean, day2.AddDate(0, 0, 2))
	if s := status(r4); s["b|x|drift"] != finding.StatusResolved || s["b||scan_error"] != finding.StatusResolved {
		t.Fatalf("r4 = %v", s)
	}
	r5 := Compare(&r4, clean, day2.AddDate(0, 0, 3))
	if len(r5.Findings) != 0 {
		t.Errorf("resolved carried again: %v", r5.Findings)
	}
}

func TestBrokenRootAndDigest(t *testing.T) {
	errScan := rep(map[string]finding.RootOutcome{"b": finding.RootError}, errF("b"))
	r := Compare(nil, errScan, day1)
	opts := Options{BrokenRootAfter: 3}
	var alertsPerRun []int
	for i := 0; i < 4; i++ {
		next := Compare(&r, errScan, day2.AddDate(0, 0, i))
		alertsPerRun = append(alertsPerRun, len(Alerts(next, opts)))
		r = next
	}
	// runs 2..5: fail counts 2,3,4,5 -> one reminder at 3
	if alertsPerRun[0] != 0 || alertsPerRun[1] != 1 || alertsPerRun[2] != 0 || alertsPerRun[3] != 0 {
		t.Errorf("alerts per run = %v", alertsPerRun)
	}

	base := Compare(nil, rep(map[string]finding.RootOutcome{"a": finding.RootDrifted}, d("a", "x", finding.SeverityLow, "p")), day1)
	cur := rep(map[string]finding.RootOutcome{"a": finding.RootDrifted}, d("a", "x", finding.SeverityLow, "p"))
	r2 := Compare(&base, cur, day2)
	if a := Alerts(r2, Options{Digest: true, DigestAfter: 3}); len(a) != 0 {
		t.Errorf("digest before threshold: %v", a)
	}
	if a := Alerts(r2, Options{Digest: true, DigestAfter: 2}); len(a) != 1 {
		t.Errorf("digest at threshold: %v", a)
	}
}

func TestAcknowledgementChangeIsChanged(t *testing.T) {
	ok := map[string]finding.RootOutcome{"r": finding.RootDrifted}
	real := d("r", "a.x", finding.SeverityHigh, "p")
	acked := real
	acked.Acknowledged, acked.AckReason, acked.Severity = true, finding.AckNotReverted, finding.SeverityInfo
	key := "r|a.x|drift"

	got := Compare(&finding.Report{Version: finding.ReportVersion, Findings: []finding.Finding{acked}}, rep(ok, real), day2)
	if status(got)[key] != finding.StatusChanged {
		t.Errorf("ack -> real = %v, want changed", status(got)[key])
	}
	got = Compare(&finding.Report{Version: finding.ReportVersion, Findings: []finding.Finding{real}}, rep(ok, acked), day2)
	if status(got)[key] != finding.StatusChanged {
		t.Errorf("real -> ack = %v, want changed", status(got)[key])
	}
}
