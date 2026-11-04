package output

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
)

var htmlGenerated = time.Date(2026, 11, 4, 12, 0, 5, 0, time.UTC)

func htmlGoldenReport() finding.Report {
	return finding.Report{
		Version: 1, Tool: "v0.2.0", Compared: true,
		StartedAt: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC), Duration: 42 * time.Second,
		Roots: []finding.RootResult{
			{Path: "envs/dev/network", Outcome: finding.RootDrifted},
			{Path: "envs/dev/data", Outcome: finding.RootDrifted},
			{Path: "envs/dev/compute", Outcome: finding.RootClean},
			{Path: "envs/prod/network", Outcome: finding.RootDrifted},
			{Path: "envs/prod/iam", Outcome: finding.RootError, FailCount: 2},
			{Path: "envs/prod/data", Outcome: finding.RootClean},
			{Path: "envs/prod/queue", Outcome: finding.RootDrifted},
			{Path: "shared", Outcome: finding.RootClean},
		},
		Findings: []finding.Finding{
			{Root: "envs/dev/network", Address: "aws_security_group.web", Kind: finding.KindDrift, Paths: []string{"ingress[0].cidr_blocks"},
				Severity: finding.SeverityHigh, Status: finding.StatusPersisting, SeenCount: 3, File: "envs/dev/network/sg.tf", Line: 12, Owner: "@org/sre"},
			{Root: "envs/dev/network", Address: "aws_vpc.main", Kind: finding.KindDrift, Severity: finding.SeverityMedium,
				Status: finding.StatusResolved, File: "envs/dev/network/vpc.tf", Line: 1},
			{Root: "envs/dev/data", Address: "aws_s3_bucket.logs", Kind: finding.KindDrift, Paths: []string{"versioning[0].enabled", "tags.Team"},
				Severity: finding.SeverityMedium, Status: finding.StatusChanged, SeenCount: 2, File: "envs/dev/data/s3.tf", Line: 30,
				Owner: "@org/data", ChangedBy: "alice"},
			{Root: "envs/dev/data", Address: "aws_s3_bucket.assets", Kind: finding.KindDrift, Paths: []string{"tags.Name"},
				Severity: finding.SeverityInfo, Status: finding.StatusNew, Acknowledged: true, AckReason: finding.AckIgnoreChanges,
				File: "envs/dev/data/s3.tf", Line: 5},
			{Root: "envs/prod/network", Address: "aws_route_table.private", Kind: finding.KindDrift, Paths: []string{"route"},
				Severity: finding.SeverityCritical, Status: finding.StatusNew, Acknowledged: true, AckReason: finding.AckNotReverted,
				File: "envs/prod/network/rt.tf", Line: 9},
			{Root: "envs/prod/network", Address: "aws_lb.front", Kind: finding.KindPending, Actions: []string{"update"},
				Paths: []string{"idle_timeout"}, Severity: finding.SeverityLow, Status: finding.StatusPersisting, SeenCount: 5,
				File: "envs/prod/network/lb (old).tf", Line: 3},
			{Root: "envs/prod/iam", Kind: finding.KindScanError, Severity: finding.SeverityHigh, Status: finding.StatusNew,
				Message: "Error: no valid credential sources\nfound", File: "envs/prod/iam/backend.tf", Line: 2},
			{Root: "envs/prod/queue", Address: "aws_sqs_queue.jobs", Kind: finding.KindPending, Actions: []string{"delete", "create"},
				Severity: finding.SeverityInfo, Status: finding.StatusUnknown, File: "envs/prod/queue/main.tf"},
		},
	}
}

func TestHTMLGolden(t *testing.T) {
	b, err := HTML(htmlGoldenReport(), goldenSource(), htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}

	checkGolden(t, "report.golden.html", string(b))
}

func TestHTMLIsDeterministic(t *testing.T) {
	a, _ := HTML(htmlGoldenReport(), goldenSource(), htmlGenerated)
	b, _ := HTML(htmlGoldenReport(), goldenSource(), htmlGenerated)

	if string(a) != string(b) {
		t.Error("two renders of the same Report differ")
	}
}

func TestHTMLEscapesUserStrings(t *testing.T) {
	r := htmlGoldenReport()
	r.Roots = append(r.Roots, finding.RootResult{Path: "envs/x/<img src=x onerror=alert(1)>", Outcome: finding.RootError})
	r.Findings = append(r.Findings,
		finding.Finding{Root: "envs/dev/network", Address: `aws_route53_record.r["a|b<c` + "`" + `d&e\"</script><script>alert(1)</script>"]`,
			Kind: finding.KindDrift, Severity: finding.SeverityLow, Status: finding.StatusNew, Paths: []string{"<b>x</b>"}},
		finding.Finding{Root: "envs/x/<img src=x onerror=alert(1)>", Kind: finding.KindScanError, Severity: finding.SeverityHigh,
			Message: "<img src=x onerror=alert(1)>"},
	)

	b, err := HTML(r, goldenSource(), htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)

	for _, raw := range []string{"<img src=x", "b<c", "</script><script>alert", "<b>x</b>"} {
		if strings.Contains(out, raw) {
			t.Errorf("raw %q appears unescaped", raw)
		}
	}
	if strings.Count(out, "<script>") != 1 {
		t.Errorf("want exactly one script element, got %d", strings.Count(out, "<script>"))
	}
	if !strings.Contains(out, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("escaped message not found")
	}
}

func TestHTMLCSPHashMatchesScript(t *testing.T) {
	b, err := HTML(htmlGoldenReport(), Source{}, htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	m := regexp.MustCompile(`script-src 'sha256-([^']+)'`).FindStringSubmatch(out)
	start := strings.Index(out, "<script>") + len("<script>")
	end := strings.Index(out, "</script>")
	sum := sha256.Sum256([]byte(out[start:end]))

	if m == nil || m[1] != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Errorf("CSP hash %v does not match the inline script", m)
	}
}

func TestHTMLHasNoExternalRequests(t *testing.T) {
	b, err := HTML(htmlGoldenReport(), Source{}, htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)

	for _, bad := range []string{"<link", "src=\"http", "@import", "url(", "<img", "<iframe"} {
		if strings.Contains(out, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
}

func TestHTMLOrdersProblemRootsFirstAndKeepsCleanRoots(t *testing.T) {
	b, err := HTML(htmlGoldenReport(), Source{}, htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)

	drift := strings.Index(out, `<span class="path">envs/prod/network`)
	clean := strings.Index(out, `<span class="path">envs/prod/data`)
	if drift < 0 || clean < 0 || drift > clean {
		t.Errorf("drifted Root at %d must precede clean Root at %d", drift, clean)
	}
	if !strings.Contains(out, `<span class="small">clean</span>`) {
		t.Error("clean Root has no clean summary")
	}
}

func TestHTMLNotComparedHidesNewAndChanged(t *testing.T) {
	r := htmlGoldenReport()
	r.Compared = false

	b, err := HTML(r, Source{}, htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(b), "No Baseline") || strings.Contains(string(b), "</b> changed</li>") {
		t.Error("not-compared page must show the Baseline note and no new/changed counters")
	}
}

func TestRootEnv(t *testing.T) {
	for in, want := range map[string]string{"envs/dev/network": "envs/dev", "a/b": "a", "shared": "", "": ""} {
		if got := rootEnv(in); got != want {
			t.Errorf("rootEnv(%q) = %q, want %q", in, got, want)
		}
	}
}
