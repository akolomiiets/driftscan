package output

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
)

var htmlGenerated = time.Date(2026, 11, 4, 12, 0, 5, 0, time.UTC)

func htmlGoldenReport() finding.Report {
	return finding.Report{
		Version: 1, Tool: "driftscan v0.2.0", Compared: true,
		StartedAt: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC), Duration: 351700 * time.Millisecond,
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
			{Root: "envs/dev/data", Address: "module.rds_core.module.parameters.aws_db_parameter_group.main[\"primary\"]", Kind: finding.KindDrift,
				Paths: manyPaths(15), Severity: finding.SeverityMedium, Status: finding.StatusPersisting, SeenCount: 2,
				File: "envs/dev/data/modules/rds_core/parameters/parameter_group.tf", Line: 44},
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

func manyPaths(n int) []string {
	var p []string
	for i := 0; i < n; i++ {
		p = append(p, "parameter["+strconv.Itoa(i)+"].apply_method")
	}
	return p
}

func TestHTMLFoldsPathsAfterSix(t *testing.T) {
	r := finding.Report{Roots: []finding.RootResult{{Path: "envs/dev/data", Outcome: finding.RootDrifted}},
		Findings: []finding.Finding{{Root: "envs/dev/data", Address: "aws_db_parameter_group.main", Kind: finding.KindDrift,
			Paths: manyPaths(15), Severity: finding.SeverityLow}}}

	b, err := HTML(r, Source{}, htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	fold := strings.Index(out, `<details class="more">`)

	if fold < 0 || !strings.Contains(out, "<summary>&#43;9 more</summary>") {
		t.Fatal("want a +9 more fold")
	}
	if got := strings.Count(out[:fold], `<span class="p">`); got != 6 {
		t.Errorf("visible paths = %d, want 6", got)
	}
	if got := strings.Count(out[fold:], `<span class="p">`); got != 9 {
		t.Errorf("folded paths = %d, want 9", got)
	}
	if !strings.Contains(out, "parameter[14].apply_method") {
		t.Error("last path missing from output")
	}
	if !strings.Contains(out, `data-q="envs/dev/data aws_db_parameter_group.main parameter[0].apply_method,`) ||
		!strings.Contains(out, "parameter[14].apply_method ") {
		t.Error("search text must cover all paths")
	}
}

func TestHTMLOmitsEmptyDetailsColumn(t *testing.T) {
	r := finding.Report{Roots: []finding.RootResult{{Path: "a/b", Outcome: finding.RootDrifted}},
		Findings: []finding.Finding{{Root: "a/b", Address: "aws_x.y", Kind: finding.KindDrift, Severity: finding.SeverityLow}}}

	b, err := HTML(r, Source{}, htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(b), `<th scope="col">Details</th>`) {
		t.Error("Details column rendered with no content")
	}
}

func TestMetaLineUsesToolOnceAndRoundsLongDurations(t *testing.T) {
	r := finding.Report{Tool: "driftscan v0.2.0", StartedAt: htmlGenerated, Duration: 5*time.Minute + 51700*time.Millisecond}

	got := metaLine(r, nil)

	if !strings.HasPrefix(got, "driftscan v0.2.0 scanned 0 Roots on ") || !strings.Contains(got, " in 5m52s.") {
		t.Errorf("meta line = %q", got)
	}
}

func TestBreakSegments(t *testing.T) {
	got := breakSegments("module.a.aws_x.y[0].z", ".", true)

	want := []string{"module.", "a.", "aws_x.", "y", "[0].", "z"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
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
	a, err := HTML(htmlGoldenReport(), goldenSource(), htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HTML(htmlGoldenReport(), goldenSource(), htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}

	if string(a) != string(b) {
		t.Error("two renders of the same Report differ")
	}
}

func TestHTMLEscapesUserStrings(t *testing.T) {
	r := htmlGoldenReport()
	const attack = `" onmouseover="alert(1)`
	r.Roots = append(r.Roots,
		finding.RootResult{Path: "envs/x/<img src=x onerror=alert(1)>", Outcome: finding.RootError},
		finding.RootResult{Path: "envs/y/" + attack, Outcome: finding.RootError})
	r.Findings = append(r.Findings,
		finding.Finding{Root: "envs/dev/network", Address: "aws_x.y" + attack, Kind: finding.KindDrift,
			Severity: finding.SeverityLow, Status: finding.StatusNew},
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
	if strings.Contains(out, attack) {
		t.Error("attribute-breaking input appears raw")
	}
	if !strings.Contains(out, `data-q="envs/dev/network aws_x.y&#34; onmouseover=&#34;alert(1)`) {
		t.Error("attribute value is not escaped as &#34; in data-q")
	}
	if !strings.Contains(out, `title="envs/y/&#34; onmouseover=&#34;alert(1)`) {
		t.Error("Root path is not escaped as &#34; in the map title")
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

func TestHTMLTemplateAndScriptHaveNoExternalRequests(t *testing.T) {
	bad := []string{"http:", "https:", "//", "url(", "@import", "src=", "srcset", "<link", "<object", "<embed", "<img",
		"<iframe", "fetch(", "XMLHttpRequest", "innerHTML"}
	for name, text := range map[string]string{"template": htmlTemplateText, "script": htmlScript} {
		for _, b := range bad {
			if strings.Contains(text, b) {
				t.Errorf("%s contains %q", name, b)
			}
		}
	}
}

func TestHTMLMapListsEnvironmentsProblemsFirst(t *testing.T) {
	r := htmlGoldenReport()
	r.Roots = append(r.Roots, finding.RootResult{Path: "envs/aaa/web", Outcome: finding.RootClean})

	b, err := HTML(r, Source{}, htmlGenerated)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)

	dev := strings.Index(out, `data-env="envs/dev">envs/dev</a>`)
	prod := strings.Index(out, `data-env="envs/prod">envs/prod</a>`)
	clean := strings.Index(out, `data-env="envs/aaa">envs/aaa</a>`)
	top := strings.Index(out, `data-env="-">(top level)</a>`)
	if dev < 0 || !(dev < prod && prod < clean && clean < top) {
		t.Errorf("map order wrong: dev %d, prod %d, clean %d, top level %d", dev, prod, clean, top)
	}
	if !strings.Contains(out, `aria-label="envs/dev/network: 1 drift, 1 resolved"`) {
		t.Error("map cell has no aria-label with the Root summary")
	}
}

func TestHeadline(t *testing.T) {
	drift := htmlRoot{State: "drift"}
	failed := htmlRoot{State: "error"}
	for name, tc := range map[string]struct {
		groups []htmlEnv
		want   string
	}{
		"drift":  {[]htmlEnv{{Roots: []htmlRoot{drift}, Counts: Counts{Drift: 1}}}, "1 drifted resource in 1 Root across 1 environment"},
		"errors": {[]htmlEnv{{Roots: []htmlRoot{failed}}}, "1 Root could not be planned. No drift found in the rest."},
		"both":   {[]htmlEnv{{Roots: []htmlRoot{drift, failed}, Counts: Counts{Drift: 3}}}, "3 drifted resources in 1 Root across 1 environment. 1 Root could not be planned."},
		"clean":  {[]htmlEnv{{}, {}}, "No drift across 2 environments"},
	} {
		if got := headline(tc.groups); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
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

	if !strings.Contains(string(b), "No Baseline") || strings.Contains(string(b), "Compared with the previous Scan") {
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
