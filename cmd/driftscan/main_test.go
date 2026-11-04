package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/akolomiiets/driftscan/internal/advise"
	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/output"
)

func TestMergePartial(t *testing.T) {
	r := func(shard string) finding.Report { return finding.Report{Shard: shard, Partial: shard != ""} }
	cases := []struct {
		name  string
		parts []finding.Report
		want  bool
	}{
		{"single full", []finding.Report{r("")}, false},
		{"all shards", []finding.Report{r("1/3"), r("3/3"), r("2/3")}, false},
		{"missing shard", []finding.Report{r("1/3"), r("3/3")}, true},
		{"mixed splits", []finding.Report{r("1/2"), r("2/3")}, true},
		{"two full", []finding.Report{r(""), r("")}, true},
	}
	for _, c := range cases {
		if got := merge(c.parts).Partial; got != c.want {
			t.Errorf("%s: partial = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseShard(t *testing.T) {
	for _, bad := range []string{"0/2", "3/2", "a/b", "2", "1/0"} {
		if _, _, err := parseShard(bad); err == nil {
			t.Errorf("parseShard(%q) accepted", bad)
		}
	}
	if i, n, err := parseShard("2/4"); err != nil || i != 2 || n != 4 {
		t.Errorf("2/4 = %d %d %v", i, n, err)
	}
}

func TestEnrichWritesOwners(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "CODEOWNERS"), []byte("/infra/app/ @org/app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(repo, "raw.json")
	raw := finding.Report{Version: finding.ReportVersion, Findings: []finding.Finding{{Root: "app", Kind: finding.KindDrift, File: "app/main.tf"}}}
	if err := writeReport(in, raw); err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	if code := run([]string{"enrich", "-repo", repo, "-prefix", "infra", in}, io.Discard, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	got, err := readReport(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Findings[0].Owner != "@org/app" {
		t.Errorf("owner = %q", got.Findings[0].Owner)
	}
}

type fakeAdvisor struct{ reply string }

func (f fakeAdvisor) Complete(context.Context, string, string) (string, error) { return f.reply, nil }

func TestAdviseWritesAdviceInPlace(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	r := finding.Report{Version: finding.ReportVersion, Findings: []finding.Finding{
		{Root: "a", Address: "aws_instance.x", Kind: finding.KindDrift, Severity: finding.SeverityHigh, Status: finding.StatusNew},
	}}
	if err := writeReport(raw, r); err != nil {
		t.Fatal(err)
	}
	newFake := func(context.Context, string) (advise.Advisor, error) {
		return fakeAdvisor{reply: `[{"address":"aws_instance.x","kind":"drift","note":"autoscaling","action":"ignore"}]`}, nil
	}

	code := cmdAdvise(context.Background(), []string{"-model", "m", raw}, io.Discard, io.Discard, newFake)

	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	got, err := readReport(raw)
	if err != nil || got.Findings[0].Advice != "autoscaling" || got.Findings[0].AdviceAction != "ignore" {
		t.Errorf("report = %+v, %v", got.Findings, err)
	}
}

func TestAdviseRequiresModel(t *testing.T) {
	newFake := func(context.Context, string) (advise.Advisor, error) {
		t.Fatal("advisor built without model")
		return nil, nil
	}
	var stderr strings.Builder

	code := cmdAdvise(context.Background(), []string{"raw.json"}, io.Discard, &stderr, newFake)

	if code != exitError || !strings.Contains(stderr.String(), "-model") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

type failingAdvisor struct{}

func (failingAdvisor) Complete(context.Context, string, string) (string, error) {
	return "", errors.New("throttled")
}

func TestAdviseExitsTwoButWritesReportWhenARequestFails(t *testing.T) {
	raw := filepath.Join(t.TempDir(), "raw.json")
	r := finding.Report{Version: finding.ReportVersion, Findings: []finding.Finding{
		{Root: "a", Address: "aws_instance.x", Kind: finding.KindDrift, Severity: finding.SeverityHigh, Status: finding.StatusNew},
	}}
	if err := writeReport(raw, r); err != nil {
		t.Fatal(err)
	}
	newFail := func(context.Context, string) (advise.Advisor, error) { return failingAdvisor{}, nil }

	code := cmdAdvise(context.Background(), []string{"-model", "m", raw}, io.Discard, io.Discard, newFail)

	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
	if _, err := readReport(raw); err != nil {
		t.Errorf("report not written: %v", err)
	}
}

func TestAdviseRejectsNonPositiveMaxFindings(t *testing.T) {
	for _, v := range []string{"0", "-1"} {
		var stderr strings.Builder

		code := cmdAdvise(context.Background(), []string{"-model", "m", "-max-findings", v, "raw.json"}, io.Discard, &stderr, nil)

		if code != exitError || !strings.Contains(stderr.String(), "-max-findings") {
			t.Errorf("max-findings %s: exit = %d, stderr = %q", v, code, stderr.String())
		}
	}
}

func runReport(t *testing.T, extra ...string) (string, string, int) {
	t.Helper()
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	r := finding.Report{Version: finding.ReportVersion, Findings: []finding.Finding{
		{Root: "a", Address: "aws_instance.x", Kind: finding.KindDrift, Severity: finding.SeverityHigh, Status: finding.StatusNew,
			Paths: []string{"tags.Name"}, File: "main.tf", Line: 4},
	}}
	if err := writeReport(raw, r); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"report", "-out", filepath.Join(dir, "out.json"), "-markdown", "", "-fail-on", "none"}, extra...)
	var stdout, stderr strings.Builder

	code := run(append(args, raw), &stdout, &stderr)

	return stdout.String(), stderr.String(), code
}

func TestAnnotationsAutoFollowsGithubActions(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	stdout, _, _ := runReport(t)
	if !strings.HasPrefix(stdout, "::error file=main.tf,line=4,title=driftscan%3A aws_instance.x::tags.Name") {
		t.Errorf("auto with GITHUB_ACTIONS=true: stdout = %q", stdout)
	}

	t.Setenv("GITHUB_ACTIONS", "")
	if stdout, _, _ := runReport(t); stdout != "" {
		t.Errorf("auto without GITHUB_ACTIONS: stdout = %q", stdout)
	}
}

func TestAnnotationsOnAndOff(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	if stdout, _, _ := runReport(t, "-annotations", "on"); !strings.HasPrefix(stdout, "::error ") {
		t.Errorf("on: stdout = %q", stdout)
	}

	t.Setenv("GITHUB_ACTIONS", "true")
	if stdout, _, _ := runReport(t, "-annotations", "off"); stdout != "" {
		t.Errorf("off: stdout = %q", stdout)
	}
}

func TestAnnotationsRejectsInvalidValue(t *testing.T) {
	stdout, stderr, code := runReport(t, "-annotations", "yes")

	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, `-annotations: unknown value "yes" (want auto, on or off)`) {
		t.Errorf("stderr = %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestReportFindsConfigInScanDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "drift.yaml"), []byte("bogus_key: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(t.TempDir(), "raw.json")
	if err := writeReport(raw, finding.Report{Version: finding.ReportVersion}); err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder

	code := run([]string{"report", "-C", dir, "-out", "", "-markdown", "", raw}, io.Discard, &stderr)

	if code != exitError || !strings.Contains(stderr.String(), "drift.yaml") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestScanAndReportValidateModesBeforeWork(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"scan annotations", []string{"scan", "-C", missing, "-annotations", "yes"}, "-annotations"},
		{"scan fail-on", []string{"scan", "-C", missing, "-fail-on", "huge"}, "-fail-on"},
		{"report annotations", []string{"report", "-C", missing, "-annotations", "yes", "raw.json"}, "-annotations"},
		{"report fail-on", []string{"report", "-C", missing, "-fail-on", "huge", "raw.json"}, "-fail-on"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr strings.Builder

			code := run(tt.args, io.Discard, &stderr)

			if code != exitError || !strings.Contains(stderr.String(), tt.want) || strings.Contains(stderr.String(), "scanning") {
				t.Errorf("exit %d, stderr %q", code, stderr.String())
			}
		})
	}
}

func TestAppendMarkdownCountsExistingContent(t *testing.T) {
	rep := finding.Report{Version: finding.ReportVersion, Compared: true}
	for i := range 200 {
		rep.Findings = append(rep.Findings, finding.Finding{Root: "a", Address: "aws_s3_bucket.b" + strconv.Itoa(i),
			Kind: finding.KindDrift, Severity: finding.SeverityHigh, Status: finding.StatusNew})
	}
	path := filepath.Join(t.TempDir(), "summary.md")
	existing := strings.Repeat("x", output.MarkdownBudget-100)
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := appendMarkdown(path, rep, output.Source{}); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.HasPrefix(got, existing+"\n## driftscan") {
		t.Errorf("summary must start on its own line, got %q", got[len(existing):][:20])
	}
	if !strings.Contains(got, " more Findings not shown") || len(got) > output.MarkdownBudget+minAppendBudget {
		t.Errorf("Findings must be dropped to fit the remaining budget, len %d", len(got))
	}
}

func TestAppendMarkdownKeepsNewlineSeparatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.md")
	if err := os.WriteFile(path, []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := appendMarkdown(path, finding.Report{Version: finding.ReportVersion}, output.Source{}); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), "before\n## driftscan") {
		t.Errorf("got %q", b)
	}
}
