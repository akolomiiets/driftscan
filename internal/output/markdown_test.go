package output

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
)

var update = flag.Bool("update", false, "rewrite golden files")

func goldenReport() finding.Report {
	return finding.Report{
		Version: 1, Compared: true, Duration: 3 * time.Second,
		Roots: []finding.RootResult{
			{Path: "envs/dev/network", Outcome: finding.RootDrifted},
			{Path: "envs/dev/data", Outcome: finding.RootDrifted},
			{Path: "envs/dev/iam", Outcome: finding.RootError, FailCount: 1},
		},
		Findings: []finding.Finding{
			{Root: "envs/dev/network", Address: "aws_security_group.web", Kind: finding.KindDrift, Paths: []string{"ingress[0].cidr_blocks"},
				Severity: finding.SeverityHigh, Status: finding.StatusPersisting, SeenCount: 3, File: "network/sg.tf", Line: 12, Owner: "@org/sre"},
			{Root: "envs/dev/network", Address: `aws_route53_record.r["a|b<c` + "`" + `d&e"]`, Kind: finding.KindDrift, Paths: []string{"ttl"},
				Severity: finding.SeverityLow, Status: finding.StatusNew, File: "network/dns (old).tf", Line: 7, Owner: "@org/sre", ChangedBy: "alice"},
			{Root: "envs/dev/data", Address: "aws_s3_bucket.logs", Kind: finding.KindDrift, Paths: []string{"versioning[0].enabled", "tags.Team"},
				Severity: finding.SeverityMedium, Status: finding.StatusChanged, SeenCount: 2, File: "data/s3.tf", Line: 30, Owner: "@org/data"},
			{Root: "envs/dev/data", Address: "aws_db_instance.main", Kind: finding.KindPending, Actions: []string{"update"},
				Paths: []string{"allocated_storage"}, Severity: finding.SeverityInfo, Status: finding.StatusNew, File: "data/rds.tf"},
			{Root: "envs/dev/iam", Kind: finding.KindScanError, Severity: finding.SeverityHigh, Status: finding.StatusNew,
				Message: "Error: no valid credential sources\nfound", File: "iam/backend.tf", Line: 2},
			{Root: "envs/dev/network", Address: "aws_vpc.main", Kind: finding.KindDrift, Severity: finding.SeverityMedium,
				Status: finding.StatusResolved, File: "network/vpc.tf", Line: 1},
			{Root: "envs/dev/data", Address: "aws_s3_bucket.assets", Kind: finding.KindDrift, Paths: []string{"tags.Name"},
				Severity: finding.SeverityInfo, Status: finding.StatusNew, Acknowledged: true, AckReason: finding.AckIgnoreChanges, File: "data/s3.tf", Line: 5},
		},
	}
}

func goldenSource() Source {
	return Source{Prefix: "infra", BlobURL: "https://github.com/acme/infra-repo/blob/abc123"}
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs; run go test ./internal/output -run Golden -update\n--- got ---\n%s", name, got)
	}
}

func TestMarkdownGoldenWithSource(t *testing.T) {
	checkGolden(t, "markdown_source.golden.md", Markdown(goldenReport(), goldenSource()))
}

func TestMarkdownGoldenWithoutSource(t *testing.T) {
	checkGolden(t, "markdown_nosource.golden.md", Markdown(goldenReport(), Source{}))
}

func TestMarkdownGoldenNotCompared(t *testing.T) {
	r := goldenReport()
	r.Compared = false
	for i := range r.Findings {
		r.Findings[i].Status = ""
	}
	checkGolden(t, "markdown_nobaseline.golden.md", Markdown(r, Source{}))
}

func TestMarkdownEscapesUserStrings(t *testing.T) {
	md := Markdown(goldenReport(), goldenSource())

	if !strings.Contains(md, "<code>aws_route53_record.r&#91;&quot;a&#124;b&lt;c&#96;d&amp;e&quot;&#93;</code>") {
		t.Errorf("address not escaped:\n%s", md)
	}
	if strings.Contains(md, "b<c") || strings.Contains(md, "sources\nfound") {
		t.Errorf("raw metacharacters or newline leaked:\n%s", md)
	}
	if !strings.Contains(md, "(https://github.com/acme/infra-repo/blob/abc123/infra/network/dns%20%28old%29.tf#L7)") {
		t.Errorf("link not escaped:\n%s", md)
	}
}

func TestMarkdownSortsFreshFirstThenSeverity(t *testing.T) {
	md := Markdown(goldenReport(), Source{})

	new1 := strings.Index(md, "aws_route53_record")
	old1 := strings.Index(md, "aws_security_group.web")
	if new1 < 0 || old1 < 0 || new1 > old1 {
		t.Errorf("new low-severity Finding must precede persisting high one:\n%s", md)
	}
}

func TestMarkdownTruncatesWholeFindings(t *testing.T) {
	old := MarkdownBudget
	defer func() { MarkdownBudget = old }()
	full := len(Markdown(goldenReport(), Source{}))
	MarkdownBudget = full - 400

	md := Markdown(goldenReport(), Source{})

	if len(md) > MarkdownBudget {
		t.Errorf("len %d exceeds budget %d", len(md), MarkdownBudget)
	}
	if !strings.Contains(md, "_1 more Findings not shown, see the report artifact._") &&
		!strings.Contains(md, "_2 more Findings not shown, see the report artifact._") {
		t.Errorf("missing or wrong more-line:\n%s", md)
	}
	if strings.Count(md, "<details") != strings.Count(md, "</details>") {
		t.Errorf("unbalanced <details>:\n%s", md)
	}
	if strings.Contains(md, "aws_s3_bucket.assets") {
		t.Errorf("lowest priority Finding must be dropped first:\n%s", md)
	}
	if !strings.Contains(md, "Error: no valid credential sources") {
		t.Errorf("Scan error must be kept:\n%s", md)
	}
}

func TestMarkdownTruncationCountsDroppedFindings(t *testing.T) {
	old := MarkdownBudget
	defer func() { MarkdownBudget = old }()
	MarkdownBudget = 1

	md := Markdown(goldenReport(), Source{})

	if !strings.Contains(md, "_7 more Findings not shown, see the report artifact._") {
		t.Errorf("expected all 7 dropped:\n%s", md)
	}
	if strings.Count(md, "<details") != 0 {
		t.Errorf("no <details> expected:\n%s", md)
	}
}

func TestMarkdownNotTruncatedWithinBudget(t *testing.T) {
	if strings.Contains(Markdown(goldenReport(), Source{}), "more Findings not shown") {
		t.Error("unexpected truncation note")
	}
}

func TestSourcePathAndURL(t *testing.T) {
	tests := []struct {
		name     string
		src      Source
		f        finding.Finding
		wantPath string
		wantURL  string
	}{
		{"prefix and line", Source{Prefix: "infra", BlobURL: "https://h/o/r/blob/s"}, finding.Finding{File: "a/b.tf", Line: 4}, "infra/a/b.tf", "https://h/o/r/blob/s/infra/a/b.tf#L4"},
		{"prefix with trailing slash", Source{Prefix: "infra/", BlobURL: "https://h/o/r/blob/s"}, finding.Finding{File: "b.tf", Line: 1}, "infra/b.tf", "https://h/o/r/blob/s/infra/b.tf#L1"},
		{"no prefix", Source{BlobURL: "https://h/o/r/blob/s"}, finding.Finding{File: "b.tf", Line: 2}, "b.tf", "https://h/o/r/blob/s/b.tf#L2"},
		{"line zero", Source{BlobURL: "https://h/o/r/blob/s"}, finding.Finding{File: "b.tf"}, "b.tf", "https://h/o/r/blob/s/b.tf"},
		{"empty file", Source{Prefix: "infra", BlobURL: "https://h/o/r/blob/s"}, finding.Finding{Line: 3}, "", ""},
		{"no blob url", Source{Prefix: "infra"}, finding.Finding{File: "b.tf", Line: 3}, "infra/b.tf", ""},
		{"special chars", Source{BlobURL: "https://h/o/r/blob/s"}, finding.Finding{File: "a b/c(d)#e?.tf", Line: 9}, "a b/c(d)#e?.tf", "https://h/o/r/blob/s/a%20b/c%28d%29%23e%3F.tf#L9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.src.Path(tt.f); got != tt.wantPath {
				t.Errorf("Path = %q, want %q", got, tt.wantPath)
			}
			if got := tt.src.URL(tt.f); got != tt.wantURL {
				t.Errorf("URL = %q, want %q", got, tt.wantURL)
			}
		})
	}
}
