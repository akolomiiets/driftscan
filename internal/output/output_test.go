package output

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
)

func sample() finding.Report {
	return finding.Report{
		Version: 1, Compared: true, Duration: 3 * time.Second,
		Roots: []finding.RootResult{
			{Path: "envs/prod/net", Outcome: finding.RootDrifted},
			{Path: "envs/prod/iam", Outcome: finding.RootError, FailCount: 1},
		},
		Findings: []finding.Finding{
			{Root: "envs/prod/net", Address: "aws_security_group.web", Type: "aws_security_group", Kind: finding.KindDrift,
				Actions: []string{"update"}, Paths: []string{"ingress[0].cidr_blocks"}, Severity: finding.SeverityHigh,
				Status: finding.StatusNew, SeenCount: 1, File: "envs/prod/net/sg.tf", Line: 12},
			{Root: "envs/prod/net", Address: "aws_instance.app", Type: "aws_instance", Kind: finding.KindDrift,
				Paths: []string{"tags.Name"}, Severity: finding.SeverityInfo, Status: finding.StatusPersisting, SeenCount: 4},
			{Root: "envs/prod/net", Address: "aws_s3_bucket.old", Type: "aws_s3_bucket", Kind: finding.KindDrift,
				Severity: finding.SeverityMedium, Status: finding.StatusResolved},
			{Root: "envs/prod/net", Address: "aws_iam_role.ci", Type: "aws_iam_role", Kind: finding.KindPending,
				Actions: []string{"update"}, Paths: []string{"max_session_duration"}, Severity: finding.SeverityInfo, Status: finding.StatusNew},
			{Root: "envs/prod/iam", Kind: finding.KindScanError, Severity: finding.SeverityHigh, Status: finding.StatusNew,
				Message: "Error: No valid credential sources found", File: "envs/prod/iam/backend.tf", Line: 2},
		},
	}
}

func TestMarkdown(t *testing.T) {
	md := Markdown(sample())
	for _, want := range []string{
		"2 Roots scanned, 1 with Drift. **2 Drift**, 1 Pending changes, 1 Scan errors, 0 acknowledged, 1 resolved.",
		"### Scan errors (1)",
		"### Drift (2)",
		"| high | new | `envs/prod/net` | `aws_security_group.web` | `ingress[0].cidr_blocks` |",
		"| info | persisting (4 scans) |",
		"### Resolved since last Scan (1)",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n%s", want, md)
		}
	}
	first := sample()
	first.Compared = false
	if !strings.Contains(Markdown(first), "No Baseline") {
		t.Error("first scan note missing")
	}
}

func TestSARIF(t *testing.T) {
	b, err := SARIF(sample(), "v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }     `json:"artifactLocation"`
						Region           *struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	res := doc.Runs[0].Results
	if doc.Version != "2.1.0" || len(res) != 4 {
		t.Fatalf("version %s, %d results (resolved must be excluded)", doc.Version, len(res))
	}
	if res[0].RuleID != "drift" || res[0].Level != "error" ||
		res[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "envs/prod/net/sg.tf" ||
		res[0].Locations[0].PhysicalLocation.Region.StartLine != 12 {
		t.Errorf("first result = %+v", res[0])
	}
	if res[1].Level != "note" || res[1].Locations[0].PhysicalLocation.ArtifactLocation.URI != "envs/prod/net/" {
		t.Errorf("info result = %+v", res[1])
	}
	if res[3].RuleID != "scan-error" || res[0].PartialFingerprints["driftscanKey/v1"] == "" {
		t.Errorf("results = %+v", res)
	}
}

func TestSlackMessages(t *testing.T) {
	r := sample()
	alerts := []finding.Finding{r.Findings[0], r.Findings[2], r.Findings[4]}
	msgs := SlackMessages(r, alerts, "scan", "https://ci/run/1")
	if len(msgs) != 1 {
		t.Fatalf("msgs = %v", msgs)
	}
	for _, want := range []string{"2 new, 1 resolved", ":red_circle: [high] `envs/prod/net` drift `aws_security_group.web`: ingress[0].cidr_blocks", "*scan error* Error: No valid", "<https://ci/run/1|run>"} {
		if !strings.Contains(msgs[0], want) {
			t.Errorf("missing %q in\n%s", want, msgs[0])
		}
	}
	if byRoot := SlackMessages(r, alerts, "root", ""); len(byRoot) != 2 || !strings.Contains(byRoot[0], "`envs/prod/iam`") {
		t.Errorf("by root = %v", byRoot)
	}
	if none := SlackMessages(r, nil, "scan", ""); none != nil {
		t.Errorf("no alerts should send nothing: %v", none)
	}
	first := sample()
	first.Compared = false
	if m := SlackMessages(first, nil, "scan", ""); len(m) != 1 || !strings.Contains(m[0], "baseline established: 2 Drift") {
		t.Errorf("first = %v", m)
	}
}

func TestSlackTruncates(t *testing.T) {
	var alerts []finding.Finding
	for i := 0; i < MaxSlackLines+5; i++ {
		alerts = append(alerts, finding.Finding{Root: "r", Address: "a", Kind: finding.KindDrift, Status: finding.StatusNew})
	}
	msgs := SlackMessages(finding.Report{Compared: true}, alerts, "scan", "")
	if !strings.Contains(msgs[0], "+5 more") {
		t.Errorf("no truncation: %s", msgs[0])
	}
}

func TestPostSlackAndOTLP(t *testing.T) {
	var got []string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		auth = r.Header.Get("Authorization")
		if strings.Contains(string(b), "fail") {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	if err := PostSlack(context.Background(), srv.Client(), srv.URL, []string{"hello"}); err != nil {
		t.Fatal(err)
	}
	if got[0] != `{"text":"hello"}` {
		t.Errorf("slack body = %s", got[0])
	}
	if err := PostSlack(context.Background(), srv.Client(), srv.URL, []string{"fail"}); err == nil {
		t.Error("want HTTP error")
	}

	payload := OTLPMetrics(sample(), time.Unix(100, 0))
	if err := PostOTLP(context.Background(), srv.Client(), srv.URL, "Authorization=Basic abc, x=y", payload); err != nil {
		t.Fatal(err)
	}
	if auth != "Basic abc" {
		t.Errorf("auth header = %q", auth)
	}
	body := got[len(got)-1]
	for _, want := range []string{`"name":"driftscan.findings"`, `"asInt":"1"`, `"stringValue":"envs/prod/iam"`, `"name":"driftscan.root.up"`, `"asInt":"0"`, `"timeUnixNano":"100000000000"`} {
		if !strings.Contains(body, want) {
			t.Errorf("otlp missing %s", want)
		}
	}
	if strings.Contains(body, "aws_s3_bucket.old") || strings.Contains(body, `"status"`+":"+`"resolved"`) {
		t.Error("resolved findings must not be counted")
	}
}

func TestOwnerShownWhenEnriched(t *testing.T) {
	r := finding.Report{Compared: true, Findings: []finding.Finding{
		{Root: "a", Address: "aws_s3_bucket.b", Kind: finding.KindDrift, Paths: []string{"acl"}, Status: finding.StatusNew, Owner: "@org/sre"},
		{Root: "a", Address: "aws_s3_bucket.c", Kind: finding.KindDrift, Paths: []string{"acl"}, Status: finding.StatusNew},
	}}
	md := Markdown(r)
	if !strings.Contains(md, "| Owner |") || !strings.Contains(md, "| @org/sre |") || !strings.Contains(md, "| - |") {
		t.Errorf("markdown missing owner column:\n%s", md)
	}
	msgs := SlackMessages(r, r.Findings, "scan", "")
	if !strings.Contains(msgs[0], "acl - @org/sre") {
		t.Errorf("slack missing owner: %s", msgs[0])
	}
	if strings.Contains(Markdown(finding.Report{Findings: r.Findings[1:]}), "Owner") {
		t.Error("owner column shown without any owner")
	}
}

func TestChangedByShownInMarkdownAndSlack(t *testing.T) {
	r := finding.Report{Findings: []finding.Finding{
		{Root: "a", Address: "aws_s3_bucket.b", Kind: finding.KindDrift, Paths: []string{"acl"}, Status: finding.StatusNew, Owner: "@org/sre", ChangedBy: "alice"},
	}}

	md := Markdown(r)
	if !strings.Contains(md, "| Owner | Changed by |") || !strings.Contains(md, "| @org/sre | alice |") {
		t.Errorf("markdown missing Changed by column:\n%s", md)
	}
	r.Findings[0].ChangedBy = ""
	if strings.Contains(Markdown(r), "Changed by") {
		t.Error("Changed by column shown without any actor")
	}
	if line := slackLine(finding.Finding{Root: "a", Address: "x", Kind: finding.KindDrift, Paths: []string{"acl"}, Owner: "o", ChangedBy: "alice"}, false); !strings.HasSuffix(line, "- o - changed by alice") {
		t.Errorf("slack line = %q", line)
	}
}

func TestAdviceShownAndLabelled(t *testing.T) {
	r := sample()
	r.Findings[0].Advice = "Likely console hotfix."
	r.Findings[0].AdviceAction = "ignore"
	r.Findings[0].AdviceIgnoreRule = "type: aws_security_group\nreason: managed"

	md := Markdown(r)
	if !strings.Contains(md, "AI-generated advice (1)") || !strings.Contains(md, "Likely console hotfix.") ||
		!strings.Contains(md, "  type: aws_security_group") {
		t.Errorf("markdown missing advice:\n%s", md)
	}
	slack := SlackMessages(r, r.Findings[:1], "scan", "")[0]
	if !strings.Contains(slack, "[AI: ignore]") {
		t.Errorf("slack missing tag: %s", slack)
	}
	if strings.Contains(Markdown(sample()), "AI-generated") {
		t.Error("advice block shown without advice")
	}
}

func TestAdviceIsHTMLEscaped(t *testing.T) {
	r := sample()
	r.Findings[0].Advice = "<img src=x onerror=1>"
	r.Findings[0].AdviceAction = "ignore"
	r.Findings[0].AdviceIgnoreRule = "reason: <b>x</b>"

	md := Markdown(r)

	if strings.Contains(md, "<img") || strings.Contains(md, "<b>") || !strings.Contains(md, "&lt;img src=x") || !strings.Contains(md, "reason: &lt;b&gt;x") {
		t.Errorf("advice not escaped:\n%s", md)
	}
}

func TestAcknowledgedShowsReason(t *testing.T) {
	r := finding.Report{Compared: true, Findings: []finding.Finding{
		{Root: "a", Address: "aws_security_group.x", Kind: finding.KindDrift, Paths: []string{"ingress[0].cidr_blocks"}, Status: finding.StatusNew, Acknowledged: true, AckReason: finding.AckNotReverted},
		{Root: "a", Address: "aws_s3_bucket.y", Kind: finding.KindDrift, Paths: []string{"tags.A"}, Status: finding.StatusNew, Acknowledged: true},
	}}
	md := Markdown(r)
	for _, want := range []string{"### Acknowledged (2)", "| Reason |", "| not reverted by apply |", "| covered by lifecycle.ignore_changes |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestSARIFAckMessageFollowsReason(t *testing.T) {
	base := finding.Finding{Root: "a", Address: "x.y", Kind: finding.KindDrift, Paths: []string{"p"}, Acknowledged: true}
	for reason, want := range map[string]string{
		"":                       "(covered by lifecycle.ignore_changes)",
		finding.AckIgnoreChanges: "(covered by lifecycle.ignore_changes)",
		finding.AckNotReverted:   "(not reverted by apply)",
	} {
		f := base
		f.AckReason = reason
		if got := sarifMessage(f); !strings.HasSuffix(got, want) {
			t.Errorf("reason %q: %q, want suffix %q", reason, got, want)
		}
	}
}
