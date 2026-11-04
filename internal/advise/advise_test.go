package advise

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/akolomiiets/driftscan/internal/finding"
)

type fakeAdvisor struct {
	mu     sync.Mutex
	system []string
	bodies []string
	reply  func(body string) (string, error)
}

func (f *fakeAdvisor) Complete(_ context.Context, system, user string) (string, error) {
	f.mu.Lock()
	f.system = append(f.system, system)
	f.bodies = append(f.bodies, user)
	f.mu.Unlock()
	return f.reply(user)
}

func drift(root, addr string, sev finding.Severity) finding.Finding {
	return finding.Finding{Root: root, Address: addr, Type: "aws_instance", Kind: finding.KindDrift,
		Paths: []string{"instance_type"}, Severity: sev, Status: finding.StatusNew}
}

// echoAll answers every finding in the request with a valid adopt note.
func echoAll(body string) (string, error) {
	var req request
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return "", err
	}
	var out []answer
	for _, f := range req.Findings {
		out = append(out, answer{Address: f.Address, Kind: f.Kind, Note: "console hotfix likely", Action: "adopt"})
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}

func TestRequestBodyIsBuiltOnlyFromReportFields(t *testing.T) {
	f := finding.Finding{
		Root: "envs/prod", Address: "aws_db_instance.main", Type: "aws_db_instance", Kind: finding.KindDrift,
		Actions: []string{"SECRET-ACTION"}, Paths: []string{"password"}, Severity: finding.SeverityHigh,
		Status: finding.StatusNew, Acknowledged: true, Message: "SECRET-MESSAGE", File: "secret/file.tf", Line: 4242,
		Owner: "@team-db", OwnerSource: "SECRET-SOURCE",
	}

	body, err := BuildRequest("envs/prod", []finding.Finding{f})
	if err != nil {
		t.Fatal(err)
	}

	var generic struct {
		Root     string                       `json:"root"`
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"address": true, "type": true, "kind": true, "paths": true, "severity": true, "acknowledged": true, "owner": true}
	for k := range generic.Findings[0] {
		if !allowed[k] {
			t.Errorf("request carries field %q that is not an allowed Report field", k)
		}
	}
	for _, leak := range []string{"SECRET-ACTION", "SECRET-MESSAGE", "secret/file.tf", "4242", "SECRET-SOURCE"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("request body leaks %q: %s", leak, body)
		}
	}
	want := `{"root":"envs/prod","findings":[{"address":"aws_db_instance.main","type":"aws_db_instance","kind":"drift","paths":["password"],"severity":"high","acknowledged":true,"owner":"@team-db"}]}`
	if string(body) != want {
		t.Errorf("body = %s\nwant   %s", body, want)
	}
}

func TestRunSendsOnlyReportFieldsToAdvisor(t *testing.T) {
	r := finding.Report{Findings: []finding.Finding{drift("a", "aws_instance.x", finding.SeverityHigh)}}
	r.Findings[0].Message = "SECRET-MESSAGE"
	r.Findings[0].File = "secret/file.tf"
	fa := &fakeAdvisor{reply: echoAll}

	Run(context.Background(), fa, &r, Options{MaxFindings: 50})

	if len(fa.bodies) != 1 || strings.Contains(fa.bodies[0], "SECRET") || strings.Contains(fa.bodies[0], "secret/file.tf") {
		t.Errorf("bodies = %v", fa.bodies)
	}
}

func TestRunBatchesPerRootAtFifteen(t *testing.T) {
	var fs []finding.Finding
	for i := range 35 {
		fs = append(fs, drift("a", "aws_instance.a"+string(rune('A'+i%26))+string(rune('a'+i/26)), finding.SeverityHigh))
	}
	fs = append(fs, drift("b", "aws_instance.b", finding.SeverityHigh))
	r := finding.Report{Findings: fs}
	fa := &fakeAdvisor{reply: echoAll}

	res := Run(context.Background(), fa, &r, Options{MaxFindings: 100})

	if len(fa.bodies) != 4 {
		t.Fatalf("requests = %d, want 4 (15 + 15 + 5 for root a, 1 for root b)", len(fa.bodies))
	}
	if res.Advised != 36 || res.Sent != 36 {
		t.Errorf("result = %+v", res)
	}
	if r.Findings[0].Advice != "console hotfix likely" || r.Findings[0].AdviceAction != "adopt" {
		t.Errorf("finding 0 = %+v", r.Findings[0])
	}
}

func TestRunSkipsInfoAcknowledgedScanErrorAndResolved(t *testing.T) {
	info := drift("a", "aws_instance.info", finding.SeverityInfo)
	ack := drift("a", "aws_instance.ack", finding.SeverityHigh)
	ack.Acknowledged = true
	errF := finding.Finding{Root: "a", Kind: finding.KindScanError, Severity: finding.SeverityHigh, Message: "boom"}
	resolved := drift("a", "aws_instance.gone", finding.SeverityHigh)
	resolved.Status = finding.StatusResolved
	ok := drift("a", "aws_instance.ok", finding.SeverityLow)
	r := finding.Report{Findings: []finding.Finding{info, ack, errF, resolved, ok}}
	fa := &fakeAdvisor{reply: echoAll}

	res := Run(context.Background(), fa, &r, Options{MaxFindings: 50})

	if res.Sent != 1 || res.Skipped != 2 {
		t.Errorf("result = %+v, want 1 sent and 2 skipped", res)
	}
	if strings.Contains(fa.bodies[0], "info") && strings.Contains(fa.bodies[0], "aws_instance.info") {
		t.Errorf("info finding sent: %s", fa.bodies[0])
	}

	res = Run(context.Background(), &fakeAdvisor{reply: echoAll}, &r, Options{MaxFindings: 50, IncludeInfo: true, IncludeAcknowledged: true})
	if res.Sent != 2 {
		t.Errorf("with includes sent = %d, want 2 (info and acknowledged; the advised one is skipped)", res.Sent)
	}
}

func TestRunCapsTotalFindingsKeepingMostSevere(t *testing.T) {
	r := finding.Report{Findings: []finding.Finding{
		drift("a", "aws_instance.low", finding.SeverityLow),
		drift("b", "aws_instance.crit", finding.SeverityCritical),
		drift("a", "aws_instance.high", finding.SeverityHigh),
	}}
	fa := &fakeAdvisor{reply: echoAll}

	res := Run(context.Background(), fa, &r, Options{MaxFindings: 2})

	if res.Sent != 2 || res.Skipped != 1 {
		t.Errorf("result = %+v", res)
	}
	if r.Findings[0].Advice != "" || r.Findings[1].Advice == "" || r.Findings[2].Advice == "" {
		t.Errorf("advice set on wrong findings: %+v", r.Findings)
	}
}

func TestParseDropsMalformedAnswers(t *testing.T) {
	long := strings.Repeat("x", 500)
	text := "```json\n[" +
		`{"address":"a","kind":"drift","note":"good","action":"revert"},` +
		`{"address":"b","kind":"drift","note":"bad action","action":"delete"},` +
		`{"address":"","kind":"drift","note":"no address","action":"adopt"},` +
		`{"address":"c","kind":"drift","note":"","action":"adopt"},` +
		`{"address":"d","kind":"drift","note":"` + long + `","action":"ignore","ignore_rule":"` + "```yaml\\ntype: aws_instance" + `"},` +
		`{"address":"e","kind":"drift","note":"rule dropped","action":"adopt","ignore_rule":"type: x"},` +
		`"not an object"` +
		"]\n```"

	got, dropped, err := parse(text)

	if err != nil || dropped != 4 || len(got) != 3 {
		t.Fatalf("got %d answers, %d dropped: %+v", len(got), dropped, got)
	}
	if len([]rune(got[1].Note)) != MaxNoteLen || !strings.HasSuffix(got[1].Note, "...") {
		t.Errorf("note not capped: len %d", len([]rune(got[1].Note)))
	}
	if got[1].IgnoreRule != "yaml\ntype: aws_instance" {
		t.Errorf("ignore_rule = %q", got[1].IgnoreRule)
	}
	if got[2].IgnoreRule != "" {
		t.Errorf("ignore_rule kept for non-ignore action: %q", got[2].IgnoreRule)
	}
}

func TestParseRejectsNonJSON(t *testing.T) {
	for _, text := range []string{"", "I cannot help", "[not json]", "] ["} {
		got, _, err := parse(text)
		if len(got) != 0 || err == nil {
			t.Errorf("parse(%q) = %v, %v", text, got, err)
		}
	}
}

func TestRunDropsAnswersForUnknownFindings(t *testing.T) {
	r := finding.Report{Findings: []finding.Finding{drift("a", "aws_instance.x", finding.SeverityHigh)}}
	fa := &fakeAdvisor{reply: func(string) (string, error) {
		return `[{"address":"aws_instance.other","kind":"drift","note":"n","action":"adopt"},{"address":"aws_instance.x","kind":"pending","note":"n","action":"adopt"}]`, nil
	}}

	res := Run(context.Background(), fa, &r, Options{MaxFindings: 50})

	if res.Advised != 0 || res.Dropped != 2 || r.Findings[0].Advice != "" {
		t.Errorf("result = %+v, finding = %+v", res, r.Findings[0])
	}
}

func TestRunKeepsGoingAfterRequestError(t *testing.T) {
	r := finding.Report{Findings: []finding.Finding{
		drift("a", "aws_instance.x", finding.SeverityHigh),
		drift("b", "aws_instance.y", finding.SeverityHigh),
	}}
	fa := &fakeAdvisor{reply: func(body string) (string, error) {
		if strings.Contains(body, `"root":"a"`) {
			return "", errors.New("throttled")
		}
		return echoAll(body)
	}}

	res := Run(context.Background(), fa, &r, Options{MaxFindings: 50})

	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Error(), "throttled") {
		t.Errorf("errors = %v", res.Errors)
	}
	if r.Findings[0].Advice != "" || r.Findings[1].Advice == "" {
		t.Errorf("findings = %+v", r.Findings)
	}
}

func TestParseAcceptsIgnoreRuleAsObjectOrString(t *testing.T) {
	text := `[{"address":"a","kind":"drift","note":"n","action":"ignore","ignore_rule":{"type":"aws_instance","attribute":"tags","reason":"asg"}},` +
		`{"address":"b","kind":"drift","note":"n","action":"ignore","ignore_rule":"type: x"},` +
		`{"address":"c","kind":"drift","note":"n","action":"ignore","ignore_rule":42}]`

	got, dropped, err := parse(text)

	if err != nil || dropped != 0 || len(got) != 3 {
		t.Fatalf("got %d answers, %d dropped, %v", len(got), dropped, err)
	}
	if got[0].IgnoreRule != "attribute: tags\nreason: asg\ntype: aws_instance" {
		t.Errorf("object rule = %q", got[0].IgnoreRule)
	}
	if got[1].IgnoreRule != "type: x" || got[2].IgnoreRule != "" {
		t.Errorf("rules = %q, %q", got[1].IgnoreRule, got[2].IgnoreRule)
	}
}

func TestParseFallsBackToBracketSlice(t *testing.T) {
	text := `Here you go: [{"address":"a","kind":"drift","note":"n","action":"adopt"}] hope it helps`

	got, _, err := parse(text)

	if err != nil || len(got) != 1 || got[0].Address != "a" {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestRunCountsWholeBatchDroppedWhenOutputUnparseable(t *testing.T) {
	r := finding.Report{Findings: []finding.Finding{
		drift("a", "aws_instance.x", finding.SeverityHigh),
		drift("a", "aws_instance.y", finding.SeverityHigh),
	}}
	fa := &fakeAdvisor{reply: func(string) (string, error) { return "sorry", nil }}

	res := Run(context.Background(), fa, &r, Options{MaxFindings: 50})

	if res.Dropped != 2 || res.Advised != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestRunSkipsFindingsThatAlreadyHaveAdvice(t *testing.T) {
	done := drift("a", "aws_instance.x", finding.SeverityHigh)
	done.Advice = "earlier note"
	r := finding.Report{Findings: []finding.Finding{done}}
	fa := &fakeAdvisor{reply: echoAll}

	res := Run(context.Background(), fa, &r, Options{MaxFindings: 50})

	if res.Sent != 0 || res.Skipped != 1 || len(fa.bodies) != 0 {
		t.Errorf("result = %+v, bodies = %v", res, fa.bodies)
	}
}

func TestRunGivesEachBatchADeadline(t *testing.T) {
	r := finding.Report{Findings: []finding.Finding{drift("a", "aws_instance.x", finding.SeverityHigh)}}
	var hasDeadline bool
	a := deadlineAdvisor{seen: &hasDeadline}

	Run(context.Background(), a, &r, Options{MaxFindings: 50})

	if !hasDeadline {
		t.Error("batch context has no deadline")
	}
}

type deadlineAdvisor struct{ seen *bool }

func (d deadlineAdvisor) Complete(ctx context.Context, _, _ string) (string, error) {
	_, *d.seen = ctx.Deadline()
	return "[]", nil
}
