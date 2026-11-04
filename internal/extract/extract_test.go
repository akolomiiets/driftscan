package extract

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/hclroot"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func byAddr(fs []finding.Finding) map[string]finding.Finding {
	m := map[string]finding.Finding{}
	for _, f := range fs {
		m[f.Address] = f
	}
	return m
}

func info() hclroot.Info {
	return hclroot.Info{IgnoreChanges: map[string][]string{
		"aws_instance.app":       {"tags"},
		"aws_security_group.web": {"tags"},
	}}
}

func TestDriftSkipsDataSourcesAndKeepsManaged(t *testing.T) {
	got, err := Drift(load(t, "drift.json"), "envs/dev", info())
	if err != nil {
		t.Fatal(err)
	}
	m := byAddr(got)
	if len(got) != 4 {
		t.Fatalf("got %d findings: %v", len(got), got)
	}
	if _, ok := m["data.aws_caller_identity.me"]; ok {
		t.Error("data source reported as drift")
	}
	for _, f := range got {
		if f.Kind != finding.KindDrift || f.Root != "envs/dev" {
			t.Errorf("bad finding %+v", f)
		}
	}
}

func TestDriftPathsAndAcknowledged(t *testing.T) {
	got, _ := Drift(load(t, "drift.json"), "r", info())
	m := byAddr(got)

	sg := m["aws_security_group.web"]
	want := []string{"ingress[0].cidr_blocks", "tags.Owner"}
	if strings.Join(sg.Paths, ",") != strings.Join(want, ",") {
		t.Errorf("sg paths = %v, want %v", sg.Paths, want)
	}
	if sg.Acknowledged {
		t.Error("sg ingress drift must not be acknowledged by ignore_changes=[tags]")
	}

	app := m["aws_instance.app[0]"]
	if !app.Acknowledged || strings.Join(app.Paths, ",") != "tags.Name" {
		t.Errorf("app = %+v, want acknowledged tags.Name", app)
	}

	rt := m["module.vpc.aws_route_table.private"]
	if strings.Join(rt.Actions, ",") != "delete" || len(rt.Paths) != 0 {
		t.Errorf("deleted resource = %+v", rt)
	}
}

func TestSensitiveValuesNeverLeak(t *testing.T) {
	got, _ := Drift(load(t, "drift.json"), "r", info())
	db := byAddr(got)["aws_db_instance.main"]
	if strings.Join(db.Paths, ",") != "password,settings" {
		t.Errorf("db paths = %v, want password,settings", db.Paths)
	}
	b, _ := json.Marshal(got)
	for _, secret := range []string{"SECRET", "hunter2", "rotated", "10.0.0.0", "0.0.0.0/0", "ami-1"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("output contains value %q: %s", secret, b)
		}
	}
}

func TestPending(t *testing.T) {
	got, err := Pending(load(t, "pending.json"), "r")
	if err != nil {
		t.Fatal(err)
	}
	m := byAddr(got)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if strings.Join(m["aws_s3_bucket.logs"].Actions, ",") != "create" {
		t.Errorf("bucket = %+v", m["aws_s3_bucket.logs"])
	}
	role := m["aws_iam_role.ci"]
	if role.Kind != finding.KindPending || strings.Join(role.Paths, ",") != "arn,max_session_duration" {
		t.Errorf("role = %+v", role)
	}
}

func TestDepthCap(t *testing.T) {
	c := map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": 1}}}}
	d := map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": 2}}}}
	set := map[string]bool{}
	diff(c, d, nil, nil, nil, set)
	if !set["a.b.c"] || len(set) != 1 {
		t.Errorf("paths = %v, want a.b.c", set)
	}
}

func TestOddKeysAreQuoted(t *testing.T) {
	set := map[string]bool{}
	diff(map[string]any{"tags": map[string]any{"kubernetes.io/role": "a"}},
		map[string]any{"tags": map[string]any{"kubernetes.io/role": "b"}}, nil, nil, nil, set)
	if !set[`tags["kubernetes.io/role"]`] {
		t.Errorf("paths = %v", set)
	}
}

func TestBadJSON(t *testing.T) {
	if _, err := Drift([]byte("{"), "r", info()); err == nil {
		t.Error("want error")
	}
}

func TestDriftReasons(t *testing.T) {
	got, err := Drift(load(t, "not_reverted.json"), "r", hclroot.Info{
		IgnoreChanges: map[string][]string{"aws_instance.ignored": {"tags"}, "aws_instance.ignorereplace": {"tags"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := byAddr(got)

	tests := []struct {
		addr   string
		acked  bool
		reason string
		paths  string
	}{
		{"aws_security_group.rules", true, finding.AckNotReverted, "ingress[0].cidr_blocks"},
		{"module.iam.aws_iam_role.svc[0]", true, finding.AckNotReverted, "inline_policy[0].policy"},
		{"aws_lambda_function.fn", false, "", "environment[0]"},
		{"aws_s3_bucket.tagged", false, "", "policy,tags_all.A"},
		{"aws_db_instance.partial", false, "", "latest_restorable_time,port"},
		{"aws_route_table.gone", false, "", ""},
		{"aws_instance.ignored", true, finding.AckIgnoreChanges, "tags.A"},
		{"aws_instance.replaced", true, finding.AckNotReverted, "arn"},
		{"aws_instance.forgotten", true, finding.AckNotReverted, "arn"},
		{"aws_instance.ignorereplace", false, "", "tags.A"},
		{"aws_instance.codedel", true, finding.AckNotReverted, "arn"},
		{"aws_instance.codedelnomod", true, finding.AckNotReverted, "arn"},
		{"aws_instance.delnoreason", false, "", "arn"},
		{"aws_instance.repreq", true, finding.AckNotReverted, "arn"},
		{"aws_instance.reptrig", true, finding.AckNotReverted, "arn"},
		{"aws_instance.repreqoverlap", false, "", "arn"},
		{"aws_instance.repcu", true, finding.AckNotReverted, "arn"},
		{"aws_instance.repcuoverlap", false, "", "arn"},
		{"aws_instance.repcuempty", false, "", "arn"},
		{"aws_instance.reptainted", false, "", "arn"},
		{"aws_security_group.setpending", false, "", "rule[1].cidr"},
		{"aws_security_group.setother", true, finding.AckNotReverted, "rule[1].cidr"},
	}
	for _, tc := range tests {
		f, ok := m[tc.addr]
		if !ok {
			t.Errorf("%s: no finding", tc.addr)
			continue
		}
		if f.Acknowledged != tc.acked || f.AckReason != tc.reason || strings.Join(f.Paths, ",") != tc.paths {
			t.Errorf("%s = acked %v reason %q paths %v, want %v %q %s", tc.addr, f.Acknowledged, f.AckReason, f.Paths, tc.acked, tc.reason, tc.paths)
		}
	}
}

func TestNotRevertedNeverLeaks(t *testing.T) {
	got, _ := Drift(load(t, "not_reverted.json"), "r", hclroot.Info{})
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "0.0.0.0/0") {
		t.Errorf("output contains a value: %s", b)
	}
}

func TestOverlap(t *testing.T) {
	tests := []struct {
		drift, planned string
		want           bool
	}{
		{"ingress[0].cidr_blocks", "ingress[0]", true},
		{"ingress[0]", "ingress[0].cidr_blocks", true},
		{"tags.A", "tags.A", true},
		{"tags.A", "tags.B", false},
		{"tags", "tags_all", false},
	}
	for _, tc := range tests {
		if got := covered(tc.drift, []string{tc.planned}) || covered(tc.planned, []string{tc.drift}); got != tc.want {
			t.Errorf("overlap(%q, %q) = %v, want %v", tc.drift, tc.planned, got, tc.want)
		}
	}
}

func TestDeposedDriftIsSkipped(t *testing.T) {
	got, _ := Drift(load(t, "not_reverted.json"), "r", hclroot.Info{})
	n := 0
	for _, f := range got {
		if f.Address == "aws_instance.replaced" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("got %d findings for the live+deposed address, want 1", n)
	}
}

func TestMissingPlannedChangeIsActionable(t *testing.T) {
	plan := `{"format_version":"1.2","resource_drift":[{"address":"aws_instance.x","mode":"managed","type":"aws_instance","name":"x",
	"change":{"actions":["update"],"before":{"arn":"a"},"after":{"arn":"b"}}}]}`
	got, err := Drift([]byte(plan), "r", hclroot.Info{})
	if err != nil || len(got) != 1 || got[0].Acknowledged {
		t.Errorf("got %+v, %v; want one actionable Finding", got, err)
	}
}

func TestReplacePaths(t *testing.T) {
	raw := []any{[]any{"rule", float64(1), "cidr"}, []any{"tags", "a.b"}, []any{"a", "b", "c", "d"}, "bad", []any{}}
	want := `rule[1].cidr,tags["a.b"],a.b.c`
	if got := strings.Join(replacePaths(raw), ","); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
