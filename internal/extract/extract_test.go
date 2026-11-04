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
	got, err := Drift(load(t, "refresh_only.json"), "envs/dev", info())
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
	got, _ := Drift(load(t, "refresh_only.json"), "r", info())
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
	got, _ := Drift(load(t, "refresh_only.json"), "r", info())
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
