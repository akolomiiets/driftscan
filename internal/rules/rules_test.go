package rules

import (
	"testing"
	"time"

	"github.com/akolomiiets/driftscan/internal/config"
	"github.com/akolomiiets/driftscan/internal/finding"
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func drift(typ, addr string, paths ...string) finding.Finding {
	return finding.Finding{Root: "envs/prod/net", Type: typ, Address: addr, Kind: finding.KindDrift, Paths: paths}
}

func mustCfg(t *testing.T, y string) config.Config {
	t.Helper()
	c, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDefaultSeverities(t *testing.T) {
	cases := []struct {
		f    finding.Finding
		want finding.Severity
	}{
		{drift("aws_iam_role", "aws_iam_role.a", "assume_role_policy"), finding.SeverityHigh},
		{drift("aws_security_group", "aws_security_group.a", "ingress"), finding.SeverityHigh},
		{drift("aws_vpc_security_group_ingress_rule", "x.a", "cidr_ipv4"), finding.SeverityHigh},
		{drift("aws_instance", "aws_instance.a", "instance_type"), finding.SeverityMedium},
		{drift("aws_instance", "aws_instance.a", "tags.Name", "tags_all.Name"), finding.SeverityInfo},
		{drift("aws_iam_role", "aws_iam_role.a", "tags.Owner"), finding.SeverityInfo},
		{drift("aws_instance", "aws_instance.a", "tags.Name", "instance_type"), finding.SeverityMedium},
		{drift("aws_instance", "aws_instance.a"), finding.SeverityMedium},
		{drift("google_project_iam_member", "x.a", "role"), finding.SeverityHigh},
		{drift("azurerm_network_security_rule", "x.a", "access"), finding.SeverityHigh},
	}
	for _, c := range cases {
		got := Apply([]finding.Finding{c.f}, config.Default(), now)
		if len(got) != 1 || got[0].Severity != c.want {
			t.Errorf("%s %v: got %v, want %v", c.f.Type, c.f.Paths, got, c.want)
		}
	}
}

func TestAcknowledgedIsInfo(t *testing.T) {
	f := drift("aws_iam_role", "aws_iam_role.a", "description")
	f.Acknowledged = true
	if got := Apply([]finding.Finding{f}, config.Default(), now); got[0].Severity != finding.SeverityInfo {
		t.Errorf("got %v", got[0].Severity)
	}
}

func TestUserRulesOverrideAndDefaultsOff(t *testing.T) {
	cfg := mustCfg(t, `
severity:
  rules:
    - type: aws_instance
      attribute: instance_type
      severity: critical
`)
	got := Apply([]finding.Finding{drift("aws_instance", "aws_instance.a", "instance_type")}, cfg, now)
	if got[0].Severity != finding.SeverityCritical {
		t.Errorf("override: %v", got[0].Severity)
	}

	off := mustCfg(t, "severity:\n  defaults: false\n")
	got = Apply([]finding.Finding{drift("aws_iam_role", "aws_iam_role.a", "x")}, off, now)
	if got[0].Severity != finding.SeverityMedium {
		t.Errorf("defaults off: %v", got[0].Severity)
	}
}

func TestPendingSeverityAndToggle(t *testing.T) {
	p := finding.Finding{Kind: finding.KindPending, Type: "aws_iam_role", Address: "aws_iam_role.a"}
	got := Apply([]finding.Finding{p}, config.Default(), now)
	if got[0].Severity != finding.SeverityInfo {
		t.Errorf("pending default: %v", got[0].Severity)
	}
	cfg := mustCfg(t, `
severity:
  rules:
    - type: "aws_iam_*"
      kind: pending
      severity: high
`)
	if got := Apply([]finding.Finding{p}, cfg, now); got[0].Severity != finding.SeverityHigh {
		t.Errorf("pending rule: %v", got[0].Severity)
	}
	off := mustCfg(t, "pending:\n  enabled: false\n")
	if got := Apply([]finding.Finding{p}, off, now); len(got) != 0 {
		t.Errorf("pending disabled: %v", got)
	}
}

func TestIgnoreRules(t *testing.T) {
	cfg := mustCfg(t, `
ignore:
  - type: aws_autoscaling_group
    attribute: desired_capacity
    reason: scaled by policy
  - address: "aws_instance.legacy*"
    reason: migration TICKET-1
    expires: 2026-11-03
  - root: "envs/prod/**"
    type: aws_lambda_function
    reason: deployed by CI
    expires: 2026-11-02
`)
	in := []finding.Finding{
		drift("aws_autoscaling_group", "aws_autoscaling_group.a", "desired_capacity"),
		drift("aws_autoscaling_group", "aws_autoscaling_group.a", "desired_capacity", "max_size"),
		drift("aws_instance", "aws_instance.legacy_1", "ami"),
		drift("aws_lambda_function", "aws_lambda_function.f", "source_code_hash"),
		{Root: "envs/prod/net", Kind: finding.KindScanError, Severity: finding.SeverityHigh},
	}
	got := Apply(in, cfg, now)
	var addrs []string
	for _, f := range got {
		addrs = append(addrs, f.Address)
	}
	// asg with only desired_capacity: ignored. asg with max_size too: kept.
	// legacy: expires today, still active. lambda: expired yesterday, kept. scan error: kept.
	want := []string{"aws_autoscaling_group.a", "aws_lambda_function.f", ""}
	if len(addrs) != len(want) {
		t.Fatalf("kept %v, want %v", addrs, want)
	}
	for i := range want {
		if addrs[i] != want[i] {
			t.Fatalf("kept %v, want %v", addrs, want)
		}
	}
}

func TestIgnoreReasonRequired(t *testing.T) {
	if _, err := config.Parse([]byte("ignore:\n  - type: x\n")); err == nil {
		t.Error("want error for missing reason")
	}
}
