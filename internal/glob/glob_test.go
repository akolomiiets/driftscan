package glob

import "testing"

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"**", "a/b/c", true},
		{"**", "", true},
		{"envs/*", "envs/prod", true},
		{"envs/*", "envs/prod/vpc", false},
		{"envs/**", "envs/prod/vpc", true},
		{"envs/**", "envs", true},
		{"**/examples/**", "modules/x/examples/basic", true},
		{"**/examples/**", "examples", true},
		{"**/test*/**", "a/tests/b", true},
		{"**/test*/**", "a/contest/b", false},
		{"envs/*/0?-vpc", "envs/dev/01-vpc", true},
		{"[", "[", true},
	}
	for _, c := range cases {
		if got := MatchPath(c.pattern, c.name); got != c.want {
			t.Errorf("MatchPath(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestMatchDotted(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"tags", "tags", true},
		{"tags.**", "tags.Name", true},
		{"tags.*", "tags", false},
		{"aws_iam_*", "aws_iam_role", true},
		{"*security_group*", "aws_vpc_security_group_ingress_rule", true},
		{"ingress[0]", "ingress[0]", true},
		{"ingress[0]", "ingress0", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name, '.'); got != c.want {
			t.Errorf("Match(%q, %q, '.') = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
