package enrich

import (
	"testing"
	"testing/fstest"

	"github.com/akolomiiets/driftscan/internal/finding"
)

const co = `# comment
*                  @org/platform
/terraform/envs/   @org/infra   # trailing comment
envs/prod/**       @org/sre @alice
*.md               @org/docs
legacy/            
`

func TestCodeownersLastMatchWins(t *testing.T) {
	c := ParseCodeowners([]byte(co))
	cases := map[string]string{
		"README.tf":                        "@org/platform",
		"terraform/envs/dev/main.tf":       "@org/infra",
		"terraform/envs/prod/vpc/main.tf":  "@org/infra",
		"envs/prod/vpc/main.tf":            "@org/sre @alice",
		"docs/x.md":                        "@org/docs",
		"terraform/legacy/old/main.tf":     "",
		"other/terraform/envs/dev/main.tf": "@org/platform",
	}
	for p, want := range cases {
		got := ""
		if o := c.Owners(p); o != nil {
			got = o[0]
			if len(o) > 1 {
				got += " " + o[1]
			}
		}
		if got != want {
			t.Errorf("%s: owners %q, want %q", p, got, want)
		}
	}
}

func TestOwnersPrefersCodeownersThenGit(t *testing.T) {
	repo := fstest.MapFS{".github/CODEOWNERS": {Data: []byte("/terraform/envs/prod/ @org/sre\n")}}
	c, err := LoadCodeowners(repo)
	if err != nil {
		t.Fatal(err)
	}
	r := finding.Report{Findings: []finding.Finding{
		{Root: "envs/prod/vpc", File: "envs/prod/vpc/main.tf"},
		{Root: "envs/dev/vpc@blue"},
		{Root: "envs/dev/vpc@green"},
	}}
	calls := 0
	git := func(dir string) string {
		calls++
		if dir != "terraform/envs/dev/vpc" {
			t.Errorf("git asked for %q", dir)
		}
		return "bob@example.com"
	}
	r = Owners(r, c, "terraform", git)
	if f := r.Findings[0]; f.Owner != "@org/sre" || f.OwnerSource != "codeowners" {
		t.Errorf("prod = %q/%q", f.Owner, f.OwnerSource)
	}
	if f := r.Findings[1]; f.Owner != "bob@example.com" || f.OwnerSource != "git" {
		t.Errorf("dev = %q/%q", f.Owner, f.OwnerSource)
	}
	if calls != 1 {
		t.Errorf("git called %d times, want 1 (cached per dir)", calls)
	}
}

func TestNoCodeownersIsNotAnError(t *testing.T) {
	c, err := LoadCodeowners(fstest.MapFS{})
	if err != nil || c != nil {
		t.Fatalf("c=%v err=%v", c, err)
	}
}

func TestCodeownersDirectoryStyleOnlyWithoutTrailingWildcard(t *testing.T) {
	c := ParseCodeowners([]byte("envs/*  @org/star\nlib/net  @org/net\n/apps/  @org/apps\n"))
	cases := map[string]string{
		"envs/main.tf":      "@org/star",
		"envs/prod":         "@org/star",
		"envs/prod/main.tf": "",
		"lib/net/a/b.tf":    "@org/net",
		"apps/x/y/main.tf":  "@org/apps",
	}
	for p, want := range cases {
		got := ""
		if o := c.Owners(p); o != nil {
			got = o[0]
		}
		if got != want {
			t.Errorf("%s: owners %q, want %q", p, got, want)
		}
	}
}
