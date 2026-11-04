package discover

import (
	"testing"
	"testing/fstest"

	"github.com/akolomiiets/driftscan/internal/config"
)

const backendS3 = `terraform {
  backend "s3" {
    bucket = "b"
    key    = "k"
  }
}
`

const resources = `resource "aws_security_group" "web" {
  name = "web"
  lifecycle {
    ignore_changes = [tags, ingress[0].cidr_blocks, description]
  }
}

resource "aws_instance" "app" {
  lifecycle {
    ignore_changes = all
  }
}

module "vpc" {
  source = "../modules/vpc"
}
`

func tree() fstest.MapFS {
	return fstest.MapFS{
		"envs/dev/vpc/backend.tf":                   {Data: []byte(backendS3)},
		"envs/dev/vpc/main.tf":                      {Data: []byte(resources)},
		"envs/prod/vpc/main.tf":                     {Data: []byte(backendS3 + resources)},
		"envs/prod/cloud/main.tf":                   {Data: []byte("terraform {\n  cloud {\n    organization = \"o\"\n  }\n}\n")},
		"modules/vpc/main.tf":                       {Data: []byte(`resource "aws_vpc" "this" {}`)},
		"modules/vpc/examples/x/main.tf":            {Data: []byte(backendS3)},
		"local/main.tf":                             {Data: []byte(`resource "local_file" "f" {}`)},
		"envs/dev/vpc/.terraform/modules/m/main.tf": {Data: []byte(backendS3)},
	}
}

func paths(rs []Root) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Path)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRootsFindsBackendDirsAndSkipsDefaults(t *testing.T) {
	got, err := Roots(tree(), config.Default())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"envs/dev/vpc", "envs/prod/vpc"}
	if !equal(paths(got), want) {
		t.Fatalf("roots = %v, want %v", paths(got), want)
	}
}

func TestRootsIncludeExcludeAndExplicit(t *testing.T) {
	cfg, err := config.Parse([]byte(`
include: ["envs/**"]
exclude: ["envs/prod/cloud"]
roots: ["local"]
env:
  - match: "envs/prod/**"
    vars: {AWS_PROFILE: production}
  - match: "**"
    vars: {TF_IN_AUTOMATION: "1"}
`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Roots(tree(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"envs/dev/vpc", "envs/prod/vpc", "local"}
	if !equal(paths(got), want) {
		t.Fatalf("roots = %v, want %v", paths(got), want)
	}
	if got[1].Env["AWS_PROFILE"] != "production" || got[1].Env["TF_IN_AUTOMATION"] != "1" {
		t.Errorf("prod env = %v", got[1].Env)
	}
	if _, ok := got[0].Env["AWS_PROFILE"]; ok {
		t.Errorf("dev got prod profile: %v", got[0].Env)
	}
}

func TestRootsExplicitMissingIsError(t *testing.T) {
	cfg, _ := config.Parse([]byte(`roots: ["nope"]`))
	if _, err := Roots(tree(), cfg); err == nil {
		t.Fatal("want error for missing explicit root")
	}
}

func TestInfoLocationsAndIgnoreChanges(t *testing.T) {
	got, err := Roots(tree(), config.Default())
	if err != nil {
		t.Fatal(err)
	}
	info := got[0].Info
	if info.BackendFile.File != "envs/dev/vpc/backend.tf" || info.BackendFile.Line != 2 {
		t.Errorf("backend = %+v", info.BackendFile)
	}
	if loc, ok := info.Locate(`aws_security_group.web`); !ok || loc.File != "envs/dev/vpc/main.tf" || loc.Line != 1 {
		t.Errorf("locate sg = %+v %v", loc, ok)
	}
	if loc, ok := info.Locate(`module.vpc.aws_vpc.this`); !ok || loc.Line != 14 {
		t.Errorf("locate module = %+v %v", loc, ok)
	}
	if _, ok := info.Locate(`aws_s3_bucket.gone`); ok {
		t.Error("unknown resource should not be located")
	}
	ign := info.IgnoredPaths(`aws_security_group.web`)
	if !equal(ign, []string{"description", "ingress[0].cidr_blocks", "tags"}) {
		t.Errorf("ignore_changes = %v", ign)
	}
	if !equal(info.IgnoredPaths(`aws_instance.app["a"]`), []string{"*"}) {
		t.Errorf("ignore all = %v", info.IgnoredPaths(`aws_instance.app["a"]`))
	}
}

func TestShard(t *testing.T) {
	rs := []Root{{Path: "a"}, {Path: "b"}, {Path: "c"}, {Path: "d"}, {Path: "e"}}
	if got := paths(Shard(rs, 1, 2)); !equal(got, []string{"a", "c", "e"}) {
		t.Errorf("shard 1/2 = %v", got)
	}
	if got := paths(Shard(rs, 2, 2)); !equal(got, []string{"b", "d"}) {
		t.Errorf("shard 2/2 = %v", got)
	}
	if got := paths(Shard(rs, 1, 1)); len(got) != 5 {
		t.Errorf("shard 1/1 = %v", got)
	}
}

func TestWorkspacesExpandRoots(t *testing.T) {
	cfg, err := config.Parse([]byte(`
workspaces:
  - match: "envs/**"
    names: [a]
  - match: "envs/prod/**"
    names: [blue, green]
env:
  - match: "envs/prod/vpc@green"
    vars: { AWS_PROFILE: green }
`))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Roots(tree(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"envs/dev/vpc@a", "envs/prod/vpc@blue", "envs/prod/vpc@green"}
	if !equal(paths(rs), want) {
		t.Fatalf("paths = %v, want %v", paths(rs), want)
	}
	g := rs[2]
	if g.Dir != "envs/prod/vpc" || g.Workspace != "green" || g.Env["TF_WORKSPACE"] != "green" || g.Env["AWS_PROFILE"] != "green" {
		t.Errorf("green root = %+v", g)
	}
	if rs[1].Env["AWS_PROFILE"] != "" {
		t.Errorf("blue got green's env: %v", rs[1].Env)
	}
}

func TestWorkspaceNamesValidated(t *testing.T) {
	for _, y := range []string{"workspaces:\n  - match: x\n    names: [\"a@b\"]\n", "workspaces:\n  - match: x\n"} {
		if _, err := config.Parse([]byte(y)); err == nil {
			t.Errorf("no error for %q", y)
		}
	}
}

func TestWorkspaceEnvRulesMatchDirAndDirAtWorkspaceInConfigOrder(t *testing.T) {
	cfg, err := config.Parse([]byte(`
workspaces:
  - match: "envs/prod/vpc"
    names: [blue, green]
env:
  - match: "envs/prod/vpc@green"
    vars: { AWS_PROFILE: green, AWS_REGION: eu-west-1 }
  - match: "envs/prod/vpc"
    vars: { AWS_PROFILE: dir, TF_WORKSPACE: ignored }
`))
	if err != nil {
		t.Fatal(err)
	}

	rs, err := Roots(tree(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	blue, green := rs[1], rs[2]
	if blue.Env["AWS_PROFILE"] != "dir" || blue.Env["AWS_REGION"] != "" {
		t.Errorf("blue env = %v", blue.Env)
	}
	if green.Env["AWS_PROFILE"] != "dir" || green.Env["AWS_REGION"] != "eu-west-1" {
		t.Errorf("green env = %v, want the later dir rule to win over the earlier dir@ws rule", green.Env)
	}
	if blue.Env["TF_WORKSPACE"] != "blue" || green.Env["TF_WORKSPACE"] != "green" {
		t.Errorf("TF_WORKSPACE must be set last: %v / %v", blue.Env, green.Env)
	}
}
