package hclroot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestDynamicBlocks(t *testing.T) {
	fsys := fstest.MapFS{"r/main.tf": {Data: []byte(`
resource "aws_security_group" "a" {
  name = "a"
  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port = ingress.value
    }
  }
  ingress {
    from_port = 1
  }
}
resource "aws_security_group" "b" {
  name = "b"
}
`)}}
	info, err := Inspect(fsys, "r")
	if err != nil {
		t.Fatal(err)
	}
	if got, known := info.DynamicBlockNames("aws_security_group.a[0]"); !known || strings.Join(got, ",") != "ingress" {
		t.Errorf("a = %q %v, want ingress", got, known)
	}
	if got, known := info.DynamicBlockNames("aws_security_group.b"); !known || len(got) != 0 {
		t.Errorf("b = %v %v, want none", got, known)
	}
	if _, known := info.DynamicBlockNames("module.m.aws_security_group.a"); known {
		t.Error("module resource known without module sources")
	}
}

func TestLoadModules(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".terraform/modules/modules.json", `{"Modules":[{"Key":"","Source":"","Dir":"."},
	{"Key":"vpc","Source":"./vpc","Dir":"vpc"},{"Key":"vpc.flow_log","Source":"./fl","Dir":".terraform/modules/vpc.flow_log"},
	{"Key":"gone","Source":"./gone","Dir":"missing"}]}`)
	write("vpc/main.tf", `resource "aws_security_group" "rds" {
  dynamic "ingress" {
    for_each = []
    content {}
  }
}
resource "aws_security_group" "plain" {}
`)
	write(".terraform/modules/vpc.flow_log/main.tf", `resource "aws_iam_role" "this" {
  dynamic "inline_policy" {
    for_each = []
    content {}
  }
}
`)
	info := Info{ModuleSources: LoadModules(dir)}

	for addr, want := range map[string]string{
		"module.vpc.aws_security_group.rds":                    "ingress",
		"module.vpc.aws_security_group.plain":                  "",
		`module.vpc.module.flow_log[0].aws_iam_role.this["a"]`: "inline_policy",
	} {
		got, known := info.DynamicBlockNames(addr)
		if !known || strings.Join(got, ",") != want {
			t.Errorf("%s = %v %v, want %q", addr, got, known, want)
		}
	}
	if _, known := info.DynamicBlockNames("module.gone.aws_x.y"); known {
		t.Error("unreadable module dir must be unknown")
	}
	if _, known := info.DynamicBlockNames("module.other.aws_x.y"); known {
		t.Error("module absent from modules.json must be unknown")
	}
	if LoadModules(t.TempDir()) != nil {
		t.Error("missing modules.json must give nil")
	}
}
