package hclroot

import (
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
	if got := strings.Join(info.DynamicBlockNames("aws_security_group.a[0]"), ","); got != "ingress" {
		t.Errorf("a = %q, want ingress", got)
	}
	if got := info.DynamicBlockNames("aws_security_group.b"); len(got) != 0 {
		t.Errorf("b = %v, want none", got)
	}
	if got := info.DynamicBlockNames("module.m.aws_security_group.a"); got != nil {
		t.Errorf("module resource = %v, want nil", got)
	}
}
