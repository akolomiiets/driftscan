package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)
	if out, err := exec.Command("git", full...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestIsShallow(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	git(t, src, "init", "-q")
	git(t, src, "commit", "-q", "--allow-empty", "-m", "one")
	git(t, src, "commit", "-q", "--allow-empty", "-m", "two")
	shallow := filepath.Join(t.TempDir(), "shallow")
	git(t, src, "clone", "-q", "--depth=1", "file://"+src, shallow)

	if !isShallow(context.Background(), shallow) {
		t.Error("shallow clone not detected")
	}
	if isShallow(context.Background(), src) {
		t.Error("full repository reported as shallow")
	}
	if isShallow(context.Background(), t.TempDir()) {
		t.Error("non-repository reported as shallow")
	}
}
