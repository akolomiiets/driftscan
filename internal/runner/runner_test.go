package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akolomiiets/driftscan/internal/discover"
)

// fakeTF logs every call with its TF_WORKSPACE and prints an empty plan for "show".
const fakeTF = `#!/bin/sh
echo "$1 ws=$TF_WORKSPACE" >> "$LOG"
case "$1" in
  init) if [ -e "$FAIL_INIT" ]; then echo 'Error: boom' >&2; exit 1; fi ;;
  workspace) printf '  default\n* blue\n' ;;
  show) echo '{"format_version":"1.2"}' ;;
esac
`

func fake(t *testing.T) (bin, log string) {
	d := t.TempDir()
	bin = filepath.Join(d, "terraform")
	if err := os.WriteFile(bin, []byte(fakeTF), 0o755); err != nil {
		t.Fatal(err)
	}
	log = filepath.Join(d, "log")
	t.Setenv("LOG", log)
	t.Setenv("FAIL_INIT", filepath.Join(d, "fail-init"))
	return bin, log
}

func TestWorkspaceRootsShareOneInitRunWithTheRootsWorkspace(t *testing.T) {
	bin, log := fake(t)
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := Exec{Binary: bin, Dir: work}
	for _, ws := range []string{"blue", "default"} {
		root := discover.Root{Path: "app@" + ws, Dir: "app", Workspace: ws, Env: map[string]string{"TF_WORKSPACE": ws}}
		if _, err := e.Run(context.Background(), root, false); err != nil {
			t.Fatalf("%s: %v", ws, err)
		}
	}
	b, _ := os.ReadFile(log)
	got := string(b)
	if strings.Count(got, "init ") != 1 || !strings.Contains(got, "init ws=blue\n") {
		t.Errorf("want one init with the first Root's TF_WORKSPACE, log:\n%s", got)
	}
	if !strings.Contains(got, "plan ws=blue\n") || !strings.Contains(got, "plan ws=default\n") {
		t.Errorf("plans not run per workspace, log:\n%s", got)
	}
}

func TestMissingWorkspaceIsAnError(t *testing.T) {
	bin, log := fake(t)
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	root := discover.Root{Path: "app@typo", Dir: "app", Workspace: "typo", Env: map[string]string{"TF_WORKSPACE": "typo"}}
	_, err := Exec{Binary: bin, Dir: work}.Run(context.Background(), root, false)
	if err == nil || !strings.Contains(err.Error(), `workspace "typo" does not exist`) {
		t.Fatalf("err = %v", err)
	}
	b, _ := os.ReadFile(log)
	if strings.Contains(string(b), "plan ") {
		t.Errorf("planned a missing workspace:\n%s", b)
	}
}

func TestStateInitsOnceAndOnlyShows(t *testing.T) {
	bin, log := fake(t)
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "app2"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := Exec{Binary: bin, Dir: work}

	out, err := e.State(context.Background(), discover.Root{Path: "app2", Dir: "app2"})

	if err != nil || !strings.Contains(string(out), "format_version") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	b, _ := os.ReadFile(log)
	if got := strings.Fields(string(b)); len(got) != 4 || got[0] != "init" || got[2] != "show" {
		t.Errorf("calls = %q, want init then show only", b)
	}
}

func TestFailedInitIsNotCachedAndNextRootRetries(t *testing.T) {
	bin, log := fake(t)
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "app3"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := Exec{Binary: bin, Dir: work}
	blue := discover.Root{Path: "app3@blue", Dir: "app3", Workspace: "blue", Env: map[string]string{"TF_WORKSPACE": "blue"}}
	def := discover.Root{Path: "app3@default", Dir: "app3", Workspace: "default", Env: map[string]string{"TF_WORKSPACE": "default"}}
	if err := os.WriteFile(os.Getenv("FAIL_INIT"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := e.Run(context.Background(), blue, false)
	if err == nil || !strings.Contains(err.Error(), "init: Error: boom") {
		t.Fatalf("err = %v", err)
	}
	if err := os.Remove(os.Getenv("FAIL_INIT")); err != nil {
		t.Fatal(err)
	}
	_, err = e.Run(context.Background(), def, false)

	if err != nil {
		t.Fatalf("second Root: %v", err)
	}
	b, _ := os.ReadFile(log)
	if got := strings.Count(string(b), "init "); got != 2 {
		t.Errorf("init ran %d times, want 2 (failure not cached):\n%s", got, b)
	}
	if _, err := e.Run(context.Background(), blue, false); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(log)
	if got := strings.Count(string(b), "init "); got != 2 {
		t.Errorf("successful init not cached, ran %d times", got)
	}
}
