//go:build integration

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akolomiiets/driftscan/internal/finding"
)

// TestIntegration runs real terraform (or tofu via DRIFTSCAN_TF_BIN) against the local provider in a
// temp dir: apply, drift the file on disk, then change the code, checking driftscan at each step.
func TestIntegration(t *testing.T) {
	bin := os.Getenv("DRIFTSCAN_TF_BIN")
	if bin == "" {
		bin = "terraform"
	}
	if _, err := exec.LookPath(bin); err != nil {
		if onGitHubActions {
			t.Fatalf("%s not installed", bin)
		}
		t.Skipf("%s not installed", bin)
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "app")
	src, err := os.ReadFile("testdata/integration/app/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "main.tf"), string(src))
	write(t, filepath.Join(dir, "drift.yaml"), "binary: "+bin+"\n")
	tf(t, bin, root, "init", "-input=false", "-no-color")
	tf(t, bin, root, "apply", "-auto-approve", "-input=false", "-no-color")

	report := filepath.Join(dir, "report.json")
	htmlPath := filepath.Join(dir, "report.html")
	scan := func(baseline string) (int, finding.Report, string) {
		var out, errb bytes.Buffer
		args := []string{"scan", "-C", dir, "-out", report, "-markdown", "", "-html", htmlPath, "-fail-on", "medium"}
		if baseline != "" {
			args = append(args, "-baseline", baseline)
		}
		code := run(args, &out, &errb)
		b, err := os.ReadFile(report)
		if err != nil {
			t.Fatalf("no report: %v\n%s", err, errb.String())
		}
		r, err := finding.Unmarshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return code, r, errb.String()
	}

	code, r, log := scan("")
	if code != 0 || len(r.Findings) != 0 || r.Roots[0].Outcome != finding.RootClean {
		t.Fatalf("clean scan: code %d findings %+v\n%s", code, r.Findings, log)
	}
	base := filepath.Join(dir, "base.json")
	if err := os.Rename(report, base); err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(root, "out", "config.txt"), "port=9999 SECRETVALUE\n")
	code, r, log = scan(base)
	if code != 1 || len(r.Findings) != 1 {
		t.Fatalf("drift scan: code %d findings %+v\n%s", code, r.Findings, log)
	}
	f := r.Findings[0]
	if f.Kind != finding.KindDrift || f.Acknowledged || f.Address != "local_file.config" || f.Status != finding.StatusNew ||
		f.File != "app/main.tf" || f.Line != 12 {
		t.Errorf("drift finding = %+v", f)
	}
	b, _ := os.ReadFile(report)
	if strings.Contains(string(b), "SECRETVALUE") || strings.Contains(string(b), "9999") {
		t.Error("report leaks a value")
	}
	h, _ := os.ReadFile(htmlPath)
	if !strings.Contains(string(h), "local_file.config") || strings.Contains(string(h), "SECRETVALUE") || strings.Contains(string(h), "9999") {
		t.Error("html report leaks a value or misses the Finding")
	}
	if err := os.Rename(report, base); err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(root, "main.tf"), strings.Replace(string(src), "port=8080", "port=8081", 1))
	_, r, log = scan(base)
	kinds := map[finding.Kind]finding.Status{}
	for _, f := range r.Findings {
		kinds[f.Kind] = f.Status
	}
	if kinds[finding.KindDrift] != finding.StatusPersisting || kinds[finding.KindPending] != finding.StatusNew {
		t.Errorf("drift+pending scan = %+v\n%s", r.Findings, log)
	}
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func tf(t *testing.T, bin, dir string, args ...string) {
	t.Helper()
	c := exec.Command(bin, args...)
	c.Dir = dir
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", bin, args, err, out)
	}
}
