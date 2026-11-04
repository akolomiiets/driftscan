// Package runner runs terraform or tofu for one Root and returns the plan JSON driftscan needs.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akolomiiets/driftscan/internal/discover"
)

// Plans holds the two plan JSON documents for one Root. Pending is nil when not requested.
type Plans struct {
	Drift   []byte
	Pending []byte
}

// Runner produces Plans for a Root. A returned error becomes a Scan error Finding; its message
// must not contain attribute values.
type Runner interface {
	Run(ctx context.Context, root discover.Root, withPending bool) (Plans, error)
}

// initMu serializes init: TF_PLUGIN_CACHE_DIR is not safe for concurrent use. Plans stay parallel.
var initMu sync.Mutex

// inits holds the directories that initialised successfully, so workspace Roots sharing a directory
// init it once. A failed init is not recorded: the next Root of the directory retries.
var inits = map[string]bool{}

// Exec runs the real binary. Dir is the directory Root paths are relative to.
type Exec struct {
	Binary string
	Dir    string
}

func (e Exec) Run(ctx context.Context, root discover.Root, withPending bool) (Plans, error) {
	tmp, err := os.MkdirTemp("", "driftscan-")
	if err != nil {
		return Plans{}, err
	}
	// The plan files contain every attribute value; they never outlive this call (ADR-0002).
	defer os.RemoveAll(tmp)

	dir, env, err := e.prepare(ctx, root)
	if err != nil {
		return Plans{}, err
	}
	var p Plans
	driftPlan := filepath.Join(tmp, "drift.tfplan")
	if _, err := e.cmd(ctx, dir, env, "plan", "-lock=false", "-input=false", "-no-color", "-out="+driftPlan); err != nil {
		return Plans{}, fmt.Errorf("plan: %w", err)
	}
	if p.Drift, err = e.cmd(ctx, dir, env, "show", "-json", "-no-color", driftPlan); err != nil {
		return Plans{}, fmt.Errorf("show: %w", err)
	}
	if !withPending {
		return p, nil
	}
	pendingPlan := filepath.Join(tmp, "pending.tfplan")
	if _, err := e.cmd(ctx, dir, env, "plan", "-refresh=false", "-lock=false", "-input=false", "-no-color", "-out="+pendingPlan); err != nil {
		return Plans{}, fmt.Errorf("plan -refresh=false: %w", err)
	}
	if p.Pending, err = e.cmd(ctx, dir, env, "show", "-json", "-no-color", pendingPlan); err != nil {
		return Plans{}, fmt.Errorf("show: %w", err)
	}
	return p, nil
}

// State returns "show -json" of the Root's current state, read-only. It contains attribute values, so
// the caller must keep it in memory and never write it out (ADR-0002, ADR-0008).
func (e Exec) State(ctx context.Context, root discover.Root) ([]byte, error) {
	dir, env, err := e.prepare(ctx, root)
	if err != nil {
		return nil, err
	}
	b, err := e.cmd(ctx, dir, env, "show", "-json", "-no-color")
	if err != nil {
		return nil, fmt.Errorf("show: %w", err)
	}
	return b, nil
}

// prepare inits the Root's directory and checks its workspace exists; it returns the directory and env.
func (e Exec) prepare(ctx context.Context, root discover.Root) (string, []string, error) {
	rel := root.Dir
	if rel == "" {
		rel = root.Path
	}
	dir := filepath.Join(e.Dir, filepath.FromSlash(rel))
	env := environ(root.Env)

	if err := e.init(ctx, dir, root.Env); err != nil {
		return "", nil, fmt.Errorf("init: %w", err)
	}
	if root.Workspace != "" {
		// A plan in a workspace that does not exist reads an empty state and reports every resource
		// as pending, so check first.
		out, err := e.cmd(ctx, dir, environ(without(root.Env, "TF_WORKSPACE")), "workspace", "list")
		if err != nil {
			return "", nil, fmt.Errorf("workspace list: %w", err)
		}
		if !hasWorkspace(out, root.Workspace) {
			return "", nil, fmt.Errorf("workspace %q does not exist", root.Workspace)
		}
	}
	return dir, env, nil
}

// init runs until it succeeds once per directory. It keeps TF_WORKSPACE: with a remote backend whose
// default workspace has no state, init without it fails with "Failed to select workspace".
func (e Exec) init(ctx context.Context, dir string, env map[string]string) error {
	initMu.Lock()
	defer initMu.Unlock()
	if inits[dir] {
		return nil
	}
	if _, err := e.cmd(ctx, dir, environ(env), "init", "-input=false", "-no-color"); err != nil {
		return err
	}
	inits[dir] = true
	return nil
}

func without(env map[string]string, key string) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		if k != key {
			out[k] = v
		}
	}
	return out
}

// hasWorkspace reads "terraform workspace list" output: one name per line, "* " marks the current one.
func hasWorkspace(out []byte, name string) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "*")) == name {
			return true
		}
	}
	return false
}

func (e Exec) cmd(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, e.Binary, args...)
	c.Dir = dir
	c.Env = env
	// On timeout ask terraform to stop so it can shut down its provider plugins, then kill.
	c.Cancel = func() error { return c.Process.Signal(os.Interrupt) }
	c.WaitDelay = 30 * time.Second
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("timed out or cancelled: %w", ctx.Err())
	}
	if err != nil {
		return nil, errors.New(Summarize(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func environ(extra map[string]string) []string {
	env := append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=0")
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+extra[k])
	}
	return env
}

// quoted matches double-quoted strings, which in terraform errors are often configuration values.
var quoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// MaxErrorLen bounds a Scan error message.
const MaxErrorLen = 300

// Summarize keeps only terraform's "Error: <summary>" headlines. Detail lines under them can quote
// configuration or API responses, so they are dropped.
func Summarize(stderr string) string {
	var heads []string
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(strings.TrimLeft(line, "│╷╵ "))
		if strings.HasPrefix(line, "Error: ") {
			heads = append(heads, line)
		}
	}
	msg := quoted.ReplaceAllString(strings.Join(heads, "; "), `"..."`)
	if msg == "" {
		msg = "terraform failed without an Error: line"
	}
	if len(msg) > MaxErrorLen {
		msg = msg[:MaxErrorLen] + "..."
	}
	return msg
}
