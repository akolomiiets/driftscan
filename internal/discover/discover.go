// Package discover finds the Roots in a tree: directories whose own .tf files declare a backend or
// cloud block, filtered by include/exclude, plus any Roots listed explicitly in config.
package discover

import (
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/akolomiiets/driftscan/internal/config"
	"github.com/akolomiiets/driftscan/internal/glob"
	"github.com/akolomiiets/driftscan/internal/hclroot"
)

// Root is one directory (and workspace) driftscan will plan, with the env its terraform processes get.
// Path is the Root's identity in Reports: Dir, or "Dir@workspace" when workspaces are configured.
type Root struct {
	Path      string
	Dir       string
	Workspace string
	Info      hclroot.Info
	Env       map[string]string
}

// Roots walks fsys from ".". Roots with a cloud block are skipped unless listed explicitly. Paths are slash-separated and relative to the walk root, "." for the top.
// Explicit config Roots are included even without a backend; a missing explicit Root is an error.
func Roots(fsys fs.FS, cfg config.Config) ([]Root, error) {
	found := map[string]hclroot.Info{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if p != "." && (d.Name() == ".terraform" || d.Name() == ".git") {
			return fs.SkipDir
		}
		entries, err := fs.ReadDir(fsys, p)
		if err != nil {
			return err
		}
		if !hclroot.HasTF(entries) {
			return nil
		}
		if !selected(cfg, p) {
			return nil
		}
		info, err := hclroot.Inspect(fsys, p)
		if err != nil {
			return err
		}
		if info.HasBackend && !info.Cloud {
			found[p] = info
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.Roots {
		p = path.Clean(p)
		if _, ok := found[p]; ok {
			continue
		}
		info, err := hclroot.Inspect(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("explicit root %q: %w", p, err)
		}
		found[p] = info
	}

	roots := make([]Root, 0, len(found))
	for p, info := range found {
		names := workspacesFor(cfg, p)
		if len(names) == 0 {
			roots = append(roots, Root{Path: p, Dir: p, Info: info, Env: EnvFor(cfg, p)})
			continue
		}
		for _, ws := range names {
			id := p + "@" + ws
			env := EnvFor(cfg, p, id)
			env["TF_WORKSPACE"] = ws
			roots = append(roots, Root{Path: id, Dir: p, Workspace: ws, Info: info, Env: env})
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Path < roots[j].Path })
	return roots, nil
}

func selected(cfg config.Config, p string) bool {
	return glob.MatchAny(cfg.Include, p, '/') && !glob.MatchAny(cfg.Exclude, p, '/')
}

func workspacesFor(cfg config.Config, dir string) []string {
	var names []string
	for _, r := range cfg.Workspaces {
		if glob.MatchPath(r.Match, dir) {
			names = r.Names
		}
	}
	return names
}

// EnvFor merges every env rule matching any of the given Root paths, in config order. A workspace
// Root passes both its dir and "dir@ws", so a rule on either applies.
func EnvFor(cfg config.Config, rootPaths ...string) map[string]string {
	env := map[string]string{}
	for _, r := range cfg.Env {
		if matchesAny(r.Match, rootPaths) {
			for k, v := range r.Vars {
				env[k] = v
			}
		}
	}
	return env
}

func matchesAny(pattern string, paths []string) bool {
	for _, p := range paths {
		if glob.MatchPath(pattern, p) {
			return true
		}
	}
	return false
}

// Shard keeps the Roots for shard i of n (1-based), assigned round-robin over the sorted list so
// every shard gets a similar count. n <= 1 keeps everything.
func Shard(roots []Root, i, n int) []Root {
	if n <= 1 {
		return roots
	}
	var out []Root
	for idx, r := range roots {
		if idx%n == i-1 {
			out = append(out, r)
		}
	}
	return out
}
