// Package enrich adds context to a raw Report after the Scan (ADR-0007): who owns each Finding.
package enrich

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"path"
	"strings"

	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/glob"
)

// codeownersPaths are where GitHub looks, in its order.
var codeownersPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

type ownerRule struct {
	pattern string
	// isDir: the pattern names a directory (last segment has no wildcard), so it also matches below.
	isDir  bool
	owners []string
}

// Codeowners is a parsed CODEOWNERS file; the last matching rule wins, as on GitHub.
type Codeowners []ownerRule

// LoadCodeowners reads the first CODEOWNERS file GitHub would use; none is not an error.
func LoadCodeowners(repo fs.FS) (Codeowners, error) {
	for _, p := range codeownersPaths {
		b, err := fs.ReadFile(repo, p)
		if err == nil {
			return ParseCodeowners(b), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return nil, nil
}

func ParseCodeowners(b []byte) Codeowners {
	var c Codeowners
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		pat := toGlob(f[0])
		last := pat[strings.LastIndex(pat, "/")+1:]
		c = append(c, ownerRule{pattern: pat, isDir: !strings.ContainsAny(last, "*?"), owners: f[1:]})
	}
	return c
}

// toGlob turns a gitignore-style CODEOWNERS pattern into a driftscan glob over repo-relative paths.
func toGlob(p string) string {
	dirOnly := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	anchored := strings.HasPrefix(p, "/") || strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")
	if !anchored {
		p = "**/" + p
	}
	if dirOnly {
		p += "/**"
	}
	return p
}

// Owners returns the owners of a repo-relative file or directory; nil when no rule matches or the
// last matching rule has no owners.
func (c Codeowners) Owners(p string) []string {
	var owners []string
	for _, r := range c {
		if glob.MatchPath(r.pattern, p) || (r.isDir && glob.MatchPath(r.pattern+"/**", p)) {
			owners = r.owners
		}
	}
	if len(owners) == 0 {
		return nil
	}
	return owners
}

// GitOwner returns who last changed a repo-relative directory, or "" if unknown.
type GitOwner func(dir string) string

// Owners sets Owner on every Finding. prefix is the scanned directory relative to the repo root
// (Finding files and Root paths are relative to it). CODEOWNERS wins; git is the fallback when set.
func Owners(r finding.Report, co Codeowners, prefix string, git GitOwner) finding.Report {
	cache := map[string]string{}
	for i, f := range r.Findings {
		dir := path.Join(prefix, RootDir(f.Root))
		target := dir
		if f.File != "" {
			target = path.Join(prefix, f.File)
		}
		if o := co.Owners(target); len(o) > 0 {
			r.Findings[i].Owner, r.Findings[i].OwnerSource = strings.Join(o, " "), "codeowners"
			continue
		}
		if git == nil {
			continue
		}
		o, ok := cache[dir]
		if !ok {
			o = git(dir)
			cache[dir] = o
		}
		if o != "" {
			r.Findings[i].Owner, r.Findings[i].OwnerSource = o, "git"
		}
	}
	return r
}

// RootDir strips the "@workspace" suffix from a Root path.
func RootDir(root string) string {
	if i := strings.LastIndex(root, "@"); i >= 0 {
		return root[:i]
	}
	return root
}
