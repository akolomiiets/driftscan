// Package glob matches slash-separated paths and dotted names against patterns with `*` and `**`.
package glob

import (
	"path"
	"strings"
)

// Match reports whether name matches pattern. Segments are split on sep; `*` and `?` match within
// one segment (path.Match rules) and a `**` segment matches zero or more segments.
// A malformed pattern never matches.
func Match(pattern, name string, sep byte) bool {
	return match(split(pattern, sep), split(name, sep))
}

// MatchPath is Match with '/' as the separator.
func MatchPath(pattern, name string) bool { return Match(pattern, name, '/') }

// MatchAny reports whether name matches at least one pattern.
func MatchAny(patterns []string, name string, sep byte) bool {
	for _, p := range patterns {
		if Match(p, name, sep) {
			return true
		}
	}
	return false
}

func split(s string, sep byte) []string {
	s = strings.Trim(s, string(sep))
	if s == "" || s == "." {
		return nil
	}
	return strings.Split(s, string(sep))
}

// literalBrackets escapes [ ] and \ so Terraform addresses like aws_x.y[0] match literally;
// driftscan globs support only * and ?.
func literalBrackets(p string) string {
	return strings.NewReplacer(`\`, `\\`, "[", `\[`, "]", `\]`).Replace(p)
}

func match(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			for i := 0; i <= len(name); i++ {
				if match(rest, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(literalBrackets(pat[0]), name[0])
		if err != nil || !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}
