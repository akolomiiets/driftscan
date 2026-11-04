package output

import (
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/akolomiiets/driftscan/internal/finding"
)

// Source maps a Finding's File (relative to the scan directory) to a repository path and a web link.
type Source struct {
	// Prefix is the scan directory relative to the repository root: "" or "infra/".
	Prefix string
	// BlobURL is "<server>/<repo>/blob/<sha>", or "" when no link can be built.
	BlobURL string
}

// Path is the repository-relative path of the Finding's file, or "" when it has none.
func (s Source) Path(f finding.Finding) string {
	if f.File == "" {
		return ""
	}
	return path.Join(s.Prefix, f.File)
}

// URL links to the Finding's file (and line) at the scanned commit, or "" when unknown.
func (s Source) URL(f finding.Finding) string {
	p := s.Path(f)
	if s.BlobURL == "" || p == "" {
		return ""
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	u := s.BlobURL + "/" + strings.Join(segs, "/")
	if f.Line > 0 {
		u += "#L" + strconv.Itoa(f.Line)
	}
	return urlParens.Replace(u)
}

var urlParens = strings.NewReplacer("(", "%28", ")", "%29")
