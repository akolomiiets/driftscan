// Package hclroot reads the HCL of one directory and answers the questions driftscan has about it:
// is it a Root, where is each resource or module block, and which attributes does lifecycle.ignore_changes cover.
package hclroot

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Location is a file (slash path relative to the scanned tree) and a 1-based line.
type Location struct {
	File string
	Line int
}

// Info is what driftscan knows about one directory's own .tf files. Modules it calls are not read.
type Info struct {
	Dir string
	// HasBackend is true when a terraform block declares a backend or cloud block.
	HasBackend bool
	// Cloud is true for a cloud block (HCP Terraform / TFE). Such Roots usually run plans remotely,
	// where saved plans are not supported, so discovery skips them unless listed explicitly.
	Cloud bool
	// BackendFile is where that block lives; the fallback location for SARIF.
	BackendFile Location
	// Resources maps "type.name" (root module, no index) to its block.
	Resources map[string]Location
	// Modules maps a module call name to its block.
	Modules map[string]Location
	// IgnoreChanges maps "type.name" to its ignore_changes paths; ["*"] means all.
	IgnoreChanges map[string][]string
	// DynamicBlocks maps "type.name" to the names of its direct `dynamic` blocks. The plan JSON
	// configuration does not list them, so extract needs them to know a block is set.
	DynamicBlocks map[string][]string
	// Errors are parse problems; Info still holds whatever parsed.
	Errors []string
}

var schema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "module", LabelNames: []string{"name"}},
	},
}

var terraformSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "backend", LabelNames: []string{"type"}},
		{Type: "cloud"},
	},
}

var resourceSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "lifecycle"}}}

var lifecycleSchema = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "ignore_changes"}}}

// Inspect parses every *.tf file directly in dir (slash path inside fsys).
func Inspect(fsys fs.FS, dir string) (Info, error) {
	info := Info{
		Dir:           dir,
		Resources:     map[string]Location{},
		Modules:       map[string]Location{},
		IgnoreChanges: map[string][]string{},
		DynamicBlocks: map[string][]string{},
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return info, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tf") {
			continue
		}
		file := path.Join(dir, e.Name())
		src, err := fs.ReadFile(fsys, file)
		if err != nil {
			info.Errors = append(info.Errors, err.Error())
			continue
		}
		info.inspectFile(file, src)
	}
	return info, nil
}

// HasTF reports whether dir directly contains at least one *.tf file.
func HasTF(entries []fs.DirEntry) bool {
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tf") {
			return true
		}
	}
	return false
}

func (info *Info) inspectFile(file string, src []byte) {
	f, diags := hclsyntax.ParseConfig(src, file, hcl.InitialPos)
	if diags.HasErrors() {
		info.Errors = append(info.Errors, diags.Error())
		if f == nil {
			return
		}
	}
	content, _, _ := f.Body.PartialContent(schema)
	for _, b := range content.Blocks {
		loc := Location{File: file, Line: b.DefRange.Start.Line}
		switch b.Type {
		case "terraform":
			tc, _, _ := b.Body.PartialContent(terraformSchema)
			if len(tc.Blocks) > 0 && !info.HasBackend {
				info.HasBackend = true
				info.Cloud = tc.Blocks[0].Type == "cloud"
				info.BackendFile = Location{File: file, Line: tc.Blocks[0].DefRange.Start.Line}
			}
		case "resource":
			addr := b.Labels[0] + "." + b.Labels[1]
			info.Resources[addr] = loc
			if paths := ignoreChanges(b.Body); paths != nil {
				info.IgnoreChanges[addr] = paths
			}
			if names := dynamicBlocks(b.Body); names != nil {
				info.DynamicBlocks[addr] = names
			}
		case "module":
			info.Modules[b.Labels[0]] = loc
		}
	}
}

func ignoreChanges(body hcl.Body) []string {
	rc, _, _ := body.PartialContent(resourceSchema)
	for _, lb := range rc.Blocks {
		lc, _, _ := lb.Body.PartialContent(lifecycleSchema)
		attr, ok := lc.Attributes["ignore_changes"]
		if !ok {
			continue
		}
		if kw := hcl.ExprAsKeyword(attr.Expr); kw == "all" {
			return []string{"*"}
		}
		exprs, diags := hcl.ExprList(attr.Expr)
		if diags.HasErrors() {
			return nil
		}
		var out []string
		for _, e := range exprs {
			trav, d := hcl.RelTraversalForExpr(e)
			if d.HasErrors() {
				continue
			}
			if p := traversalPath(trav); p != "" {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

func dynamicBlocks(body hcl.Body) []string {
	sb, ok := body.(*hclsyntax.Body)
	if !ok {
		return nil
	}
	var out []string
	for _, b := range sb.Blocks {
		if b.Type == "dynamic" && len(b.Labels) == 1 {
			out = append(out, b.Labels[0])
		}
	}
	sort.Strings(out)
	return out
}

func traversalPath(t hcl.Traversal) string {
	var sb strings.Builder
	for _, step := range t {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			sb.WriteString(s.Name)
		case hcl.TraverseAttr:
			sb.WriteString("." + s.Name)
		case hcl.TraverseIndex:
			if s.Key.Type().FriendlyName() == "number" {
				bf := s.Key.AsBigFloat()
				sb.WriteString(fmt.Sprintf("[%s]", bf.Text('f', -1)))
			} else if s.Key.Type().FriendlyName() == "string" {
				sb.WriteString(KeyStep(s.Key.AsString(), false))
			}
		}
	}
	return strings.TrimPrefix(sb.String(), ".")
}

// Locate returns the best source location for a resource address: its resource block, else the
// calling module block, else the backend file. ok is false when nothing in the Root matched.
func (info Info) Locate(address string) (Location, bool) {
	if strings.HasPrefix(address, "module.") {
		rest := strings.TrimPrefix(address, "module.")
		name := rest
		if i := strings.IndexAny(rest, ".["); i >= 0 {
			name = rest[:i]
		}
		if loc, ok := info.Modules[name]; ok {
			return loc, true
		}
		return info.BackendFile, false
	}
	if loc, ok := info.Resources[ResourceKey(address)]; ok {
		return loc, true
	}
	return info.BackendFile, false
}

// IgnoredPaths returns the ignore_changes paths for a root-module resource address.
func (info Info) IgnoredPaths(address string) []string {
	if strings.HasPrefix(address, "module.") || strings.HasPrefix(address, "data.") {
		return nil
	}
	return info.IgnoreChanges[ResourceKey(address)]
}

var plainKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// KeyStep renders one map key of an attribute path: ".key" (or "key" at the top) when it is a plain
// identifier, else ["key"]. extract and ignore_changes must render paths the same way.
func KeyStep(k string, top bool) string {
	if plainKey.MatchString(k) {
		if top {
			return k
		}
		return "." + k
	}
	return "[" + strconv.Quote(k) + "]"
}

// ResourceKey turns "aws_sg.x[0]" or `aws_sg.x["a"]` into "aws_sg.x".
func ResourceKey(address string) string {
	if i := strings.IndexByte(address, '['); i >= 0 {
		return address[:i]
	}
	return address
}

// DynamicBlockNames returns the direct dynamic block names of a root-module resource address.
func (info Info) DynamicBlockNames(address string) []string {
	if strings.HasPrefix(address, "module.") || strings.HasPrefix(address, "data.") {
		return nil
	}
	return info.DynamicBlocks[ResourceKey(address)]
}
