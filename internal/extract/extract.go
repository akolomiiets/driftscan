// Package extract turns plan JSON into redacted Findings. It is the only place that ever holds
// attribute values; nothing it returns carries one (ADR-0002).
package extract

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/hclroot"
)

// MaxPathDepth caps attribute paths so a large nested diff yields a few readable paths.
const MaxPathDepth = 3

// Drift reads the JSON of `plan -refresh-only` and returns one Drift Finding per drifted managed resource.
func Drift(planJSON []byte, root string, info hclroot.Info) ([]finding.Finding, error) {
	p, err := parse(planJSON)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, rc := range p.ResourceDrift {
		f, ok := fromChange(rc, root, finding.KindDrift)
		if !ok {
			continue
		}
		f.Acknowledged, f.AckReason = acknowledge(f, info.IgnoredPaths(f.Address), unsetInConfig(p.Config, rc, info))
		out = append(out, f)
	}
	return out, nil
}

// Pending reads the JSON of `plan -refresh=false` and returns one Pending change Finding per
// managed resource the plan would change.
func Pending(planJSON []byte, root string) ([]finding.Finding, error) {
	p, err := parse(planJSON)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, rc := range p.ResourceChanges {
		if f, ok := fromChange(rc, root, finding.KindPending); ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func parse(b []byte) (*tfjson.Plan, error) {
	var p tfjson.Plan
	if err := p.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("parse plan JSON: %w", err)
	}
	return &p, nil
}

func fromChange(rc *tfjson.ResourceChange, root string, kind finding.Kind) (finding.Finding, bool) {
	if rc == nil || rc.Change == nil || rc.Mode != tfjson.ManagedResourceMode {
		return finding.Finding{}, false
	}
	a := rc.Change.Actions
	if a.NoOp() || a.Read() || len(a) == 0 {
		return finding.Finding{}, false
	}
	f := finding.Finding{
		Root:    root,
		Address: rc.Address,
		Type:    rc.Type,
		Kind:    kind,
	}
	for _, act := range a {
		f.Actions = append(f.Actions, string(act))
	}
	if a.Update() {
		f.Paths = changedPaths(rc.Change)
	}
	return f, true
}

func changedPaths(c *tfjson.Change) []string {
	set := map[string]bool{}
	sens := mergeSensitive(c.BeforeSensitive, c.AfterSensitive)
	diff(c.Before, c.After, c.AfterUnknown, sens, nil, set)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// diff records the path of every difference between before and after. It stops descending at
// MaxPathDepth, at a sensitive marker (so map keys under a sensitive value are never exposed) and
// at an unknown marker.
func diff(before, after, unknown, sens any, path []string, out map[string]bool) {
	if sens == true || unknown == true || len(path) >= MaxPathDepth {
		if !equalJSON(before, after) || unknown == true {
			out[render(path)] = true
		}
		return
	}
	bm, bok := before.(map[string]any)
	am, aok := after.(map[string]any)
	if bok && aok {
		for _, k := range unionKeys(bm, am) {
			diff(bm[k], am[k], child(unknown, k), child(sens, k), append(path, hclroot.KeyStep(k, len(path) == 0)), out)
		}
		return
	}
	bl, blok := before.([]any)
	al, alok := after.([]any)
	if blok && alok {
		n := max(len(bl), len(al))
		for i := 0; i < n; i++ {
			var b, a any
			if i < len(bl) {
				b = bl[i]
			}
			if i < len(al) {
				a = al[i]
			}
			diff(b, a, childIdx(unknown, i), childIdx(sens, i), append(path, "["+strconv.Itoa(i)+"]"), out)
		}
		return
	}
	if !equalJSON(before, after) {
		out[render(path)] = true
	}
}

func render(path []string) string {
	if len(path) == 0 {
		return "*"
	}
	return strings.Join(path, "")
}

func unionKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	var keys []string
	for k := range a {
		seen[k] = true
		keys = append(keys, k)
	}
	for k := range b {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func child(marker any, k string) any {
	if m, ok := marker.(map[string]any); ok {
		return m[k]
	}
	return nil
}

func childIdx(marker any, i int) any {
	if l, ok := marker.([]any); ok && i < len(l) {
		return l[i]
	}
	return nil
}

// mergeSensitive ORs two sensitivity trees so a value sensitive on either side is treated as sensitive.
func mergeSensitive(a, b any) any {
	if a == true || b == true {
		return true
	}
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok || bok {
		out := map[string]any{}
		for _, k := range unionKeys(am, bm) {
			out[k] = mergeSensitive(am[k], bm[k])
		}
		return out
	}
	al, alok := a.([]any)
	bl, blok := b.([]any)
	if alok || blok {
		n := max(len(al), len(bl))
		out := make([]any, n)
		for i := range out {
			var x, y any
			if i < len(al) {
				x = al[i]
			}
			if i < len(bl) {
				y = bl[i]
			}
			out[i] = mergeSensitive(x, y)
		}
		return out
	}
	return nil
}

func equalJSON(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			w, ok := bv[k]
			if !ok || !equalJSON(v, w) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !equalJSON(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

// acknowledge reports whether every drifted path is either covered by lifecycle.ignore_changes or
// not set in the resource's configuration, and which of the two applied.
func acknowledge(f finding.Finding, ignored []string, unset func(path string) bool) (bool, string) {
	if len(f.Paths) == 0 {
		return false, ""
	}
	for _, ig := range ignored {
		if ig == "*" {
			return true, finding.AckIgnoreChanges
		}
	}
	byIgnore, byConfig := false, false
	for _, p := range f.Paths {
		switch {
		case covered(p, ignored):
			byIgnore = true
		case unset(p):
			byConfig = true
		default:
			return false, ""
		}
	}
	switch {
	case byIgnore && byConfig:
		return true, finding.AckMixed
	case byConfig:
		return true, finding.AckNotInConfig
	}
	return true, finding.AckIgnoreChanges
}

func covered(p string, ignored []string) bool {
	for _, ig := range ignored {
		if p == ig || strings.HasPrefix(p, ig+".") || strings.HasPrefix(p, ig+"[") {
			return true
		}
	}
	return false
}

// unsetInConfig returns a test for "this drifted path is provably not set in the resource's
// configuration" (ADR-0011). It answers false whenever that cannot be proven, so the Finding stays Drift.
func unsetInConfig(cfg *tfjson.Config, rc *tfjson.ResourceChange, info hclroot.Info) func(string) bool {
	never := func(string) bool { return false }
	if cfg == nil || rc == nil || rc.Change == nil {
		return never
	}
	res, inModule, ok := findConfigResource(cfg, rc.Address)
	if !ok {
		return never
	}
	dynamic := map[string]bool{}
	for _, n := range info.DynamicBlockNames(rc.Address) {
		dynamic[n] = true
	}
	return func(path string) bool {
		name := topName(path)
		if name == "" {
			return false
		}
		if _, set := res.Expressions[name]; set || dynamic[name] {
			return false
		}
		// `dynamic` blocks are absent from expressions, and a module's source is not read, so a
		// block-shaped value in a module resource may be a dynamic block.
		return !(inModule && blockShaped(child(rc.Change.Before, name), child(rc.Change.After, name)))
	}
}

// topName is the top-level attribute or block name of a path, "" when it cannot be read.
func topName(path string) string {
	if path == "" || path[0] == '[' || path == "*" {
		return ""
	}
	if i := strings.IndexAny(path, ".["); i >= 0 {
		return path[:i]
	}
	return path
}

// blockShaped is true for a list or map holding objects, how nested blocks appear in a plan.
func blockShaped(vals ...any) bool {
	for _, v := range vals {
		switch t := v.(type) {
		case []any:
			for _, e := range t {
				if _, ok := e.(map[string]any); ok {
					return true
				}
			}
		case map[string]any:
			for _, e := range t {
				switch e.(type) {
				case map[string]any, []any:
					return true
				}
			}
		}
	}
	return false
}

// findConfigResource follows a plan address such as `module.a[0].module.b["k"].aws_x.y[1]` through
// the configuration's module_calls, ignoring instance keys. inModule is false for a root resource.
func findConfigResource(cfg *tfjson.Config, address string) (res *tfjson.ConfigResource, inModule, ok bool) {
	if cfg.RootModule == nil {
		return nil, false, false
	}
	segs := splitAddress(address)
	mod := cfg.RootModule
	for len(segs) >= 4 && segs[0] == "module" {
		call := mod.ModuleCalls[stripKey(segs[1])]
		if call == nil || call.Module == nil {
			return nil, false, false
		}
		mod, segs, inModule = call.Module, segs[2:], true
	}
	if len(segs) != 2 {
		return nil, false, false
	}
	typ, name := stripKey(segs[0]), stripKey(segs[1])
	for _, r := range mod.Resources {
		if r.Mode == tfjson.ManagedResourceMode && r.Type == typ && r.Name == name {
			return r, inModule, true
		}
	}
	return nil, false, false
}

func stripKey(seg string) string {
	if i := strings.IndexByte(seg, '['); i >= 0 {
		return seg[:i]
	}
	return seg
}

// splitAddress splits on dots outside brackets and quotes, so `a["x.y"]` stays one segment.
func splitAddress(a string) []string {
	var segs []string
	depth, quoted, start := 0, false, 0
	for i := 0; i < len(a); i++ {
		switch c := a[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case quoted:
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == '.' && depth == 0:
			segs = append(segs, a[start:i])
			start = i + 1
		}
	}
	return append(segs, a[start:])
}
