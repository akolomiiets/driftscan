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

// Drift reads the JSON of a normal plan (refresh on) and returns one Drift Finding per drifted managed
// resource. A Finding is acknowledged when applying the code would not undo the drift (ADR-0011).
func Drift(planJSON []byte, root string, info hclroot.Info) ([]finding.Finding, error) {
	p, err := parse(planJSON)
	if err != nil {
		return nil, err
	}
	// Keyed by address and deposed key: a replaced resource has a live and a deposed object.
	planned := map[string]*tfjson.ResourceChange{}
	for _, rc := range p.ResourceChanges {
		if rc != nil {
			planned[rc.Address+"\x00"+rc.DeposedKey] = rc
		}
	}
	var out []finding.Finding
	for _, rc := range p.ResourceDrift {
		// A deposed object is a leftover of a replace, not the live resource; skip it.
		if rc != nil && rc.DeposedKey != "" {
			continue
		}
		f, ok := fromChange(rc, root, finding.KindDrift)
		if !ok {
			continue
		}
		f.Acknowledged, f.AckReason = acknowledge(f, info.IgnoredPaths(f.Address), planned[f.Address+"\x00"])
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

// acknowledge decides whether applying the code would leave the drift alone. The plan must have an
// entry for the resource (else it is actionable, fail closed). No change, or forget, leaves the drift:
// "ignore_changes" when lifecycle.ignore_changes covers every drifted path, else "not_reverted". An
// update leaves it when ignore_changes covers it or the update touches none of the drifted paths.
// A delete leaves it only when the code caused it (resource removed from config), not drift. A
// replace leaves it when neither its replace paths nor its changed paths touch a drifted path and
// the reason is a request or trigger, or the plan names replace paths. A create is always actionable.
func acknowledge(f finding.Finding, ignored []string, planned *tfjson.ResourceChange) (bool, string) {
	if planned == nil || planned.Change == nil {
		return false, ""
	}
	reason := finding.AckNotReverted
	if allIgnored(f, ignored) {
		reason = finding.AckIgnoreChanges
	}
	if !leavesDrift(f, ignored, planned) {
		return false, ""
	}
	return true, reason
}

func leavesDrift(f finding.Finding, ignored []string, planned *tfjson.ResourceChange) bool {
	c := planned.Change
	a := c.Actions
	switch {
	case len(a) == 0 || a.NoOp() || a.Read() || a.Forget():
		return true
	case a.Update():
		if allIgnored(f, ignored) {
			return true
		}
		return len(f.Paths) > 0 && !touches(f.Paths, changedPaths(c))
	case a.Delete():
		return codeDrivenDelete[planned.ActionReason]
	case a.Replace():
		return replaceLeavesDrift(f, c, planned.ActionReason)
	}
	return false
}

// codeDrivenDelete lists the action reasons for a delete that comes from a code change, which is
// reported as Pending, not a revert of drift.
var codeDrivenDelete = map[tfjson.ActionReason]bool{
	tfjson.ActionReasonDeleteBecauseNoResourceConfig: true,
	tfjson.ActionReasonDeleteBecauseNoModule:         true,
	tfjson.ActionReasonDeleteBecauseWrongRepetition:  true,
	tfjson.ActionReasonDeleteBecauseCountIndex:       true,
	tfjson.ActionReasonDeleteBecauseEachKey:          true,
	tfjson.ActionReasonDeleteBecauseNoMoveTarget:     true,
}

func replaceLeavesDrift(f finding.Finding, c *tfjson.Change, reason tfjson.ActionReason) bool {
	if len(f.Paths) == 0 {
		return false
	}
	replace := replacePaths(c.ReplacePaths)
	if touches(f.Paths, changedPaths(c), replace) {
		return false
	}
	switch reason {
	case tfjson.ActionReasonReplaceByRequest, tfjson.ActionReasonReplaceByTriggers:
		return true
	case tfjson.ActionReasonReplaceBecauseCannotUpdate:
		return len(replace) > 0
	}
	return false
}

// touches reports whether any drifted path overlaps a planned path (one is a segment-aligned prefix
// of the other).
func touches(drift []string, planned ...[]string) bool {
	for _, set := range planned {
		for _, pp := range set {
			for _, dp := range drift {
				if covered(dp, []string{pp}) || covered(pp, []string{dp}) {
					return true
				}
			}
		}
	}
	return false
}

// replacePaths renders replace_paths (arrays of string and number steps) like drift paths, cut at MaxPathDepth.
func replacePaths(raw []any) []string {
	var out []string
	for _, r := range raw {
		steps, ok := r.([]any)
		if !ok {
			continue
		}
		var path []string
	walk:
		for _, st := range steps {
			if len(path) == MaxPathDepth {
				break
			}
			switch v := st.(type) {
			case string:
				path = append(path, hclroot.KeyStep(v, len(path) == 0))
			case float64:
				path = append(path, "["+strconv.Itoa(int(v))+"]")
			default:
				// A set element keyed by its value (an object): keep the prefix so overlap stays wide.
				break walk
			}
		}
		if len(path) > 0 {
			out = append(out, render(path))
		}
	}
	return out
}

// allIgnored is true when every drifted path is covered by lifecycle.ignore_changes.
func allIgnored(f finding.Finding, ignored []string) bool {
	if len(ignored) == 0 || len(f.Paths) == 0 {
		return false
	}
	for _, ig := range ignored {
		if ig == "*" {
			return true
		}
	}
	for _, p := range f.Paths {
		if !covered(p, ignored) {
			return false
		}
	}
	return true
}

func covered(p string, ignored []string) bool {
	for _, ig := range ignored {
		if p == ig || strings.HasPrefix(p, ig+".") || strings.HasPrefix(p, ig+"[") {
			return true
		}
	}
	return false
}
