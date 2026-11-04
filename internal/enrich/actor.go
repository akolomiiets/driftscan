package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/akolomiiets/driftscan/internal/discover"
	"github.com/akolomiiets/driftscan/internal/finding"
)

// StateReader returns "show -json" of a Root's current state (runner.Exec implements it).
type StateReader interface {
	State(ctx context.Context, root discover.Root) ([]byte, error)
}

// Event is the newest write event CloudTrail has for a resource.
type Event struct {
	Actor string
	Name  string
	Time  time.Time
}

// Trail looks up the newest write event for a resource name since start, with the credentials and
// region of root; ok is false when none. Errors must not contain the resource name.
type Trail interface {
	LastWrite(ctx context.Context, root discover.Root, resourceName string, start time.Time) (ev Event, ok bool, err error)
}

// lookback is how far back every lookup starts: the change that caused a Drift happened before it
// was detected, so FirstSeen is too late a start.
const lookback = 90 * 24 * time.Hour

// Actors sets ChangedBy, ChangedAt and ChangeEvent on AWS Drift Findings (ADR-0008). Resource ids and
// ARNs are read from the state in memory only: they are never stored on the Report or printed.
// Failures are warnings on warn (addresses only), never fatal.
func Actors(ctx context.Context, r finding.Report, roots []discover.Root, st StateReader, tr Trail, now time.Time, warn io.Writer) finding.Report {
	byPath := map[string]discover.Root{}
	for _, root := range roots {
		byPath[root.Path] = root
	}
	idx := map[string][]int{}
	var order []string
	for i, f := range r.Findings {
		if f.Kind != finding.KindDrift || !strings.HasPrefix(f.Type, "aws_") || f.Address == "" {
			continue
		}
		if _, seen := idx[f.Root]; !seen {
			order = append(order, f.Root)
		}
		idx[f.Root] = append(idx[f.Root], i)
	}
	for _, path := range order {
		root, ok := byPath[path]
		if !ok {
			fmt.Fprintf(warn, "driftscan: cloudtrail: Root %s not found in the scanned directory\n", path)
			continue
		}
		raw, err := st.State(ctx, root)
		var ids map[string][]string
		if err == nil {
			ids, err = stateIdentifiers(raw)
		}
		if err != nil {
			fmt.Fprintf(warn, "driftscan: cloudtrail: Root %s: %v\n", path, err)
			continue
		}
		for _, i := range idx[path] {
			f := r.Findings[i]
			names := ids[f.Address]
			if len(names) == 0 {
				fmt.Fprintf(warn, "driftscan: cloudtrail: %s %s: no id or arn in state\n", path, f.Address)
				continue
			}
			ev, found, err := lookup(ctx, tr, root, names, now.Add(-lookback))
			if err != nil {
				fmt.Fprintf(warn, "driftscan: cloudtrail: %s %s: %v\n", path, f.Address, err)
				continue
			}
			if found {
				r.Findings[i].ChangedBy, r.Findings[i].ChangedAt, r.Findings[i].ChangeEvent = ev.Actor, ev.Time.UTC(), ev.Name
			}
		}
	}
	return r
}

// lookup tries each name in order (id, then arn) and returns the first hit.
func lookup(ctx context.Context, tr Trail, root discover.Root, names []string, start time.Time) (Event, bool, error) {
	var firstErr error
	for _, n := range names {
		ev, ok, err := tr.LastWrite(ctx, root, n, start)
		if err != nil {
			firstErr = err
			continue
		}
		if ok {
			return ev, true, nil
		}
	}
	return Event{}, false, firstErr
}

// stateIdentifiers maps resource address to its [id, arn] values (those present and non-empty).
func stateIdentifiers(raw []byte) (map[string][]string, error) {
	var s tfjson.State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	out := map[string][]string{}
	if s.Values == nil || s.Values.RootModule == nil {
		return out, nil
	}
	var walk func(m *tfjson.StateModule)
	walk = func(m *tfjson.StateModule) {
		for _, res := range m.Resources {
			for _, k := range []string{"id", "arn"} {
				if v, ok := res.AttributeValues[k].(string); ok && v != "" {
					out[res.Address] = append(out[res.Address], v)
				}
			}
		}
		for _, c := range m.ChildModules {
			walk(c)
		}
	}
	walk(s.Values.RootModule)
	return out, nil
}
