// Package unmanaged counts AWS resources that exist but that no Terraform state manages (ADR-0010).
// It reads state ids and AWS Config inventory behind interfaces and never keeps attribute values.
package unmanaged

import (
	"context"
	"fmt"
	"sort"
	"sync"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/akolomiiets/driftscan/internal/discover"
)

// DefaultTypes are the AWS Config resource types counted when none are configured.
var DefaultTypes = []string{
	"AWS::EC2::Instance",
	"AWS::EC2::SecurityGroup",
	"AWS::S3::Bucket",
	"AWS::IAM::Role",
	"AWS::RDS::DBInstance",
	"AWS::Lambda::Function",
}

// Resource is one inventory entry from AWS Config.
type Resource struct {
	Type string
	ID   string
	ARN  string
}

// Inventory lists existing resources of the given Config resource types.
type Inventory interface {
	List(ctx context.Context, types []string) ([]Resource, error)
}

// StateReader returns the JSON rendering of a Root's current state.
type StateReader interface {
	State(ctx context.Context, root discover.Root) ([]byte, error)
}

// TypeCount is the result for one resource type. Examples are unmanaged ids, only when requested.
type TypeCount struct {
	Type      string   `json:"type"`
	Total     int      `json:"total"`
	Managed   int      `json:"managed"`
	Unmanaged int      `json:"unmanaged"`
	Examples  []string `json:"examples,omitempty"`
}

// Result is the full unmanaged count, sorted by type.
type Result struct {
	Types []TypeCount `json:"types"`
}

// TotalUnmanaged sums the unmanaged count over all types.
func (r Result) TotalUnmanaged() int {
	n := 0
	for _, t := range r.Types {
		n += t.Unmanaged
	}
	return n
}

// Managed holds the id and arn attributes of managed resources, kept apart: an id such as a bucket
// name is shared by sub-resources and by other types, an ARN is not.
type Managed struct {
	IDs  map[string]bool
	ARNs map[string]bool
}

// ManagedIDs reads every Root's state and collects the id and arn of each managed resource.
// Any Root that cannot be read is an error: a partial set would inflate the count.
func ManagedIDs(ctx context.Context, r StateReader, roots []discover.Root, concurrency int) (Managed, error) {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		set  = Managed{IDs: map[string]bool{}, ARNs: map[string]bool{}}
		errs []error
		sem  = make(chan struct{}, max(concurrency, 1))
	)
	for _, root := range roots {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			got, err := rootIDs(ctx, r, root)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", root.Path, err))
				return
			}
			for _, id := range got.ids {
				set.IDs[id] = true
			}
			for _, arn := range got.arns {
				set.ARNs[arn] = true
			}
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
		return Managed{}, fmt.Errorf("reading state of %d Roots failed, first: %w", len(errs), errs[0])
	}
	return set, nil
}

type rootSet struct{ ids, arns []string }

func rootIDs(ctx context.Context, r StateReader, root discover.Root) (rootSet, error) {
	b, err := r.State(ctx, root)
	if err != nil {
		return rootSet{}, err
	}
	var st tfjson.State
	if err := st.UnmarshalJSON(b); err != nil {
		return rootSet{}, fmt.Errorf("parse state: %w", err)
	}
	if st.Values == nil || st.Values.RootModule == nil {
		return rootSet{}, nil
	}
	var out rootSet
	var walk func(m *tfjson.StateModule)
	walk = func(m *tfjson.StateModule) {
		for _, res := range m.Resources {
			if res.Mode != tfjson.ManagedResourceMode {
				continue
			}
			if s, ok := res.AttributeValues["id"].(string); ok && s != "" {
				out.ids = append(out.ids, s)
			}
			if s, ok := res.AttributeValues["arn"].(string); ok && s != "" {
				out.arns = append(out.arns, s)
			}
		}
		for _, c := range m.ChildModules {
			walk(c)
		}
	}
	walk(st.Values.RootModule)
	return out, nil
}

// Count matches the inventory against the managed set. A Config row with an ARN is managed only when
// the ARN equals an arn attribute of a managed resource. A row without an ARN falls back to its
// resourceId matching an id attribute. Every requested type appears in the result, with zeros when
// Config returned nothing. examples caps the unmanaged ARNs (else resourceIds) listed.
func Count(inv []Resource, managed Managed, types []string, examples int) Result {
	by := map[string]*TypeCount{}
	for _, t := range types {
		by[t] = &TypeCount{Type: t}
	}
	for _, res := range inv {
		tc, ok := by[res.Type]
		if !ok {
			continue
		}
		tc.Total++
		if isManaged(res, managed) {
			tc.Managed++
			continue
		}
		tc.Unmanaged++
		if len(tc.Examples) < examples {
			tc.Examples = append(tc.Examples, exampleOf(res))
		}
	}
	var out Result
	for _, tc := range by {
		sort.Strings(tc.Examples)
		out.Types = append(out.Types, *tc)
	}
	sort.Slice(out.Types, func(i, j int) bool { return out.Types[i].Type < out.Types[j].Type })
	return out
}

func isManaged(res Resource, m Managed) bool {
	if res.ARN != "" {
		return m.ARNs[res.ARN]
	}
	return m.IDs[res.ID]
}

func exampleOf(res Resource) string {
	if res.ARN != "" {
		return res.ARN
	}
	return res.ID
}
