package unmanaged

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/configservice"

	"github.com/akolomiiets/driftscan/internal/discover"
)

type fakeState map[string]string

func (f fakeState) State(_ context.Context, r discover.Root) ([]byte, error) {
	s, ok := f[r.Path]
	if !ok {
		return nil, errors.New("boom")
	}
	return []byte(s), nil
}

const stateA = `{"format_version":"1.0","values":{"root_module":{
 "resources":[
  {"address":"aws_s3_bucket.a","mode":"managed","type":"aws_s3_bucket","name":"a","values":{"id":"bucket-a","arn":"arn:aws:s3:::bucket-a","secret":"hunter2"}},
  {"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","name":"me","values":{"id":"123456789012"}}],
 "child_modules":[{"address":"module.m","resources":[
  {"address":"module.m.aws_instance.i","mode":"managed","type":"aws_instance","name":"i","values":{"id":"i-1"}}]}]}}}`

func TestManagedIDs(t *testing.T) {
	roots := []discover.Root{{Path: "a"}, {Path: "empty"}}
	st := fakeState{"a": stateA, "empty": `{"format_version":"1.0"}`}

	ids, err := ManagedIDs(context.Background(), st, roots, 2)

	if err != nil {
		t.Fatal(err)
	}
	if len(ids.IDs) != 2 || !ids.IDs["bucket-a"] || !ids.IDs["i-1"] {
		t.Fatalf("ids = %v", ids.IDs)
	}
	if len(ids.ARNs) != 1 || !ids.ARNs["arn:aws:s3:::bucket-a"] {
		t.Fatalf("arns = %v", ids.ARNs)
	}
	if ids.IDs["hunter2"] || ids.IDs["123456789012"] {
		t.Error("kept a non-id value or a data source")
	}
}

func TestManagedIDsStateErrorFails(t *testing.T) {
	_, err := ManagedIDs(context.Background(), fakeState{}, []discover.Root{{Path: "x"}}, 1)
	if err == nil || !strings.Contains(err.Error(), "x: boom") {
		t.Fatalf("err = %v", err)
	}
}

func TestManagedIDsBadJSON(t *testing.T) {
	_, err := ManagedIDs(context.Background(), fakeState{"x": "nope"}, []discover.Root{{Path: "x"}}, 1)
	if err == nil {
		t.Fatal("want error")
	}
}

func TestCount(t *testing.T) {
	inv := []Resource{
		{"AWS::S3::Bucket", "bucket-a", "arn:aws:s3:::bucket-a"},
		{"AWS::S3::Bucket", "bucket-z", "arn:aws:s3:::bucket-z"},
		{"AWS::S3::Bucket", "bucket-y", "arn:aws:s3:::bucket-y"},
		{"AWS::IAM::Role", "AROA1", "arn:aws:iam::1:role/r"},
		{"AWS::Other::Thing", "t", ""},
	}
	managed := Managed{
		IDs:  map[string]bool{"bucket-z": true},
		ARNs: map[string]bool{"arn:aws:s3:::bucket-a": true, "arn:aws:iam::1:role/r": true},
	}

	r := Count(inv, managed, []string{"AWS::S3::Bucket", "AWS::IAM::Role", "AWS::EC2::Instance"}, 1)

	got := map[string]TypeCount{}
	for _, tc := range r.Types {
		got[tc.Type] = tc
	}
	b := got["AWS::S3::Bucket"]
	if b.Total != 3 || b.Managed != 1 || b.Unmanaged != 2 || len(b.Examples) != 1 || b.Examples[0] != "arn:aws:s3:::bucket-z" {
		t.Errorf("bucket = %+v", b)
	}
	if role := got["AWS::IAM::Role"]; role.Managed != 1 || role.Unmanaged != 0 {
		t.Errorf("role matched by arn = %+v", role)
	}
	if ec2 := got["AWS::EC2::Instance"]; ec2.Total != 0 {
		t.Errorf("ec2 = %+v", ec2)
	}
	if _, ok := got["AWS::Other::Thing"]; ok {
		t.Error("unrequested type in result")
	}
	if r.TotalUnmanaged() != 2 {
		t.Errorf("total = %d", r.TotalUnmanaged())
	}
	if r.Types[0].Type != "AWS::EC2::Instance" {
		t.Errorf("not sorted: %+v", r.Types)
	}
}

func TestCountSubResourceIDDoesNotMarkBucketManaged(t *testing.T) {
	inv := []Resource{{"AWS::S3::Bucket", "b", "arn:aws:s3:::b"}}
	managed := Managed{IDs: map[string]bool{"b": true}}

	r := Count(inv, managed, []string{"AWS::S3::Bucket"}, 0)

	if r.Types[0].Managed != 0 || r.Types[0].Unmanaged != 1 {
		t.Errorf("%+v", r.Types[0])
	}
}

func TestCountSameNameOtherTypeIsNotManaged(t *testing.T) {
	inv := []Resource{
		{"AWS::IAM::Role", "AROA1", "arn:aws:iam::1:role/api-handler"},
		{"AWS::Lambda::Function", "api-handler", "arn:aws:lambda:us-east-1:1:function:api-handler"},
	}
	managed := Managed{ARNs: map[string]bool{"arn:aws:iam::1:role/api-handler": true}}

	r := Count(inv, managed, []string{"AWS::IAM::Role", "AWS::Lambda::Function"}, 0)

	if r.Types[0].Type != "AWS::IAM::Role" || r.Types[0].Managed != 1 {
		t.Errorf("role = %+v", r.Types[0])
	}
	if r.Types[1].Managed != 0 || r.Types[1].Unmanaged != 1 {
		t.Errorf("lambda = %+v", r.Types[1])
	}
}

func TestCountFallsBackToIDWhenNoARN(t *testing.T) {
	inv := []Resource{{"AWS::EC2::Instance", "i-1", ""}, {"AWS::EC2::Instance", "i-2", ""}}
	managed := Managed{IDs: map[string]bool{"i-1": true}}

	r := Count(inv, managed, []string{"AWS::EC2::Instance"}, 5)

	if r.Types[0].Managed != 1 || r.Types[0].Unmanaged != 1 || r.Types[0].Examples[0] != "i-2" {
		t.Errorf("%+v", r.Types[0])
	}
}

func TestCountNoExamplesByDefault(t *testing.T) {
	r := Count([]Resource{{"AWS::S3::Bucket", "b", ""}}, Managed{}, []string{"AWS::S3::Bucket"}, 0)
	if r.Types[0].Unmanaged != 1 || r.Types[0].Examples != nil {
		t.Errorf("%+v", r.Types[0])
	}
}

type fakeConfig struct {
	exprs   []string
	aggName string
	pages   [][]string
}

func (f *fakeConfig) page(expr string) ([]string, *string) {
	f.exprs = append(f.exprs, expr)
	p := f.pages[0]
	f.pages = f.pages[1:]
	if len(f.pages) == 0 {
		return p, nil
	}
	tok := "next"
	return p, &tok
}

func (f *fakeConfig) SelectResourceConfig(_ context.Context, in *configservice.SelectResourceConfigInput, _ ...func(*configservice.Options)) (*configservice.SelectResourceConfigOutput, error) {
	r, tok := f.page(*in.Expression)
	return &configservice.SelectResourceConfigOutput{Results: r, NextToken: tok}, nil
}

func (f *fakeConfig) SelectAggregateResourceConfig(_ context.Context, in *configservice.SelectAggregateResourceConfigInput, _ ...func(*configservice.Options)) (*configservice.SelectAggregateResourceConfigOutput, error) {
	f.aggName = *in.ConfigurationAggregatorName
	r, tok := f.page(*in.Expression)
	return &configservice.SelectAggregateResourceConfigOutput{Results: r, NextToken: tok}, nil
}

func TestConfigInventoryPaginates(t *testing.T) {
	f := &fakeConfig{pages: [][]string{
		{`{"resourceType":"AWS::S3::Bucket","resourceId":"b1","arn":"arn:b1"}`},
		{`{"resourceType":"AWS::S3::Bucket","resourceId":"b2"}`},
	}}

	got, err := ConfigInventory{API: f}.List(context.Background(), []string{"AWS::S3::Bucket", "AWS::EC2::Instance"})

	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ARN != "arn:b1" || got[1].ID != "b2" {
		t.Errorf("got %+v", got)
	}
	want := "SELECT resourceType, resourceId, arn WHERE resourceType IN ('AWS::S3::Bucket', 'AWS::EC2::Instance')"
	if len(f.exprs) != 2 || f.exprs[0] != want {
		t.Errorf("exprs = %q", f.exprs)
	}
}

func TestConfigInventoryAggregator(t *testing.T) {
	f := &fakeConfig{pages: [][]string{{`{"resourceType":"AWS::S3::Bucket","resourceId":"b"}`}}}

	got, err := ConfigInventory{API: f, Aggregator: "org"}.List(context.Background(), []string{"AWS::S3::Bucket"})

	if err != nil || len(got) != 1 || f.aggName != "org" {
		t.Fatalf("got %+v err %v agg %q", got, err, f.aggName)
	}
}

func TestConfigInventoryRejectsBadType(t *testing.T) {
	_, err := ConfigInventory{API: &fakeConfig{}}.List(context.Background(), []string{"x' OR 1=1"})
	if err == nil {
		t.Fatal("want error")
	}
}

func TestRender(t *testing.T) {
	r := Result{Types: []TypeCount{{Type: "AWS::S3::Bucket", Total: 3, Managed: 1, Unmanaged: 2, Examples: []string{"b1"}}}}

	md := Markdown(r)
	if !strings.Contains(md, "| `AWS::S3::Bucket` | 3 | 1 | 2 |") || !strings.Contains(md, "`b1`") {
		t.Errorf("md = %s", md)
	}
	j, _ := JSON(r)
	if !strings.Contains(string(j), `"unmanaged": 2`) {
		t.Errorf("json = %s", j)
	}
	o := string(OTLPMetrics(r, time.Unix(1, 0)))
	if !strings.Contains(o, `"driftscan.unmanaged"`) || !strings.Contains(o, `"resource_type"`) || !strings.Contains(o, `"asInt":"2"`) {
		t.Errorf("otlp = %s", o)
	}
	plain, _ := JSON(Result{Types: []TypeCount{{Type: "t"}}})
	if strings.Contains(string(plain), "examples") {
		t.Error("examples should be omitted when empty")
	}
}
