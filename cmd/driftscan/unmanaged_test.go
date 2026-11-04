package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akolomiiets/driftscan/internal/discover"
	"github.com/akolomiiets/driftscan/internal/unmanaged"
)

type fakeState struct{}

func (fakeState) State(context.Context, discover.Root) ([]byte, error) {
	return []byte(`{"format_version":"1.0","values":{"root_module":{"resources":[{"address":"aws_s3_bucket.a","mode":"managed","type":"aws_s3_bucket","name":"a","values":{"id":"b1"}}]}}}`), nil
}

type fakeInv struct{}

func (fakeInv) List(context.Context, []string) ([]unmanaged.Resource, error) {
	return []unmanaged.Resource{{Type: "AWS::S3::Bucket", ID: "b1"}, {Type: "AWS::S3::Bucket", ID: "b2"}}, nil
}

func TestUnmanagedEndToEnd(t *testing.T) {
	res, err := runUnmanaged(context.Background(), fakeState{}, fakeInv{}, []discover.Root{{Path: "a"}}, []string{"AWS::S3::Bucket"}, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	summary := filepath.Join(dir, "sum.md")
	var stdout, stderr bytes.Buffer

	code := emitUnmanaged(context.Background(), res, unmanagedOut{out: filepath.Join(dir, "u.json"), markdown: summary, failOver: 0}, &stdout, &stderr)

	if code != exitFindings {
		t.Errorf("code = %d, want %d (1 unmanaged > 0)", code, exitFindings)
	}
	j, _ := os.ReadFile(filepath.Join(dir, "u.json"))
	if !strings.Contains(string(j), `"unmanaged": 1`) || !strings.Contains(string(j), `"b2"`) {
		t.Errorf("json = %s", j)
	}
	md, _ := os.ReadFile(summary)
	if !strings.Contains(string(md), "| `AWS::S3::Bucket` | 2 | 1 | 1 |") {
		t.Errorf("md = %s", md)
	}
}

func TestUnmanagedExitZeroByDefault(t *testing.T) {
	res := unmanaged.Result{Types: []unmanaged.TypeCount{{Type: "AWS::S3::Bucket", Unmanaged: 9}}}
	var stdout, stderr bytes.Buffer

	code := emitUnmanaged(context.Background(), res, unmanagedOut{markdown: "", failOver: -1}, &stdout, &stderr)

	if code != exitOK {
		t.Errorf("code = %d", code)
	}
}

func TestUnmanagedBadTypeIsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cmdUnmanaged(context.Background(), []string{"-types", "bogus"}, &stdout, &stderr); code != exitError {
		t.Errorf("code = %d", code)
	}
}

func TestEmitUnmanagedWarnsOnTypeWithoutRecords(t *testing.T) {
	res := unmanaged.Result{Types: []unmanaged.TypeCount{{Type: "AWS::IAM::Role"}, {Type: "AWS::S3::Bucket", Total: 1, Unmanaged: 1}}}
	var stdout, stderr bytes.Buffer

	code := emitUnmanaged(context.Background(), res, unmanagedOut{markdown: "", failOver: -1}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("code = %d", code)
	}
	want := "no AWS Config records for AWS::IAM::Role: recorder off, type not recorded, or wrong region (IAM is recorded only in the home region)"
	if !strings.Contains(stderr.String(), want) || strings.Contains(stderr.String(), "records for AWS::S3::Bucket") {
		t.Errorf("stderr = %s", stderr.String())
	}
}
