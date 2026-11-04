package enrich

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/akolomiiets/driftscan/internal/discover"
	"github.com/akolomiiets/driftscan/internal/finding"
)

const secretID = "i-0secret123"
const secretARN = "arn:aws:ec2:us-east-1:111111111111:instance/i-0secret123"

const stateJSON = `{"format_version":"1.0","values":{"root_module":{
 "resources":[
  {"address":"aws_instance.web","type":"aws_instance","values":{"id":"` + secretID + `","arn":"` + secretARN + `","password":"hunter2"}},
  {"address":"aws_s3_bucket.noid","type":"aws_s3_bucket","values":{"bucket":"b"}}],
 "child_modules":[{"address":"module.m","resources":[
  {"address":"module.m.aws_sqs_queue.q","type":"aws_sqs_queue","values":{"arn":"arn:q"}}]}]}}}`

type fakeState struct {
	json  string
	err   error
	calls []string
}

func (f *fakeState) State(_ context.Context, r discover.Root) ([]byte, error) {
	f.calls = append(f.calls, r.Path)
	return []byte(f.json), f.err
}

type call struct {
	root  string
	name  string
	start time.Time
}

type fakeTrail struct {
	events map[string]Event
	errs   map[string]error
	calls  []call
}

func (f *fakeTrail) LastWrite(_ context.Context, root discover.Root, name string, start time.Time) (Event, bool, error) {
	f.calls = append(f.calls, call{root.Path, name, start})
	if err := f.errs[name]; err != nil {
		return Event{}, false, err
	}
	ev, ok := f.events[name]
	return ev, ok, nil
}

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func drift(root, addr, typ string) finding.Finding {
	return finding.Finding{Root: root, Address: addr, Type: typ, Kind: finding.KindDrift}
}

func TestActorsSetsChangedByAndKeepsReportValueFree(t *testing.T) {
	ev := Event{Actor: "alice", Name: "ModifyInstanceAttribute", Time: now.Add(-time.Hour)}
	tr := &fakeTrail{events: map[string]Event{secretID: ev}}
	r := finding.Report{Findings: []finding.Finding{drift("a", "aws_instance.web", "aws_instance")}}
	var warn bytes.Buffer

	out := Actors(context.Background(), r, []discover.Root{{Path: "a"}}, &fakeState{json: stateJSON}, tr, now, &warn)

	f := out.Findings[0]
	if f.ChangedBy != "alice" || f.ChangeEvent != "ModifyInstanceAttribute" || !f.ChangedAt.Equal(ev.Time) {
		t.Fatalf("got %+v", f)
	}
	b, _ := out.Marshal()
	for _, secret := range []string{secretID, secretARN, "hunter2"} {
		if strings.Contains(string(b)+warn.String(), secret) {
			t.Errorf("%q leaked into Report or warnings", secret)
		}
	}
}

func TestActorsAlwaysLooksBackNinetyDaysAndUsesTheRootOfTheFinding(t *testing.T) {
	a := drift("a", "aws_instance.web", "aws_instance")
	a.FirstSeen = now.Add(-48 * time.Hour)
	b := drift("b", "aws_instance.web", "aws_instance")
	tr := &fakeTrail{}
	roots := []discover.Root{{Path: "a"}, {Path: "b"}}

	Actors(context.Background(), finding.Report{Findings: []finding.Finding{a, b}}, roots, &fakeState{json: stateJSON}, tr, now, &bytes.Buffer{})

	want := now.Add(-90 * 24 * time.Hour)
	for _, c := range tr.calls {
		if !c.start.Equal(want) {
			t.Errorf("start = %v, want %v", c.start, want)
		}
	}
	if tr.calls[0].root != "a" || tr.calls[2].root != "b" {
		t.Errorf("roots = %q, %q", tr.calls[0].root, tr.calls[2].root)
	}
}

func TestActorsFallsBackToArnWhenIDHasNoEvent(t *testing.T) {
	tr := &fakeTrail{events: map[string]Event{secretARN: {Actor: "bob", Name: "X", Time: now}}}
	r := finding.Report{Findings: []finding.Finding{drift("a", "aws_instance.web", "aws_instance")}}

	out := Actors(context.Background(), r, []discover.Root{{Path: "a"}}, &fakeState{json: stateJSON}, tr, now, &bytes.Buffer{})

	if out.Findings[0].ChangedBy != "bob" || len(tr.calls) != 2 {
		t.Fatalf("got %+v after %d calls", out.Findings[0], len(tr.calls))
	}
}

func TestActorsUsesArnOnlyResourceInChildModule(t *testing.T) {
	tr := &fakeTrail{events: map[string]Event{"arn:q": {Actor: "carol", Time: now}}}
	r := finding.Report{Findings: []finding.Finding{drift("a", "module.m.aws_sqs_queue.q", "aws_sqs_queue")}}

	out := Actors(context.Background(), r, []discover.Root{{Path: "a"}}, &fakeState{json: stateJSON}, tr, now, &bytes.Buffer{})

	if out.Findings[0].ChangedBy != "carol" {
		t.Fatalf("got %+v", out.Findings[0])
	}
}

func TestActorsSkipsNonAWSNonDriftAndReadsStateOncePerRoot(t *testing.T) {
	pending := drift("a", "aws_instance.web", "aws_instance")
	pending.Kind = finding.KindPending
	r := finding.Report{Findings: []finding.Finding{
		pending,
		drift("a", "google_x.y", "google_x"),
		drift("a", "aws_instance.web", "aws_instance"),
		drift("a", "aws_sqs_queue.q", "aws_sqs_queue"),
	}}
	st := &fakeState{json: stateJSON}

	Actors(context.Background(), r, []discover.Root{{Path: "a"}}, st, &fakeTrail{}, now, &bytes.Buffer{})

	if len(st.calls) != 1 {
		t.Errorf("state read %d times, want 1", len(st.calls))
	}
}

func TestActorsNeverReadsStateWithoutAWSDrift(t *testing.T) {
	st := &fakeState{json: stateJSON}
	r := finding.Report{Findings: []finding.Finding{drift("a", "google_x.y", "google_x")}}

	Actors(context.Background(), r, []discover.Root{{Path: "a"}}, st, &fakeTrail{}, now, &bytes.Buffer{})

	if len(st.calls) != 0 {
		t.Errorf("state read for a Root without AWS Drift")
	}
}

func TestActorsWarnsAndContinues(t *testing.T) {
	cases := []struct {
		name  string
		st    *fakeState
		tr    *fakeTrail
		roots []discover.Root
		want  string
	}{
		{"state error", &fakeState{err: errors.New("init: Error: boom")}, &fakeTrail{}, []discover.Root{{Path: "a"}}, "init: Error: boom"},
		{"bad state json", &fakeState{json: "{"}, &fakeTrail{}, []discover.Root{{Path: "a"}}, "parse state"},
		{"no id or arn", &fakeState{json: stateJSON}, &fakeTrail{}, []discover.Root{{Path: "a"}}, "no id or arn"},
		{"unknown Root", &fakeState{json: stateJSON}, &fakeTrail{}, nil, "not found"},
		{"lookup error", &fakeState{json: stateJSON}, &fakeTrail{errs: map[string]error{secretID: errors.New("ThrottlingException"), secretARN: errors.New("ThrottlingException")}}, []discover.Root{{Path: "a"}}, "ThrottlingException"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, typ := "aws_instance.web", "aws_instance"
			if c.name == "no id or arn" {
				addr, typ = "aws_s3_bucket.noid", "aws_s3_bucket"
			}
			r := finding.Report{Findings: []finding.Finding{drift("a", addr, typ)}}
			var warn bytes.Buffer

			out := Actors(context.Background(), r, c.roots, c.st, c.tr, now, &warn)

			if !strings.Contains(warn.String(), c.want) {
				t.Errorf("warning %q does not contain %q", warn.String(), c.want)
			}
			if out.Findings[0].ChangedBy != "" {
				t.Errorf("ChangedBy set despite failure")
			}
		})
	}
}

func TestActorsKeepsIdHitWhenArnLookupFails(t *testing.T) {
	tr := &fakeTrail{
		events: map[string]Event{secretID: {Actor: "dave", Time: now}},
		errs:   map[string]error{secretARN: errors.New("x")},
	}
	r := finding.Report{Findings: []finding.Finding{drift("a", "aws_instance.web", "aws_instance")}}

	out := Actors(context.Background(), r, []discover.Root{{Path: "a"}}, &fakeState{json: stateJSON}, tr, now, &bytes.Buffer{})

	if out.Findings[0].ChangedBy != "dave" {
		t.Fatalf("got %+v", out.Findings[0])
	}
}
