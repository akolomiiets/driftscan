package output

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/akolomiiets/driftscan/internal/finding"
)

func drift(addr string, sev finding.Severity, status finding.Status) finding.Finding {
	return finding.Finding{Root: "envs/dev", Address: addr, Kind: finding.KindDrift, Severity: sev, Status: status,
		Paths: []string{"tags.Name"}, File: "sg.tf", Line: 3}
}

func annotate(pending bool, fs ...finding.Finding) []string {
	return Annotations(finding.Report{Findings: fs}, Source{Prefix: "infra/"}, pending)
}

func TestAnnotationsLine(t *testing.T) {
	f := drift("aws_security_group.web", finding.SeverityHigh, finding.StatusNew)
	f.Paths = []string{"ingress[0].cidr_blocks", "tags.Name"}
	f.File, f.Line = "envs/dev/sg.tf", 12

	got := annotate(true, f)

	want := "::error file=infra/envs/dev/sg.tf,line=12,title=driftscan%3A aws_security_group.web::ingress[0].cidr_blocks, tags.Name"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAnnotationsEscapesPropertiesAndData(t *testing.T) {
	f := drift(`aws_x.y["a,b:c%"]`, finding.SeverityCritical, finding.StatusChanged)
	scan := finding.Finding{Root: "r:1,2", Kind: finding.KindScanError, Severity: finding.SeverityMedium,
		Status: finding.StatusNew, Message: "50% bad\r\nline two"}

	got := annotate(true, f, scan)

	want := []string{
		"::error file=infra/sg.tf,line=3,title=driftscan%3A aws_x.y[\"a%2Cb%3Ac%25\"]::tags.Name",
		"::warning title=driftscan%3A Scan error in r%3A1%2C2::50%25 bad%0D%0Aline two",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAnnotationsLevels(t *testing.T) {
	ack := drift("ack", finding.SeverityCritical, finding.StatusNew)
	ack.Acknowledged = true
	pend := drift("pend", finding.SeverityHigh, finding.StatusNew)
	pend.Kind = finding.KindPending
	cases := map[string]struct {
		f    finding.Finding
		want string
	}{
		"critical drift":     {drift("a", finding.SeverityCritical, finding.StatusNew), "::error "},
		"high drift changed": {drift("a", finding.SeverityHigh, finding.StatusChanged), "::error "},
		"medium drift":       {drift("a", finding.SeverityMedium, finding.StatusNew), "::warning "},
		"low drift":          {drift("a", finding.SeverityLow, finding.StatusNew), "::warning "},
		"info drift":         {drift("a", finding.SeverityInfo, finding.StatusNew), "::warning "},
		"pending":            {pend, "::notice "},
		"acknowledged":       {ack, ""},
		"persisting":         {drift("a", finding.SeverityHigh, finding.StatusPersisting), ""},
		"resolved":           {drift("a", finding.SeverityHigh, finding.StatusResolved), ""},
		"unknown":            {drift("a", finding.SeverityHigh, finding.StatusUnknown), ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := annotate(true, c.f)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no annotation, got %q", got)
				}
				return
			}
			if len(got) != 1 || !strings.HasPrefix(got[0], c.want) {
				t.Fatalf("want prefix %q, got %q", c.want, got)
			}
		})
	}
}

func TestAnnotationsPendingToggle(t *testing.T) {
	pend := drift("pend", finding.SeverityInfo, finding.StatusNew)
	pend.Kind = finding.KindPending
	pend.Paths = nil

	if got := annotate(false, pend); len(got) != 0 {
		t.Fatalf("pending off: got %q", got)
	}
	got := annotate(true, pend)
	if len(got) != 1 || !strings.HasSuffix(got[0], "::pending change") {
		t.Fatalf("pending on: got %q", got)
	}
}

func TestAnnotationsMessageFallbacks(t *testing.T) {
	f := drift("a", finding.SeverityHigh, finding.StatusNew)
	f.Paths, f.Actions = nil, []string{"delete", "create"}
	if got := annotate(true, f); !strings.HasSuffix(got[0], "::delete, create") {
		t.Fatalf("actions fallback: got %q", got)
	}
	f.Actions = nil
	if got := annotate(true, f); !strings.HasSuffix(got[0], "::drift") {
		t.Fatalf("drift fallback: got %q", got)
	}
}

func TestAnnotationsWithoutFileOrLine(t *testing.T) {
	noFile := drift("a", finding.SeverityHigh, finding.StatusNew)
	noFile.File, noFile.Line = "", 7
	noLine := drift("b", finding.SeverityHigh, finding.StatusNew)
	noLine.Line = 0

	got := annotate(true, noFile, noLine)

	want := []string{
		"::error title=driftscan%3A a::tags.Name",
		"::error file=infra/sg.tf,title=driftscan%3A b::tags.Name",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAnnotationsTruncatePerLevel(t *testing.T) {
	var fs []finding.Finding
	for i := 0; i < 12; i++ {
		fs = append(fs, drift(fmt.Sprintf("hi.%02d", i), finding.SeverityHigh, finding.StatusNew))
	}
	for i := 0; i < 3; i++ {
		fs = append(fs, drift(fmt.Sprintf("lo.%02d", i), finding.SeverityLow, finding.StatusNew))
	}

	got := annotate(true, fs...)

	if len(got) != 13 {
		t.Fatalf("want 9+1 errors and 3 warnings, got %d: %q", len(got), got)
	}
	wantSummary := "::error title=driftscan::3 more error Findings, see the step summary or report artifact"
	if got[9] != wantSummary {
		t.Fatalf("summary: got %q, want %q", got[9], wantSummary)
	}
	if !strings.Contains(got[8], "hi.08") || !strings.HasPrefix(got[10], "::warning ") {
		t.Fatalf("unexpected order: %q", got)
	}
}

func TestAnnotationsOrderIsDeterministic(t *testing.T) {
	a := drift("z", finding.SeverityMedium, finding.StatusNew)
	b := drift("a", finding.SeverityMedium, finding.StatusNew)
	b.Root = "envs/prod"
	c := drift("b", finding.SeverityMedium, finding.StatusNew)
	d := drift("m", finding.SeverityLow, finding.StatusNew)
	e := drift("x", finding.SeverityHigh, finding.StatusNew)
	want := annotate(true, a, b, c, d, e)

	got := annotate(true, e, d, c, b, a)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order depends on input:\n%q\n%q", got, want)
	}
	titles := []string{"x", "b", "z", "a", "m"}
	for i, title := range titles {
		if !strings.Contains(got[i], "driftscan%3A "+title+"::") {
			t.Fatalf("position %d: want %s, got %q", i, title, got[i])
		}
	}
}
