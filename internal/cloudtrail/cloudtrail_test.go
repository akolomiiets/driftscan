package cloudtrail

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
)

type fakeAPI struct {
	pages []*cloudtrail.LookupEventsOutput
	err   error
	calls int
}

func (f *fakeAPI) LookupEvents(_ context.Context, _ *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	i := min(f.calls-1, len(f.pages)-1)
	return f.pages[i], nil
}

var start = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

func ev(readOnly string, at time.Time) types.Event {
	return types.Event{ReadOnly: aws.String(readOnly), EventName: aws.String("Do"), Username: aws.String("alice"), EventTime: aws.Time(at)}
}

func page(next string, events ...types.Event) *cloudtrail.LookupEventsOutput {
	out := &cloudtrail.LookupEventsOutput{Events: events}
	if next != "" {
		out.NextToken = aws.String(next)
	}
	return out
}

func newClient(api lookupAPI) *Client { return &Client{api: api} }

func TestLastWritePagesPastReadOnlyEventsUntilAWrite(t *testing.T) {
	var pages []*cloudtrail.LookupEventsOutput
	for range 9 {
		pages = append(pages, page("n", ev("true", start.Add(48*time.Hour))))
	}
	pages = append(pages, page("", ev("false", start.Add(24*time.Hour))))
	api := &fakeAPI{pages: pages}

	got, ok, err := newClient(api).LastWrite(context.Background(), "r", start)

	if err != nil || !ok || got.Actor != "alice" || got.Name != "Do" {
		t.Fatalf("got %+v ok=%v err=%v", got, ok, err)
	}
	if api.calls != 10 {
		t.Errorf("calls = %d, want 10", api.calls)
	}
}

func TestLastWriteStopsWhenNoNextToken(t *testing.T) {
	api := &fakeAPI{pages: []*cloudtrail.LookupEventsOutput{page("", ev("true", start.Add(time.Hour)))}}

	_, ok, err := newClient(api).LastWrite(context.Background(), "r", start)

	if err != nil || ok || api.calls != 1 {
		t.Fatalf("ok=%v err=%v calls=%d", ok, err, api.calls)
	}
}

func TestLastWriteStopsAtEventsOlderThanStart(t *testing.T) {
	api := &fakeAPI{pages: []*cloudtrail.LookupEventsOutput{
		page("n", ev("true", start.Add(time.Hour)), ev("false", start.Add(-time.Hour))),
	}}

	_, ok, err := newClient(api).LastWrite(context.Background(), "r", start)

	if err != nil || ok || api.calls != 1 {
		t.Fatalf("ok=%v err=%v calls=%d, want a write older than start ignored", ok, err, api.calls)
	}
}

func TestLastWriteHasASafetyCap(t *testing.T) {
	api := &fakeAPI{pages: []*cloudtrail.LookupEventsOutput{page("n", ev("true", start.Add(time.Hour)))}}

	_, ok, err := newClient(api).LastWrite(context.Background(), "r", start)

	if err != nil || ok || api.calls != maxPages {
		t.Fatalf("ok=%v err=%v calls=%d, want %d", ok, err, api.calls, maxPages)
	}
}

func TestLookupErrorShowsClientSideMessageButOnlyCodeForAPIErrors(t *testing.T) {
	api := &fakeAPI{err: errors.New("failed to resolve region")}
	_, _, err := newClient(api).LastWrite(context.Background(), "r", start)
	if err == nil || !strings.Contains(err.Error(), "failed to resolve region") {
		t.Errorf("client-side err = %v", err)
	}

	api = &fakeAPI{err: &smithy.GenericAPIError{Code: "ThrottlingException", Message: "secret-resource-id"}}
	_, _, err = newClient(api).LastWrite(context.Background(), "secret-resource-id", start)
	if err == nil || err.Error() != "LookupEvents: ThrottlingException" {
		t.Errorf("api err = %v", err)
	}
}

func TestTrailCachesOneClientPerProfileAndRegion(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "x")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "x")
	tr := New()
	a := map[string]string{"AWS_PROFILE": "", "AWS_REGION": "us-east-1"}
	b := map[string]string{"AWS_REGION": "us-east-2"}

	c1, err1 := tr.client(context.Background(), a)
	c2, err2 := tr.client(context.Background(), map[string]string{"AWS_REGION": "us-east-1", "OTHER": "x"})
	c3, err3 := tr.client(context.Background(), b)

	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatal(err1, err2, err3)
	}
	if c1 != c2 || c1 == c3 || len(tr.clients) != 2 {
		t.Errorf("clients not cached per (profile, region): %d", len(tr.clients))
	}
}
