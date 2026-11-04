// Package cloudtrail is the AWS adapter for enrich.Trail. Only driftscan enrich imports it (ADR-0007).
package cloudtrail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"

	"github.com/akolomiiets/driftscan/internal/discover"
	"github.com/akolomiiets/driftscan/internal/enrich"
)

// maxPages is a safety cap only; paging normally stops at the first write event, the end of the
// results or the first event older than the start time.
const maxPages = 50

type lookupAPI interface {
	LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// Client calls LookupEvents, at most one request per interval (CloudTrail allows 2 per second).
type Client struct {
	api      lookupAPI
	interval time.Duration
	last     time.Time
}

type clientKey struct{ profile, region string }

// Trail implements enrich.Trail with one Client per distinct (AWS_PROFILE, AWS_REGION) of the Root
// env, falling back to the default credential chain for a key that is empty. Clients are built on
// first use and cached.
type Trail struct {
	clients map[clientKey]*Client
}

func New() *Trail {
	return &Trail{clients: map[clientKey]*Client{}}
}

func (t *Trail) client(ctx context.Context, env map[string]string) (*Client, error) {
	key := clientKey{env["AWS_PROFILE"], env["AWS_REGION"]}
	if c, ok := t.clients[key]; ok {
		return c, nil
	}
	var opts []func(*config.LoadOptions) error
	if key.profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(key.profile))
	}
	if key.region != "" {
		opts = append(opts, config.WithRegion(key.region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	c := &Client{api: cloudtrail.NewFromConfig(cfg), interval: 500 * time.Millisecond}
	t.clients[key] = c
	return c, nil
}

func (t *Trail) LastWrite(ctx context.Context, root discover.Root, resourceName string, start time.Time) (enrich.Event, bool, error) {
	c, err := t.client(ctx, root.Env)
	if err != nil {
		return enrich.Event{}, false, err
	}
	return c.LastWrite(ctx, resourceName, start)
}

func (c *Client) throttle(ctx context.Context) error {
	if wait := c.interval - time.Since(c.last); wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.last = time.Now()
	return nil
}

// LastWrite pages through LookupEvents (newest first) until a write event is found, there is no
// next page, or an event older than start is seen.
func (c *Client) LastWrite(ctx context.Context, resourceName string, start time.Time) (enrich.Event, bool, error) {
	in := &cloudtrail.LookupEventsInput{
		LookupAttributes: []types.LookupAttribute{{
			AttributeKey:   types.LookupAttributeKeyResourceName,
			AttributeValue: aws.String(resourceName),
		}},
		StartTime: aws.Time(start),
	}
	for range maxPages {
		if err := c.throttle(ctx); err != nil {
			return enrich.Event{}, false, err
		}
		out, err := c.api.LookupEvents(ctx, in)
		if err != nil {
			return enrich.Event{}, false, lookupError(err)
		}
		reachedStart := false
		for _, e := range out.Events {
			if e.EventTime != nil && e.EventTime.Before(start) {
				reachedStart = true
				break
			}
			if aws.ToString(e.ReadOnly) == "false" {
				return enrich.Event{Actor: aws.ToString(e.Username), Name: aws.ToString(e.EventName), Time: aws.ToTime(e.EventTime)}, true, nil
			}
		}
		if reachedStart || out.NextToken == nil {
			break
		}
		in.NextToken = out.NextToken
	}
	return enrich.Event{}, false, nil
}

// lookupError keeps only the code of an API error, since its message can echo the resource name.
// Other errors are client-side (no region, no credentials) and safe to show.
func lookupError(err error) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return fmt.Errorf("LookupEvents: %s", ae.ErrorCode())
	}
	return fmt.Errorf("LookupEvents failed: %s", err.Error())
}
