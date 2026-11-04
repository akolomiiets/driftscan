package unmanaged

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

var typeRe = regexp.MustCompile(`^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$`)

// ValidateTypes rejects anything that is not a Config resource type, since the names go into a query.
func ValidateTypes(types []string) error {
	for _, t := range types {
		if !typeRe.MatchString(t) {
			return fmt.Errorf("invalid resource type %q, want e.g. AWS::S3::Bucket", t)
		}
	}
	return nil
}

// ConfigAPI is the part of the AWS Config client that is used; *configservice.Client satisfies it.
type ConfigAPI interface {
	SelectResourceConfig(ctx context.Context, in *configservice.SelectResourceConfigInput, opts ...func(*configservice.Options)) (*configservice.SelectResourceConfigOutput, error)
	SelectAggregateResourceConfig(ctx context.Context, in *configservice.SelectAggregateResourceConfigInput, opts ...func(*configservice.Options)) (*configservice.SelectAggregateResourceConfigOutput, error)
}

// ConfigInventory lists resources with an AWS Config advanced query. With Aggregator set it queries
// the aggregator (all accounts and regions it covers) instead of the client's own account and region.
type ConfigInventory struct {
	API        ConfigAPI
	Aggregator string
}

func (c ConfigInventory) List(ctx context.Context, types []string) ([]Resource, error) {
	if err := ValidateTypes(types); err != nil {
		return nil, err
	}
	quoted := make([]string, len(types))
	for i, t := range types {
		quoted[i] = "'" + t + "'"
	}
	expr := "SELECT resourceType, resourceId, arn WHERE resourceType IN (" + strings.Join(quoted, ", ") + ")"

	var out []Resource
	var token *string
	for {
		var rows []string
		if c.Aggregator != "" {
			resp, err := c.API.SelectAggregateResourceConfig(ctx, &configservice.SelectAggregateResourceConfigInput{
				ConfigurationAggregatorName: aws.String(c.Aggregator), Expression: aws.String(expr), Limit: 100, NextToken: token,
			})
			if err != nil {
				return nil, fmt.Errorf("config select aggregate: %w", err)
			}
			rows, token = resp.Results, resp.NextToken
		} else {
			resp, err := c.API.SelectResourceConfig(ctx, &configservice.SelectResourceConfigInput{
				Expression: aws.String(expr), Limit: 100, NextToken: token,
			})
			if err != nil {
				return nil, fmt.Errorf("config select: %w", err)
			}
			rows, token = resp.Results, resp.NextToken
		}
		for _, row := range rows {
			var r struct {
				ResourceType string `json:"resourceType"`
				ResourceID   string `json:"resourceId"`
				ARN          string `json:"arn"`
			}
			if err := json.Unmarshal([]byte(row), &r); err != nil {
				return nil, fmt.Errorf("config result: %w", err)
			}
			out = append(out, Resource{Type: r.ResourceType, ID: r.ResourceID, ARN: r.ARN})
		}
		if token == nil || *token == "" {
			return out, nil
		}
	}
}
