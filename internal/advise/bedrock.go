package advise

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

// converser is the part of the Bedrock runtime client used here.
type converser interface {
	Converse(ctx context.Context, in *bedrockruntime.ConverseInput, opts ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}

// Bedrock calls the Amazon Bedrock Converse API, so the data stays in the caller's AWS account.
type Bedrock struct {
	client converser
	model  string
}

// NewBedrock uses the default AWS credential and region chain.
func NewBedrock(ctx context.Context, model string) (*Bedrock, error) {
	if model == "" {
		return nil, errors.New("model is required (-model or advisor.model in drift.yaml)")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &Bedrock{client: bedrockruntime.NewFromConfig(cfg), model: model}, nil
}

func (b *Bedrock) Complete(ctx context.Context, system, user string) (string, error) {
	out, err := b.client.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId: aws.String(b.model),
		System:  []types.SystemContentBlock{&types.SystemContentBlockMemberText{Value: system}},
		Messages: []types.Message{{
			Role:    types.ConversationRoleUser,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: user}},
		}},
		InferenceConfig: &types.InferenceConfiguration{MaxTokens: aws.Int32(8192), Temperature: aws.Float32(0)},
	})
	if err != nil {
		return "", fmt.Errorf("bedrock converse: %w", err)
	}
	if out.StopReason == types.StopReasonMaxTokens {
		return "", errors.New("bedrock converse: response truncated at max_tokens")
	}
	msg, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return "", errors.New("bedrock converse: no message in response")
	}
	var sb strings.Builder
	for _, c := range msg.Value.Content {
		if t, ok := c.(*types.ContentBlockMemberText); ok {
			sb.WriteString(t.Value)
		}
	}
	return sb.String(), nil
}
