package advise

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

type fakeConverse struct {
	in  *bedrockruntime.ConverseInput
	out *bedrockruntime.ConverseOutput
	err error
}

func (f *fakeConverse) Converse(_ context.Context, in *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	f.in = in
	return f.out, f.err
}

func TestBedrockCompleteSendsModelAndJoinsText(t *testing.T) {
	fc := &fakeConverse{out: &bedrockruntime.ConverseOutput{Output: &types.ConverseOutputMemberMessage{Value: types.Message{
		Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "[1,"}, &types.ContentBlockMemberText{Value: "2]"}},
	}}}}
	b := &Bedrock{client: fc, model: "test-model"}

	got, err := b.Complete(context.Background(), "sys", "user body")

	if err != nil || got != "[1,2]" {
		t.Fatalf("got %q, %v", got, err)
	}
	if *fc.in.ModelId != "test-model" {
		t.Errorf("model = %s", *fc.in.ModelId)
	}
	if u := fc.in.Messages[0].Content[0].(*types.ContentBlockMemberText).Value; u != "user body" {
		t.Errorf("user text = %q", u)
	}
}

func TestBedrockCompleteReturnsErrors(t *testing.T) {
	b := &Bedrock{client: &fakeConverse{err: errors.New("denied")}, model: "m"}
	if _, err := b.Complete(context.Background(), "s", "u"); err == nil {
		t.Error("want error")
	}
	b = &Bedrock{client: &fakeConverse{out: &bedrockruntime.ConverseOutput{}}, model: "m"}
	if _, err := b.Complete(context.Background(), "s", "u"); err == nil {
		t.Error("want error for missing message")
	}
}

func TestNewBedrockRequiresModel(t *testing.T) {
	if _, err := NewBedrock(context.Background(), ""); err == nil {
		t.Error("want error for empty model")
	}
}

func TestBedrockCompleteErrorsWhenTruncatedAtMaxTokens(t *testing.T) {
	fc := &fakeConverse{out: &bedrockruntime.ConverseOutput{
		StopReason: types.StopReasonMaxTokens,
		Output: &types.ConverseOutputMemberMessage{Value: types.Message{
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "[{\"address\":"}},
		}},
	}}
	b := &Bedrock{client: fc, model: "m"}

	_, err := b.Complete(context.Background(), "s", "u")

	if err == nil || !strings.Contains(err.Error(), "max_tokens") {
		t.Errorf("err = %v", err)
	}
	if *fc.in.InferenceConfig.MaxTokens != 8192 {
		t.Errorf("max tokens = %d", *fc.in.InferenceConfig.MaxTokens)
	}
}
