package plan

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/core/llm"
)

// mockLLMClient is a test double that returns a fixed stream.
type mockLLMClient struct {
	tokens []string
	err    error
}

func (m *mockLLMClient) Complete(_ context.Context, _ string, _ llm.CompleteOptions) (*llm.Stream, error) {
	if m.err != nil {
		return nil, m.err
	}
	ch := make(chan string, len(m.tokens))
	for _, t := range m.tokens {
		ch <- t
	}
	close(ch)
	return llm.NewTestStream(ch), nil
}

func TestLLMPlanClientGeneratePlan(t *testing.T) {
	llmClient := &mockLLMClient{tokens: []string{"# ADR\n\nUse S3."}}
	client := &LLMPlanClient{
		LLM:      llmClient,
		Fallback: &MockClient{},
	}

	p, err := client.GeneratePlan(context.Background(), "static site", "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Version != 1 {
		t.Fatalf("expected version 1, got %d", p.Version)
	}
	if !strings.Contains(p.ADRContent, "Use S3") {
		t.Fatalf("expected LLM ADR content, got: %s", p.ADRContent)
	}
	// Fallback components should still be present.
	if !hasComponent(p.Components, "S3") {
		t.Fatalf("expected S3 component, got: %v", p.Components)
	}
}

func TestLLMPlanClientRefinePlan(t *testing.T) {
	llmClient := &mockLLMClient{tokens: []string{"# ADR\n\nAdd CDN."}}
	client := &LLMPlanClient{
		LLM:      llmClient,
		Fallback: &MockClient{},
	}

	initial, _ := client.GeneratePlan(context.Background(), "static site", "claude")
	refined, err := client.RefinePlan(context.Background(), initial, "add CDN", "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if refined.Version != 2 {
		t.Fatalf("expected version 2, got %d", refined.Version)
	}
	if !strings.Contains(refined.ADRContent, "Add CDN") {
		t.Fatalf("expected LLM refined ADR content, got: %s", refined.ADRContent)
	}
	if !hasComponent(refined.Components, "CloudFront") {
		t.Fatalf("expected CloudFront after CDN refine, got: %v", refined.Components)
	}
}

func TestLLMPlanClientFallbackOnError(t *testing.T) {
	llmClient := &mockLLMClient{err: context.Canceled}
	client := &LLMPlanClient{
		LLM:      llmClient,
		Fallback: &MockClient{},
	}

	p, err := client.GeneratePlan(context.Background(), "static site", "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Version != 1 {
		t.Fatalf("expected fallback plan version 1, got %d", p.Version)
	}
}

func TestLLMPlanClientNoFallback(t *testing.T) {
	llmClient := &mockLLMClient{err: context.Canceled}
	client := &LLMPlanClient{LLM: llmClient}

	_, err := client.GeneratePlan(context.Background(), "static site", "claude")
	if err == nil {
		t.Fatal("expected error when LLM fails and no fallback")
	}
}
