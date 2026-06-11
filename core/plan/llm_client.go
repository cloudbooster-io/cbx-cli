package plan

import (
	"context"
	"fmt"

	"github.com/cloudbooster-io/cbx-cli/core/llm"
)

// LLMPlanClient implements Client by delegating to an underlying LLM. If the
// LLM call fails it falls back to MockClient behaviour so that offline/demo
// workflows continue to work.
type LLMPlanClient struct {
	LLM      llm.LLMClient
	Fallback Client
}

// GeneratePlan implements Client.
func (c *LLMPlanClient) GeneratePlan(ctx context.Context, intent, provider string) (*Plan, error) {
	if c.LLM == nil {
		if c.Fallback != nil {
			return c.Fallback.GeneratePlan(ctx, intent, provider)
		}
		return nil, fmt.Errorf("no LLM client available")
	}

	prompt := fmt.Sprintf(`You are a cloud architecture expert. The user wants: %q.
Respond with a concise architecture decision record (ADR) in Markdown format describing the recommended AWS infrastructure.`, intent)

	stream, err := c.LLM.Complete(ctx, prompt, llm.CompleteOptions{
		Temperature: 0.7,
		MaxTokens:   2048,
	})
	if err != nil {
		if c.Fallback != nil {
			return c.Fallback.GeneratePlan(ctx, intent, provider)
		}
		return nil, err
	}

	adr, err := stream.Collect()
	if err != nil {
		if c.Fallback != nil {
			return c.Fallback.GeneratePlan(ctx, intent, provider)
		}
		return nil, err
	}

	// Use fallback for structured components so that keyword-based
	// refinements continue to work deterministically.
	p, err := c.fallbackPlan(ctx, intent, provider)
	if err != nil {
		return nil, err
	}
	if adr != "" {
		p.ADRContent = adr
	}
	return p, nil
}

// RefinePlan implements Client.
func (c *LLMPlanClient) RefinePlan(ctx context.Context, current *Plan, refineText, provider string) (*Plan, error) {
	if c.LLM == nil {
		if c.Fallback != nil {
			return c.Fallback.RefinePlan(ctx, current, refineText, provider)
		}
		return nil, fmt.Errorf("no LLM client available")
	}

	prompt := fmt.Sprintf(`You are a cloud architecture expert. The current plan intent is: %q.
The user wants to refine it with: %q.
Respond with an updated architecture decision record (ADR) in Markdown format.`, current.Intent, refineText)

	stream, err := c.LLM.Complete(ctx, prompt, llm.CompleteOptions{
		Temperature: 0.7,
		MaxTokens:   2048,
	})
	if err != nil {
		if c.Fallback != nil {
			return c.Fallback.RefinePlan(ctx, current, refineText, provider)
		}
		return nil, err
	}

	adr, err := stream.Collect()
	if err != nil {
		if c.Fallback != nil {
			return c.Fallback.RefinePlan(ctx, current, refineText, provider)
		}
		return nil, err
	}

	p, err := c.fallbackRefine(ctx, current, refineText, provider)
	if err != nil {
		return nil, err
	}
	if adr != "" {
		p.ADRContent = adr
	}
	return p, nil
}

func (c *LLMPlanClient) fallbackPlan(ctx context.Context, intent, provider string) (*Plan, error) {
	if c.Fallback != nil {
		return c.Fallback.GeneratePlan(ctx, intent, provider)
	}
	m := &MockClient{}
	return m.GeneratePlan(ctx, intent, provider)
}

func (c *LLMPlanClient) fallbackRefine(ctx context.Context, current *Plan, refineText, provider string) (*Plan, error) {
	if c.Fallback != nil {
		return c.Fallback.RefinePlan(ctx, current, refineText, provider)
	}
	m := &MockClient{}
	return m.RefinePlan(ctx, current, refineText, provider)
}
