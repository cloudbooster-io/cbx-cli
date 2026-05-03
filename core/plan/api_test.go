package plan

import (
	"context"
	"strings"
	"testing"
)

func TestMockClientGeneratePlan(t *testing.T) {
	client := &MockClient{}
	plan, err := client.GeneratePlan(context.Background(), "static site with auth", "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Version != 1 {
		t.Fatalf("expected version 1, got %d", plan.Version)
	}
	if !strings.Contains(plan.Intent, "static site with auth") {
		t.Fatalf("expected intent in plan, got: %s", plan.Intent)
	}
	if !hasComponent(plan.Components, "Cognito") {
		t.Fatalf("expected Cognito for auth intent, got components: %v", plan.Components)
	}
}

func TestMockClientRefinePlan(t *testing.T) {
	client := &MockClient{}
	initial, err := client.GeneratePlan(context.Background(), "static site", "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasComponent(initial.Components, "CloudFront") {
		t.Fatal("initial plan should not have CloudFront")
	}

	refined, err := client.RefinePlan(context.Background(), initial, "add CDN", "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if refined.Version != 2 {
		t.Fatalf("expected version 2, got %d", refined.Version)
	}
	if !hasComponent(refined.Components, "CloudFront") {
		t.Fatalf("refined plan should have CloudFront, got components: %v", refined.Components)
	}
}

func TestMockClientPostgresReplace(t *testing.T) {
	client := &MockClient{}
	plan, err := client.GeneratePlan(context.Background(), "use postgres", "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasComponent(plan.Components, "DynamoDB") {
		t.Fatal("expected DynamoDB to be replaced by RDS PostgreSQL")
	}
	if !hasComponent(plan.Components, "RDS PostgreSQL") {
		t.Fatalf("expected RDS PostgreSQL, got components: %v", plan.Components)
	}
}
