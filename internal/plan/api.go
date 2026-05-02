package plan

import (
	"context"
	"strings"
)

// Client generates and refines architecture plans.
type Client interface {
	GeneratePlan(ctx context.Context, intent, provider string) (*Plan, error)
	RefinePlan(ctx context.Context, current *Plan, refineText, provider string) (*Plan, error)
}

// MockClient is a testable mock that returns plans based on keywords.
type MockClient struct{}

// GeneratePlan creates a plan based on the intent string.
func (m *MockClient) GeneratePlan(_ context.Context, intent, _ string) (*Plan, error) {
	components := defaultComponents()
	components = applyRefinements(components, intent)
	return buildPlan(intent, components, 1), nil
}

// RefinePlan updates a plan based on refinement text.
func (m *MockClient) RefinePlan(_ context.Context, current *Plan, refineText, _ string) (*Plan, error) {
	components := make([]Component, len(current.Components))
	copy(components, current.Components)
	components = applyRefinements(components, refineText)
	return buildPlan(current.Intent+" + "+refineText, components, current.Version+1), nil
}

func defaultComponents() []Component {
	return []Component{
		{Name: "S3", Description: "Static asset hosting", Service: "S3"},
		{Name: "API Gateway", Description: "REST API fronting", Service: "APIGateway"},
		{Name: "Lambda", Description: "Serverless compute", Service: "Lambda"},
		{Name: "DynamoDB", Description: "NoSQL data store", Service: "DynamoDB"},
	}
}

func applyRefinements(components []Component, text string) []Component {
	text = strings.ToLower(text)

	if strings.Contains(text, "cdn") || strings.Contains(text, "cloudfront") {
		if !hasComponent(components, "CloudFront") {
			components = append([]Component{
				{Name: "CloudFront", Description: "CDN and edge caching", Service: "CloudFront"},
			}, components...)
		}
	}

	if strings.Contains(text, "auth") {
		if !hasComponent(components, "Cognito") {
			components = append(components, Component{
				Name: "Cognito", Description: "User authentication and authorization", Service: "Cognito",
			})
		}
	}

	if strings.Contains(text, "postgres") || strings.Contains(text, "postgresql") {
		components = replaceComponent(components, "DynamoDB", Component{
			Name: "RDS PostgreSQL", Description: "Relational database", Service: "RDS",
		})
	} else if strings.Contains(text, "mysql") {
		components = replaceComponent(components, "DynamoDB", Component{
			Name: "RDS MySQL", Description: "Relational database", Service: "RDS",
		})
	}

	if strings.Contains(text, "multi-region") {
		if !hasComponent(components, "Route 53") {
			components = append(components, Component{
				Name: "Route 53", Description: "DNS and global traffic management", Service: "Route53",
			})
		}
		if !hasComponent(components, "DynamoDB Global Tables") && hasComponent(components, "DynamoDB") {
			components = replaceComponent(components, "DynamoDB", Component{
				Name: "DynamoDB Global Tables", Description: "Multi-region NoSQL data", Service: "DynamoDB",
			})
		}
	}

	return components
}

func hasComponent(components []Component, name string) bool {
	for _, c := range components {
		if c.Name == name {
			return true
		}
	}
	return false
}

func replaceComponent(components []Component, name string, replacement Component) []Component {
	for i, c := range components {
		if c.Name == name {
			components[i] = replacement
			return components
		}
	}
	return append(components, replacement)
}

func buildPlan(intent string, components []Component, version int) *Plan {
	p := &Plan{
		Intent:     intent,
		Components: components,
		Version:    version,
	}
	p.ADRContent = RenderADR(p)
	p.D2Content = RenderD2(p)
	p.MermaidContent = RenderMermaid(p)
	p.HTMLContent = RenderHTML(p)
	return p
}
