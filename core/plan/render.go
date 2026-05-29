package plan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// RenderADR generates an Architecture Decision Record in Markdown.
func RenderADR(p *Plan) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# ADR: %s\n\n", output.TitleCase(p.Intent)))
	sb.WriteString("## Status\nProposed\n\n")
	sb.WriteString(fmt.Sprintf("## Context\nThe user requested: %q\n\n", p.Intent))
	sb.WriteString("## Options\n")
	sb.WriteString("- Serverless (AWS Lambda + API Gateway)\n")
	sb.WriteString("- Containerized (ECS/Fargate)\n")
	sb.WriteString("- VM-based (EC2)\n\n")
	sb.WriteString("## Decision\nWe will deploy a serverless architecture using AWS services.\n\n")
	sb.WriteString("## Tradeoffs\n")
	sb.WriteString("- **Operational complexity** — Reduced with managed services\n")
	sb.WriteString("- **Cost predictability** — Pay-per-use vs. provisioned capacity\n\n")
	sb.WriteString("## Consequences\n")
	sb.WriteString("- Scalable without managing servers\n")
	sb.WriteString("- Pay-per-use cost model\n")
	if hasComponent(p.Components, "CloudFront") {
		sb.WriteString("- Fast global delivery via CloudFront\n")
	}
	if hasComponent(p.Components, "DynamoDB Global Tables") {
		sb.WriteString("- Multi-region data replication\n")
	}
	sb.WriteString("\n")
	for _, c := range p.Components {
		sb.WriteString(fmt.Sprintf("## %s\n\n%s\n\n", c.Name, c.Description))
	}
	return sb.String()
}

// RenderD2 generates a D2 diagram.
func RenderD2(p *Plan) string {
	var sb strings.Builder
	sb.WriteString("direction: right\n\n")
	for _, c := range p.Components {
		shape := "rectangle"
		switch c.Service {
		case "CloudFront":
			shape = "cloud"
		case "S3", "DynamoDB", "DynamoDB Global Tables":
			shape = "cylinder"
		case "APIGateway":
			shape = "diamond"
		case "Lambda":
			shape = "hexagon"
		case "Cognito":
			shape = "circle"
		}
		id := nodeID(c.Name)
		sb.WriteString(fmt.Sprintf("%s: %s {\n  shape: %s\n}\n\n", id, c.Name, shape))
	}

	sb.WriteString("users: Users {\n  shape: person\n}\n\n")

	if cf := findComponent(p.Components, "CloudFront"); cf != nil {
		sb.WriteString(fmt.Sprintf("users -> %s: static assets\n", nodeID(cf.Name)))
	}
	if s3 := findComponent(p.Components, "S3"); s3 != nil {
		if cf := findComponent(p.Components, "CloudFront"); cf != nil {
			sb.WriteString(fmt.Sprintf("%s -> %s: origin\n", nodeID(cf.Name), nodeID(s3.Name)))
		}
	}
	if api := findComponent(p.Components, "API Gateway"); api != nil {
		sb.WriteString(fmt.Sprintf("users -> %s: API calls\n", nodeID(api.Name)))
	}
	if lambda := findComponent(p.Components, "Lambda"); lambda != nil {
		if api := findComponent(p.Components, "API Gateway"); api != nil {
			sb.WriteString(fmt.Sprintf("%s -> %s: invoke\n", nodeID(api.Name), nodeID(lambda.Name)))
		}
	}
	if db := findComponent(p.Components, "DynamoDB"); db != nil {
		if lambda := findComponent(p.Components, "Lambda"); lambda != nil {
			sb.WriteString(fmt.Sprintf("%s -> %s: read/write\n", nodeID(lambda.Name), nodeID(db.Name)))
		}
	}
	if auth := findComponent(p.Components, "Cognito"); auth != nil {
		if lambda := findComponent(p.Components, "Lambda"); lambda != nil {
			sb.WriteString(fmt.Sprintf("%s -> %s: verify token\n", nodeID(lambda.Name), nodeID(auth.Name)))
		}
	}

	return sb.String()
}

// RenderMermaid generates a Mermaid flowchart.
func RenderMermaid(p *Plan) string {
	var sb strings.Builder
	sb.WriteString("flowchart LR\n")
	for _, c := range p.Components {
		sb.WriteString(fmt.Sprintf("    %s[%s]\n", nodeID(c.Name), c.Name))
	}
	sb.WriteString("    users[Users]\n")

	if cf := findComponent(p.Components, "CloudFront"); cf != nil {
		sb.WriteString(fmt.Sprintf("    users --> %s\n", nodeID(cf.Name)))
	}
	if api := findComponent(p.Components, "API Gateway"); api != nil {
		sb.WriteString(fmt.Sprintf("    users --> %s\n", nodeID(api.Name)))
	}
	if lambda := findComponent(p.Components, "Lambda"); lambda != nil {
		if api := findComponent(p.Components, "API Gateway"); api != nil {
			sb.WriteString(fmt.Sprintf("    %s --> %s\n", nodeID(api.Name), nodeID(lambda.Name)))
		}
	}
	if db := findComponent(p.Components, "DynamoDB"); db != nil {
		if lambda := findComponent(p.Components, "Lambda"); lambda != nil {
			sb.WriteString(fmt.Sprintf("    %s --> %s\n", nodeID(lambda.Name), nodeID(db.Name)))
		}
	}
	if auth := findComponent(p.Components, "Cognito"); auth != nil {
		if lambda := findComponent(p.Components, "Lambda"); lambda != nil {
			sb.WriteString(fmt.Sprintf("    %s --> %s\n", nodeID(lambda.Name), nodeID(auth.Name)))
		}
	}

	// Click events linking to ADR anchors (dash-style slugs for GitHub compatibility).
	for _, c := range p.Components {
		sb.WriteString(fmt.Sprintf("    click %s href \"#%s\"\n", nodeID(c.Name), slugID(c.Name)))
	}

	return sb.String()
}

// RenderHTML generates a simple HTML preview.
func RenderHTML(p *Plan) string {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html>\n<html>\n<head><title>CloudBooster Plan</title></head>\n<body>\n")
	sb.WriteString(fmt.Sprintf("<h1>Plan: %s</h1>\n", p.Intent))
	sb.WriteString("<h2>Components</h2>\n<ul>\n")
	for _, c := range p.Components {
		sb.WriteString(fmt.Sprintf("<li><strong>%s</strong> — %s</li>\n", c.Name, c.Description))
	}
	sb.WriteString("</ul>\n")
	sb.WriteString("<h2>Diagram</h2>\n<pre>\n")
	sb.WriteString(p.MermaidContent)
	sb.WriteString("</pre>\n")
	sb.WriteString("</body>\n</html>\n")
	return sb.String()
}

// ExportJSON exports the plan as a JSON string.
func ExportJSON(p *Plan) (string, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func nodeID(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, " ", "_"))
}

func slugID(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, " ", "-"))
}

func findComponent(components []Component, name string) *Component {
	for i := range components {
		if components[i].Name == name {
			return &components[i]
		}
	}
	return nil
}
