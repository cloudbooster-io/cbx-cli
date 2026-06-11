package plan

import (
	"strings"
	"testing"
)

func TestRenderADR(t *testing.T) {
	p := &Plan{
		Intent: "static site",
		Components: []Component{
			{Name: "S3", Description: "Static hosting", Service: "S3"},
		},
		Version: 1,
	}
	adr := RenderADR(p)
	if !strings.Contains(adr, "ADR: Static Site") {
		t.Fatalf("expected ADR title, got:\n%s", adr)
	}
	if !strings.Contains(adr, "S3") {
		t.Fatalf("expected S3 component, got:\n%s", adr)
	}
	if !strings.Contains(adr, "## Options") {
		t.Fatalf("expected Options section, got:\n%s", adr)
	}
	if !strings.Contains(adr, "## Tradeoffs") {
		t.Fatalf("expected Tradeoffs section, got:\n%s", adr)
	}
	if !strings.Contains(adr, "## S3") {
		t.Fatalf("expected per-component S3 section, got:\n%s", adr)
	}
}

func TestTitleCase(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"static site", "Static Site"},
		{"  multiple   spaces  ", "Multiple Spaces"},
		{"Already Title", "Already Title"},
		{"s3 + lambda", "S3 + Lambda"},
	}
	for _, c := range cases {
		if got := titleCase(c.in); got != c.want {
			t.Errorf("titleCase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRenderD2(t *testing.T) {
	p := &Plan{
		Intent: "api",
		Components: []Component{
			{Name: "Lambda", Description: "Compute", Service: "Lambda"},
		},
		Version: 1,
	}
	d2 := RenderD2(p)
	if !strings.Contains(d2, "direction: right") {
		t.Fatalf("expected direction, got:\n%s", d2)
	}
	if !strings.Contains(d2, "Lambda") {
		t.Fatalf("expected Lambda node, got:\n%s", d2)
	}
}

func TestRenderMermaid(t *testing.T) {
	p := &Plan{
		Intent: "api",
		Components: []Component{
			{Name: "Lambda", Description: "Compute", Service: "Lambda"},
		},
		Version: 1,
	}
	mmd := RenderMermaid(p)
	if !strings.Contains(mmd, "flowchart LR") {
		t.Fatalf("expected flowchart header, got:\n%s", mmd)
	}
	if !strings.Contains(mmd, "lambda[Lambda]") {
		t.Fatalf("expected Lambda node, got:\n%s", mmd)
	}
	if !strings.Contains(mmd, "click lambda href \"#lambda\"") {
		t.Fatalf("expected click directive, got:\n%s", mmd)
	}
}

func TestRenderMermaidClickEvents(t *testing.T) {
	p := &Plan{
		Intent: "static site with auth",
		Components: []Component{
			{Name: "S3", Description: "Static hosting", Service: "S3"},
			{Name: "API Gateway", Description: "REST API fronting", Service: "APIGateway"},
			{Name: "Lambda", Description: "Serverless compute", Service: "Lambda"},
			{Name: "Cognito", Description: "Auth", Service: "Cognito"},
		},
		Version: 1,
	}
	mmd := RenderMermaid(p)
	wantLinks := []string{
		"click s3 href \"#s3\"",
		"click api_gateway href \"#api-gateway\"",
		"click lambda href \"#lambda\"",
		"click cognito href \"#cognito\"",
	}
	for _, want := range wantLinks {
		if !strings.Contains(mmd, want) {
			t.Fatalf("expected %q in mermaid, got:\n%s", want, mmd)
		}
	}
}

func TestRenderHTML(t *testing.T) {
	p := &Plan{
		Intent: "api",
		Components: []Component{
			{Name: "Lambda", Description: "Compute", Service: "Lambda"},
		},
		Version: 1,
	}
	html := RenderHTML(p)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Fatalf("expected HTML doctype, got:\n%s", html)
	}
	if !strings.Contains(html, "Lambda") {
		t.Fatalf("expected Lambda in HTML, got:\n%s", html)
	}
}

func TestExportJSON(t *testing.T) {
	p := &Plan{
		Intent:     "api",
		Components: []Component{{Name: "Lambda", Description: "Compute", Service: "Lambda"}},
		Version:    1,
	}
	jsonStr, err := ExportJSON(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(jsonStr, `"intent": "api"`) {
		t.Fatalf("expected intent in JSON, got:\n%s", jsonStr)
	}
}
