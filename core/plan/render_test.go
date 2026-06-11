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
	if !strings.Contains(mmd, `lambda["Lambda"]`) {
		t.Fatalf("expected quoted Lambda node, got:\n%s", mmd)
	}
	if !strings.Contains(mmd, "click lambda href \"#lambda\"") {
		t.Fatalf("expected click directive, got:\n%s", mmd)
	}
}

// TestRenderMermaidHostileNames pins the label hardening: component names are
// LLM/user-influenced, so quotes and newlines must not break out of the
// quoted node-label context and inject arbitrary Mermaid directives.
func TestRenderMermaidHostileNames(t *testing.T) {
	hostile := "Bad\"]\nclick users href \"javascript:alert(1)\""
	p := &Plan{
		Intent: "api",
		Components: []Component{
			{Name: hostile, Description: "Compute", Service: "Lambda"},
		},
		Version: 1,
	}
	mmd := RenderMermaid(p)
	if strings.Contains(mmd, "\nclick users href") {
		t.Fatalf("hostile name broke out of the label context:\n%s", mmd)
	}
	if !strings.Contains(mmd, "#quot;") {
		t.Fatalf("expected embedded quotes escaped as #quot;, got:\n%s", mmd)
	}
	// The node ID and slug must stay in their safe charsets.
	for _, line := range strings.Split(strings.TrimSuffix(mmd, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, `["`) && !strings.HasSuffix(trimmed, `"]`) {
			t.Fatalf("unterminated quoted label in line %q", line)
		}
	}
	if strings.Contains(nodeID(hostile), `"`) || strings.Contains(slugID(hostile), `"`) {
		t.Fatalf("nodeID/slugID leaked quotes: %q / %q", nodeID(hostile), slugID(hostile))
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

func TestRenderHTMLEscapesHostileNames(t *testing.T) {
	p := &Plan{
		Intent: "api <script>alert(2)</script>",
		Components: []Component{
			{Name: "<script>alert(1)</script>", Description: "Compute", Service: "Lambda"},
		},
		Version: 1,
	}
	p.MermaidContent = RenderMermaid(p)
	html := RenderHTML(p)
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "<script>alert(2)</script>") {
		t.Fatalf("hostile markup emitted unescaped:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("expected entity-escaped component name, got:\n%s", html)
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
