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
