package cmd

import (
	"html/template"
	"strings"
	"testing"
)

func TestMarkdownToHTML(t *testing.T) {
	md := `# Title

## Section A

Some **bold** text.

- Item one
- Item two

## Section B

Another paragraph.
`
	html, headings, err := markdownToHTML(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(html, "<h1 id=\"title\">Title</h1>") {
		t.Errorf("expected h1, got: %s", html)
	}
	if !strings.Contains(html, "<h2 id=\"section-a\">Section A</h2>") {
		t.Errorf("expected h2, got: %s", html)
	}
	if !strings.Contains(html, "<strong>bold</strong>") {
		t.Errorf("expected bold, got: %s", html)
	}
	if !strings.Contains(html, "<li>Item one</li>") {
		t.Errorf("expected list item, got: %s", html)
	}
	if !strings.Contains(html, "<p>Another paragraph.</p>") {
		t.Errorf("expected paragraph, got: %s", html)
	}

	if len(headings) != 3 {
		t.Fatalf("expected 3 headings, got %d", len(headings))
	}
	if headings[0].Level != 1 || headings[0].Text != "Title" || headings[0].ID != "title" {
		t.Errorf("unexpected first heading: %+v", headings[0])
	}
}

func TestSlugify(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Hello World", "hello-world"},
		{"UPPER CASE", "upper-case"},
		{"a-b_c", "a-b-c"},
		{"special!@#chars", "specialchars"},
		{"", ""},
	}
	for _, c := range cases {
		got := slugify(c.in)
		if got != c.want {
			t.Errorf("slugify(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGeneratePlanHTML(t *testing.T) {
	intent := "deploy api"
	adr := "# ADR: Deploy Api\n\n## Status\nProposed\n"
	mermaid := template.HTML("graph TD\n    A --> B\n")

	b, err := generatePlanHTML(intent, adr, mermaid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	html := string(b)

	if !strings.Contains(html, "Deploy Api") {
		t.Error("expected title in HTML")
	}
	if !strings.Contains(html, "Proposed") {
		t.Error("expected ADR content in HTML")
	}
	if !strings.Contains(html, "mermaid.initialize") {
		t.Error("expected mermaid init script")
	}
	if !strings.Contains(html, "graph TD") {
		t.Error("expected mermaid diagram source")
	}
}

func TestDecompressMermaidJS(t *testing.T) {
	js, err := decompressMermaidJS()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(js) == 0 {
		t.Fatal("expected non-empty mermaid JS")
	}
	if !strings.Contains(js, "mermaid") {
		t.Error("expected 'mermaid' in decompressed JS")
	}
}

func TestGenerateRandomPath(t *testing.T) {
	p1, err := generateRandomPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p1) != 32 {
		t.Errorf("expected length 32, got %d", len(p1))
	}
	p2, err := generateRandomPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1 == p2 {
		t.Error("expected different random paths")
	}
}

func TestIsCI(t *testing.T) {
	// The function reads the environment; we can only test the current state.
	// Just ensure it doesn't panic.
	_ = isCI()
}
