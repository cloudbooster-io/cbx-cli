package chat

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestStreamRendererAccumulation(t *testing.T) {
	renderer := NewStreamRenderer()
	tokens := []string{"The", " ", "quick", " ", "brown", " ", "fox"}
	for _, tok := range tokens {
		renderer.AppendToken(tok)
	}
	want := "The quick brown fox"
	if got := renderer.Content(); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestStreamRendererAutoScroll(t *testing.T) {
	renderer := NewStreamRenderer()
	if !renderer.AutoScroll() {
		t.Fatal("expected auto-scroll to be enabled by default")
	}
	renderer.SetAutoScroll(false)
	if renderer.AutoScroll() {
		t.Fatal("expected auto-scroll to be disabled after SetAutoScroll(false)")
	}
	renderer.Reset()
	if !renderer.AutoScroll() {
		t.Fatal("expected auto-scroll to be re-enabled after Reset")
	}
}

func TestStreamRendererGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/tokens.json")
	if err != nil {
		t.Fatalf("reading tokens fixture: %v", err)
	}
	var tokens []string
	if err := json.Unmarshal(data, &tokens); err != nil {
		t.Fatalf("parsing tokens fixture: %v", err)
	}

	renderer := NewStreamRenderer()
	for _, tok := range tokens {
		renderer.AppendToken(tok)
	}

	want, err := os.ReadFile("testdata/stream.golden")
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}

	if got := renderer.Content(); got != string(want) {
		t.Fatalf("golden mismatch:\nwant: %q\ngot:  %q", string(want), got)
	}
}

func TestModelStreamRendererWiring(t *testing.T) {
	m := NewModel()
	sr := NewStreamRenderer()
	m.SetStreamRenderer(sr)

	// Simulate appending some base content.
	m.AppendContent("User: hello")

	// Feed tokens through the model's Update loop.
	tokens := []string{"H", "i", "!"}
	var updated tea.Model = m
	for _, tok := range tokens {
		updated, _ = updated.Update(StreamTokenMsg(tok))
	}
	model := updated.(Model)

	if model.streamRenderer.Content() != "Hi!" {
		t.Fatalf("expected stream content %q, got %q", "Hi!", model.streamRenderer.Content())
	}

	// Viewport should contain both base content and streamed tokens.
	view := model.viewport.View()
	if !strings.Contains(view, "User: hello") {
		t.Fatalf("expected viewport to contain base content, got:\n%s", view)
	}
	if !strings.Contains(view, "Hi!") {
		t.Fatalf("expected viewport to contain stream content, got:\n%s", view)
	}
}

func TestModelStreamRendererAutoScrollIntegration(t *testing.T) {
	m := NewModel()
	sr := NewStreamRenderer()
	m.SetStreamRenderer(sr)

	// Feed a token to establish content.
	updated, _ := m.Update(StreamTokenMsg("x"))
	model := updated.(Model)
	if !model.streamRenderer.AutoScroll() {
		t.Fatal("expected auto-scroll to be enabled by default")
	}

	// PgUp should disable auto-scroll.
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	model = updated.(Model)
	if model.streamRenderer.AutoScroll() {
		t.Fatal("expected auto-scroll to be disabled after pgup")
	}

	// PgDown should re-enable auto-scroll.
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	model = updated.(Model)
	if !model.streamRenderer.AutoScroll() {
		t.Fatal("expected auto-scroll to be re-enabled after pgdown")
	}
}

func TestModelCommitStream(t *testing.T) {
	m := NewModel()
	sr := NewStreamRenderer()
	m.SetStreamRenderer(sr)

	m.AppendContent("User: hello")
	updated, _ := m.Update(StreamTokenMsg("world"))
	model := updated.(Model)

	model.CommitStream()

	if model.streamRenderer.Content() != "" {
		t.Fatalf("expected stream renderer to be reset, got %q", model.streamRenderer.Content())
	}
	if !strings.Contains(model.viewportContent, "world") {
		t.Fatalf("expected viewportContent to contain committed stream, got %q", model.viewportContent)
	}
	if !strings.Contains(model.viewport.View(), "world") {
		t.Fatalf("expected viewport to show committed content")
	}
}
