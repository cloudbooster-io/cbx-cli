package chat

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestModelCtrlCCancelsWhenPipelineRunning(t *testing.T) {
	m := NewModel()
	cancelled := false
	m.SetPipelineRunning(true)
	m.SetOnCancel(func() {
		cancelled = true
	})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model := updated.(Model)
	if !cancelled {
		t.Fatal("expected OnCancel to be called")
	}
	if model.textarea.Value() != "" {
		t.Fatal("expected textarea to remain unchanged when cancelling")
	}
}

func TestModelCtrlCClearsWhenPipelineNotRunning(t *testing.T) {
	m := NewModel()
	m.textarea.SetValue("hello")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model := updated.(Model)
	if model.textarea.Value() != "" {
		t.Fatalf("expected textarea to be cleared, got %q", model.textarea.Value())
	}
}

func TestModelOnSubmitEmptyResponseSkipped(t *testing.T) {
	m := NewModel()
	called := false
	m.OnSubmit = func(input string) (string, error) {
		called = true
		return "", nil
	}
	m.textarea.SetValue("test")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(Model)
	if !called {
		t.Fatal("expected OnSubmit to be called")
	}
	// The user message should still be appended, but no assistant response —
	// handleSubmit always appends the user message.
	if !strings.Contains(model.viewportContent, "test") {
		t.Fatal("expected the user message to be appended to the viewport")
	}
}
