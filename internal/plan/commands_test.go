package plan

import (
	"strings"
	"testing"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/tui/chat"
)

func TestCmdVariantsCap(t *testing.T) {
	session := NewSession(".")
	session.CurrentPlan = &Plan{Version: 1}
	_, err := cmdVariants([]string{"3"}, session)
	if err == nil {
		t.Fatal("expected error for variant count > 2")
	}
	if !strings.Contains(err.Error(), "free tier capped") {
		t.Fatalf("expected free tier cap message, got: %v", err)
	}
}

func TestCmdQuitUnsaved(t *testing.T) {
	session := NewSession(".")
	session.Unsaved = true
	msg, err := cmdQuit(session)
	if err != nil {
		t.Fatalf("expected no error on first quit with unsaved changes, got: %v", err)
	}
	if !strings.Contains(msg, "unsaved changes") {
		t.Fatalf("expected unsaved changes warning, got: %s", msg)
	}

	// Second quit should succeed
	msg, err = cmdQuit(session)
	if err != chat.ErrQuit {
		t.Fatalf("expected chat.ErrQuit on second quit, got: %v", err)
	}
	if !strings.Contains(msg, "Goodbye") {
		t.Fatalf("expected goodbye message, got: %s", msg)
	}
}
