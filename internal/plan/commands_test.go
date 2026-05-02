package plan

import (
	"strings"
	"testing"
)

func TestParseSlashCommand(t *testing.T) {
	tests := []struct {
		input   string
		wantCmd string
		wantArgs []string
		wantErr bool
	}{
		{"/save", "save", nil, false},
		{"/save v1", "save", []string{"v1"}, false},
		{"/refine add CDN", "refine", []string{"add", "CDN"}, false},
		{"/diagram mermaid", "diagram", []string{"mermaid"}, false},
		{"save", "", nil, true},
		{"/", "", nil, true},
		{"", "", nil, true},
	}

	for _, tt := range tests {
		cmd, err := ParseSlashCommand(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseSlashCommand(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSlashCommand(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if cmd.Name != tt.wantCmd {
			t.Errorf("ParseSlashCommand(%q) cmd.Name = %q, want %q", tt.input, cmd.Name, tt.wantCmd)
		}
		if len(cmd.Args) != len(tt.wantArgs) {
			t.Errorf("ParseSlashCommand(%q) cmd.Args = %v, want %v", tt.input, cmd.Args, tt.wantArgs)
			continue
		}
		for i := range cmd.Args {
			if cmd.Args[i] != tt.wantArgs[i] {
				t.Errorf("ParseSlashCommand(%q) cmd.Args[%d] = %q, want %q", tt.input, i, cmd.Args[i], tt.wantArgs[i])
			}
		}
	}
}

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
	if err != ErrQuit {
		t.Fatalf("expected ErrQuit on second quit, got: %v", err)
	}
	if !strings.Contains(msg, "Goodbye") {
		t.Fatalf("expected goodbye message, got: %s", msg)
	}
}
