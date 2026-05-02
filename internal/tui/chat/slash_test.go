package chat

import (
	"testing"
)

func TestParseSlashCommand(t *testing.T) {
	tests := []struct {
		input    string
		wantCmd  string
		wantArgs []string
		wantErr  bool
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

func TestRegistryExecute(t *testing.T) {
	r := NewRegistry()
	r.Register(Command{
		Name:    "hello",
		Summary: "Say hello",
		Handler: func(args []string) (string, error) {
			return "Hello!", nil
		},
	})

	result, err := r.Execute("hello", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Hello!" {
		t.Fatalf("expected %q, got %q", "Hello!", result)
	}
}

func TestRegistryExecuteUnknown(t *testing.T) {
	r := NewRegistry()
	r.Register(Command{Name: "save", Summary: "Save"})
	_, err := r.Execute("sav", nil)
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	if err.Error() != "unknown command: /sav. Did you mean: /save?" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRegistryHelp(t *testing.T) {
	r := NewRegistry()
	r.Register(Command{Name: "save", Args: "[path]", Summary: "Save"})
	r.Register(Command{Name: "quit", Summary: "Exit"})
	help := r.Help()
	if help == "" {
		t.Fatal("expected non-empty help")
	}
	if help != "Available commands:\n  /quit                       — Exit\n  /save       [path]          — Save\n" {
		t.Fatalf("unexpected help output:\n%s", help)
	}
}
