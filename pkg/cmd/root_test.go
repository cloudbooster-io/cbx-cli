package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootVersionFlag(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected --version to exit 0, got error: %v", err)
	}

	if !strings.Contains(out.String(), "cbx version") {
		t.Fatalf("expected output to contain 'cbx version', got: %s", out.String())
	}
}

func TestRootHelpFlag(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected --help to exit 0, got error: %v", err)
	}
}

func TestRootUnknownSubcommand(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"unknowncmd"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected unknown subcommand to return an error, got nil")
	}
}
