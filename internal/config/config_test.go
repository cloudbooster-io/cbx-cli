package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	cfg.Auth.Email = "test@example.com"
	cfg.Auth.Token = "token123"
	cfg.LLM.Providers["claude"] = LLMProvider{Name: "claude", LoggedIn: true}

	if err := Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	cfg2, err := Load()
	if err != nil {
		t.Fatalf("Load round-trip failed: %v", err)
	}
	if cfg2.Auth.Email != "test@example.com" {
		t.Fatalf("email mismatch: %q", cfg2.Auth.Email)
	}
	if !cfg2.LLM.Providers["claude"].LoggedIn {
		t.Fatal("expected claude logged in")
	}
}

func TestPath(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	want := filepath.Join(tmpDir, ".cbx", "config.json")
	if got := Path(); got != want {
		t.Fatalf("Path() = %q, want %q", got, want)
	}
}
