package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CBX_CONFIG_DIR", tmpDir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	cfg.Auth.Email = "test@example.com"
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
	t.Setenv("CBX_CONFIG_DIR", tmpDir)
	want := filepath.Join(tmpDir, "config.json")
	if got := Path(); got != want {
		t.Fatalf("Path() = %q, want %q", got, want)
	}
}

func TestDir_ExplicitOverride(t *testing.T) {
	resetLegacyNudgeForTest()
	t.Setenv("CBX_CONFIG_DIR", "/tmp/my-cbx-override")
	t.Setenv("XDG_CONFIG_HOME", "/should/be/ignored")
	if got := Dir(); got != "/tmp/my-cbx-override" {
		t.Fatalf("Dir() = %q, want override path", got)
	}
}

func TestDir_XDG(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("XDG resolution not used on Windows")
	}
	resetLegacyNudgeForTest()
	tmpDir := t.TempDir()
	t.Setenv("CBX_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	want := filepath.Join(tmpDir, "cbx")
	if got := Dir(); got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
}

func TestDir_LegacyFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("legacy ~/.cbx fallback not used on Windows")
	}
	resetLegacyNudgeForTest()
	home := t.TempDir()
	t.Setenv("CBX_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	// Create only the legacy dir.
	legacy := filepath.Join(home, ".cbx")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}

	var nudgeCalls int
	prev := LegacyConfigNudge
	LegacyConfigNudge = func(_, _ string) { nudgeCalls++ }
	defer func() { LegacyConfigNudge = prev }()

	if got := Dir(); got != legacy {
		t.Fatalf("Dir() = %q, want legacy %q", got, legacy)
	}
	if nudgeCalls != 1 {
		t.Fatalf("expected 1 nudge call, got %d", nudgeCalls)
	}

	// Second call: still legacy, but no second nudge (sync.Once).
	if got := Dir(); got != legacy {
		t.Fatalf("Dir() = %q, want legacy", got)
	}
	if nudgeCalls != 1 {
		t.Fatalf("expected nudge to fire only once, got %d", nudgeCalls)
	}
}

func TestDir_DefaultXDG(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("default ~/.config not used on Windows")
	}
	resetLegacyNudgeForTest()
	home := t.TempDir()
	t.Setenv("CBX_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".config", "cbx")
	if got := Dir(); got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
}

func TestDir_LegacyAndNewBothExistPrefersNew(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("legacy ~/.cbx fallback not used on Windows")
	}
	resetLegacyNudgeForTest()
	home := t.TempDir()
	t.Setenv("CBX_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	if err := os.MkdirAll(filepath.Join(home, ".cbx"), 0o700); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}
	want := filepath.Join(home, ".config", "cbx")
	if err := os.MkdirAll(want, 0o700); err != nil {
		t.Fatalf("mkdir new: %v", err)
	}

	var nudgeCalls int
	prev := LegacyConfigNudge
	LegacyConfigNudge = func(_, _ string) { nudgeCalls++ }
	defer func() { LegacyConfigNudge = prev }()

	if got := Dir(); got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
	if nudgeCalls != 0 {
		t.Fatalf("expected no nudge when new dir exists, got %d", nudgeCalls)
	}
}

func TestLoad_MigratesRetiredClaudeModel(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())

	cfg := &Config{
		LLM: LLMConfig{Providers: map[string]LLMProvider{
			"claude": {Name: "claude", Model: "claude-sonnet-4-20250514", AuthMode: AuthModeAPIKey},
			"codex":  {Name: "codex", Model: "gpt-5", AuthMode: AuthModeAPIKey},
		}},
	}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m := got.LLM.Providers["claude"].Model; m != "claude-sonnet-4-6" {
		t.Errorf("retired claude model not migrated: got %q, want claude-sonnet-4-6", m)
	}
	if m := got.LLM.Providers["codex"].Model; m != "gpt-5" {
		t.Errorf("non-retired model must be untouched: got %q", m)
	}
}
