package config

import (
	"testing"
)

func TestEnv_CBXWins(t *testing.T) {
	resetDeprecationCacheForTest()
	var warnCalls int
	prev := DeprecatedEnvWarn
	DeprecatedEnvWarn = func(_, _ string) { warnCalls++ }
	defer func() { DeprecatedEnvWarn = prev }()

	t.Setenv("CBX_API_URL", "https://new.example.com")
	t.Setenv("CB_API_URL", "https://old.example.com")

	if got := Env("API_URL"); got != "https://new.example.com" {
		t.Fatalf("Env returned %q, want CBX_ value", got)
	}
	if warnCalls != 0 {
		t.Fatalf("expected no warning when CBX_ is set, got %d", warnCalls)
	}
}

func TestEnv_CBFallbackWarns(t *testing.T) {
	resetDeprecationCacheForTest()
	var got [2]string
	var calls int
	prev := DeprecatedEnvWarn
	DeprecatedEnvWarn = func(oldName, newName string) {
		got[0], got[1] = oldName, newName
		calls++
	}
	defer func() { DeprecatedEnvWarn = prev }()

	t.Setenv("CBX_API_URL", "")
	t.Setenv("CB_API_URL", "https://legacy.example.com")

	if v := Env("API_URL"); v != "https://legacy.example.com" {
		t.Fatalf("Env returned %q, want legacy value", v)
	}
	if calls != 1 {
		t.Fatalf("expected 1 warning, got %d", calls)
	}
	if got[0] != "CB_API_URL" || got[1] != "CBX_API_URL" {
		t.Fatalf("unexpected warning args: %v", got)
	}
}

func TestEnv_WarnOnlyOnce(t *testing.T) {
	resetDeprecationCacheForTest()
	var calls int
	prev := DeprecatedEnvWarn
	DeprecatedEnvWarn = func(_, _ string) { calls++ }
	defer func() { DeprecatedEnvWarn = prev }()

	t.Setenv("CBX_NO_UPDATE_CHECK", "")
	t.Setenv("CB_NO_UPDATE_CHECK", "1")

	_ = Env("NO_UPDATE_CHECK")
	_ = Env("NO_UPDATE_CHECK")
	_ = Env("NO_UPDATE_CHECK")
	if calls != 1 {
		t.Fatalf("expected 1 warning across 3 reads, got %d", calls)
	}
}

func TestEnv_NeitherSet(t *testing.T) {
	resetDeprecationCacheForTest()
	prev := DeprecatedEnvWarn
	called := false
	DeprecatedEnvWarn = func(_, _ string) { called = true }
	defer func() { DeprecatedEnvWarn = prev }()

	t.Setenv("CBX_DOES_NOT_EXIST", "")
	t.Setenv("CB_DOES_NOT_EXIST", "")

	if v := Env("DOES_NOT_EXIST"); v != "" {
		t.Fatalf("expected empty, got %q", v)
	}
	if called {
		t.Fatal("expected no warning when neither is set")
	}
}
