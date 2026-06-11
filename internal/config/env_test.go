package config

import (
	"testing"
)

func TestEnv_ReturnsCBXValue(t *testing.T) {
	t.Setenv("CBX_NO_UPDATE_CHECK", "1")

	if got := Env("NO_UPDATE_CHECK"); got != "1" {
		t.Fatalf("Env returned %q, want CBX_ value", got)
	}
}

func TestEnv_LegacyCBFormIgnored(t *testing.T) {
	t.Setenv("CBX_NO_UPDATE_CHECK", "")
	t.Setenv("CB_NO_UPDATE_CHECK", "1")

	if v := Env("NO_UPDATE_CHECK"); v != "" {
		t.Fatalf("Env returned %q, want empty: the removed CB_ fallback must not be consulted", v)
	}
}

func TestEnv_NotSet(t *testing.T) {
	t.Setenv("CBX_DOES_NOT_EXIST", "")

	if v := Env("DOES_NOT_EXIST"); v != "" {
		t.Fatalf("expected empty, got %q", v)
	}
}
