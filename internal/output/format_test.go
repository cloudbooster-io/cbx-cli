package output

import "testing"

func TestFormatRoundTrip(t *testing.T) {
	t.Cleanup(func() { SetFormat("") })

	if Format() != "" {
		// Reset in case other tests left state behind.
		SetFormat("")
	}
	if got := Format(); got != "" {
		t.Fatalf("expected empty default, got %q", got)
	}

	SetFormat("json")
	if got := Format(); got != "json" {
		t.Fatalf("expected json, got %q", got)
	}

	SetFormat("yaml")
	if got := Format(); got != "yaml" {
		t.Fatalf("expected yaml, got %q", got)
	}

	SetFormat("")
	if got := Format(); got != "" {
		t.Fatalf("expected empty after reset, got %q", got)
	}
}
