package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStyleEnabled(t *testing.T) {
	// Force TTY on.
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()
	// Clear any ambient NO_COLOR so forcing styling actually enables it.
	t.Setenv("NO_COLOR", "")

	Configure(false, false)
	if !Enabled() {
		t.Fatal("expected Enabled() == true when TTY is on and no suppress flags")
	}
}

func TestStyleDisabledNoColor(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()

	Configure(true, false)
	if Enabled() {
		t.Fatal("expected Enabled() == false when noColor is true")
	}
	if Success.Render("ok") != "ok" {
		t.Fatal("expected Success style to be a no-op when disabled")
	}
}

func TestStyleDisabledQuiet(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()

	Configure(false, true)
	if Enabled() {
		t.Fatal("expected Enabled() == false when quiet is true")
	}
}

func TestStyleDisabledNonTTY(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()

	Configure(false, false)
	if Enabled() {
		t.Fatal("expected Enabled() == false when non-TTY")
	}
}

func TestSymbolFallback(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()

	Configure(false, false)

	cases := []struct {
		name string
		want string
	}{
		{"check", "[OK]"},
		{"cross", "[FAIL]"},
		{"arrow", "->"},
		{"bullet", ">"},
		{"diamond", "#"},
		{"warning", "[WARN]"},
		{"unknown", "unknown"},
	}
	for _, c := range cases {
		if got := Symbol(c.name); got != c.want {
			t.Fatalf("Symbol(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSymbolRich(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()
	// Clear any ambient NO_COLOR so forcing styling actually enables it.
	t.Setenv("NO_COLOR", "")

	Configure(false, false)

	cases := []struct {
		name string
		want string
	}{
		{"check", "✓"},
		{"cross", "✗"},
		{"arrow", "→"},
		{"bullet", "▸"},
		{"diamond", "◆"},
		{"warning", "⚠"},
	}
	for _, c := range cases {
		if got := Symbol(c.name); got != c.want {
			t.Fatalf("Symbol(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestStyleGolden(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()
	Configure(false, false)

	var got string
	for _, name := range []string{"check", "cross", "arrow", "bullet", "diamond", "warning"} {
		got += Symbol(name) + "\n"
	}
	got += Success.Render("success") + "\n"
	got += Warning.Render("warning") + "\n"
	got += Error.Render("error") + "\n"
	got += Info.Render("info") + "\n"
	got += Dim.Render("dim") + "\n"

	goldenPath := filepath.Join("testdata", "style_plain.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(goldenPath, []byte(got), 0o644)
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", goldenPath, err)
	}
	if got != string(wantBytes) {
		t.Fatalf("style golden mismatch.\nGOT:\n%s\n\nWANT:\n%s", got, string(wantBytes))
	}
}
