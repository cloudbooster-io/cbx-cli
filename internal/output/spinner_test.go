package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpinnerFrame(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()
	// Clear any ambient NO_COLOR so forcing styling actually enables it.
	t.Setenv("NO_COLOR", "")
	Configure(false, false)

	s := NewSpinner("loading")
	s.SetFrames([]string{"a", "b", "c"})
	s.SetFrameIdx(0)
	if got := s.Frame(); got != "a loading" {
		t.Fatalf("frame 0 = %q, want %q", got, "a loading")
	}
	s.SetFrameIdx(1)
	if got := s.Frame(); got != "b loading" {
		t.Fatalf("frame 1 = %q, want %q", got, "b loading")
	}
}

func TestSpinnerNonTTY(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()
	Configure(false, false)

	var buf bytes.Buffer
	s := NewSpinner("loading")
	s.SetWriter(&buf)
	s.Start()
	s.Stop()

	out := buf.String()
	if !strings.Contains(out, "loading...") {
		t.Fatalf("expected static message on non-TTY, got: %q", out)
	}
}

func TestSpinnerGolden(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()
	// Clear any ambient NO_COLOR so forcing styling actually enables it.
	t.Setenv("NO_COLOR", "")
	Configure(false, false)

	s := NewSpinner("working")
	s.SetFrames([]string{"|", "/", "-", "\\"})
	s.SetFrameIdx(2)
	got := s.Frame()

	goldenPath := filepath.Join("testdata", "spinner_frame.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(goldenPath, []byte(got), 0o644)
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", goldenPath, err)
	}
	if got != string(wantBytes) {
		t.Fatalf("spinner golden mismatch.\nGOT:\n%s\n\nWANT:\n%s", got, string(wantBytes))
	}
}
