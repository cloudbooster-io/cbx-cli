package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProgressRender(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()
	// Clear any ambient NO_COLOR so forcing styling actually enables it.
	t.Setenv("NO_COLOR", "")
	Configure(false, false)

	p := NewProgress()
	p.SetWidth(10)
	p.SetStartTime(time.Now().Add(-1 * time.Minute))

	out := p.Render(50, 100)
	if !strings.Contains(out, "50.0%") {
		t.Fatalf("expected 50.0%% in output, got: %s", out)
	}
	if !strings.Contains(out, "██████████") || !strings.Contains(out, "░░░░░░░░░░") {
		// 50% of 10 = 5 filled, 5 empty
		if !strings.Contains(out, "█████") {
			t.Fatalf("expected filled bar, got: %s", out)
		}
	}
}

func TestProgressNonTTY(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()
	Configure(false, false)

	p := NewProgress()
	out := p.Render(75, 100)
	if out != "75%" {
		t.Fatalf("expected plain percent on non-TTY, got: %q", out)
	}
}

func TestProgressFinish(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()
	Configure(false, false)

	var buf bytes.Buffer
	p := NewProgress()
	p.SetWriter(&buf)
	p.Finish(100, 100)
	out := buf.String()
	if !strings.Contains(out, "100%") {
		t.Fatalf("expected 100%% in finish output, got: %q", out)
	}
}

func TestProgressGolden(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()
	// Clear any ambient NO_COLOR so forcing styling actually enables it.
	t.Setenv("NO_COLOR", "")
	Configure(false, false)

	p := NewProgress()
	p.SetWidth(20)
	p.SetStartTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	p.nowFn = func() time.Time { return time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC) }
	got := p.Render(7, 10)

	goldenPath := filepath.Join("testdata", "progress_70.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(goldenPath, []byte(got), 0o644)
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", goldenPath, err)
	}
	if got != string(wantBytes) {
		t.Fatalf("progress golden mismatch.\nGOT:\n%s\n\nWANT:\n%s", got, string(wantBytes))
	}
}
