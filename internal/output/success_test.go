package output

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr redirects os.Stderr around fn and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	_ = w.Close()
	return <-done
}

func TestSuccessfWritesToStderr(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()
	Configure(false, false)

	// Confirm nothing leaks to stdout.
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = wOut
	defer func() { os.Stdout = oldStdout }()
	doneOut := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(rOut)
		doneOut <- string(b)
	}()

	stderrOut := captureStderr(t, func() {
		Successf("hello %s", "world")
	})
	_ = wOut.Close()
	stdoutOut := <-doneOut

	if stdoutOut != "" {
		t.Fatalf("expected nothing on stdout, got: %q", stdoutOut)
	}
	if !strings.Contains(stderrOut, "hello world") {
		t.Fatalf("expected stderr to contain message, got: %q", stderrOut)
	}
}

func TestSuccessfASCIIFallback(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()
	// noColor=true disables styling and triggers ASCII glyphs.
	Configure(true, false)

	got := captureStderr(t, func() {
		Successf("done")
	})
	if !strings.Contains(got, "[OK]") {
		t.Fatalf("expected ASCII fallback [OK], got: %q", got)
	}
	if strings.Contains(got, "✓") { // ✓
		t.Fatalf("did not expect rich glyph in ASCII mode, got: %q", got)
	}
}

func TestSuccessfNoColorEnv(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = oldFn }()

	t.Setenv("NO_COLOR", "1")
	Configure(false, false)

	got := captureStderr(t, func() {
		Successf("ok")
	})
	// NO_COLOR disables styling — output must not contain ANSI escape codes.
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("expected no ANSI escape with NO_COLOR set, got: %q", got)
	}
	if !strings.Contains(got, "ok") {
		t.Fatalf("expected message body in output, got: %q", got)
	}
}
