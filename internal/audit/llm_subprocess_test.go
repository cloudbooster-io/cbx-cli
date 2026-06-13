package audit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withFakeClaudeBinary writes a tiny shell script that mimics `claude -p`
// at <tmp>/claude, prepends its dir to PATH, and points claudeCodeBinary
// at it. The script reads stdin and echoes the supplied response on
// stdout, optionally exiting non-zero. Returns a restore function.
func withFakeClaudeBinary(t *testing.T, response string, exitCode int) func() {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only; subprocess path covered on linux/darwin")
	}

	dir := t.TempDir()
	script := "#!/bin/sh\n"
	script += "cat > /dev/null\n" // drain stdin so the cmd doesn't block on a closed pipe
	script += "printf '%s' " + shellQuote(response) + "\n"
	if exitCode != 0 {
		script += "exit " + itoa(exitCode) + "\n"
	}
	binPath := filepath.Join(dir, "claude")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+origPath)

	origBinary := claudeCodeBinary
	claudeCodeBinary = "claude"

	return func() {
		claudeCodeBinary = origBinary
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestClaudeCLIStreamer_HappyPath(t *testing.T) {
	restore := withFakeClaudeBinary(t, `{"findings":[{"title":"From Claude Code","severity":"high","resource":"r1"}]}`, 0)
	defer restore()

	s, err := newClaudeCLIStreamer("")
	if err != nil {
		t.Fatalf("newClaudeCLIStreamer: %v", err)
	}

	var sb strings.Builder
	if err := s.Stream(context.Background(), "audit this", func(tok string) {
		sb.WriteString(tok)
	}); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if !strings.Contains(sb.String(), "From Claude Code") {
		t.Errorf("expected fake response on stdout, got %q", sb.String())
	}
}

func TestClaudeCLIStreamer_NonZeroExitSurfacesStderr(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ncat > /dev/null\necho 'auth required' >&2\nexit 7\n"
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s, err := newClaudeCLIStreamer("")
	if err != nil {
		t.Fatalf("newClaudeCLIStreamer: %v", err)
	}
	streamErr := s.Stream(context.Background(), "x", func(string) {})
	if streamErr == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !strings.Contains(streamErr.Error(), "auth required") {
		t.Errorf("expected stderr to surface in error; got %v", streamErr)
	}
	if !strings.Contains(streamErr.Error(), "exited 7") {
		t.Errorf("expected exit code in error; got %v", streamErr)
	}
}

func TestNewClaudeCLIStreamer_MissingBinary(t *testing.T) {
	// Empty PATH so exec.LookPath fails deterministically.
	t.Setenv("PATH", "")
	orig := claudeCodeBinary
	claudeCodeBinary = "claude-does-not-exist-xyz"
	defer func() { claudeCodeBinary = orig }()

	_, err := newClaudeCLIStreamer("")
	if err == nil {
		t.Fatal("expected error when claude binary is missing")
	}
	if !strings.Contains(err.Error(), "requires the 'claude' CLI on PATH") {
		t.Errorf("error should hint at install path; got %v", err)
	}
}

func TestNewLLMAnalyzer_ClaudeCodeProvider(t *testing.T) {
	restore := withFakeClaudeBinary(t, `{"findings":[]}`, 0)
	defer restore()

	a, err := newLLMAnalyzer(Options{LLMProvider: ClaudeCodeProvider}, IaCTypeTerraform)
	if err != nil {
		t.Fatalf("newLLMAnalyzer: %v", err)
	}
	if a.provider != ClaudeCodeProvider {
		t.Errorf("provider = %q, want %q", a.provider, ClaudeCodeProvider)
	}
	if _, ok := a.streamer.(*claudeCLIStreamer); !ok {
		t.Errorf("expected claudeCLIStreamer, got %T", a.streamer)
	}
	// claude-code MUST NOT touch the on-disk config — verify by passing
	// an Options that would fail config.Load() validation in the HTTP
	// path (empty providers map). The test passes if no config-loading
	// error surfaces.
}

func TestClaudeCodeProviderEndToEnd(t *testing.T) {
	// Fake `claude` returns a structured-finding payload; verify the full
	// analyzer pipeline (gather → invoke → parse) plumbs it through.
	restore := withFakeClaudeBinary(t,
		`{"findings":[{"rule_id":"LLM-CC-001","title":"From Claude Code","severity":"high","resource":"aws_s3_bucket.x","service":"S3"}]}`,
		0)
	defer restore()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "x" {}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	a, err := newLLMAnalyzer(Options{LLMProvider: ClaudeCodeProvider}, IaCTypeTerraform)
	if err != nil {
		t.Fatalf("newLLMAnalyzer: %v", err)
	}

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "LLM-CC-001" {
		t.Fatalf("expected single LLM-CC-001 finding, got %+v", findings)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityHigh)
	}
}

func TestClaudeCLIStreamer_ModelOverride(t *testing.T) {
	restore := withFakeClaudeBinary(t, "[]", 0)
	defer restore()

	s, err := newClaudeCLIStreamer("claude-opus-4-8")
	if err != nil {
		t.Fatalf("newClaudeCLIStreamer: %v", err)
	}
	if s.model != "claude-opus-4-8" {
		t.Fatalf("model = %q, want claude-opus-4-8", s.model)
	}
}

func TestClaudeCLIStreamer_NonZeroExit_FallsBackToStdout(t *testing.T) {
	// `claude -p` reports auth/model/limit failures on STDOUT with an
	// empty stderr — the error must carry that message, not a bare
	// "exited 1".
	restore := withFakeClaudeBinary(t, "Invalid API key · Please run /login", 1)
	defer restore()

	s, err := newClaudeCLIStreamer("")
	if err != nil {
		t.Fatalf("newClaudeCLIStreamer: %v", err)
	}
	streamErr := s.Stream(context.Background(), "x", func(string) {})
	if streamErr == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !strings.Contains(streamErr.Error(), "Invalid API key") {
		t.Errorf("expected stdout message in error; got %v", streamErr)
	}
	if !strings.Contains(streamErr.Error(), "exited 1") {
		t.Errorf("expected exit code in error; got %v", streamErr)
	}
}

func TestClaudeCLIStreamer_NonZeroExit_StderrStillWins(t *testing.T) {
	// When both streams carry content, stderr is the diagnostic channel.
	dir := t.TempDir()
	script := "#!/bin/sh\ncat > /dev/null\nprintf 'partial completion' \necho 'rate limited' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s, err := newClaudeCLIStreamer("")
	if err != nil {
		t.Fatalf("newClaudeCLIStreamer: %v", err)
	}
	streamErr := s.Stream(context.Background(), "x", func(string) {})
	if streamErr == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !strings.Contains(streamErr.Error(), "rate limited") {
		t.Errorf("stderr should win when present; got %v", streamErr)
	}
	if strings.Contains(streamErr.Error(), "partial completion") {
		t.Errorf("stdout must not be mixed in when stderr has the message; got %v", streamErr)
	}
}

func TestClaudeCLIStreamer_NonZeroExit_StdoutFallbackTruncated(t *testing.T) {
	// A failed run can leave a partial completion on stdout; the fallback
	// caps it so the error still reads as an error.
	long := strings.Repeat("y", 600)
	restore := withFakeClaudeBinary(t, long, 1)
	defer restore()

	s, err := newClaudeCLIStreamer("")
	if err != nil {
		t.Fatalf("newClaudeCLIStreamer: %v", err)
	}
	streamErr := s.Stream(context.Background(), "x", func(string) {})
	if streamErr == nil {
		t.Fatal("expected error on non-zero exit")
	}
	// Assert on the message tail only — the prefix carries the binary's
	// temp path, whose random segment could collide with the filler.
	_, msg, found := strings.Cut(streamErr.Error(), "exited 1: ")
	if !found {
		t.Fatalf("unexpected error shape: %v", streamErr)
	}
	if got := strings.Count(msg, "y"); got != 500 {
		t.Errorf("stdout fallback should cap at 500 chars, found %d", got)
	}
	if !strings.HasSuffix(msg, "…") {
		t.Errorf("expected truncation marker; got %v", streamErr)
	}
}
