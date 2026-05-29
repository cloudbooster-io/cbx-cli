package plan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// withFakeClaudeBinary writes a tiny shell script that mimics `claude -p` at
// <tmp>/claude, prepends its dir to PATH, and points claudeCodeBinary at it.
// The script drains stdin and echoes the supplied response on stdout,
// optionally exiting non-zero. Returns a restore function. Mirrors the helper
// in internal/audit/llm_subprocess_test.go.
func withFakeClaudeBinary(t *testing.T, response string, exitCode int) func() {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only")
	}

	dir := t.TempDir()
	script := "#!/bin/sh\n"
	script += "cat > /dev/null\n"
	script += "printf '%s' '" + strings.ReplaceAll(response, "'", `'\''`) + "'\n"
	if exitCode != 0 {
		script += "exit " + itoa(exitCode) + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	orig := claudeCodeBinary
	claudeCodeBinary = "claude"
	return func() { claudeCodeBinary = orig }
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestIsCLIExecutor(t *testing.T) {
	if !IsCLIExecutor(CLIExecutorClaudeCode) {
		t.Errorf("IsCLIExecutor(%q) = false, want true", CLIExecutorClaudeCode)
	}
	for _, name := range []string{"claude", "openai", "codex", ""} {
		if IsCLIExecutor(name) {
			t.Errorf("IsCLIExecutor(%q) = true, want false", name)
		}
	}
}

func TestCLIStreamer_HappyPath(t *testing.T) {
	restore := withFakeClaudeBinary(t, "ranked components here", 0)
	defer restore()

	s, err := newCLIStreamer(CLIExecutorClaudeCode)
	if err != nil {
		t.Fatalf("newCLIStreamer: %v", err)
	}
	var sb strings.Builder
	if err := s.Stream(context.Background(), "plan this", func(tok string) { sb.WriteString(tok) }); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if !strings.Contains(sb.String(), "ranked components here") {
		t.Errorf("expected fake response on stdout, got %q", sb.String())
	}
}

func TestCLIStreamer_NonZeroExitSurfacesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat > /dev/null\necho 'auth required' >&2\nexit 7\n"
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	orig := claudeCodeBinary
	claudeCodeBinary = "claude"
	defer func() { claudeCodeBinary = orig }()

	s, err := newCLIStreamer(CLIExecutorClaudeCode)
	if err != nil {
		t.Fatalf("newCLIStreamer: %v", err)
	}
	streamErr := s.Stream(context.Background(), "x", func(string) {})
	if streamErr == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !strings.Contains(streamErr.Error(), "auth required") || !strings.Contains(streamErr.Error(), "exited 7") {
		t.Errorf("expected stderr + exit code in error; got %v", streamErr)
	}
}

func TestNewCLIStreamer_MissingBinary(t *testing.T) {
	t.Setenv("PATH", "")
	orig := claudeCodeBinary
	claudeCodeBinary = "claude-does-not-exist-xyz"
	defer func() { claudeCodeBinary = orig }()

	if _, err := newCLIStreamer(CLIExecutorClaudeCode); err == nil {
		t.Fatal("expected error when claude binary is missing")
	} else if !strings.Contains(err.Error(), "requires the 'claude' CLI on PATH") {
		t.Errorf("error should hint at install path; got %v", err)
	}
}

// TestRunner_CLIExecutorDefault is the regression for the reported bug:
// `cbx llm default claude-code` (no api provider configured, so an empty
// Providers map) must let `cbx plan` run via the local CLI rather than
// failing with "provider claude-code not configured".
func TestRunner_CLIExecutorDefault(t *testing.T) {
	restore := withFakeClaudeBinary(t, "**Refined components**\n", 0)
	defer restore()

	cfg := &config.Config{}
	cfg.LLM.Default = CLIExecutorClaudeCode // empty Providers map on purpose

	runner := NewRunner(cfg, "", "", nil)
	var streamed strings.Builder
	prog := &captureProgress{onToken: func(tok string) { streamed.WriteString(tok) }}

	plan, err := runner.Run(context.Background(), "S3 + Lambda image processor", prog)
	if err != nil {
		t.Fatalf("Run with CLI-executor default: %v", err)
	}
	if plan == nil {
		t.Fatal("expected a plan, got nil")
	}
	if !strings.Contains(streamed.String(), "Refined components") {
		t.Errorf("expected the fake CLI output to be streamed; got %q", streamed.String())
	}
}

// captureProgress is a minimal Progress that forwards tokens to a callback.
type captureProgress struct {
	onToken func(string)
}

func (c *captureProgress) PhaseStart(int, int, string) {}
func (c *captureProgress) SetStatus(string, string)    {}
func (c *captureProgress) Token(t string) {
	if c.onToken != nil {
		c.onToken(t)
	}
}
func (c *captureProgress) Candidate(string, string) {}
func (c *captureProgress) Commit()                  {}
