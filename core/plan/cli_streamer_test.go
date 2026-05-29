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

// writeFakeCLIBinary writes a tiny shell script that mimics a non-interactive
// LLM CLI at <tmp>/<binName>, prepends its dir to PATH. The script drains stdin
// and echoes `response` on stdout, optionally exiting non-zero. Both the claude
// and codex executors default their binary name to <binName>, so exec.LookPath
// resolves the fake. Mirrors the helper in internal/audit/llm_subprocess_test.go.
func writeFakeCLIBinary(t *testing.T, binName, response string, exitCode int) {
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
	if err := os.WriteFile(filepath.Join(dir, binName), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// withFakeClaudeBinary installs a fake `claude` and points claudeCodeBinary at
// it. Returns a restore function.
func withFakeClaudeBinary(t *testing.T, response string, exitCode int) func() {
	writeFakeCLIBinary(t, "claude", response, exitCode)
	orig := claudeCodeBinary
	claudeCodeBinary = "claude"
	return func() { claudeCodeBinary = orig }
}

// withFakeCodexBinary installs a fake `codex` and points codexBinary at it.
// Returns a restore function.
func withFakeCodexBinary(t *testing.T, response string, exitCode int) func() {
	writeFakeCLIBinary(t, "codex", response, exitCode)
	orig := codexBinary
	codexBinary = "codex"
	return func() { codexBinary = orig }
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
	for _, name := range []string{CLIExecutorClaudeCode, CLIExecutorCodex} {
		if !IsCLIExecutor(name) {
			t.Errorf("IsCLIExecutor(%q) = false, want true", name)
		}
	}
	// `claude` and `openai` are HTTP api-provider names, not CLI executors.
	for _, name := range []string{"claude", "openai", "gpt-4o", ""} {
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

func TestCLIStreamer_Codex_HappyPath(t *testing.T) {
	restore := withFakeCodexBinary(t, "ranked components from codex", 0)
	defer restore()

	s, err := newCLIStreamer(CLIExecutorCodex)
	if err != nil {
		t.Fatalf("newCLIStreamer(codex): %v", err)
	}
	var sb strings.Builder
	if err := s.Stream(context.Background(), "plan this", func(tok string) { sb.WriteString(tok) }); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if !strings.Contains(sb.String(), "ranked components from codex") {
		t.Errorf("expected fake codex response on stdout, got %q", sb.String())
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

func TestNewCLIStreamer_Codex_MissingBinary(t *testing.T) {
	t.Setenv("PATH", "")
	orig := codexBinary
	codexBinary = "codex-does-not-exist-xyz"
	defer func() { codexBinary = orig }()

	if _, err := newCLIStreamer(CLIExecutorCodex); err == nil {
		t.Fatal("expected error when codex binary is missing")
	} else if !strings.Contains(err.Error(), "requires the 'codex' CLI on PATH") {
		t.Errorf("error should hint at install path; got %v", err)
	}
}

func TestNewCLIStreamer_UnknownExecutor(t *testing.T) {
	if _, err := newCLIStreamer("not-an-executor"); err == nil {
		t.Fatal("expected error for an unknown executor name")
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

// TestRunner_CodexExecutorDefault mirrors TestRunner_CLIExecutorDefault for the
// codex CLI executor: `cbx llm default codex` with no api provider configured
// must run via the local `codex` binary.
func TestRunner_CodexExecutorDefault(t *testing.T) {
	restore := withFakeCodexBinary(t, "**Codex-refined components**\n", 0)
	defer restore()

	cfg := &config.Config{}
	cfg.LLM.Default = CLIExecutorCodex // empty Providers map on purpose

	runner := NewRunner(cfg, "", "", nil)
	var streamed strings.Builder
	prog := &captureProgress{onToken: func(tok string) { streamed.WriteString(tok) }}

	plan, err := runner.Run(context.Background(), "S3 + Lambda image processor", prog)
	if err != nil {
		t.Fatalf("Run with codex CLI-executor default: %v", err)
	}
	if plan == nil {
		t.Fatal("expected a plan, got nil")
	}
	if !strings.Contains(streamed.String(), "Codex-refined components") {
		t.Errorf("expected the fake codex output to be streamed; got %q", streamed.String())
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
