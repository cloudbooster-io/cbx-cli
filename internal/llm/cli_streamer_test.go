package llm

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

	s, err := newCLIStreamer(CLIExecutorClaudeCode, "")
	if err != nil {
		t.Fatalf("newCLIStreamer: %v", err)
	}
	var sb strings.Builder
	if err := s.Stream(context.Background(), "analyse this", func(tok string) { sb.WriteString(tok) }); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if !strings.Contains(sb.String(), "ranked components here") {
		t.Errorf("expected fake response on stdout, got %q", sb.String())
	}
}

func TestCLIStreamer_Codex_HappyPath(t *testing.T) {
	restore := withFakeCodexBinary(t, "ranked components from codex", 0)
	defer restore()

	s, err := newCLIStreamer(CLIExecutorCodex, "")
	if err != nil {
		t.Fatalf("newCLIStreamer(codex): %v", err)
	}
	var sb strings.Builder
	if err := s.Stream(context.Background(), "analyse this", func(tok string) { sb.WriteString(tok) }); err != nil {
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

	s, err := newCLIStreamer(CLIExecutorClaudeCode, "")
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

	if _, err := newCLIStreamer(CLIExecutorClaudeCode, ""); err == nil {
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

	if _, err := newCLIStreamer(CLIExecutorCodex, ""); err == nil {
		t.Fatal("expected error when codex binary is missing")
	} else if !strings.Contains(err.Error(), "requires the 'codex' CLI on PATH") {
		t.Errorf("error should hint at install path; got %v", err)
	}
}

func TestNewCLIStreamer_UnknownExecutor(t *testing.T) {
	if _, err := newCLIStreamer("not-an-executor", ""); err == nil {
		t.Fatal("expected error for an unknown executor name")
	}
}

func TestCLIStreamer_ModelOverride_Args(t *testing.T) {
	restore := withFakeClaudeBinary(t, "ok", 0)
	defer restore()

	s, err := newCLIStreamer(CLIExecutorClaudeCode, "claude-opus-4-8")
	if err != nil {
		t.Fatalf("newCLIStreamer: %v", err)
	}
	want := []string{"-p", "--output-format", "text", "--model", "claude-opus-4-8"}
	if len(s.args) != len(want) {
		t.Fatalf("args = %v, want %v", s.args, want)
	}
	for i := range want {
		if s.args[i] != want[i] {
			t.Fatalf("args = %v, want %v", s.args, want)
		}
	}
}

func TestCLIStreamer_Codex_ModelOverride_StdinMarkerStaysLast(t *testing.T) {
	restore := withFakeCodexBinary(t, "ok", 0)
	defer restore()

	s, err := newCLIStreamer(CLIExecutorCodex, "gpt-5-codex")
	if err != nil {
		t.Fatalf("newCLIStreamer(codex): %v", err)
	}
	if got := s.args[len(s.args)-1]; got != "-" {
		t.Fatalf("stdin marker must stay last, got args %v", s.args)
	}
	foundModel := false
	for i, a := range s.args {
		if a == "--model" && i+1 < len(s.args) && s.args[i+1] == "gpt-5-codex" {
			foundModel = true
		}
	}
	if !foundModel {
		t.Fatalf("expected --model gpt-5-codex in args, got %v", s.args)
	}
}

func TestCLIStreamer_NoModel_NoFlag(t *testing.T) {
	restore := withFakeClaudeBinary(t, "ok", 0)
	defer restore()

	s, err := newCLIStreamer(CLIExecutorClaudeCode, "")
	if err != nil {
		t.Fatalf("newCLIStreamer: %v", err)
	}
	for _, a := range s.args {
		if a == "--model" {
			t.Fatalf("no model configured but --model passed: %v", s.args)
		}
	}
}

func TestCLIStreamer_NonZeroExit_FallsBackToStdout(t *testing.T) {
	// `claude -p` reports auth/model/limit failures on STDOUT with an
	// empty stderr — the error must carry that message, not a bare
	// "exited 1".
	restore := withFakeClaudeBinary(t, "Invalid API key · Please run /login", 1)
	defer restore()

	s, err := newCLIStreamer(CLIExecutorClaudeCode, "")
	if err != nil {
		t.Fatalf("newCLIStreamer: %v", err)
	}
	streamErr := s.Stream(context.Background(), "x", func(string) {})
	if streamErr == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !strings.Contains(streamErr.Error(), "Invalid API key") {
		t.Errorf("expected stdout message in error; got %v", streamErr)
	}
}

func TestProbeCLIExecutor_HappyPath(t *testing.T) {
	restore := withFakeClaudeBinary(t, "ok", 0)
	defer restore()

	resp, err := ProbeCLIExecutor(context.Background(), CLIExecutorClaudeCode, "")
	if err != nil {
		t.Fatalf("ProbeCLIExecutor: %v", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %q, want ok", resp)
	}
}

func TestProbeCLIExecutor_EmptyCompletionIsError(t *testing.T) {
	restore := withFakeClaudeBinary(t, "", 0)
	defer restore()

	_, err := ProbeCLIExecutor(context.Background(), CLIExecutorClaudeCode, "")
	if err == nil {
		t.Fatal("expected error for empty completion")
	}
	if !strings.Contains(err.Error(), "empty completion") {
		t.Errorf("expected empty-completion error; got %v", err)
	}
}

func TestProbeCLIExecutor_AuthFailureCarriesCLIMessage(t *testing.T) {
	restore := withFakeClaudeBinary(t, "Invalid API key · Please run /login", 1)
	defer restore()

	_, err := ProbeCLIExecutor(context.Background(), CLIExecutorClaudeCode, "")
	if err == nil {
		t.Fatal("expected probe failure")
	}
	if !strings.Contains(err.Error(), "Invalid API key") {
		t.Errorf("probe error should carry the CLI's own message; got %v", err)
	}
}

func TestProbeCLIExecutor_MissingBinary(t *testing.T) {
	t.Setenv("PATH", "")
	orig := claudeCodeBinary
	claudeCodeBinary = "claude-does-not-exist-xyz"
	defer func() { claudeCodeBinary = orig }()

	_, err := ProbeCLIExecutor(context.Background(), CLIExecutorClaudeCode, "")
	if err == nil {
		t.Fatal("expected error when binary is missing")
	}
}
