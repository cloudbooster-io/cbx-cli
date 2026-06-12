package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// writeFakeClaudeCLI installs a fake `claude` on PATH that answers
// --version and serves a canned completion for `-p` invocations. A
// non-zero promptExit prints promptOut on STDOUT — mirroring how the
// real CLI reports prompt-time failures (auth, model, limits).
func writeFakeClaudeCLI(t *testing.T, promptOut string, promptExit int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then\n" +
		"  printf 'claude 9.9.9 (fake)\\n'\n" +
		"  exit 0\n" +
		"fi\n" +
		"cat > /dev/null\n" +
		"printf '%s' '" + strings.ReplaceAll(promptOut, "'", `'\''`) + "'\n" +
		"exit " + strconv.Itoa(promptExit) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func runLLMCLITest(t *testing.T) (string, error) {
	t.Helper()
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"llm", "cli", "test", "claude-code"})
	err := cmd.Execute()
	return out.String(), err
}

func TestLLMCLITest_PromptProbe_OK(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	writeFakeClaudeCLI(t, "ok", 0)

	out, err := runLLMCLITest(t)
	if err != nil {
		t.Fatalf("llm cli test claude-code: %v\n%s", err, out)
	}
}

func TestLLMCLITest_PromptProbe_FailureSurfacesCLIMessage(t *testing.T) {
	// --version succeeds but the prompt fails — the exact gap the probe
	// exists to close. The command error must carry the CLI's own
	// failure text (printed on stdout by the real `claude -p`).
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	writeFakeClaudeCLI(t, "Invalid API key · Please run /login", 1)

	_, err := runLLMCLITest(t)
	if err == nil {
		t.Fatal("expected the prompt probe to fail the command")
	}
	if !strings.Contains(err.Error(), "Invalid API key") {
		t.Errorf("error should carry the CLI's own message; got %v", err)
	}
}

func TestLLMCLITest_PromptProbe_EmptyCompletionFails(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	writeFakeClaudeCLI(t, "", 0)

	_, err := runLLMCLITest(t)
	if err == nil {
		t.Fatal("expected empty completion to fail the probe")
	}
}
