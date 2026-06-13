package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	var err error
	binaryPath, err = buildBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build cbx binary: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[e2e] built cbx binary at %s\n", binaryPath)
	code := m.Run()
	_ = os.Remove(binaryPath)
	os.Exit(code)
}

func buildBinary() (string, error) {
	repoRoot, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(repoRoot)
		if parent == repoRoot {
			return "", fmt.Errorf("go.mod not found")
		}
		repoRoot = parent
	}
	binName := "cbx"
	if filepath.Separator == '\\' {
		binName += ".exe"
	}
	binPath := filepath.Join(repoRoot, "bin", binName)
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		return "", err
	}
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/cbx")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, out)
	}
	return binPath, nil
}

// isolatedEnv builds the child-process environment for a cbx invocation:
// the host environment with HOME and the XDG base dirs pinned inside the
// per-test home, plus any test-specific overrides. Pinning the XDG vars is
// load-bearing: config.Dir() prefers $XDG_CONFIG_HOME over $HOME, and
// GitHub-hosted runners set it — without the override every test process
// would share the runner's real config dir (and race on config.json).
// Duplicate keys are fine; os/exec uses the last occurrence.
func isolatedEnv(home string, env map[string]string) []string {
	full := append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
	)
	for k, v := range env {
		full = append(full, fmt.Sprintf("%s=%s", k, v))
	}
	return full
}

// runCBX executes the cbx binary with an isolated HOME.
func runCBX(t *testing.T, env map[string]string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runCBXWithHome(t, "", env, args...)
}

func runCBXWithHome(t *testing.T, home string, env map[string]string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runCBXWithHomeAndDir(t, home, "", env, args...)
}

func runCBXWithHomeAndDir(t *testing.T, home, dir string, env map[string]string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(binaryPath, args...)
	if dir != "" {
		cmd.Dir = dir
	}

	if home == "" {
		// Create an isolated HOME inside a temp dir.
		tmpDir := t.TempDir()
		home = filepath.Join(tmpDir, "home")
		if err := os.MkdirAll(home, 0o755); err != nil {
			t.Fatalf("creating fake home: %v", err)
		}
	}

	cmd.Env = isolatedEnv(home, env)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running cbx %s: %v", strings.Join(args, " "), err)
	}

	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), exitCode
}

// runCBXInteractive runs cbx with piped stdin for interactive testing.
func runCBXInteractive(t *testing.T, home, dir string, env map[string]string, stdinLines []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(binaryPath, args...)
	if dir != "" {
		cmd.Dir = dir
	}

	if home == "" {
		tmpDir := t.TempDir()
		home = filepath.Join(tmpDir, "home")
		if err := os.MkdirAll(home, 0o755); err != nil {
			t.Fatalf("creating fake home: %v", err)
		}
	}

	cmd.Env = isolatedEnv(home, env)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("creating stdin pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting cbx %s: %v", strings.Join(args, " "), err)
	}

	for _, line := range stdinLines {
		_, _ = fmt.Fprintln(stdinPipe, line)
	}
	_ = stdinPipe.Close()

	err = cmd.Wait()
	exitCode = 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running cbx %s: %v", strings.Join(args, " "), err)
	}

	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), exitCode
}

func requireJSONValid(t *testing.T, s string) {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("expected valid JSON, got error: %v\ninput:\n%s", err, s)
	}
}
