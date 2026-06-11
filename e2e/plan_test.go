package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanEndToEnd(t *testing.T) {
	t.Parallel()

	llmEnv := map[string]string{
		"CBX_KEYCHAIN_MOCK":     "1",
		"CBX_LLM_SKIP_VALIDATE": "1",
	}

	t.Run("plan_without_llm_login_fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, stderr, code := runCBXInDir(t, tmpDir, nil, "plan", "static site with auth")
		if code == 0 {
			t.Fatal("expected cbx plan to fail without LLM login")
		}
		if !strings.Contains(stderr, "no LLM provider configured") {
			t.Fatalf("expected 'no LLM provider configured' error, got: %s", stderr)
		}
	})

	t.Run("llm_login_claude_then_plan_writes_md", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		// Step 1: cbx llm api login claude — success message is decoration,
		// routed to stderr in B6 so stdout stays clean for data.
		_, stderr, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, llmEnv, "llm", "api", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("cbx llm api login claude exited %d", code)
		}
		if !strings.Contains(stderr, "Logged in to api/claude") {
			t.Fatalf("expected login confirmation on stderr, got: %s", stderr)
		}

		// Step 2: cbx plan "static site with auth" --no-tui
		stdout, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "plan", "--no-tui", "static site with auth")
		if code != 0 {
			t.Fatalf("cbx plan exited %d", code)
		}
		if !strings.Contains(stdout, "Wrote") {
			t.Fatalf("expected output mentioning written files, got: %s", stdout)
		}

		// Assert plan.md exists and has expected content
		mdPath := filepath.Join(tmpDir, "plan.md")
		requireFileExists(t, mdPath)
		requireFileContains(t, mdPath, "ADR:")
		requireFileContains(t, mdPath, "static site with auth")
		requireFileContains(t, mdPath, "```mermaid")

		// Default is mermaid, so plan.d2 should NOT exist
		d2Path := filepath.Join(tmpDir, "plan.d2")
		if _, err := os.Stat(d2Path); err == nil {
			t.Fatalf("expected plan.d2 to NOT exist in default mermaid mode")
		}
	})

	t.Run("plan_with_diagram_d2_writes_md_and_d2", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		// Login
		_, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, llmEnv, "llm", "api", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("login failed with code %d", code)
		}

		// Plan with --diagram=d2 --no-tui
		stdout, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "plan", "--no-tui", "--diagram=d2", "static site with auth")
		if code != 0 {
			t.Fatalf("cbx plan exited %d", code)
		}
		if !strings.Contains(stdout, "Wrote") {
			t.Fatalf("expected output mentioning written files, got: %s", stdout)
		}

		requireFileExists(t, filepath.Join(tmpDir, "plan.md"))
		requireFileExists(t, filepath.Join(tmpDir, "plan.d2"))
		requireFileContains(t, filepath.Join(tmpDir, "plan.d2"), "direction:")
	})

	t.Run("plan_with_json_flag_emits_envelope", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		// Login
		_, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, llmEnv, "llm", "api", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("login failed with code %d", code)
		}

		// Plan with --json
		stdout, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "plan", "--json", "static site with auth")
		if code != 0 {
			t.Fatalf("cbx plan exited %d", code)
		}

		requireJSONValid(t, stdout)
		if !strings.Contains(stdout, `"markdown"`) {
			t.Fatalf("expected markdown in JSON envelope, got: %s", stdout)
		}

		// Should not write files in --json mode
		mdPath := filepath.Join(tmpDir, "plan.md")
		if _, err := os.Stat(mdPath); err == nil {
			t.Fatalf("expected plan.md to NOT exist in --json mode")
		}
	})

	t.Run("plan_with_output_dir_flag", func(t *testing.T) {
		tmpDir := t.TempDir()
		outDir := filepath.Join(tmpDir, "output")
		homeDir := filepath.Join(tmpDir, "home")

		// Login
		_, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, llmEnv, "llm", "api", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("login failed with code %d", code)
		}

		// Create output dir
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			t.Fatalf("creating output dir: %v", err)
		}

		// Plan with --output-dir flag (-d) --no-tui
		stdout, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "plan", "--no-tui", "-d", outDir, "static site with auth")
		if code != 0 {
			t.Fatalf("cbx plan exited %d", code)
		}
		if !strings.Contains(stdout, outDir) {
			t.Fatalf("expected output dir in stdout, got: %s", stdout)
		}

		requireFileExists(t, filepath.Join(outDir, "plan.md"))
	})

	t.Run("plan_with_variants_writes_multiple_files", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		// Login
		_, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, llmEnv, "llm", "api", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("login failed with code %d", code)
		}

		// Plan with --variants=2 --no-tui
		stdout, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "plan", "--no-tui", "--variants=2", "static site with auth")
		if code != 0 {
			t.Fatalf("cbx plan exited %d", code)
		}
		if !strings.Contains(stdout, "plan.md") {
			t.Fatalf("expected plan.md in summary, got: %s", stdout)
		}
		if !strings.Contains(stdout, "plan-v2.md") {
			t.Fatalf("expected plan-v2.md in summary, got: %s", stdout)
		}

		requireFileExists(t, filepath.Join(tmpDir, "plan.md"))
		requireFileExists(t, filepath.Join(tmpDir, "plan-v2.md"))
	})

	t.Run("interactive_refine_and_save_with_diff", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		// Login
		_, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, llmEnv, "llm", "api", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("login failed with code %d", code)
		}

		// Run interactive plan: send intent via stdin, then slash commands.
		// No positional intent so auto-detect does not route to headless.
		_, _, code = runCBXInteractive(t, homeDir, tmpDir, nil,
			[]string{
				`static site with auth`,
				`/save v1`,
				`/refine "add CDN"`,
				`/save v2`,
				`/quit`,
			},
			"plan",
		)
		if code != 0 {
			t.Fatalf("interactive plan exited %d", code)
		}

		v1Path := filepath.Join(tmpDir, "v1", "plan.md")
		v2Path := filepath.Join(tmpDir, "v2", "plan.md")
		requireFileExists(t, v1Path)
		requireFileExists(t, v2Path)

		v1Data, err := os.ReadFile(v1Path)
		if err != nil {
			t.Fatalf("reading v1 plan: %v", err)
		}
		v2Data, err := os.ReadFile(v2Path)
		if err != nil {
			t.Fatalf("reading v2 plan: %v", err)
		}

		// v1 should not have CloudFront (added by CDN refine)
		if strings.Contains(string(v1Data), "CloudFront") {
			t.Fatalf("v1 plan should not contain CloudFront before refine, got:\n%s", string(v1Data))
		}
		// v2 should have CloudFront
		if !strings.Contains(string(v2Data), "CloudFront") {
			t.Fatalf("v2 plan should contain CloudFront after refine, got:\n%s", string(v2Data))
		}
	})
}
