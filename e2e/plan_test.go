package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanEndToEnd(t *testing.T) {
	t.Parallel()

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

	t.Run("llm_login_claude_then_plan_writes_adr_and_d2", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		// Step 1: cbx llm login claude
		stdout, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "llm", "login", "claude")
		if code != 0 {
			t.Fatalf("cbx llm login claude exited %d", code)
		}
		if !strings.Contains(stdout, "Logged in to claude") {
			t.Fatalf("expected login confirmation, got: %s", stdout)
		}

		// Step 2: cbx plan "static site with auth"
		stdout, _, code = runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "plan", "static site with auth")
		if code != 0 {
			t.Fatalf("cbx plan exited %d", code)
		}
		if !strings.Contains(stdout, "Wrote") {
			t.Fatalf("expected output mentioning written files, got: %s", stdout)
		}

		// Assert plan.adr.md exists and has expected content
		adrPath := filepath.Join(tmpDir, "plan.adr.md")
		requireFileExists(t, adrPath)
		requireFileContains(t, adrPath, "ADR:")
		requireFileContains(t, adrPath, "static site with auth")

		// Assert plan.d2 exists and has expected content
		d2Path := filepath.Join(tmpDir, "plan.d2")
		requireFileExists(t, d2Path)
		requireFileContains(t, d2Path, "direction:")
	})

	t.Run("plan_with_output_dir_flag", func(t *testing.T) {
		tmpDir := t.TempDir()
		outDir := filepath.Join(tmpDir, "output")
		homeDir := filepath.Join(tmpDir, "home")

		// Login
		_, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "llm", "login", "claude")
		if code != 0 {
			t.Fatalf("login failed with code %d", code)
		}

		// Create output dir
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			t.Fatalf("creating output dir: %v", err)
		}

		// Plan with --output flag
		stdout, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "plan", "-o", outDir, "static site with auth")
		if code != 0 {
			t.Fatalf("cbx plan exited %d", code)
		}
		if !strings.Contains(stdout, outDir) {
			t.Fatalf("expected output dir in stdout, got: %s", stdout)
		}

		requireFileExists(t, filepath.Join(outDir, "plan.adr.md"))
		requireFileExists(t, filepath.Join(outDir, "plan.d2"))
	})

	t.Run("interactive_refine_and_save_with_diff", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		// Login
		_, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, nil, "llm", "login", "claude")
		if code != 0 {
			t.Fatalf("login failed with code %d", code)
		}

		// Run interactive plan: save v1, refine with CDN, save v2, quit
		_, _, code = runCBXInteractive(t, homeDir, tmpDir, nil,
			[]string{
				`/save v1`,
				`/refine "add CDN"`,
				`/save v2`,
				`/quit`,
			},
			"plan", "--interactive", "static site with auth",
		)
		if code != 0 {
			t.Fatalf("interactive plan exited %d", code)
		}

		v1Path := filepath.Join(tmpDir, "v1", "plan.adr.md")
		v2Path := filepath.Join(tmpDir, "v2", "plan.adr.md")
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
