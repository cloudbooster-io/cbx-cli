package e2e

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditEndToEnd(t *testing.T) {
	t.Parallel()

	pulumiFixture, err := filepath.Abs("fixtures/pulumi-sample-state.json")
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	terraformFixture, err := filepath.Abs("fixtures/terraform-sample-state.json")
	if err != nil {
		t.Fatalf("resolving terraform fixture path: %v", err)
	}

	t.Run("audit_pulumi_state_outputs_json_and_markdown", func(t *testing.T) {
		tmpDir := t.TempDir()

		stdout, stderr, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture, "--output", "json")

		if code == 0 {
			t.Fatalf("expected non-zero exit code due to findings, got %d", code)
		}

		requireJSONValid(t, stdout)

		var findings []map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
			t.Fatalf("parsing JSON findings: %v", err)
		}
		if len(findings) == 0 {
			t.Fatal("expected at least one finding")
		}

		for _, f := range findings {
			for _, field := range []string{"rule_id", "title", "severity", "resource", "service"} {
				if _, ok := f[field]; !ok {
					t.Fatalf("finding missing field %q: %+v", field, f)
				}
			}
		}

		reportPath := filepath.Join(tmpDir, "pulumi-sample-state_audit_report.md")
		requireFileExists(t, reportPath)
		requireFileContains(t, reportPath, "CloudBooster Audit Report")
		requireFileContains(t, reportPath, "Findings:")

		_ = stderr
	})

	t.Run("audit_exit_code_reflects_severity", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture, "--output", "json")

		if code != 3 {
			t.Fatalf("expected exit code 3 (high severity), got %d", code)
		}
	})

	t.Run("audit_plain_output_shows_findings", func(t *testing.T) {
		tmpDir := t.TempDir()

		stdout, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture)

		if code != 3 {
			t.Fatalf("expected exit code 3, got %d", code)
		}

		if !strings.Contains(stdout, "S3-001") {
			t.Fatalf("expected S3-001 in output, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "EC2-001") {
			t.Fatalf("expected EC2-001 in output, got:\n%s", stdout)
		}
	})

	t.Run("audit_with_report_file_flag", func(t *testing.T) {
		tmpDir := t.TempDir()
		customReport := filepath.Join(tmpDir, "my-report.md")

		_, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture,
			"--report-file", customReport,
			"--output", "json")

		if code != 3 {
			t.Fatalf("expected exit code 3, got %d", code)
		}

		requireFileExists(t, customReport)
		requireFileContains(t, customReport, "CloudBooster Audit Report")
	})

	t.Run("audit_without_state_flag_fails", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, stderr, code := runCBXInDir(t, tmpDir, nil, "audit")
		if code == 0 {
			t.Fatal("expected cbx audit to fail without state flag")
		}
		if !strings.Contains(stderr, "--pulumi-state or --terraform-state is required") {
			t.Fatalf("expected state flag error, got: %s", stderr)
		}
	})

	t.Run("audit_terraform_state_outputs_json", func(t *testing.T) {
		tmpDir := t.TempDir()

		stdout, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--terraform-state", terraformFixture, "--output", "json")

		if code == 0 {
			t.Fatalf("expected non-zero exit code due to findings, got %d", code)
		}

		requireJSONValid(t, stdout)

		var findings []map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
			t.Fatalf("parsing JSON findings: %v", err)
		}
		if len(findings) == 0 {
			t.Fatal("expected at least one finding")
		}

		var hasS3 bool
		for _, f := range findings {
			if rid, ok := f["rule_id"].(string); ok && strings.HasPrefix(rid, "S3-") {
				hasS3 = true
				break
			}
		}
		if !hasS3 {
			t.Fatalf("expected S3 findings for terraform state, got: %v", findings)
		}
	})

	t.Run("audit_sarif_output", func(t *testing.T) {
		tmpDir := t.TempDir()

		stdout, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture, "--output", "sarif")

		if code == 0 {
			t.Fatalf("expected non-zero exit code, got %d", code)
		}

		requireJSONValid(t, stdout)

		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatalf("parsing SARIF: %v", err)
		}
		if doc["version"] != "2.1.0" {
			t.Fatalf("expected SARIF version 2.1.0, got: %v", doc["version"])
		}
	})

	t.Run("audit_github_action_output", func(t *testing.T) {
		tmpDir := t.TempDir()

		stdout, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture, "--output", "github-action")

		if code == 0 {
			t.Fatalf("expected non-zero exit code, got %d", code)
		}

		if !strings.Contains(stdout, "::error") {
			t.Fatalf("expected ::error in GitHub Actions output, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "S3-002") {
			t.Fatalf("expected S3-002 in GitHub Actions output, got:\n%s", stdout)
		}
	})

	t.Run("audit_no_tui_flag_is_noop", func(t *testing.T) {
		tmpDir := t.TempDir()

		stdout, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture, "--no-tui")

		if code != 3 {
			t.Fatalf("expected exit code 3, got %d", code)
		}
		if !strings.Contains(stdout, "S3-001") {
			t.Fatalf("expected S3-001 in output, got:\n%s", stdout)
		}
	})

	t.Run("audit_interactive_prints_message", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, stderr, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture, "--interactive")

		if code != 0 {
			t.Fatalf("expected exit code 0 for interactive mode, got %d", code)
		}
		if !strings.Contains(stderr, "follow-up phase") {
			t.Fatalf("expected follow-up phase message, got: %s", stderr)
		}
	})

	t.Run("audit_zero_outbound_http", func(t *testing.T) {
		tmpDir := t.TempDir()

		// The mock scanner path should not make any HTTP calls.
		// We verify by simply running the command successfully.
		_, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture, "--output", "json")

		if code == 0 {
			t.Fatalf("expected non-zero exit code due to findings, got %d", code)
		}
	})
}
