package e2e

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditEndToEnd(t *testing.T) {
	t.Parallel()

	fixturePath, err := filepath.Abs("fixtures/pulumi-sample-state.json")
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}

	t.Run("audit_pulumi_state_outputs_json_and_markdown", func(t *testing.T) {
		tmpDir := t.TempDir()

		stdout, stderr, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", fixturePath, "--output", "json")

		if code == 0 {
			// We expect some findings, so exit code should be > 0
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

		// Verify finding structure
		for _, f := range findings {
			for _, field := range []string{"rule_id", "title", "severity", "resource", "service"} {
				if _, ok := f[field]; !ok {
					t.Fatalf("finding missing field %q: %+v", field, f)
				}
			}
		}

		// Verify markdown report was written
		reportPath := filepath.Join(tmpDir, "pulumi-sample-state_audit_report.md")
		requireFileExists(t, reportPath)
		requireFileContains(t, reportPath, "CloudBooster Audit Report")
		requireFileContains(t, reportPath, "Findings:")

		_ = stderr
	})

	t.Run("audit_exit_code_reflects_severity", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", fixturePath, "--output", "json")

		// The fixture has high-severity findings (S3-002, EC2-001), so exit should be 3
		if code != 3 {
			t.Fatalf("expected exit code 3 (high severity), got %d", code)
		}
	})

	t.Run("audit_plain_output_shows_findings", func(t *testing.T) {
		tmpDir := t.TempDir()

		stdout, _, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", fixturePath)

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
			"audit", "--pulumi-state", fixturePath,
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
}
