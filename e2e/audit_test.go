package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
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

		var envelope struct {
			Data []map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
			t.Fatalf("parsing JSON envelope: %v", err)
		}
		findings := envelope.Data
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

		var envelope struct {
			Data []map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
			t.Fatalf("parsing JSON envelope: %v", err)
		}
		findings := envelope.Data
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

		// Run with an invalid HTTP proxy and a fake SENTRY_DSN.
		// If the audit code path (or any dependency) makes an outbound
		// HTTP call, the invalid proxy will cause a connection error.
		env := map[string]string{
			"SENTRY_DSN": "https://fake@example.com/1",
			"HTTP_PROXY": "http://127.0.0.1:1",
		}
		stdout, stderr, code := runCBXInDir(t, tmpDir, env,
			"audit", "--pulumi-state", pulumiFixture, "--output", "json")

		// Exit code should still be driven by findings (high severity → 3),
		// not by an HTTP / proxy error.
		if code != 3 {
			t.Fatalf("expected exit code 3 from findings, got %d (stderr: %s)", code, stderr)
		}

		// Assert valid JSON output — an HTTP failure would likely prevent this.
		requireJSONValid(t, stdout)

		// Assert stderr does not contain proxy-related error indicators.
		lower := strings.ToLower(stderr)
		indicators := []string{"proxy", "connection refused", "dial tcp", "timeout", "no such host"}
		for _, ind := range indicators {
			if strings.Contains(lower, ind) {
				t.Fatalf("unexpected network error indicator %q in stderr (possible outbound HTTP): %s", ind, stderr)
			}
		}
	})

	t.Run("audit_no_api_imports", func(t *testing.T) {
		// Verify that internal/audit does not import network/API packages.
		// This is a compile-time package boundary guard.
		cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "../internal/audit")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list failed: %v\n%s", err, out)
		}

		forbidden := []string{
			"net/http",
			"internal/plan",
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			for _, f := range forbidden {
				if line == f || strings.HasSuffix(line, "/"+f) {
					t.Fatalf("internal/audit imports forbidden package %q", f)
				}
			}
		}
	})

	t.Run("audit_large_file_no_tui_fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		largeFile := filepath.Join(tmpDir, "large.tfstate")
		createLargeStateFile(t, largeFile)

		_, stderr, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--terraform-state", largeFile, "--no-tui")

		if code == 0 {
			t.Fatalf("expected non-zero exit code, got %d", code)
		}
		if !strings.Contains(stderr, "size limit") {
			t.Fatalf("expected size limit error, got: %s", stderr)
		}
	})

	t.Run("audit_large_file_with_yes_succeeds", func(t *testing.T) {
		tmpDir := t.TempDir()
		largeFile := filepath.Join(tmpDir, "large.tfstate")
		createLargeStateFile(t, largeFile)

		// With --yes the size guard is bypassed. The parser then fails
		// because the state contains no real resources, proving the guard
		// was skipped.
		_, stderr, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--terraform-state", largeFile, "--yes")

		if code == 0 {
			t.Fatalf("expected non-zero exit code (no resources), got %d", code)
		}
		if strings.Contains(stderr, "size limit") {
			t.Fatalf("did not expect size limit error, got: %s", stderr)
		}
	})

	t.Run("audit_large_file_prompt_decline", func(t *testing.T) {
		tmpDir := t.TempDir()
		largeFile := filepath.Join(tmpDir, "large.tfstate")
		createLargeStateFile(t, largeFile)

		_, stderr, code := runCBXInteractive(t, "", tmpDir, nil, []string{"n"},
			"audit", "--terraform-state", largeFile)

		if code == 0 {
			t.Fatalf("expected non-zero exit code, got %d", code)
		}
		if !strings.Contains(stderr, "user declined") {
			t.Fatalf("expected user declined message, got: %s", stderr)
		}
	})

	t.Run("audit_malformed_json_three_line_error", func(t *testing.T) {
		tmpDir := t.TempDir()
		badFile := filepath.Join(tmpDir, "bad.json")
		if err := os.WriteFile(badFile, []byte(`{"invalid`), 0o644); err != nil {
			t.Fatalf("writing file: %v", err)
		}

		_, stderr, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", badFile)

		if code == 0 {
			t.Fatalf("expected non-zero exit code, got %d", code)
		}
		lines := strings.Count(stderr, "\n")
		if lines != 2 {
			t.Fatalf("expected three-line error (2 newlines), got %d lines: %s", lines+1, stderr)
		}
	})

	t.Run("audit_terraform_remote_exec_blocked", func(t *testing.T) {
		tmpDir := t.TempDir()
		badFile := filepath.Join(tmpDir, "bad.tfstate")
		state := map[string]interface{}{
			"terraform_version": "1.5.0",
			"serial":            1,
			"resources": []interface{}{
				map[string]interface{}{
					"mode": "managed",
					"type": "aws_instance",
					"name": "web",
					"provisioner": []interface{}{
						map[string]interface{}{
							"type":   "remote-exec",
							"inline": []interface{}{"echo hello"},
						},
					},
					"instances": []interface{}{
						map[string]interface{}{
							"attributes": map[string]interface{}{
								"ami": "ami-123",
							},
						},
					},
				},
			},
		}
		writeJSONFile(t, badFile, state)

		_, stderr, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--terraform-state", badFile)

		if code == 0 {
			t.Fatalf("expected non-zero exit code, got %d", code)
		}
		if !strings.Contains(stderr, "blocked provisioner") {
			t.Fatalf("expected blocked provisioner error, got: %s", stderr)
		}
		lines := strings.Count(stderr, "\n")
		if lines != 2 {
			t.Fatalf("expected three-line error (2 newlines), got %d lines: %s", lines+1, stderr)
		}
	})

	t.Run("audit_all_scanners_fail_exits_nonzero", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, stderr, code := runCBXInDir(t, tmpDir, nil,
			"audit", "--pulumi-state", pulumiFixture, "--scanners", "tfsec")

		if code == 0 {
			t.Fatalf("expected non-zero exit code when all scanners fail, got %d", code)
		}
		if !strings.Contains(stderr, "tfsec") {
			t.Fatalf("expected stderr to mention tfsec failure, got: %s", stderr)
		}
	})
}

func createLargeStateFile(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating file: %v", err)
	}
	defer f.Close()

	header := `{"terraform_version":"1.0.0","serial":1,"resources":[],"pad":"`
	footer := `"}`
	target := 100*1024*1024 + 1
	padding := target - len(header) - len(footer)
	if padding < 0 {
		padding = 0
	}

	if _, err := f.WriteString(header); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if _, err := f.WriteString(strings.Repeat(" ", padding)); err != nil {
		t.Fatalf("writing padding: %v", err)
	}
	if _, err := f.WriteString(footer); err != nil {
		t.Fatalf("writing footer: %v", err)
	}
}

func writeJSONFile(t *testing.T, path string, v interface{}) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling JSON: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}
}
