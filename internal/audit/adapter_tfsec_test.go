package audit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestParseTfsecOutput(t *testing.T) {
	data, err := os.ReadFile("testdata/tfsec.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("parseTfsecOutput: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f0 := findings[0]
	if f0.RuleID != "AVD-AWS-0089" {
		t.Errorf("expected rule_id AVD-AWS-0089, got %s", f0.RuleID)
	}
	if f0.Title != "aws-s3-enable-versioning" {
		t.Errorf("expected title aws-s3-enable-versioning, got %s", f0.Title)
	}
	if f0.Severity != SeverityWarning {
		t.Errorf("expected severity warning, got %s", f0.Severity)
	}
	if f0.Resource != "my-bucket" {
		t.Errorf("expected resource my-bucket, got %s", f0.Resource)
	}
	if f0.Service != "S3" {
		t.Errorf("expected service S3, got %s", f0.Service)
	}
	if f0.Remediation != "Enable versioning for S3 buckets" {
		t.Errorf("expected remediation 'Enable versioning for S3 buckets', got %s", f0.Remediation)
	}

	f1 := findings[1]
	if f1.RuleID != "AVD-AWS-0132" {
		t.Errorf("expected rule_id AVD-AWS-0132, got %s", f1.RuleID)
	}
	if f1.Severity != SeverityHigh {
		t.Errorf("expected severity high, got %s", f1.Severity)
	}
}

func TestTfsecScanSource_SupportsSource(t *testing.T) {
	a := &tfsecAdapter{}
	if !a.SupportsSource() {
		t.Fatal("tfsec must report SupportsSource() == true once MR 2 lands")
	}
}

// TestTfsecScanSource_RunsAgainstDir exercises ScanSource end-to-end. When
// tfsec is not on PATH (the default CI environment for unit tests), the
// adapter must surface a missing-binary error instead of silently skipping —
// and crucially must NOT fail with a "ErrSourceModeUnsupported"-style error.
//
// When tfsec IS installed locally, the same call must succeed against a
// minimal fixture and return at least one finding (we ship an unencrypted
// S3 bucket as the canary).
func TestTfsecScanSource_RunsAgainstDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/main.tf", []byte(`resource "aws_s3_bucket" "b" { bucket = "demo" }
`), 0o644); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}

	a := &tfsecAdapter{}
	findings, err := a.ScanSource(context.Background(), dir)

	if _, lookErr := exec.LookPath("tfsec"); lookErr != nil {
		// Binary missing — expect a checkVersion-derived error. The exact
		// message depends on the OS install hint, so just assert non-nil
		// and not the source-mode sentinel.
		if err == nil {
			t.Fatal("expected missing-binary error when tfsec is not installed")
		}
		if errors.Is(err, ErrSourceModeUnsupported) {
			t.Fatal("ScanSource must not return ErrSourceModeUnsupported once wired")
		}
		return
	}

	// tfsec present locally — must succeed and produce findings.
	if err != nil {
		t.Fatalf("ScanSource with tfsec installed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one tfsec finding for an unencrypted S3 bucket")
	}
}
