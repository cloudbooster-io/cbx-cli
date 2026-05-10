package audit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestParseTrivyOutput(t *testing.T) {
	data, err := os.ReadFile("testdata/trivy.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("parseTrivyOutput: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f0 := findings[0]
	if f0.RuleID != "AVD-AWS-0089" {
		t.Errorf("expected rule_id AVD-AWS-0089, got %s", f0.RuleID)
	}
	if f0.Title != "S3 bucket should have versioning enabled" {
		t.Errorf("expected title 'S3 bucket should have versioning enabled', got %s", f0.Title)
	}
	if f0.Severity != SeverityWarning {
		t.Errorf("expected severity warning, got %s", f0.Severity)
	}
	if f0.Resource != "aws_s3_bucket.my_bucket.tf.json" {
		t.Errorf("expected resource aws_s3_bucket.my_bucket.tf.json, got %s", f0.Resource)
	}
	if f0.Service != "AWS" {
		t.Errorf("expected service AWS, got %s", f0.Service)
	}

	f1 := findings[1]
	if f1.RuleID != "AVD-AWS-0132" {
		t.Errorf("expected rule_id AVD-AWS-0132, got %s", f1.RuleID)
	}
	if f1.Severity != SeverityHigh {
		t.Errorf("expected severity high, got %s", f1.Severity)
	}
}

func TestTrivyScanSource_SupportsSource(t *testing.T) {
	a := &trivyAdapter{}
	if !a.SupportsSource() {
		t.Fatal("trivy must report SupportsSource() == true once MR 3 lands")
	}
}

// TestTrivyScanSource_RunsAgainstDir mirrors the tfsec source-mode adapter
// test: graceful skip-as-success when trivy isn't on PATH, real run when
// it is.
func TestTrivyScanSource_RunsAgainstDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/main.tf", []byte(`resource "aws_s3_bucket" "b" { bucket = "demo" }
`), 0o644); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}

	a := &trivyAdapter{}
	_, err := a.ScanSource(context.Background(), dir)

	if _, lookErr := exec.LookPath("trivy"); lookErr != nil {
		if err == nil {
			t.Fatal("expected missing-binary error when trivy is not installed")
		}
		if errors.Is(err, ErrSourceModeUnsupported) {
			t.Fatal("ScanSource must not return ErrSourceModeUnsupported once wired")
		}
		return
	}

	// trivy present locally — must succeed; finding count depends on
	// the bundled policy DB so we don't assert it.
	if err != nil {
		t.Fatalf("ScanSource with trivy installed: %v", err)
	}
}
