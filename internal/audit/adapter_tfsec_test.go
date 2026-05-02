package audit

import (
	"os"
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
