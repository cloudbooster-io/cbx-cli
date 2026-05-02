package audit

import (
	"os"
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
