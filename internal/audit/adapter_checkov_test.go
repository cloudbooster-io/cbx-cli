package audit

import (
	"os"
	"testing"
)

func TestParseCheckovOutput(t *testing.T) {
	data, err := os.ReadFile("testdata/checkov.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("parseCheckovOutput: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f0 := findings[0]
	if f0.RuleID != "CKV_AWS_19" {
		t.Errorf("expected rule_id CKV_AWS_19, got %s", f0.RuleID)
	}
	if f0.Title != "Ensure S3 bucket has versioning enabled" {
		t.Errorf("expected title 'Ensure S3 bucket has versioning enabled', got %s", f0.Title)
	}
	if f0.Severity != SeverityWarning {
		t.Errorf("expected severity warning, got %s", f0.Severity)
	}
	if f0.Resource != "aws_s3_bucket.my_bucket" {
		t.Errorf("expected resource aws_s3_bucket.my_bucket, got %s", f0.Resource)
	}
	if f0.Service != "AWS" {
		t.Errorf("expected service AWS, got %s", f0.Service)
	}

	f1 := findings[1]
	if f1.RuleID != "CKV_AWS_145" {
		t.Errorf("expected rule_id CKV_AWS_145, got %s", f1.RuleID)
	}
	if f1.Severity != SeverityHigh {
		t.Errorf("expected severity high, got %s", f1.Severity)
	}
}
