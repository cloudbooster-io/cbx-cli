package audit

import (
	"os"
	"testing"
)

func TestParseProwlerOutput(t *testing.T) {
	data, err := os.ReadFile("testdata/prowler.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	findings, err := parseProwlerOutput(data)
	if err != nil {
		t.Fatalf("parseProwlerOutput: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f0 := findings[0]
	if f0.RuleID != "s3_bucket_versioning" {
		t.Errorf("expected rule_id s3_bucket_versioning, got %s", f0.RuleID)
	}
	if f0.Title != "Ensure S3 bucket has versioning enabled" {
		t.Errorf("expected title 'Ensure S3 bucket has versioning enabled', got %s", f0.Title)
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

	f1 := findings[1]
	if f1.RuleID != "s3_bucket_default_encryption" {
		t.Errorf("expected rule_id s3_bucket_default_encryption, got %s", f1.RuleID)
	}
	if f1.Severity != SeverityHigh {
		t.Errorf("expected severity high, got %s", f1.Severity)
	}

	// PASS findings should be filtered out.
	for _, f := range findings {
		if f.RuleID == "ec2_securitygroup_allow_ingress_from_internet_to_any_port" {
			t.Errorf("PASS finding should be filtered out")
		}
	}
}
