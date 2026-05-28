package audit

import (
	"strings"
	"testing"
)

func TestRenderPlain(t *testing.T) {
	findings := []Finding{
		{RuleID: "S3-002", Title: "S3 encryption", Severity: SeverityHigh, Resource: "bucket-1", Service: "S3", Remediation: "Enable SSE"},
		{RuleID: "S3-001", Title: "S3 versioning", Severity: SeverityWarning, Resource: "bucket-1", Service: "S3", Remediation: "Enable versioning"},
	}
	out := RenderPlain(findings, "state.json")
	if !strings.Contains(out, "HIGH") {
		t.Fatal("expected HIGH in plain output")
	}
	if !strings.Contains(out, "WARNING") {
		t.Fatal("expected WARNING in plain output")
	}
	if !strings.Contains(out, "S3-002") {
		t.Fatal("expected S3-002 in plain output")
	}
	if !strings.Contains(out, "report") {
		t.Fatal("expected report link in plain output")
	}
}

func TestRenderJSON(t *testing.T) {
	findings := []Finding{
		{RuleID: "EC2-001", Title: "SG open", Severity: SeverityHigh, Resource: "sg-1", Service: "EC2", Remediation: "Fix it"},
	}
	out, err := RenderJSON(findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"rule_id": "EC2-001"`) {
		t.Fatalf("expected EC2-001 in JSON, got:\n%s", out)
	}
}

func TestRenderMarkdown(t *testing.T) {
	findings := []Finding{
		{RuleID: "IAM-001", Title: "IAM trust", Severity: SeverityWarning, Resource: "role-1", Service: "IAM", Description: "Too broad", Remediation: "Scope it"},
	}
	out := RenderMarkdown(findings)
	if !strings.Contains(out, "# CloudBooster Audit Report") {
		t.Fatal("expected report header")
	}
	if !strings.Contains(out, "IAM-001") {
		t.Fatal("expected IAM-001 in markdown")
	}
}

func TestRenderSARIF(t *testing.T) {
	findings := []Finding{
		{RuleID: "LAMBDA-001", Title: "Env vars", Severity: SeverityInfo, Resource: "func-1", Service: "Lambda", Description: "Plain text", Remediation: "Use Secrets Manager"},
	}
	out, err := RenderSARIF(findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Fatalf("expected SARIF version, got:\n%s", out)
	}
	if !strings.Contains(out, "LAMBDA-001") {
		t.Fatal("expected LAMBDA-001 in SARIF")
	}
}

func TestRenderGitHubAction(t *testing.T) {
	findings := []Finding{
		{RuleID: "S3-002", Title: "Encryption", Severity: SeverityHigh, Resource: "bucket", Service: "S3", Description: "No encryption"},
		{RuleID: "S3-001", Title: "Versioning", Severity: SeverityWarning, Resource: "bucket", Service: "S3", Description: "No versioning"},
		{RuleID: "LAMBDA-001", Title: "Env", Severity: SeverityInfo, Resource: "func", Service: "Lambda", Description: "Plain env"},
	}
	out := RenderGitHubAction(findings)
	if !strings.Contains(out, "::error") {
		t.Fatal("expected ::error for high severity")
	}
	if !strings.Contains(out, "::warning") {
		t.Fatal("expected ::warning for warning severity")
	}
	if !strings.Contains(out, "::notice") {
		t.Fatal("expected ::notice for info severity")
	}
}

func TestRenderPlainNoFindings(t *testing.T) {
	out := RenderPlain([]Finding{}, "state.json")
	if !strings.Contains(strings.ToLower(out), "no findings") {
		t.Fatal("expected 'no findings' message")
	}
}
