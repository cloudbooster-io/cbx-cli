package audit

import (
	"fmt"
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"

	auditcore "github.com/cloudbooster-io/cbx-cli/internal/audit"
)

// TestShowcase renders the TUI at a handful of realistic sizes so a
// developer can run `go test -run TestShowcase -v` and eyeball the
// output. Skipped unless the AUDITTUI_SHOWCASE env var is set so the
// regular test suite stays output-clean.
func TestShowcase(t *testing.T) {
	if os.Getenv("AUDITTUI_SHOWCASE") == "" {
		t.Skip("set AUDITTUI_SHOWCASE=1 to render the showcase")
	}
	// Pretend we're on a colour terminal even under `go test`.
	lipgloss.SetColorProfile(0) // 0 = TrueColor
	findings := sampleFindings()

	cases := []struct {
		name        string
		w, h        int
		setup       func(*Model)
		description string
	}{
		{"wide-default", 160, 40, nil, "two-pane layout, list focused"},
		{"wide-focused-detail", 160, 40, func(m *Model) { m.focus = focusDetail }, "two-pane, detail focused"},
		{"narrow-list", 80, 30, nil, "narrow list only"},
		{"narrow-drilldown", 80, 30, func(m *Model) { m.mode = detailMode; m.SetSize(80, 30) }, "narrow detail drilldown"},
		{"help-overlay", 160, 40, func(m *Model) { m.mode = helpMode }, "centered help overlay"},
	}
	for _, c := range cases {
		m := NewModel(findings).
			WithContext("AWS · 123456789012 (platform-prod) · eu-central-1").
			WithReportPath("/tmp/123456789012_audit_report.md")
		m.SetSize(c.w, c.h)
		if c.setup != nil {
			c.setup(&m)
		}
		fmt.Printf("\n=== %s (%dx%d) — %s ===\n", c.name, c.w, c.h, c.description)
		fmt.Println(m.View())
		fmt.Println()
	}
}

func sampleFindings() []auditcore.Finding {
	return []auditcore.Finding{
		{
			RuleID:      "LLM-claudecode-06577160",
			Title:       "IAM role inline policy grants Action:* / Resource:*",
			Severity:    auditcore.SeverityCritical,
			Service:     "iam",
			Resource:    "aws://eu-central-1/AWS::IAM::Role/cbx-audit-overprivileged",
			Description: "An inline policy attached to the role allows every action against every resource, defeating least-privilege.",
			Remediation: "Delete the wildcard inline policy. Re-author as a customer-managed policy scoped to the specific service(s) and resource ARNs the workload requires. Add a permission boundary so future drift cannot re-introduce wildcard grants.",
		},
		{
			RuleID:      "LLM-claudecode-cfb9ec63",
			Title:       "IAM role uses AdministratorAccess managed policy",
			Severity:    auditcore.SeverityCritical,
			Service:     "iam",
			Resource:    "aws://eu-central-1/AWS::IAM::Role/cbx-audit-lambda-admin",
			Description: "The role attaches the AWS-managed AdministratorAccess policy, granting unrestricted access to every AWS API.",
			Remediation: "Replace AdministratorAccess with a customer-managed least-privilege policy listing only the specific actions/resources the Lambda actually needs.",
		},
		{
			RuleID:      "LLM-claudecode-66b94ff5",
			Title:       "Lambda function executes with AdministratorAccess role",
			Severity:    auditcore.SeverityHigh,
			Service:     "lambda",
			Resource:    "aws://eu-central-1/AWS::Lambda::Function/cbx-audit-lambda",
			Description: "The Lambda runtime assumes a role with administrator-level privileges, expanding the blast radius of any code defect to the entire AWS account.",
			Remediation: "Re-bind the function to a least-privilege execution role that lists only the AWS APIs the handler invokes.",
		},
		{
			RuleID:      "LLM-claudecode-86651e0e",
			Title:       "EC2 instance allows IMDSv1 (HttpTokens optional)",
			Severity:    auditcore.SeverityHigh,
			Service:     "ec2",
			Resource:    "aws://eu-central-1/AWS::EC2::Instance/i-007ee3a2027c19191",
			Description: "Instance metadata service v1 is reachable without a session token, exposing the role credentials to SSRF.",
			Remediation: "Set metadata_http_tokens=required on the instance. The sibling instance i-09f22ec6781a3ac29 already requires IMDSv2 — mirror that configuration.",
		},
		{
			RuleID:      "LLM-claudecode-46f6d61f",
			Title:       "S3 bucket policy does not enforce HTTPS-only access",
			Severity:    auditcore.SeverityWarning,
			Service:     "s3",
			Resource:    "aws://eu-central-1/AWS::S3::Bucket/cbx-audit-plain-69667",
			Description: "Without an aws:SecureTransport deny, clients can downgrade requests to plain HTTP, leaking credentials in transit.",
			Remediation: "Attach a bucket policy with a Deny statement on s3:* for Condition Bool {aws:SecureTransport: false} (the tls-enforcement facet pattern).",
		},
		{
			RuleID:      "LLM-claudecode-ff01db00",
			Title:       "CloudWatch log group has no retention policy",
			Severity:    auditcore.SeverityWarning,
			Service:     "logs",
			Resource:    "aws://eu-central-1/AWS::Logs::LogGroup//cbx-audit-test/no-retention",
			Description: "Log groups with retention_in_days unset accumulate storage indefinitely.",
			Remediation: "Set retention_in_days explicitly. CB suggests 14 days for dev/MVP and 30–90 days for production.",
		},
		{
			RuleID:      "LLM-claudecode-65fd308d",
			Title:       "S3 bucket has no versioning enabled",
			Severity:    auditcore.SeverityInfo,
			Service:     "s3",
			Resource:    "aws://eu-central-1/AWS::S3::Bucket/cbx-audit-plain-69667",
			Description: "Versioning lets you recover from accidental deletes and overwrites; without it, a bad client wipes data irrecoverably.",
			Remediation: "If the bucket holds anything meant to survive accidents, enable the versioning facet (and consider MFA Delete for highly sensitive data).",
		},
	}
}
