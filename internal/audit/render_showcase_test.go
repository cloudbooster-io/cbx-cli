package audit

import (
	"fmt"
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// TestRenderPlainShowcase is the design-loop fixture: it builds the 13
// findings from the user's actual `cbx audit aws --region eu-central-1`
// run and prints the rendered output. Skipped unless CBX_SHOWCASE=1 is
// set so it doesn't run in regular CI. Invoke with:
//
//	CBX_SHOWCASE=1 go test -v -run Showcase ./internal/audit | less -R
//
// The "less -R" pass keeps ANSI styling visible.
func TestRenderPlainShowcase(t *testing.T) {
	if os.Getenv("CBX_SHOWCASE") == "" {
		t.Skip("set CBX_SHOWCASE=1 to print the audit showcase rendering")
	}

	// Force styled output on regardless of TTY detection — we want to
	// see the chips when the test output is piped to less.
	prev := os.Getenv("NO_COLOR")
	_ = os.Unsetenv("NO_COLOR")
	defer os.Setenv("NO_COLOR", prev)

	// Pretend we're on a TTY so the chips, borders, and OSC-8 links
	// render the way the user actually sees them.
	output.ForceStyledForTesting()
	output.ResetAdvisories()
	output.AdviseTitle("legacy-config-dir",
		"using legacy config dir ~/.cbx")
	output.Advise(output.Advisory{
		Code:  "legacy-config-dir-hint",
		Title: "future cbx releases will look in ~/.config/cbx (XDG)",
		Hint:  "mv ~/.cbx ~/.config/cbx",
	})
	output.Advise(output.Advisory{
		Code:  "discovery-warnings",
		Title: "2 non-fatal warnings during discovery",
		Hint:  "cbx audit aws --diagnose",
	})

	findings := []Finding{
		{
			RuleID:      "LLM-claudecode-969e4f76",
			Title:       "IAM role attached to AdministratorAccess managed policy",
			Severity:    SeverityCritical,
			Resource:    "aws://eu-central-1/AWS::IAM::Role/cbx-audit-lambda-admin",
			Service:     "iam",
			Remediation: "Detach AdministratorAccess and replace with a customer-managed policy scoped to the specific services, actions, and resource ARNs the Lambda actually needs. Use IAM Access Analyzer to derive a least-privilege policy from observed activity.",
		},
		{
			RuleID:      "LLM-claudecode-b67ba560",
			Title:       "Lambda function uses an Administrator-equivalent execution role",
			Severity:    SeverityCritical,
			Resource:    "aws://eu-central-1/AWS::Lambda::Function/cbx-audit-lambda",
			Service:     "lambda",
			Remediation: "Replace the execution role with one bound to a least-privilege customer-managed policy covering only the AWS APIs this function calls. Audit with IAM Access Analyzer to derive minimum permissions.",
		},
		{
			RuleID:      "LLM-claudecode-bd7c49d1",
			Title:       "RDS Postgres instance is publicly accessible",
			Severity:    SeverityCritical,
			Resource:    "aws://eu-central-1/AWS::RDS::DBInstance/cbx-audit-pg",
			Service:     "rds",
			Remediation: "Set PubliclyAccessible=false, move the DB into private subnets, and restrict inbound on 5432 to the application security group only.",
		},
		{
			RuleID:      "LLM-claudecode-14e34cd8",
			Title:       "RDS Postgres instance has automated backups disabled",
			Severity:    SeverityHigh,
			Resource:    "aws://eu-central-1/AWS::RDS::DBInstance/cbx-audit-pg",
			Service:     "rds",
			Remediation: "Set BackupRetentionPeriod to at least 7 days (14+ for production) and configure a backup window outside peak write IOPS.",
		},
		{
			RuleID:      "LLM-claudecode-318306f3",
			Title:       "EC2 instance allows IMDSv1 (metadata_http_tokens not required)",
			Severity:    SeverityHigh,
			Resource:    "aws://eu-central-1/AWS::EC2::Instance/i-007ee3a2027c19191",
			Service:     "ec2",
			Remediation: "Modify instance metadata options to set HttpTokens=required (IMDSv2 only). Set the account-level default for HttpTokens to required so all future launches inherit this posture.",
		},
		{
			RuleID:      "LLM-claudecode-508d53da",
			Title:       "RDS Postgres instance has storage encryption disabled",
			Severity:    SeverityHigh,
			Resource:    "aws://eu-central-1/AWS::RDS::DBInstance/cbx-audit-pg",
			Service:     "rds",
			Remediation: "Snapshot the instance, copy the snapshot with encryption enabled (AWS-managed or customer-managed KMS key), and restore a new encrypted instance from the encrypted snapshot. Cut over and retire the unencrypted instance.",
		},
		{
			RuleID:      "LLM-claudecode-8f891a4e",
			Title:       "S3 bucket has all Block Public Access flags disabled",
			Severity:    SeverityHigh,
			Resource:    "aws://eu-central-1/AWS::S3::Bucket/cbx-audit-public-69667",
			Service:     "s3",
			Remediation: "Apply the aws:s3/public-access-block@v1 facet with block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets all set to true. If public web delivery is required, front the bucket with CloudFront using Origin Access Control instead of a public bucket policy.",
		},
		{
			RuleID:      "LLM-claudecode-5ad42c03",
			Title:       "S3 bucket has versioning disabled",
			Severity:    SeverityWarning,
			Resource:    "aws://eu-central-1/AWS::S3::Bucket/cbx-audit-plain-69667",
			Service:     "s3",
			Remediation: "Attach the aws:s3/versioning@v1 facet to enable object versioning on the bucket.",
		},
		{
			RuleID:      "LLM-claudecode-5ad42c03",
			Title:       "S3 bucket has versioning disabled",
			Severity:    SeverityWarning,
			Resource:    "aws://eu-central-1/AWS::S3::Bucket/cbx-audit-public-69667",
			Service:     "s3",
			Remediation: "Attach the aws:s3/versioning@v1 facet to enable object versioning on the bucket.",
		},
		{
			RuleID:      "LLM-claudecode-794d4736",
			Title:       "RDS Postgres instance has deletion protection disabled",
			Severity:    SeverityWarning,
			Resource:    "aws://eu-central-1/AWS::RDS::DBInstance/cbx-audit-pg",
			Service:     "rds",
			Remediation: "Enable DeletionProtection on the DB instance.",
		},
		{
			RuleID:      "LLM-claudecode-88a2e70a",
			Title:       "EC2 instance has no IAM instance profile attached",
			Severity:    SeverityWarning,
			Resource:    "aws://eu-central-1/AWS::EC2::Instance/i-007ee3a2027c19191",
			Service:     "ec2",
			Remediation: "Create an IAM role with a least-privilege policy scoped to the workload, wrap it in an instance profile, and attach it to the instance.",
		},
		{
			RuleID:      "LLM-claudecode-88a2e70a",
			Title:       "EC2 instance has no IAM instance profile attached",
			Severity:    SeverityWarning,
			Resource:    "aws://eu-central-1/AWS::EC2::Instance/i-09f22ec6781a3ac29",
			Service:     "ec2",
			Remediation: "Create an IAM role with a least-privilege policy scoped to the workload, wrap it in an instance profile, and attach it to the instance.",
		},
		{
			RuleID:      "LLM-claudecode-bade863f",
			Title:       "RDS Postgres instance runs single-AZ",
			Severity:    SeverityWarning,
			Resource:    "aws://eu-central-1/AWS::RDS::DBInstance/cbx-audit-pg",
			Service:     "rds",
			Remediation: "Enable Multi-AZ on the instance and set client DNS TTL below 30s so applications re-resolve the endpoint after failover.",
		},
	}

	// Render the header card (the bit currently emitted directly from
	// pkg/cmd/audit_aws.go). Showcasing it here makes the design loop
	// faster — we see the whole composition in one place.
	header := output.Card{
		Label: output.Chip("AWS", lipgloss.Color("231"), lipgloss.Color("236")),
		Title: "audit · 123456789012",
		Rows: []output.CardRow{
			{Key: "identity", Value: "…/AWSReservedSSO_AdministratorAccess_…/jane.doe"},
			{Key: "regions", Value: "eu-central-1"},
			{Key: "resources", Value: "33"},
			{Key: "components", Value: "31  " + output.Dim.Render("(1 tag · 30 cb-primitive)")},
			{Key: "CloudTrail", Value: output.Dim.Render("~84 Read events generated by this run")},
		},
		Footer: "audited with cbx — Apache-2.0 · grounded in CloudBooster knowledge",
	}
	fmt.Println(header.Render())

	fmt.Print(RenderPlain(findings, "aws://123456789012"))

	// Empty-case showcase: prove the no-findings render is also pretty.
	fmt.Println()
	fmt.Println("--- empty-findings case ---")
	fmt.Println()
	output.ResetAdvisories()
	fmt.Print(RenderPlain([]Finding{}, "aws://123456789012"))
}
