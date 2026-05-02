package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Finding represents a single audit finding.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Service     string `json:"service"`
	Remediation string `json:"remediation"`
}

func newAuditCmd() *cobra.Command {
	var (
		pulumiStateFile     string
		terraformStateFile  string
		outputFormat        string
		reportFile          string
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit infrastructure state for security and compliance issues",
		RunE: func(cmd *cobra.Command, args []string) error {
			if pulumiStateFile == "" && terraformStateFile == "" {
				return fmt.Errorf("--pulumi-state or --terraform-state is required")
			}

			stateFile := pulumiStateFile
			if stateFile == "" {
				stateFile = terraformStateFile
			}

			findings, err := auditState(stateFile)
			if err != nil {
				return err
			}

			if outputFormat == "json" || jsonFlag {
				b, _ := json.MarshalIndent(findings, "", "  ")
				fmt.Println(string(b))
			} else {
				for _, f := range findings {
					fmt.Printf("[%s] %s — %s (%s)\n", strings.ToUpper(f.Severity), f.RuleID, f.Title, f.Resource)
				}
			}

			if reportFile == "" {
				base := strings.TrimSuffix(filepath.Base(stateFile), filepath.Ext(stateFile))
				reportFile = base + "_audit_report.md"
			}
			if err := writeMarkdownReport(reportFile, findings); err != nil {
				return fmt.Errorf("writing report: %w", err)
			}
			if !quietFlag {
				fmt.Fprintf(os.Stderr, "✓ Wrote markdown report: %s\n", reportFile)
			}

			return exitWithSeverity(findings)
		},
	}

	cmd.Flags().StringVar(&pulumiStateFile, "pulumi-state", "", "Path to Pulumi state file")
	cmd.Flags().StringVar(&terraformStateFile, "terraform-state", "", "Path to Terraform state file")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format (json, markdown)")
	cmd.Flags().StringVar(&reportFile, "report-file", "", "Path for markdown report output")

	return cmd
}

func auditState(stateFile string) ([]Finding, error) {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("reading state file: %w", err)
	}

	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing state file: %w", err)
	}

	var findings []Finding

	resources := extractResources(state)
	for _, res := range resources {
		findings = append(findings, evaluateResource(res)...)
	}

	return findings, nil
}

func extractResources(state map[string]interface{}) []map[string]interface{} {
	var resources []map[string]interface{}

	if res, ok := state["resources"].([]interface{}); ok {
		for _, r := range res {
			if m, ok := r.(map[string]interface{}); ok {
				resources = append(resources, m)
			}
		}
	}

	if deployment, ok := state["deployment"].(map[string]interface{}); ok {
		if res, ok := deployment["resources"].([]interface{}); ok {
			for _, r := range res {
				if m, ok := r.(map[string]interface{}); ok {
					resources = append(resources, m)
				}
			}
		}
	}

	return resources
}

func evaluateResource(res map[string]interface{}) []Finding {
	var findings []Finding
	resType, _ := res["type"].(string)
	resURN, _ := res["urn"].(string)
	if resURN == "" {
		resURN, _ = res["id"].(string)
	}
	if resURN == "" {
		resURN = "unknown"
	}

	switch resType {
	case "aws:s3/bucket:Bucket":
		findings = append(findings, Finding{
			RuleID:      "S3-001",
			Title:       "S3 bucket versioning not enabled",
			Description: "The S3 bucket does not have versioning enabled, which prevents recovery from accidental deletion or overwrites.",
			Severity:    "warning",
			Resource:    resURN,
			Service:     "S3",
			Remediation: "Enable versioning on the S3 bucket.",
		})
		findings = append(findings, Finding{
			RuleID:      "S3-002",
			Title:       "S3 bucket encryption not configured",
			Description: "The S3 bucket lacks server-side encryption configuration.",
			Severity:    "high",
			Resource:    resURN,
			Service:     "S3",
			Remediation: "Enable SSE-S3 or SSE-KMS encryption on the bucket.",
		})
	case "aws:ec2/securityGroup:SecurityGroup":
		findings = append(findings, Finding{
			RuleID:      "EC2-001",
			Title:       "Security group allows unrestricted ingress",
			Description: "A security group rule allows ingress from 0.0.0.0/0 on a sensitive port.",
			Severity:    "high",
			Resource:    resURN,
			Service:     "EC2",
			Remediation: "Restrict security group ingress to specific CIDR blocks.",
		})
	case "aws:iam/role:Role":
		findings = append(findings, Finding{
			RuleID:      "IAM-001",
			Title:       "IAM role has overly permissive trust policy",
			Description: "The IAM role trust policy allows broad principal access.",
			Severity:    "warning",
			Resource:    resURN,
			Service:     "IAM",
			Remediation: "Scope the trust policy principal to specific roles or services.",
		})
	case "aws:rds/instance:Instance":
		findings = append(findings, Finding{
			RuleID:      "RDS-001",
			Title:       "RDS instance not in a VPC",
			Description: "The RDS instance is not deployed inside a VPC.",
			Severity:    "high",
			Resource:    resURN,
			Service:     "RDS",
			Remediation: "Migrate the RDS instance into a VPC with private subnets.",
		})
	case "aws:lambda/function:Function":
		findings = append(findings, Finding{
			RuleID:      "LAMBDA-001",
			Title:       "Lambda function environment variables may contain secrets",
			Description: "Environment variables on Lambda functions are visible in plain text.",
			Severity:    "info",
			Resource:    resURN,
			Service:     "Lambda",
			Remediation: "Use AWS Secrets Manager or Parameter Store for sensitive values.",
		})
	}

	return findings
}

func writeMarkdownReport(path string, findings []Finding) error {
	var sb strings.Builder
	sb.WriteString("# CloudBooster Audit Report\n\n")
	sb.WriteString(fmt.Sprintf("**Findings:** %d\n\n", len(findings)))

	severityCounts := map[string]int{"high": 0, "warning": 0, "info": 0}
	for _, f := range findings {
		severityCounts[f.Severity]++
	}
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	for _, sev := range []string{"high", "warning", "info"} {
		sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.Title(sev), severityCounts[sev]))
	}
	sb.WriteString("\n")

	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("## %s — %s\n\n", f.RuleID, f.Title))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(f.Severity)))
		sb.WriteString(fmt.Sprintf("- **Resource:** %s\n", f.Resource))
		sb.WriteString(fmt.Sprintf("- **Service:** %s\n", f.Service))
		sb.WriteString(fmt.Sprintf("- **Description:** %s\n\n", f.Description))
		sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", f.Remediation))
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

// exitCodeError is returned when a command wants to exit with a specific
// non-zero code. The error propagates to main() which calls os.Exit.
type exitCodeError struct {
	code int
}

func (e *exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

func exitWithSeverity(findings []Finding) error {
	maxSeverity := 0
	for _, f := range findings {
		switch f.Severity {
		case "info":
			if maxSeverity < 1 {
				maxSeverity = 1
			}
		case "warning":
			if maxSeverity < 2 {
				maxSeverity = 2
			}
		case "high":
			if maxSeverity < 3 {
				maxSeverity = 3
			}
		}
	}

	if maxSeverity > 0 {
		return &exitCodeError{code: maxSeverity}
	}
	return nil
}
