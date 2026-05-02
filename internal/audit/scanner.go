package audit

import (
	"context"
	"errors"
	"fmt"
)

// RunScanners executes all given scanners against the resources and
// returns a deduplicated slice of findings. Errors from individual
// scanners are collected and returned as a joined error; scanners that
// fail do not block findings from successful scanners.
// Deprecated: use RunProviders from the orchestrator instead.
func RunScanners(scanners []Scanner, resources []Resource) ([]Finding, error) {
	seen := make(map[string]struct{})
	var findings []Finding
	var errs []error
	for _, s := range scanners {
		res, err := s.Scan(context.Background(), resources)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
			continue
		}
		for _, f := range res {
			key := f.RuleID + "|" + f.Resource
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}
	return findings, errors.Join(errs...)
}

// MockScanners returns a set of scanner implementations that do not
// perform any outbound network calls or invoke external binaries.
func MockScanners() []FindingProvider {
	return []FindingProvider{
		&staticScanner{},
	}
}

// AllScanners returns every available scanner including external-tool
// adapters. Callers should be prepared for individual adapters to fail
// when their underlying binary is not installed.
func AllScanners() []Scanner {
	return []Scanner{
		&staticScanner{},
		&tfsecAdapter{},
		&checkovAdapter{},
		&prowlerAdapter{},
		&trivyAdapter{},
	}
}

// staticScanner implements FindingProvider with hard-coded rules that mirror
// the checks originally in cmd/cbx/audit.go.
type staticScanner struct{}

func (s *staticScanner) Name() string { return "static" }

func (s *staticScanner) Scan(_ context.Context, resources []Resource) ([]Finding, error) {
	var findings []Finding
	for _, res := range resources {
		findings = append(findings, evaluateResource(res)...)
	}
	return findings, nil
}

func evaluateResource(res DiscoveredResource) []Finding {
	var findings []Finding
	resType := res.Type
	resURN := res.URN
	if resURN == "" {
		resURN = res.ID
	}
	if resURN == "" {
		resURN = "unknown"
	}

	switch resType {
	case "aws:s3/bucket:Bucket", "aws_s3_bucket":
		findings = append(findings, Finding{
			RuleID:      "S3-001",
			Title:       "S3 bucket versioning not enabled",
			Description: "The S3 bucket does not have versioning enabled, which prevents recovery from accidental deletion or overwrites.",
			Severity:    SeverityWarning,
			Resource:    resURN,
			Service:     "S3",
			Remediation: "Enable versioning on the S3 bucket.",
		})
		findings = append(findings, Finding{
			RuleID:      "S3-002",
			Title:       "S3 bucket encryption not configured",
			Description: "The S3 bucket lacks server-side encryption configuration.",
			Severity:    SeverityHigh,
			Resource:    resURN,
			Service:     "S3",
			Remediation: "Enable SSE-S3 or SSE-KMS encryption on the bucket.",
		})
	case "aws:ec2/securityGroup:SecurityGroup", "aws_security_group":
		findings = append(findings, Finding{
			RuleID:      "EC2-001",
			Title:       "Security group allows unrestricted ingress",
			Description: "A security group rule allows ingress from 0.0.0.0/0 on a sensitive port.",
			Severity:    SeverityHigh,
			Resource:    resURN,
			Service:     "EC2",
			Remediation: "Restrict security group ingress to specific CIDR blocks.",
		})
	case "aws:iam/role:Role", "aws_iam_role":
		findings = append(findings, Finding{
			RuleID:      "IAM-001",
			Title:       "IAM role has overly permissive trust policy",
			Description: "The IAM role trust policy allows broad principal access.",
			Severity:    SeverityWarning,
			Resource:    resURN,
			Service:     "IAM",
			Remediation: "Scope the trust policy principal to specific roles or services.",
		})
	case "aws:rds/instance:Instance", "aws_db_instance":
		findings = append(findings, Finding{
			RuleID:      "RDS-001",
			Title:       "RDS instance not in a VPC",
			Description: "The RDS instance is not deployed inside a VPC.",
			Severity:    SeverityHigh,
			Resource:    resURN,
			Service:     "RDS",
			Remediation: "Migrate the RDS instance into a VPC with private subnets.",
		})
	case "aws:lambda/function:Function", "aws_lambda_function":
		findings = append(findings, Finding{
			RuleID:      "LAMBDA-001",
			Title:       "Lambda function environment variables may contain secrets",
			Description: "Environment variables on Lambda functions are visible in plain text.",
			Severity:    SeverityInfo,
			Resource:    resURN,
			Service:     "Lambda",
			Remediation: "Use AWS Secrets Manager or Parameter Store for sensitive values.",
		})
	}

	return findings
}
