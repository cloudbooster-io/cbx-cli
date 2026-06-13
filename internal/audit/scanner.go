package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

// RunScanners executes all given scanners against the resources and
// returns a deduplicated slice of findings. Errors from individual
// scanners are collected and returned as a joined error; scanners that
// fail do not block findings from successful scanners.
// Deprecated: use RunProvidersWithProgress from the orchestrator instead.
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
// perform any outbound network calls or invoke external binaries. The
// orphan provider lands here because the `cbx audit aws` subcommand
// invokes the runner with MockScanners: true (plan §7.10 — no external
// CLI dependencies in AWS mode); the provider filters to CFN-shaped
// resource types internally so it stays a no-op for non-AWS modes.
//
// This set is also what an empty Options.Scanners resolves to — external
// scanners are opt-in by name (see selectProviders), upholding the
// zero-value-Options safety guarantee documented on Options.
func MockScanners() []FindingProvider {
	return []FindingProvider{
		&staticScanner{},
		&orphanProvider{},
	}
}

// AllScanners returns every available scanner including external-tool
// adapters. Callers should be prepared for individual adapters to fail
// when their underlying binary is not installed. Never selected
// implicitly: Options resolution maps an empty Scanners list to
// MockScanners, so the external adapters run only when named explicitly.
func AllScanners() []Scanner {
	return []Scanner{
		&staticScanner{},
		&orphanProvider{},
		&tfsecAdapter{},
		&checkovAdapter{},
		&prowlerAdapter{},
		&trivyAdapter{},
	}
}

// staticScanner implements FindingProvider with hard-coded rules that mirror
// the checks originally in pkg/cmd/audit.go.
type staticScanner struct{}

func (s *staticScanner) Name() string { return "static" }

func (s *staticScanner) Scan(_ context.Context, resources []Resource) ([]Finding, error) {
	var findings []Finding
	for _, res := range resources {
		findings = append(findings, evaluateResource(res)...)
	}
	return findings, nil
}

func (s *staticScanner) SupportsSource() bool { return true }

// ScanSource produces real CB findings against the source tree when an HCL
// parser is available for the detected IaC flavor (Terraform today), and
// falls back to the historical mock-by-directory-name set otherwise. The
// mock fallback keeps `cbx audit --source ./anything` working with no
// external dependencies on directories that aren't Terraform yet (CFN,
// K8s, Helm — Phase 4b/c/d in the design doc).
func (s *staticScanner) ScanSource(_ context.Context, dir string) ([]Finding, error) {
	if dir == "" {
		return nil, nil
	}

	if findings := scanTerraformSourceIfPossible(dir); findings != nil {
		return findings, nil
	}

	base := filepath.Base(dir)
	if base == "." || base == "/" || base == "" {
		base = "source"
	}

	// A 0..2 derived deterministically from the directory base name picks
	// which of the canonical mock findings get emitted, so test fixtures
	// can rely on a stable shape without coupling to a single hard-coded set.
	sum := sha256.Sum256([]byte(base))
	n := int(binary.BigEndian.Uint16(sum[:2]) % 3)

	resource := strings.ToLower(base) + "/main.tf"
	pool := []Finding{
		{
			RuleID:      "MOCK-SRC-001",
			Title:       "S3 bucket declared without server-side encryption",
			Description: "A bucket resource in the source tree does not configure SSE.",
			Severity:    SeverityHigh,
			Resource:    resource,
			Service:     "S3",
			Remediation: "Add an aws_s3_bucket_server_side_encryption_configuration resource.",
			File:        resource,
			Line:        1,
		},
		{
			RuleID:      "MOCK-SRC-002",
			Title:       "Security group permits 0.0.0.0/0 ingress",
			Description: "A security group rule in the source tree allows ingress from anywhere.",
			Severity:    SeverityWarning,
			Resource:    resource,
			Service:     "EC2",
			Remediation: "Restrict cidr_blocks to specific networks.",
			File:        resource,
			Line:        2,
		},
		{
			RuleID:      "MOCK-SRC-003",
			Title:       "IAM role trust policy is overly permissive",
			Description: "A trust policy in the source tree allows broad principal access.",
			Severity:    SeverityInfo,
			Resource:    resource,
			Service:     "IAM",
			Remediation: "Scope the principal to specific roles or services.",
			File:        resource,
			Line:        3,
		},
	}

	// Always return at least one finding so the source-mode happy path is
	// observable, but vary the count between 1 and 3 across directory names.
	return pool[:n+1], nil
}

// scanTerraformSourceIfPossible runs the HCL T1 parser over dir and
// evaluates each parsed resource through the same rule table the state
// scanner uses. Returns nil (signalling "fall back to mock") when no *.tf
// file is found under dir; returns a non-nil (possibly empty) slice
// otherwise to distinguish "terraform parsed, zero findings" from "no
// terraform here at all."
func scanTerraformSourceIfPossible(dir string) []Finding {
	if !hasTerraformFile(dir) {
		return nil
	}
	resources, _ := parsers.ParseTerraformSource(dir) // diagnostics non-fatal
	findings := []Finding{}
	for _, r := range resources {
		findings = append(findings, evaluateResource(r)...)
	}
	return findings
}

// hasTerraformFile is a cheap "is this a Terraform tree?" pre-check so
// CFN/K8s/Helm directories don't pay the parser cost. Mirrors the parser's
// own walk filter and .git/.terraform/node_modules skips.
func hasTerraformFile(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, _ error) error {
		if d == nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != dir && (name == ".git" || name == ".terraform" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(d.Name())
		if strings.HasSuffix(lower, ".tf") || strings.HasSuffix(lower, ".tf.json") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
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
