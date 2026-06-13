package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// checkovAdapter implements Scanner by invoking the checkov binary.
// checkov scans IaC files for security and compliance issues.
// Network access: denied by default (the binary works offline with
// its built-in policies; external APIs are optional).
type checkovAdapter struct{}

func (a *checkovAdapter) Name() string { return "checkov" }

// SupportsSource reports checkov's source-mode capability. checkov scans
// IaC source trees natively, so source mode is its primary input shape.
func (a *checkovAdapter) SupportsSource() bool { return true }

// ScanSource invokes checkov against the user's IaC directory directly,
// using its native -d (directory) input mode rather than the synthesized
// state file used in state mode. parseCheckovOutput is reused unchanged.
func (a *checkovAdapter) ScanSource(ctx context.Context, dir string) ([]Finding, error) {
	meta := scannerRegistry["checkov"]
	if err := checkVersion(ctx, meta); err != nil {
		return nil, err
	}

	// --soft-fail keeps checkov's exit code at 0 when it discovers
	// violations. Without it, runScanner sees the non-zero exit, treats
	// it as an exec failure, and the JSON envelope never reaches the
	// parser — even though the run was successful from our perspective.
	// tfsec uses the same flag for the same reason.
	out, err := runScanner(ctx, meta.Name, []string{"-d", dir, "--output", "json", "--compact", "--quiet", "--soft-fail"}, meta.AllowAWS)
	if err != nil {
		return nil, fmt.Errorf("running checkov: %w\noutput: %s", err, string(out))
	}

	return parseCheckovOutput(out)
}

func (a *checkovAdapter) Scan(ctx context.Context, resources []Resource) ([]Finding, error) {
	meta := scannerRegistry["checkov"]
	if err := checkVersion(ctx, meta); err != nil {
		return nil, err
	}

	statePath, err := writeTerraformStateFile(resources)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(filepath.Dir(statePath)) }()

	out, err := runScanner(ctx, meta.Name, []string{"-f", statePath, "--output", "json", "--compact", "--quiet", "--soft-fail"}, meta.AllowAWS)
	if err != nil {
		return nil, fmt.Errorf("running checkov: %w\noutput: %s", err, string(out))
	}

	return parseCheckovOutput(out)
}

func parseCheckovOutput(data []byte) ([]Finding, error) {
	var doc struct {
		CheckType string `json:"check_type"`
		Results   struct {
			FailedChecks []struct {
				CheckID   string   `json:"check_id"`
				CheckName string   `json:"check_name"`
				Resource  string   `json:"resource"`
				FilePath  string   `json:"file_path"`
				Severity  string   `json:"severity"`
				Guideline string   `json:"guideline"`
				CodeBlock []string `json:"code_block"`
			} `json:"failed_checks"`
		} `json:"results"`
		Summary struct {
			Passed int `json:"passed"`
			Failed int `json:"failed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing checkov output: %w", err)
	}

	var findings []Finding
	for _, c := range doc.Results.FailedChecks {
		sev := strings.ToLower(c.Severity)
		if sev == "" {
			sev = "medium"
		}
		rem := "See " + c.CheckID + " documentation for remediation steps."
		if c.Guideline != "" {
			rem = c.Guideline
		}
		findings = append(findings, Finding{
			RuleID:      c.CheckID,
			Title:       c.CheckName,
			Description: c.CheckName,
			Severity:    mapCheckovSeverity(sev),
			Resource:    c.Resource,
			Service:     inferServiceFromCheckID(c.CheckID),
			Remediation: rem,
		})
	}
	return findings, nil
}

// inferServiceFromCheckID extracts a service name from a Checkov check
// ID like "CKV_AWS_19" → "AWS".
func inferServiceFromCheckID(id string) string {
	parts := strings.Split(id, "_")
	if len(parts) >= 2 {
		return strings.ToUpper(parts[1])
	}
	return ""
}
