package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// tfsecAdapter implements Scanner by invoking the tfsec binary.
// tfsec scans Terraform configuration files for security issues.
// Network access: denied by default (the binary works offline).
type tfsecAdapter struct{}

func (a *tfsecAdapter) Name() string { return "tfsec" }

// SupportsSource reports tfsec's source-mode capability. tfsec is a static
// analyzer over Terraform HCL, so source mode is its native input — we wire
// it on directly.
func (a *tfsecAdapter) SupportsSource() bool { return true }

// ScanSource invokes tfsec against the user's IaC directory directly,
// skipping the synthetic-temp-dir step that state mode needs. Output schema
// is identical, so parseTfsecOutput is reused verbatim.
func (a *tfsecAdapter) ScanSource(ctx context.Context, dir string) ([]Finding, error) {
	meta := scannerRegistry["tfsec"]
	if err := checkVersion(ctx, meta); err != nil {
		return nil, err
	}

	out, err := runScanner(ctx, meta.Name, []string{dir, "--format", "json", "--no-colour", "--soft-fail"}, meta.AllowAWS)
	if err != nil {
		return nil, fmt.Errorf("running tfsec: %w\noutput: %s", err, string(out))
	}

	return parseTfsecOutput(out)
}

func (a *tfsecAdapter) Scan(ctx context.Context, resources []Resource) ([]Finding, error) {
	meta := scannerRegistry["tfsec"]
	if err := checkVersion(ctx, meta); err != nil {
		return nil, err
	}

	dir, err := writeResourcesToTempDir(resources)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	out, err := runScanner(ctx, meta.Name, []string{dir, "--format", "json", "--no-colour", "--soft-fail"}, meta.AllowAWS)
	if err != nil {
		return nil, fmt.Errorf("running tfsec: %w\noutput: %s", err, string(out))
	}

	return parseTfsecOutput(out)
}

func parseTfsecOutput(data []byte) ([]Finding, error) {
	var doc struct {
		Results []struct {
			RuleID          string `json:"rule_id"`
			LongID          string `json:"long_id"`
			RuleDescription string `json:"rule_description"`
			RuleProvider    string `json:"rule_provider"`
			RuleService     string `json:"rule_service"`
			Impact          string `json:"impact"`
			Resolution      string `json:"resolution"`
			Description     string `json:"description"`
			Severity        string `json:"severity"`
			Resource        string `json:"resource"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing tfsec output: %w", err)
	}

	var findings []Finding
	for _, r := range doc.Results {
		desc := r.Description
		if desc == "" {
			desc = r.RuleDescription
		}
		rem := r.Resolution
		if rem == "" {
			rem = r.Impact
		}
		findings = append(findings, Finding{
			RuleID:      r.RuleID,
			Title:       r.LongID,
			Description: desc,
			Severity:    mapTfsecSeverity(r.Severity),
			Resource:    r.Resource,
			Service:     strings.ToUpper(r.RuleService),
			Remediation: rem,
		})
	}
	return findings, nil
}
