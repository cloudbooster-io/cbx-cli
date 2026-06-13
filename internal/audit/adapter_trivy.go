package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// trivyAdapter implements Scanner by invoking the trivy binary.
// trivy scans configuration files for security issues.
// Network access: allowed (trivy may download vulnerability DBs).
type trivyAdapter struct{}

func (a *trivyAdapter) Name() string { return "trivy" }

// SupportsSource reports trivy's source-mode capability. `trivy config`
// scans IaC trees natively (the same surface state mode points at, but
// without the synthetic .tf.json shim).
func (a *trivyAdapter) SupportsSource() bool { return true }

// ScanSource invokes `trivy config` against the user's IaC directory
// directly. parseTrivyOutput is reused unchanged.
func (a *trivyAdapter) ScanSource(ctx context.Context, dir string) ([]Finding, error) {
	meta := scannerRegistry["trivy"]
	if err := checkVersion(ctx, meta); err != nil {
		return nil, err
	}

	out, err := runScanner(ctx, meta.Name, []string{"config", dir, "--format", "json", "--severity", "LOW,MEDIUM,HIGH,CRITICAL", "--exit-code", "0"}, meta.AllowAWS)
	if err != nil {
		return nil, fmt.Errorf("running trivy: %w\noutput: %s", err, string(out))
	}

	return parseTrivyOutput(out)
}

func (a *trivyAdapter) Scan(ctx context.Context, resources []Resource) ([]Finding, error) {
	meta := scannerRegistry["trivy"]
	if err := checkVersion(ctx, meta); err != nil {
		return nil, err
	}

	dir, err := writeResourcesToTempDir(resources)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	out, err := runScanner(ctx, meta.Name, []string{"config", dir, "--format", "json", "--severity", "LOW,MEDIUM,HIGH,CRITICAL", "--exit-code", "0"}, meta.AllowAWS)
	if err != nil {
		return nil, fmt.Errorf("running trivy: %w\noutput: %s", err, string(out))
	}

	return parseTrivyOutput(out)
}

func parseTrivyOutput(data []byte) ([]Finding, error) {
	var doc struct {
		SchemaVersion int `json:"SchemaVersion"`
		Results       []struct {
			Target            string `json:"Target"`
			Class             string `json:"Class"`
			Type              string `json:"Type"`
			Misconfigurations []struct {
				Type        string `json:"Type"`
				ID          string `json:"ID"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
				Message     string `json:"Message"`
				Resolution  string `json:"Resolution"`
				Severity    string `json:"Severity"`
				PrimaryURL  string `json:"PrimaryURL"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}

	var findings []Finding
	for _, r := range doc.Results {
		for _, m := range r.Misconfigurations {
			desc := m.Description
			if desc == "" {
				desc = m.Message
			}
			rem := m.Resolution
			if rem == "" && m.PrimaryURL != "" {
				rem = "See " + m.PrimaryURL
			}
			findings = append(findings, Finding{
				RuleID:      m.ID,
				Title:       m.Title,
				Description: desc,
				Severity:    mapTrivySeverity(m.Severity),
				Resource:    r.Target,
				Service:     inferServiceFromTrivyID(m.ID),
				Remediation: rem,
			})
		}
	}
	return findings, nil
}

// inferServiceFromTrivyID extracts a service name from a Trivy check ID
// like "AVD-AWS-0089" → "AWS".
func inferServiceFromTrivyID(id string) string {
	parts := strings.Split(id, "-")
	if len(parts) >= 2 {
		return strings.ToUpper(parts[1])
	}
	return ""
}
