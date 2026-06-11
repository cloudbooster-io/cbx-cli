package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// prowlerAdapter implements Scanner by invoking the prowler binary.
// prowler scans live AWS infrastructure for security issues.
// Network access: allowed (prowler requires AWS API access).
// AWS_* environment variables are passed through to the subprocess.
type prowlerAdapter struct{}

func (a *prowlerAdapter) Name() string { return "prowler" }

// SupportsSource is permanently false for prowler: it scans live AWS, not
// IaC source files.
func (a *prowlerAdapter) SupportsSource() bool { return false }

// ScanSource is unsupported by design — prowler audits running cloud
// resources, not declared IaC. See plan §4.5.
func (a *prowlerAdapter) ScanSource(_ context.Context, _ string) ([]Finding, error) {
	return nil, ErrSourceModeUnsupported
}

func (a *prowlerAdapter) Scan(ctx context.Context, resources []Resource) ([]Finding, error) {
	meta := scannerRegistry["prowler"]
	if err := checkVersion(ctx, meta); err != nil {
		return nil, err
	}

	outDir, err := os.MkdirTemp("", "cbx-prowler-*")
	if err != nil {
		return nil, fmt.Errorf("creating prowler output dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(outDir) }()

	// Prowler writes JSON output to a file in the output directory. It may
	// exit non-zero even on a successful scan, so a run error alone is not
	// fatal — the missing JSON file below is. Context cancellation is the
	// exception: the subprocess was killed, so no output can be expected.
	if _, err := runScanner(ctx, meta.Name, []string{"--output-mode", "json", "--output-directory", outDir, "--status", "FAIL"}, meta.AllowAWS); err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("running prowler: %w", err)
	}

	// Find the JSON output file prowler created.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return nil, fmt.Errorf("reading prowler output dir: %w", err)
	}
	var jsonFile string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			jsonFile = filepath.Join(outDir, entry.Name())
			break
		}
	}
	if jsonFile == "" {
		return nil, fmt.Errorf("prowler did not produce JSON output in %s", outDir)
	}

	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("reading prowler output: %w", err)
	}

	return parseProwlerOutput(data)
}

func parseProwlerOutput(data []byte) ([]Finding, error) {
	var rawFindings []struct {
		AssessmentStartTime string `json:"AssessmentStartTime"`
		FindingUniqueId     string `json:"FindingUniqueId"`
		Provider            string `json:"Provider"`
		CheckID             string `json:"CheckID"`
		CheckTitle          string `json:"CheckTitle"`
		ServiceName         string `json:"ServiceName"`
		Status              string `json:"Status"`
		StatusExtended      string `json:"StatusExtended"`
		Severity            string `json:"Severity"`
		ResourceId          string `json:"ResourceId"`
		ResourceArn         string `json:"ResourceArn"`
		Region              string `json:"Region"`
	}
	if err := json.Unmarshal(data, &rawFindings); err != nil {
		return nil, fmt.Errorf("parsing prowler output: %w", err)
	}

	var findings []Finding
	for _, f := range rawFindings {
		if f.Status != "FAIL" {
			continue
		}
		res := f.ResourceId
		if res == "" {
			res = f.ResourceArn
		}
		findings = append(findings, Finding{
			RuleID:      f.CheckID,
			Title:       f.CheckTitle,
			Description: f.StatusExtended,
			Severity:    mapProwlerSeverity(f.Severity),
			Resource:    res,
			Service:     strings.ToUpper(f.ServiceName),
			Remediation: "Review " + f.CheckID + " in Prowler documentation.",
		})
	}
	return findings, nil
}
