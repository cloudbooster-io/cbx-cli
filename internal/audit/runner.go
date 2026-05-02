package audit

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Result holds the outcome of an audit run.
type Result struct {
	Findings   []Finding
	ReportPath string
}

// Run executes the full audit pipeline for the given state file.
func Run(opts Options) (*Result, error) {
	resources, err := ParseState(opts.StateFile)
	if err != nil {
		return nil, err
	}

	var scanners []Scanner
	if opts.MockScanners {
		scanners = MockScanners()
	} else {
		// Production path: in a future iteration this would load real
		// prowler / trivy / checkov / tfsec adapters. For now we keep
		// the same zero-network behaviour by defaulting to mocks.
		scanners = MockScanners()
	}

	findings := RunScanners(scanners, resources)

	reportPath := opts.ReportFile
	if reportPath == "" {
		base := strings.TrimSuffix(filepath.Base(opts.StateFile), filepath.Ext(opts.StateFile))
		reportPath = base + "_audit_report.md"
	}

	if err := WriteMarkdownReport(reportPath, findings); err != nil {
		return nil, fmt.Errorf("writing report: %w", err)
	}

	return &Result{
		Findings:   findings,
		ReportPath: reportPath,
	}, nil
}
