package audit

import (
	"context"
	"fmt"
	"os"
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
	resources, err := ParseState(opts)
	if err != nil {
		return nil, err
	}

	var providers []FindingProvider
	if opts.MockScanners {
		providers = MockScanners()
	} else {
		// Production path: in a future iteration this would load real
		// prowler / trivy / checkov / tfsec adapters. For now we keep
		// the same zero-network behaviour by defaulting to mocks.
		providers = MockScanners()
	}

	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	findings := RunProviders(ctx, providers, resources, opts.TimeoutPerScanner)

	reportPath := opts.ReportFile
	if reportPath == "" {
		base := strings.TrimSuffix(filepath.Base(opts.StateFile), filepath.Ext(opts.StateFile))
		reportPath = base + "_audit_report.md"
	}

	if err := os.WriteFile(reportPath, []byte(RenderMarkdown(findings)), 0o644); err != nil {
		return nil, fmt.Errorf("writing report: %w", err)
	}

	return &Result{
		Findings:   findings,
		ReportPath: reportPath,
	}, nil
}
