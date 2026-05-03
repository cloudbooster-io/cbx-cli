package audit

import (
	"context"
	"errors"
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

// Collect executes the audit pipeline and returns findings without writing a
// report. It is used by the interactive TUI path.
func Collect(opts Options) ([]Finding, error) {
	resources, err := ParseState(opts)
	if err != nil {
		return nil, err
	}

	var providers []FindingProvider
	if opts.MockScanners {
		providers = MockScanners()
	} else {
		for _, s := range loadScanners(opts.Scanners) {
			providers = append(providers, s)
		}
	}

	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	var findings []Finding
	var scanErrs []error
	seen := make(map[string]struct{})
	for r := range RunProvidersWithProgress(ctx, providers, resources, opts.TimeoutPerScanner) {
		if r.Err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("%s: %w", r.ProviderName, r.Err))
		}
		for _, f := range r.Findings {
			key := f.RuleID + "|" + f.Resource
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}
	if len(scanErrs) > 0 {
		return findings, errors.Join(scanErrs...)
	}
	return findings, nil
}

// Run executes the full audit pipeline for the given state file.
func Run(opts Options) (*Result, error) {
	findings, err := Collect(opts)
	if err != nil && findings == nil {
		return nil, err
	}

	reportPath := opts.ReportFile
	if reportPath == "" {
		base := strings.TrimSuffix(filepath.Base(opts.StateFile), filepath.Ext(opts.StateFile))
		reportPath = base + "_audit_report.md"
	}

	if writeErr := os.WriteFile(reportPath, []byte(RenderMarkdown(findings)), 0o644); writeErr != nil {
		return nil, fmt.Errorf("writing report: %w", writeErr)
	}

	result := &Result{
		Findings:   findings,
		ReportPath: reportPath,
	}

	if err != nil {
		return result, fmt.Errorf("running scanners: %w", err)
	}
	return result, nil
}

// loadScanners returns the scanners requested by name. If names is empty
// every registered scanner (static + external adapters) is returned.
func loadScanners(names []string) []Scanner {
	if len(names) == 0 {
		return AllScanners()
	}
	registry := map[string]Scanner{
		"static":  &staticScanner{},
		"tfsec":   &tfsecAdapter{},
		"checkov": &checkovAdapter{},
		"prowler": &prowlerAdapter{},
		"trivy":   &trivyAdapter{},
	}
	var scanners []Scanner
	for _, name := range names {
		if s, ok := registry[name]; ok {
			scanners = append(scanners, s)
		}
	}
	return scanners
}
