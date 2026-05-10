package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/parsers"
)

// Result holds the outcome of an audit run.
type Result struct {
	Findings   []Finding
	ReportPath string
}

// Collect executes the audit pipeline and returns findings without writing a
// report. It is used by the interactive TUI path.
func Collect(opts Options) ([]Finding, error) {
	if opts.SourceDir != "" {
		return collectFromSource(opts)
	}
	return collectFromState(opts)
}

func collectFromState(opts Options) ([]Finding, error) {
	resources, err := ParseState(opts)
	if err != nil {
		return nil, err
	}

	providers := selectProviders(opts)

	ctx, cancel := contextWithOptionalTimeout(context.Background(), opts.Timeout)
	defer cancel()

	return collectFindings(RunProvidersWithProgress(ctx, providers, resources, opts.TimeoutPerScanner))
}

func collectFromSource(opts Options) ([]Finding, error) {
	if err := validateSourceDir(opts.SourceDir); err != nil {
		return nil, err
	}

	iacType := resolveIaCType(opts)

	all := selectProviders(opts)
	var providers []FindingProvider
	for _, p := range all {
		if !p.SupportsSource() {
			continue
		}
		if !providerSupportsIaCType(p, iacType) {
			continue
		}
		providers = append(providers, p)
	}

	// Guard against a silent zero-findings result when --scanners + --iac-type
	// combine to select nothing. Without this the channel closes immediately
	// and the user sees "exit 0, no findings" which reads as a clean scan.
	if len(providers) == 0 {
		return nil, parsers.ThreeLineError(
			"no source-mode scanners selected",
			fmt.Sprintf("no provider supports both source mode and iac-type=%q", iacTypeForMessage(iacType)),
			"omit --scanners to use the built-in source-mode mock, or pick a different --iac-type",
		)
	}

	ctx, cancel := contextWithOptionalTimeout(context.Background(), opts.Timeout)
	defer cancel()

	return collectFindings(RunProvidersSourceWithProgress(ctx, providers, opts.SourceDir, opts.TimeoutPerScanner))
}

// resolveIaCType returns the effective IaC type for a source-mode run:
// the user's explicit --iac-type when set to anything other than "auto",
// otherwise the result of detectIaCType. May return "" for an empty or
// unrecognised tree — in that case providerSupportsIaCType errs on the
// permissive side (treats "" as "any").
func resolveIaCType(opts Options) string {
	if opts.IaCType != "" && opts.IaCType != IaCTypeAuto {
		return opts.IaCType
	}
	return detectIaCType(opts.SourceDir)
}

// providerSupportsIaCType encodes the per-adapter capability table:
//   - tfsec scans Terraform only.
//   - checkov + trivy + the static mock handle every IaC type the CLI knows
//     about (the real binaries self-detect; the mock is type-agnostic).
//
// The empty string ("" — no detection / unknown type) is treated as "any" so
// that exotic / unclassified trees still get scanned by the universal
// providers instead of being silently filtered out.
func providerSupportsIaCType(p FindingProvider, iacType string) bool {
	if iacType == "" {
		return true
	}
	if p.Name() == "tfsec" {
		return iacType == IaCTypeTerraform
	}
	return true
}

func iacTypeForMessage(t string) string {
	if t == "" {
		return IaCTypeAuto
	}
	return t
}

// selectProviders resolves the FindingProvider list for an audit run,
// respecting MockScanners and the --scanners filter.
func selectProviders(opts Options) []FindingProvider {
	if opts.MockScanners {
		return MockScanners()
	}
	scanners := loadScanners(opts.Scanners)
	providers := make([]FindingProvider, 0, len(scanners))
	providers = append(providers, scanners...)
	return providers
}

// collectFindings drains a ProviderResult stream into a deduplicated
// findings slice plus a joined error. The dedupe key matches the legacy
// logic: rule_id|resource.
func collectFindings(stream <-chan ProviderResult) ([]Finding, error) {
	var findings []Finding
	var scanErrs []error
	seen := make(map[string]struct{})
	for r := range stream {
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

func contextWithOptionalTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d > 0 {
		return context.WithTimeout(parent, d)
	}
	return parent, func() {}
}

// validateSourceDir ensures the source-mode input path is a readable
// directory before any scanner is dispatched. The 100 MB state-file guard
// is intentionally not applied here — source repos routinely exceed it and
// scanner binaries enforce their own limits (plan §4.7).
func validateSourceDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return parsers.ThreeLineError(
			"failed to read source directory",
			fmt.Sprintf("%v", err),
			"verify the path exists and is readable",
		)
	}
	if !info.IsDir() {
		return parsers.ThreeLineError(
			"source path is not a directory",
			fmt.Sprintf("%s is a regular file", dir),
			"pass a directory containing IaC source files",
		)
	}
	return nil
}

// Run executes the full audit pipeline for the given state file.
func Run(opts Options) (*Result, error) {
	findings, err := Collect(opts)
	if err != nil && findings == nil {
		return nil, err
	}

	reportPath := opts.ReportFile
	if reportPath == "" {
		reportPath = defaultReportPath(opts)
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

// DefaultReportPath returns the report path that Run uses when
// Options.ReportFile is empty. Exported so the interactive (TUI) path can
// share the same naming convention.
func DefaultReportPath(opts Options) string { return defaultReportPath(opts) }

func defaultReportPath(opts Options) string {
	if opts.SourceDir != "" {
		base := filepath.Base(opts.SourceDir)
		if base == "." || base == "/" || base == "" {
			base = "source"
		}
		return base + "_audit_report.md"
	}
	base := strings.TrimSuffix(filepath.Base(opts.StateFile), filepath.Ext(opts.StateFile))
	return base + "_audit_report.md"
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
