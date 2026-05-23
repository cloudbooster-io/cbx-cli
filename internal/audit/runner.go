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

	// MockOnly is true when a source-mode run produced findings only from the
	// built-in static (mock) scanner — i.e. no real scanner binary was
	// configured. The CLI renders a banner in that case so users don't mistake
	// MOCK-SRC-* findings for a real audit. Always false for state-mode runs.
	MockOnly bool
}

// Collect executes the audit pipeline and returns findings without writing a
// report. It is used by the interactive TUI path. Note: opts.AWS audits go
// through CollectFromResources instead — the AWS subcommand owns its own
// discovery so it can render the account / region header before scanning.
func Collect(opts Options) ([]Finding, error) {
	if opts.SourceDir != "" {
		return collectFromSource(opts)
	}
	return collectFromState(opts)
}

// CollectFromResources runs the configured FindingProviders against a
// pre-discovered resource set and returns the aggregated findings.
// Used by code paths that own their own discovery (currently only the
// `cbx audit aws` subcommand). Bypasses Collect's input-mode dispatch.
//
// When opts.LLMProvider is set the LLM analyzer fully replaces the
// rule-based provider list — we don't run native rules in parallel with
// the LLM, mirroring the source-mode behaviour and avoiding double-
// counted findings against the same rule_id namespace. The analyzer
// takes the discovered resources directly via ScanResources (the
// source-mode entry point ScanSource is irrelevant here since AWS
// audits have no IaC tree).
func CollectFromResources(opts Options, resources []DiscoveredResource) ([]Finding, error) {
	ctx, cancel := contextWithOptionalTimeout(context.Background(), opts.Timeout)
	defer cancel()

	if opts.LLMProvider != "" {
		analyzer, err := newLLMAnalyzer(opts, IaCTypeCloudFormation)
		if err != nil {
			return nil, err
		}
		return analyzer.ScanResources(ctx, resources)
	}

	providers := selectProviders(opts)
	return collectFindings(RunProvidersWithProgress(ctx, providers, resources, opts.TimeoutPerScanner))
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

	// --llm replaces the scanner list with the LLM analyzer for this run.
	// We don't merge the two — the plan §5.1 declares them mutually
	// exclusive at the CLI layer, so by the time we reach here Scanners
	// is empty.
	var providers []FindingProvider
	if opts.LLMProvider != "" {
		analyzer, err := newLLMAnalyzer(opts, iacType)
		if err != nil {
			return nil, err
		}
		providers = []FindingProvider{analyzer}
	} else {
		var err error
		providers, err = sourceProviders(opts, iacType)
		if err != nil {
			return nil, err
		}
	}

	ctx, cancel := contextWithOptionalTimeout(context.Background(), opts.Timeout)
	defer cancel()

	return collectFindings(RunProvidersSourceWithProgress(ctx, providers, opts.SourceDir, opts.TimeoutPerScanner))
}

// sourceProviders resolves the FindingProvider list that will actually run in
// a source-mode audit, applying both the source-support filter and the
// iac-type filter. Returns a three-line error when --scanners + --iac-type
// combine to select nothing (otherwise the runner would close its channel
// immediately and the user would see a misleading "exit 0, no findings").
func sourceProviders(opts Options, iacType string) ([]FindingProvider, error) {
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

	if len(providers) == 0 {
		return nil, parsers.ThreeLineError(
			"no source-mode scanners selected",
			fmt.Sprintf("no provider supports both source mode and iac-type=%q", iacTypeForMessage(iacType)),
			"omit --scanners to use the built-in source-mode mock, or pick a different --iac-type",
		)
	}

	return providers, nil
}

// UsedMockOnlyForSource reports whether a source-mode audit invoked with the
// given Options would produce findings only from the built-in static (mock)
// scanner. Returns false for state-mode runs and for source-mode runs where
// at least one real scanner is in the effective provider list. Mirrors
// collectFromSource's filter so the CLI banner stays consistent with the
// actual runner behaviour.
func UsedMockOnlyForSource(opts Options) bool {
	if opts.SourceDir == "" {
		return false
	}
	providers, err := sourceProviders(opts, resolveIaCType(opts))
	if err != nil || len(providers) == 0 {
		return false
	}
	for _, p := range providers {
		if p.Name() != "static" {
			return false
		}
	}
	return true
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
		MockOnly:   UsedMockOnlyForSource(opts),
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
	if opts.AWS {
		// AWS account ID is the natural namespace; the subcommand fills
		// it into opts.AWSAccountID after preflight. Falls back to
		// "aws" when the field is empty (e.g. tests).
		base := opts.AWSAccountID
		if base == "" {
			base = "aws"
		}
		return base + "_audit_report.md"
	}
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
		"orphan":  &orphanProvider{},
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
