package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

// Result holds the outcome of an audit run.
type Result struct {
	Findings   []Finding
	ReportPath string

	// HTMLReportPath is the path to the self-contained HTML report
	// written alongside the markdown report for `cbx audit aws`. Empty
	// for source/state-mode runs (HTML is AWS-only for now). The HTML
	// file embeds the markdown source so the in-browser "Download
	// Markdown" button works without the .md sibling on disk.
	HTMLReportPath string `json:"html_report_path,omitempty"`

	// MockOnly is true when a source-mode run produced findings only from the
	// built-in static (mock) scanner — i.e. no real scanner binary was
	// configured. The CLI renders a banner in that case so users don't mistake
	// MOCK-SRC-* findings for a real audit. Always false for state-mode runs.
	MockOnly bool

	// Components is the post-discovery grouping output. Populated by the
	// `cbx audit aws` subcommand from the tag-based + CB-primitive lenses
	// (see internal/audit/group); empty for state / source mode where no
	// grouping pass runs. Read by downstream consumers through pkg/audit so the
	// proprietary edition can render the same component sections without
	// re-importing internal/audit/group.
	Components []group.Component `json:"components,omitempty"`

	// Diagram is a Mermaid `flowchart` source representing the audited
	// infrastructure, organized by Components (with a per-service
	// fallback bucket for unassigned resources). Embedded as a fenced
	// ```mermaid block in the markdown report so GitLab/GitHub
	// renders it inline. Empty for non-AWS audit paths.
	Diagram string `json:"diagram,omitempty"`

	// DiagramSVG is a fully styled, self-contained SVG of the
	// audited infrastructure intended for the HTML report (and for
	// sharing on social). Uses an AWS-Architecture-Center palette
	// with branded monogram badges per service. Populated alongside
	// Diagram for live-AWS runs; empty otherwise.
	DiagramSVG string `json:"-"`

	// DiagramSVGFile is the basename of the sibling SVG file the
	// markdown report should link to (e.g. "123456789012_audit_report.svg").
	// When non-empty, RenderAWSMarkdown emits an
	// `![Architecture](file.svg)` image tag at the Architecture
	// section; markdown viewers that sanitize inline <svg> still
	// see the diagram. Empty -> markdown falls back to inline SVG.
	DiagramSVGFile string `json:"-"`

	// LLMConnections lists the architecture data-flow edges the
	// grounded analyzer inferred (CloudFront → S3 origin, API
	// Gateway → Lambda, Lambda → DynamoDB via IAM policies, etc.).
	// Drawn as labelled arrows in the SVG alongside the
	// deterministic Inputs-based edges. Nil when the run wasn't
	// grounded.
	LLMConnections []LLMConnection `json:"llm_connections,omitempty"`
}

// Collect executes the audit pipeline and returns findings without writing a
// report. It is used by the interactive TUI path. Note: opts.AWS audits go
// through CollectFromResources instead — the AWS subcommand owns its own
// discovery so it can render the account / region header before scanning.
//
// Collect is CollectContext with a background parent context; library
// callers that need cancellation should use CollectContext directly.
func Collect(opts Options) ([]Finding, error) {
	return CollectContext(context.Background(), opts)
}

// CollectContext is Collect with a caller-supplied parent context so library
// consumers can cancel an in-flight audit. A pre-cancelled ctx returns
// ctx.Err() before any scanner is dispatched; mid-flight cancellation
// propagates into every provider Scan call. opts.Timeout still applies — it
// is layered onto ctx via context.WithTimeout, so whichever expires first
// wins.
func CollectContext(ctx context.Context, opts Options) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.SourceDir != "" {
		return collectFromSource(ctx, opts)
	}
	return collectFromState(ctx, opts)
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
	findings, _, err := CollectFromResourcesWithDiagram(opts, resources)
	return findings, err
}

// CollectFromResourcesWithDiagram is the richer-return sibling of
// CollectFromResources: it surfaces the LLM-inferred architecture
// connections (CloudFront → S3 origin, API Gateway → Lambda, etc.)
// alongside the security findings so the report renderer can draw
// labelled arrows between resources. Non-LLM paths return a nil
// connections slice — those audits rely solely on the deterministic
// Inputs-based edge inference in BuildArchitectureSVG.
func CollectFromResourcesWithDiagram(opts Options, resources []DiscoveredResource) ([]Finding, []LLMConnection, error) {
	ctx, cancel := contextWithOptionalTimeout(context.Background(), opts.Timeout)
	defer cancel()

	if opts.LLMProvider != "" {
		analyzer, err := newLLMAnalyzer(opts, IaCTypeCloudFormation)
		if err != nil {
			return nil, nil, err
		}
		findings, scanErr := analyzer.ScanResources(ctx, resources)
		return findings, analyzer.LastConnections(), scanErr
	}

	providers := selectProviders(opts)
	findings, err := collectFindings(RunProvidersWithProgress(ctx, providers, resources, opts.TimeoutPerScanner))
	return findings, nil, err
}

func collectFromState(ctx context.Context, opts Options) ([]Finding, error) {
	resources, err := ParseState(opts)
	if err != nil {
		return nil, err
	}

	providers := selectProviders(opts)

	ctx, cancel := contextWithOptionalTimeout(ctx, opts.Timeout)
	defer cancel()

	return collectFindings(RunProvidersWithProgress(ctx, providers, resources, opts.TimeoutPerScanner))
}

func collectFromSource(ctx context.Context, opts Options) ([]Finding, error) {
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

	ctx, cancel := contextWithOptionalTimeout(ctx, opts.Timeout)
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
// respecting MockScanners and the Scanners name filter. External scanners
// are strictly opt-in by name: when MockScanners is false AND Scanners is
// empty, the built-in zero-network mock set runs — never the external-tool
// adapters. This is the library-mode safety guarantee documented on
// Options: a zero-value Options never executes external binaries or
// network-capable scanners.
func selectProviders(opts Options) []FindingProvider {
	if opts.MockScanners || len(opts.Scanners) == 0 {
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

// RunFromResources mirrors Run for the live-AWS path: it takes a
// pre-discovered []DiscoveredResource (assembled by the AWS
// subcommand's CloudControl walk + per-service describers), runs the
// scanner pipeline, groups the resources, writes the markdown report,
// and returns a populated Result. downstream consumers calls this through pkg/audit
// to consume the same envelope the CLI produces.
//
// Grouping uses CFNTypeToCBPrimitive — AWS audits always emit CFN-
// shaped resources, so the static lookup plus the per-resource
// describer override (read by group.groupByCBPrimitive itself) cover
// every case.
//
// When awsCtx is non-nil the report is rendered via RenderAWSMarkdown
// (Audited-Account header + Components section + Account-wide
// findings, plan §7.7 + §7.12). A nil awsCtx falls back to
// RenderMarkdown so testing callers without account metadata still
// get a sensible report.
func RunFromResources(opts Options, resources []DiscoveredResource, awsCtx *AWSAuditContext) (*Result, error) {
	findings, llmConns, scanErr := CollectFromResourcesWithDiagram(opts, resources)
	if scanErr != nil && findings == nil {
		return nil, scanErr
	}

	// AWS-only finding post-process, run as ONE pass before grouping /
	// rendering / exit-code so the report bucket, the JSON envelope, and the
	// exit code all stay consistent from a single mutation. Ordering is
	// load-bearing:
	//  1. Merge the deterministic discovery-integrity warnings (computed
	//     Go-side during discovery) into the finding set so they reach the
	//     report, the JSON envelope, and the exit code — not just the returned
	//     Result. See DiscoveryIntegrityFinding.
	//  2. Drop the auditor's own IAM-user finding (the #1 FP) — done before
	//     the floor so it never promotes the caller's own admin user to
	//     critical.
	//  3. Raise the unambiguous account-takeover / audit-integrity classes
	//     over the full set (which now includes the integrity findings from
	//     step 1). See severity_floor.go.
	//  4. Cap the canonical AWS-managed OrganizationAccountAccessRole's
	//     cross-account-admin trust finding to info — done AFTER the floor so it
	//     overrides both the floor's raise and the LLM's HIGH base. See
	//     downgradeCanonicalOrgRoleFindings in severity_floor.go.
	if awsCtx != nil {
		if len(awsCtx.DiscoveryIntegrityFindings) > 0 {
			findings = append(findings, awsCtx.DiscoveryIntegrityFindings...)
		}
		findings = dropSelfIdentityFindings(findings, awsCtx.CallerARN)
		findings = applySeverityFloor(findings, resources, awsCtx.AccountID)
		findings = downgradeCanonicalOrgRoleFindings(findings, resources)
	}

	components := group.Group(resources, group.Options{
		LookupPrimitive: CFNTypeToCBPrimitive,
	})

	reportPath := opts.ReportFile
	if reportPath == "" {
		reportPath = defaultReportPath(opts)
	}

	result := &Result{
		Findings:       findings,
		ReportPath:     reportPath,
		Components:     components,
		Diagram:        BuildArchitectureDiagram(resources, components),
		LLMConnections: llmConns,
	}
	if awsCtx != nil {
		result.DiagramSVG = BuildArchitectureSVG(resources, components, *awsCtx, llmConns, findings)
		// Sibling SVG file alongside the .md/.html — markdown viewers
		// that sanitize inline <svg> link to this asset instead.
		if result.DiagramSVG != "" {
			svgPath := strings.TrimSuffix(reportPath, ".md") + ".svg"
			// 0o600: the report, its SVG/HTML siblings and the state sidecar
			// all embed the account ID, resource inventory and findings —
			// owner-only, not the world-readable default, on shared hosts.
			if err := os.WriteFile(svgPath, []byte(result.DiagramSVG), 0o600); err == nil {
				result.DiagramSVGFile = filepath.Base(svgPath)
			}
		}
	}

	var report string
	if awsCtx != nil {
		report = RenderAWSMarkdown(result, *awsCtx)
	} else {
		report = RenderMarkdown(findings)
	}
	if writeErr := os.WriteFile(reportPath, []byte(report), 0o600); writeErr != nil {
		return nil, fmt.Errorf("writing report: %w", writeErr)
	}

	// Companion HTML report — AWS-only because it's the only path with
	// the rich AWSAuditContext the HTML header expects (account ID,
	// regions, identity). The markdown source is embedded inline so
	// the in-browser "Download Markdown" button is self-sufficient
	// even if the .md sibling is deleted or moved.
	if awsCtx != nil {
		htmlPath := strings.TrimSuffix(reportPath, ".md") + ".html"
		html := RenderAWSHTML(result, *awsCtx, report)
		if writeErr := os.WriteFile(htmlPath, []byte(html), 0o600); writeErr != nil {
			return nil, fmt.Errorf("writing html report: %w", writeErr)
		}
		result.HTMLReportPath = htmlPath

		// Sidecar state JSON — captures every input the renderer
		// needs so dev iteration (tools/diagram-replay) can rebuild
		// the diagram in <1s without re-running discovery / LLM.
		// Write failures don't break the report — they're a
		// convenience for the dev loop, not a correctness signal.
		statePath := strings.TrimSuffix(reportPath, ".md") + ".state.json"
		state := AuditState{
			Version:        1,
			Context:        *awsCtx,
			Resources:      resources,
			Components:     components,
			Findings:       findings,
			LLMConnections: llmConns,
		}
		_ = SaveAuditState(statePath, state)
	}

	if scanErr != nil {
		return result, fmt.Errorf("running scanners: %w", scanErr)
	}
	return result, nil
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

	if writeErr := os.WriteFile(reportPath, []byte(RenderMarkdown(findings)), 0o600); writeErr != nil {
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

// loadScanners returns the scanners requested by name; unknown names are
// silently skipped. The external-tool adapters (tfsec, checkov, prowler,
// trivy) are reachable only through an explicit name here — an empty list
// resolves to nothing (selectProviders maps "no names" to MockScanners
// before ever calling this, keeping external scanners opt-in by name).
func loadScanners(names []string) []Scanner {
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
