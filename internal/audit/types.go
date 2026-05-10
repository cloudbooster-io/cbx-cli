package audit

import (
	"context"
	"errors"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/parsers"
)

// ErrSourceModeUnsupported is returned by FindingProvider.ScanSource when a
// provider has no source-mode implementation. The runner filters such
// providers out via SupportsSource; the sentinel exists so adapters that are
// invoked directly can still signal the condition unambiguously.
var ErrSourceModeUnsupported = errors.New("provider does not support source-mode scanning")

// IaC type constants used by Options.IaCType.
const (
	IaCTypeAuto           = "auto"
	IaCTypeTerraform      = "terraform"
	IaCTypeCloudFormation = "cloudformation"
	IaCTypeK8s            = "k8s"
	IaCTypeHelm           = "helm"
)

// Severity levels for audit findings.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding represents a single audit finding.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Service     string `json:"service"`
	Remediation string `json:"remediation"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
}

// DiscoveredResource is an alias for the shared shape defined in the parsers
// sub-package so that scanner code and CLI code can refer to it without
// importing parsers directly everywhere.
type DiscoveredResource = parsers.DiscoveredResource

// Resource is an alias for DiscoveredResource — kept for legacy callers.
type Resource = DiscoveredResource

// FindingProvider evaluates IaC inputs and returns security findings.
//
// State mode (Scan) operates on parsed resources extracted from a Pulumi or
// Terraform state file. Source mode (ScanSource) operates on an on-disk IaC
// source directory. Providers that cannot implement source mode return
// ErrSourceModeUnsupported and report SupportsSource() == false; the runner
// filters them out before dispatching a source-mode audit.
type FindingProvider interface {
	Name() string
	Scan(ctx context.Context, resources []Resource) ([]Finding, error)
	ScanSource(ctx context.Context, dir string) ([]Finding, error)
	SupportsSource() bool
}

// Scanner is the legacy alias for FindingProvider.
type Scanner = FindingProvider

// Options configures an audit run.
type Options struct {
	StateFile         string
	OutputFormat      string
	ReportFile        string
	Interactive       bool
	NoTUI             bool
	Quiet             bool
	Yes               bool          // when true, bypass interactive confirmations
	MockScanners      bool          // when true, use mock scanner implementations (zero network)
	Scanners          []string      // scanner names to run; empty means all available
	Timeout           time.Duration // overall audit timeout
	TimeoutPerScanner time.Duration // timeout for each individual scanner/provider

	// SourceDir, when non-empty, switches the runner into source mode and
	// audits the IaC source tree rooted at this path. Mutually exclusive with
	// StateFile (validated at the CLI layer; Options itself stays dumb).
	SourceDir string

	// IaCType narrows source-mode auto-detection to a specific IaC flavor.
	// Empty or "auto" lets scanners decide. Used in Phase 2; shipped in
	// Phase 1 so the flag is stable from the start.
	IaCType string
}
