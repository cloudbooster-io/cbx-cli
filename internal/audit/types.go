package audit

import (
	"context"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/parsers"
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

// FindingProvider evaluates a set of resources and returns security findings.
type FindingProvider interface {
	Name() string
	Scan(ctx context.Context, resources []Resource) ([]Finding, error)
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
}
