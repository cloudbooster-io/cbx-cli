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

// AccountPosture is the cross-package shape of the AWS account-level
// configuration probes (default EBS encryption per region, IAM
// account summary, password policy presence). Owned here rather than
// in internal/audit/discover/aws so internal/audit can render it into
// the LLM prompt without an import cycle — discover/aws populates the
// struct, the LLM analyzer reads it. See discover/aws/account_posture.go
// for the probe implementations.
type AccountPosture struct {
	EBSEncryptionByDefault map[string]bool  `json:"ebs_encryption_by_default,omitempty"`
	IAMSummary             map[string]int32 `json:"iam_summary,omitempty"`
	PasswordPolicyPresent  *bool            `json:"password_policy_present,omitempty"`
	Errors                 []string         `json:"errors,omitempty"`
}

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
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Resource    string    `json:"resource"`
	Service     string    `json:"service"`
	Remediation string    `json:"remediation"`
	File        string    `json:"file,omitempty"`
	Line        int       `json:"line,omitempty"`
	CBSource    *CBSource `json:"cb_source,omitempty"`
}

// CBSource records which CB-knowledge MCP call the LLM cited when grounding
// a finding. Only set by the grounded analyzer (--cb-knowledge); absent for
// every other code path. Optional even on the grounded path — the model is
// allowed to emit findings without a citation, which the analyzer soft-warns.
type CBSource struct {
	Tool    string `json:"tool"`
	Key     string `json:"key,omitempty"`
	Snippet string `json:"snippet,omitempty"`
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

	// LLMProvider, when non-empty, switches a source-mode audit to the LLM
	// analyzer using the configured provider (claude / codex / ollama —
	// whatever the user has logged in via `cbx llm login`). Mutually
	// exclusive with Scanners at the CLI layer. Implies network egress —
	// document accordingly.
	LLMProvider string

	// LLMMaxFiles caps the number of source files sent to the LLM. Zero
	// means "use the default" (defaultLLMMaxFiles).
	LLMMaxFiles int

	// LLMMaxBytesPerFile caps the per-file bytes shipped to the LLM. Files
	// exceeding this are truncated and flagged. Zero means "use the
	// default" (defaultLLMMaxBytesPerFile).
	LLMMaxBytesPerFile int

	// CBKnowledge selects the Phase F grounded path: the LLM analyzer
	// spawns a `claude -p` subprocess wired to cbx-mcp via --mcp-config and
	// is instructed to cite a CB-knowledge tool call on every finding.
	// Only valid when LLMProvider == ClaudeCodeProvider.
	CBKnowledge bool

	// LLMMaxCost is the USD ceiling for a single grounded audit. When the
	// terminating `result.total_cost_usd` from claude's stream-json exceeds
	// this value the analyzer emits a warning finding; partial findings
	// already returned are preserved. Zero means "no cap" (no warning is
	// ever emitted). The CLI default is 2.00; library callers passing
	// Options directly must set this explicitly or accept "no cap".
	LLMMaxCost float64

	// AWS, when true, switches the runner into live-AWS mode. Set by the
	// `cbx audit aws` subcommand. Mutually exclusive with StateFile /
	// SourceDir at the CLI layer.
	AWS bool

	// AWSProfile names the AWS SDK profile to use for live-AWS audit.
	// Resolution precedence: AWSConfigFile > AWSProfile > AWS_PROFILE env
	// > "default". Only meaningful when AWS is true.
	AWSProfile string

	// AWSConfigFile is the optional path to an AWS credentials file. When
	// set, it overrides profile resolution (equivalent to setting
	// AWS_SHARED_CREDENTIALS_FILE for this run). Only meaningful when AWS
	// is true.
	AWSConfigFile string

	// Regions is the resolved AWS region list for live-AWS audit. Empty
	// means "use the profile default; prompt if none." A single literal
	// "all" expands to every enabled region in the account during runtime
	// resolution. Only meaningful when AWS is true.
	Regions []string

	// AWSConcurrency caps concurrent AWS API calls per service. Zero means
	// the default (4). Only meaningful when AWS is true.
	AWSConcurrency int

	// Diagnose, when true, emits per-call IAM permission errors and a
	// recommended IAM policy patch at the end of a live-AWS audit. Only
	// meaningful when AWS is true.
	Diagnose bool

	// AWSAccountID is populated by the AWS subcommand after STS preflight
	// so downstream rendering (default report path, header lines) can
	// reference the audited account without re-querying.
	AWSAccountID string

	// AWSAccountPosture carries the pre-fetched account-level
	// configuration probes (see discover/aws/account_posture.go).
	// Threaded through Options so the LLM analyzer can fold posture
	// into its prompt without changing the FindingProvider interface.
	// Only meaningful for AWS audits.
	AWSAccountPosture *AccountPosture
}
