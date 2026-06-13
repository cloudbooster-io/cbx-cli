package audit

import (
	"context"
	"errors"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
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

	// TrailCoverageByRegion maps each audited region → whether at
	// least one CloudTrail trail covers it (a multi-region trail in
	// the account, or a region-local trail homed in that region).
	// Computed post-discovery from the AWS::CloudTrail::Trail resources
	// — see discover/aws/crossref_cloudtrail.go. A region missing from
	// the map means the probe wasn't computed (e.g. no trails
	// discovered at all); a region with value=false is a finding.
	TrailCoverageByRegion map[string]bool `json:"trail_coverage_by_region,omitempty"`

	// GuardDutyByRegion maps each audited region → the GuardDuty
	// detector state: "enabled" (a detector exists and is actively
	// monitoring), "disabled" (a detector exists but is suspended — a
	// real regression: someone turned threat detection off), or
	// "absent" (no detector in the region). See
	// discover/aws/account_posture.go:probeGuardDuty. A region absent
	// from the map means the probe failed (recorded in Errors).
	GuardDutyByRegion map[string]string `json:"guardduty_by_region,omitempty"`

	// ConfigRecorderByRegion maps each audited region → AWS Config
	// configuration-recorder coverage. The load-bearing signal is
	// whether global (account-wide) resource types like IAM are
	// captured — see ConfigRecorderState and
	// discover/aws/account_posture.go:probeConfigRecorders. Global
	// types only need recording in ONE region, so consumers must
	// aggregate across regions before flagging (the prompt renders a
	// derived "recorded in at least one region" line for that reason).
	ConfigRecorderByRegion map[string]ConfigRecorderState `json:"config_recorder_by_region,omitempty"`

	// GlueCatalogPolicyByRegion maps each audited region that has a Glue
	// Data Catalog resource policy → its summary. The Data Catalog has
	// at most one resource policy per account per region; it has no CFN
	// type, so it can't ride in through CloudControl discovery and is
	// fetched account-side via glue:GetResourcePolicy (see
	// discover/aws/account_posture.go). Regions with no resource policy
	// are omitted from the map (the common case) — a region whose entry
	// reports GrantsWildcardPrincipal=true exposes the entire catalog to
	// a wildcard principal and is a finding.
	GlueCatalogPolicyByRegion map[string]*GlueCatalogPolicy `json:"glue_catalog_policy_by_region,omitempty"`

	// CredentialReport carries the IAM credential-report-derived console-MFA
	// posture. Non-nil ⇒ iam:GetCredentialReport was read successfully; nil ⇒
	// the probe didn't run or failed (recorded in Errors) and the prompt must
	// treat console-MFA coverage as UNKNOWN. See
	// discover/aws/account_posture.go:probeConsoleUsersWithoutMFA.
	CredentialReport *CredentialReportPosture `json:"credential_report,omitempty"`

	Errors []string `json:"errors,omitempty"`
}

// CredentialReportPosture summarises IAM console-login MFA coverage from
// the credential report. ConsoleUsersWithoutMFA names the users that have a
// console password (password_enabled=true) but no MFA device
// (mfa_active=false) — CIS 1.10 / FSBP IAM.5. The account root user is
// excluded (its MFA is the AccountMFAEnabled summary counter).
// ConsolePasswordUsersEvaluated is how many console-password users were
// checked, so the prompt can render an "evaluated N, without MFA M" line —
// an empty offender list with N>0 is positive confirmation, NOT silence.
type CredentialReportPosture struct {
	ConsolePasswordUsersEvaluated int      `json:"console_password_users_evaluated"`
	ConsoleUsersWithoutMFA        []string `json:"console_users_without_mfa,omitempty"`
}

// ConfigRecorderState is the per-region AWS Config configuration-recorder
// shape carried in AccountPosture.ConfigRecorderByRegion. Present is
// false when no recorder exists in the region (still a recorded entry so
// the LLM knows the region was probed). RecordsGlobalTypes collapses the
// AWS RecordingGroup nuance (AllSupported+IncludeGlobalResourceTypes, or
// an inclusion strategy that lists a global IAM type) into one signal so
// the prompt doesn't have to reason over AWS schema details.
type ConfigRecorderState struct {
	Present            bool `json:"present"`
	RecordsGlobalTypes bool `json:"records_global_types"`
}

// GlueCatalogPolicy summarises the AWS Glue Data Catalog resource
// policy discovered in one region. Populated only for regions where a
// policy is actually set; see discover/aws/account_posture.go.
type GlueCatalogPolicy struct {
	// GrantsWildcardPrincipal is true when an Allow statement names a
	// wildcard principal ("*" or {"AWS":"*"}) with no scoping Condition
	// — the cross-account / public Data Catalog exposure pattern. Same
	// analysis the S3 describer applies to bucket policies.
	GrantsWildcardPrincipal bool `json:"grants_wildcard_principal"`

	// Document is the raw resource-policy JSON, surfaced so the grounded
	// analyzer can cite the offending statement (mirrors the S3
	// describer's cb_describer_bucket_policy_document).
	Document string `json:"document,omitempty"`
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

// LLMConnection is one architectural data-flow edge inferred by the
// grounded analyzer. These complement the deterministic Inputs-based
// edges (Instance→SG, IGW→VPC, etc.) the diagram renderer always
// draws — LLM edges add the semantic flows that aren't visible in
// raw CloudControl fields:
//   - CloudFront → S3 origin (from Origins.S3OriginConfig.DomainName)
//   - API Gateway → Lambda integration (from method URI ARNs)
//   - Lambda → DynamoDB / S3 / Secrets (from IAM policy actions)
//   - AppSync → Lambda resolvers / DynamoDB data sources
//
// From / To are resource URNs from the discovered set; the renderer
// silently drops edges whose endpoints aren't on the diagram.
type LLMConnection struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label,omitempty"`
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
//
// Library-mode safety guarantee: a zero-value Options never executes
// external binaries or network-capable scanners. External scanners are
// strictly opt-in by name via Scanners — when MockScanners is false and
// Scanners is empty, the built-in zero-network mock set runs.
type Options struct {
	StateFile    string
	OutputFormat string
	ReportFile   string
	Interactive  bool
	NoTUI        bool
	Quiet        bool
	Yes          bool // when true, bypass interactive confirmations

	// MockScanners forces the built-in zero-network mock scanner set,
	// overriding any Scanners selection. External scanners are opt-in by
	// name regardless of this flag — see Scanners.
	MockScanners bool

	// Scanners selects FindingProviders by name (static, orphan, tfsec,
	// checkov, prowler, trivy). The external-tool adapters — tfsec,
	// checkov, prowler (scans live AWS), trivy (may download vulnerability
	// DBs) — run ONLY when explicitly named here. Empty means the built-in
	// zero-network mock set, never "all available".
	Scanners []string

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
	// whatever the user has logged in via `cbx llm api login`). Mutually
	// exclusive with Scanners at the CLI layer. Implies network egress —
	// document accordingly.
	LLMProvider string

	// LLMModel, when non-empty, pins the model the LLM provider uses (passed
	// to the claude CLI as --model). Empty means the CLI's own configured
	// default. Set from `cbx llm model claude-code <model>` config or the
	// --llm-model flag.
	LLMModel string

	// LLMMaxFiles caps the number of source files sent to the LLM. Zero
	// means "use the default" (defaultLLMMaxFiles).
	LLMMaxFiles int

	// LLMMaxBytesPerFile caps the per-file bytes shipped to the LLM. Files
	// exceeding this are truncated and flagged. Zero means "use the
	// default" (defaultLLMMaxBytesPerFile).
	LLMMaxBytesPerFile int

	// CBKnowledge selects the Phase F grounded path: the analyzer fetches
	// CloudBooster's curated AWS knowledge directly over the CB knowledge
	// API (Go-side), inlines it into the prompt, and runs a `claude -p`
	// subprocess (no MCP) instructed to cite that grounding on every finding.
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
