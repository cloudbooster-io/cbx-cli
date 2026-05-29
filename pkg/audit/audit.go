// Package audit re-exports the cbx-cli audit surface so downstream
// modules — notably a proprietary downstream edition — can consume Findings,
// Components, Options, and the entry points (Run, Collect,
// CollectFromResources) without reaching into internal/audit.
//
// Per CLAUDE.md, packages under pkg/ are pure facades: type aliases
// and var X = internal.X re-exports. No logic lives here. Add a
// re-export when (and only when) downstream consumers legitimately needs the symbol
// — every entry is part of the semver-public contract.
package audit

import (
	"github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
)

// --- core finding / report types ---

// Finding is a single audit finding emitted by a FindingProvider. The
// JSON shape is part of the contract — downstream consumers and downstream consumers
// rely on the field names + tags exposed here.
type Finding = audit.Finding

// CBSource carries the grounded-analyzer citation attached to a finding
// when --cb-knowledge is on. Optional on every other code path.
type CBSource = audit.CBSource

// Result is the top-level audit outcome.
type Result = audit.Result

// Options configures an audit run.
type Options = audit.Options

// Resource / DiscoveredResource is the normalized resource shape every
// FindingProvider consumes — extracted from state files, parsed IaC
// source, or live AWS CloudControl discovery depending on the run mode.
type Resource = audit.Resource
type DiscoveredResource = audit.DiscoveredResource

// Component is one named grouping of resources (tag-based or
// CB-primitive). Populated by `cbx audit aws`; empty for state/source
// mode runs. Lives in internal/audit/group; re-exported here so downstream consumers
// can render Components without taking a transitive group import.
type Component = group.Component

// --- severity constants ---

// Severity levels for findings. Surface-compatible with anything that
// switches on the string value.
const (
	SeverityInfo     = audit.SeverityInfo
	SeverityWarning  = audit.SeverityWarning
	SeverityHigh     = audit.SeverityHigh
	SeverityCritical = audit.SeverityCritical
)

// --- IaC type constants used by Options.IaCType ---

const (
	IaCTypeAuto           = audit.IaCTypeAuto
	IaCTypeTerraform      = audit.IaCTypeTerraform
	IaCTypeCloudFormation = audit.IaCTypeCloudFormation
	IaCTypeK8s            = audit.IaCTypeK8s
	IaCTypeHelm           = audit.IaCTypeHelm
)

// --- errors ---

// ErrSourceModeUnsupported is the sentinel a FindingProvider returns
// from ScanSource when it has no source-mode implementation.
var ErrSourceModeUnsupported = audit.ErrSourceModeUnsupported

// ExitCodeError carries the audit's intended process exit code. Wrap
// or unwrap with errors.As to extract Code.
type ExitCodeError = audit.ExitCodeError

// --- entry points ---

// Run executes the full audit pipeline including writing a markdown
// report. Returns a Result whose Findings / Components / ReportPath
// fields are fully populated.
var Run = audit.Run

// Collect dispatches Pulumi-state / Terraform-state / source-mode
// audits via Options. AWS audits go through CollectFromResources
// instead — see the inline doc on internal/audit.Collect.
var Collect = audit.Collect

// CollectFromResources runs the audit pipeline against a pre-
// discovered []DiscoveredResource, bypassing input-mode dispatch. The
// `cbx audit aws` subcommand owns its own discovery and uses this
// entry point.
var CollectFromResources = audit.CollectFromResources

// RunFromResources is the AWS-mode mirror of Run: it takes a pre-
// discovered resource set, runs the scanner pipeline, groups
// resources, writes the markdown report, and returns a populated
// Result. downstream consumers uses this to consume the same envelope the CLI
// produces — Findings + Components attached, ReportPath populated.
// A non-nil AWSAuditContext drives the audit-flavoured markdown
// renderer (header + Components section + Account-wide findings);
// pass nil to fall back to the generic RenderMarkdown.
var RunFromResources = audit.RunFromResources

// AWSAuditContext carries the live-AWS metadata the audit-mode
// markdown renderer reads at the top of the report: account, identity,
// regions, and the estimated CloudTrail event count.
type AWSAuditContext = audit.AWSAuditContext

// RenderAWSMarkdown formats a Result as the audit-mode markdown report
// (Audited Account header, Components section with findings rendered
// under their primary component, and an Account-wide Findings section
// for everything else). Plan §7.7 + §7.12.
var RenderAWSMarkdown = audit.RenderAWSMarkdown

// --- rendering / exit helpers ---

// RenderMarkdown formats findings as a Markdown report body.
var RenderMarkdown = audit.RenderMarkdown

// RenderPlain formats findings as a terminal-friendly string with the
// given label header.
var RenderPlain = audit.RenderPlain

// DefaultReportPath returns the report path Run uses when
// Options.ReportFile is empty.
var DefaultReportPath = audit.DefaultReportPath

// ExitWithSeverity maps the highest severity in findings to the
// canonical exit code; returns nil for an empty / info-only set.
var ExitWithSeverity = audit.ExitWithSeverity

// --- primitive lookup helpers (consumed by the grounded path) ---

// CFNTypeToCBPrimitive returns the CB primitive id for a CFN type, or
// "" when the type isn't authored. Engine-split DBs always return ""
// here — use the describer-resolved override on r.Inputs instead.
var CFNTypeToCBPrimitive = audit.CFNTypeToCBPrimitive

// TFTypeToCBPrimitive returns the CB primitive id for a Terraform AWS
// type, or "".
var TFTypeToCBPrimitive = audit.TFTypeToCBPrimitive

// PulumiTypeToCBPrimitive returns the CB primitive id for a Pulumi
// type token, or "".
var PulumiTypeToCBPrimitive = audit.PulumiTypeToCBPrimitive

// RDSPrimitiveFor maps an RDS Engine attribute value to its
// engine-split CB primitive id (rds_postgres / rds_mysql / etc.).
var RDSPrimitiveFor = audit.RDSPrimitiveFor

// --- LLM provider constants ---

// ClaudeCodeProvider is the provider string accepted by --llm in both
// source and AWS modes when grounding is desired.
const ClaudeCodeProvider = audit.ClaudeCodeProvider
