package audit

import (
	"fmt"
	"strings"
)

// DiscoveryIntegrityRuleID is the stable rule id for discovery-integrity
// warnings. Exported so downstream consumers and tests can match on it
// without re-typing the string literal.
const DiscoveryIntegrityRuleID = "CBX-DISCOVERY-INTEGRITY"

// DiscoveryIntegrityFinding builds the deterministic `warning` finding emitted
// when the discovery-integrity probe (internal/audit/discover/aws/integrity.go)
// catches CloudControl's silent-empty miss: an independent re-list saw `count`
// resources of `cfnType` (in `region`, empty for global types) that the audit's
// discovery pass dropped.
//
// Severity is `warning` (exit code 2) — not `info` — deliberately. A fired
// probe means the audit may be a FALSE clean for this type: the operator could
// be told they're secure when a resource went un-audited, which is the worst
// outcome for a security audit, so CI must not stay green on it. (Contrast the
// LLM-CB-UNGROUNDED / LLM-CB-COST-CAP info findings, which are about grounding
// QUALITY, not missed resources.)
//
// Resource is unique per (type, region) so the RuleID|Resource dedup in
// RunProviders never collapses two distinct misses into one.
func DiscoveryIntegrityFinding(cfnType, region string, count int) Finding {
	scope := cfnType
	resource := cfnType
	if region != "" {
		scope = cfnType + " in " + region
		resource = cfnType + "@" + region
	}
	return Finding{
		RuleID: DiscoveryIntegrityRuleID,
		Title:  fmt.Sprintf("Discovery may be incomplete for %s", scope),
		Description: fmt.Sprintf(
			"An independent re-list saw %d %s resource(s) that this audit's discovery pass did not return — AWS CloudControl ListResources silently returned an empty set for the type (no error, no permission denial). The CB-curated checks for %s could not run against the missed resource(s), so a clean result for this type is NOT trustworthy.",
			count, cfnType, cfnType,
		),
		Severity:    SeverityWarning,
		Resource:    resource,
		Service:     cfnServiceLabel(cfnType),
		Remediation: "Re-run `cbx audit aws` (the miss is non-deterministic and usually clears on retry). If it persists, inspect this type directly via the AWS console/CLI — CloudControl ListResources is under-returning it in this account.",
	}
}

// ExitWithSeverityStrict maps findings to a process exit code like
// ExitWithSeverity, but treats discovery-integrity warnings (RuleID ==
// DiscoveryIntegrityRuleID) as ADVISORY unless strict is set.
//
// The discovery-integrity probe reads two correlated, flaky CloudControl
// ListResources calls; a transient silent-empty on the first read fires the
// warning even when nothing is actually wrong (see integrity.go). So by default
// (strict == false) those findings are excluded from the exit-code calculation —
// a flaky re-list no longer reddens an otherwise-clean audit. Any non-integrity
// finding (a real warning/high/critical) still gates exactly as before, so a
// genuine problem sitting alongside a flaky probe continues to exit non-zero.
//
// With strict == true the integrity warnings are included and the result is
// byte-identical to ExitWithSeverity — restoring the gating for callers (CI) that
// want a possibly-incomplete discovery to fail the run. Wired to the `--strict`
// flag on `cbx audit aws`.
//
// The filter discriminates on the stable RuleID, NOT on severity, so it is
// robust even if applySeverityFloor ever promotes an integrity finding above
// warning. It builds a COPY for the exit calculation only and must never mutate
// or drop findings from the caller's slice: the integrity finding has to survive
// into result.Findings so the rendered report and the `discovery_integrity` JSON
// key keep showing it — only the exit code looks past it.
func ExitWithSeverityStrict(findings []Finding, strict bool) error {
	if strict {
		return ExitWithSeverity(findings)
	}
	gating := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == DiscoveryIntegrityRuleID {
			continue
		}
		gating = append(gating, f)
	}
	return ExitWithSeverity(gating)
}

// cfnServiceLabel pulls the service token out of a CFN type name
// ("AWS::S3::Bucket" → "S3"), falling back to the whole string for
// non-standard shapes.
func cfnServiceLabel(cfnType string) string {
	parts := strings.Split(cfnType, "::")
	if len(parts) >= 2 {
		return parts[1]
	}
	return cfnType
}
