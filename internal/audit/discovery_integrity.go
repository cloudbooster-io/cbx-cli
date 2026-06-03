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
