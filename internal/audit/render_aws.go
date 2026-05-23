package audit

import (
	"fmt"
	"sort"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/group"
)

// AWSAuditContext carries the live-AWS audit metadata RenderAWSMarkdown
// needs at the top of the report — values the discover layer already
// resolved (account / identity / regions) plus the event-count estimate
// (plan §7.7). State and source mode runs don't have an equivalent
// context, so they keep using the mode-agnostic RenderMarkdown.
type AWSAuditContext struct {
	AccountID  string
	Identity   string
	Regions    []string
	EventCount int
}

// RenderAWSMarkdown emits the AWS-mode report shape from plan §7.7 +
// §7.12: an Audited Account header, a Components section with findings
// rendered under their primary component, and an Account-wide Findings
// section for everything that didn't match a component. The function
// preserves the deterministic severity-grouped finding layout used by
// RenderMarkdown so existing rendering muscle memory still applies.
//
// "Primary component" = first component (by sorted order) whose
// Resources set contains the finding's Resource. A resource can belong
// to multiple components (one tag-based and one cb-primitive in v1) —
// we render the finding once to keep the report from double-counting,
// rather than under every matching lens. Resources appear under every
// component they belong to; only findings are deduplicated.
func RenderAWSMarkdown(result *Result, ctx AWSAuditContext) string {
	var sb strings.Builder
	sb.WriteString("# CloudBooster Audit Report — AWS\n\n")
	writeAWSHeader(&sb, ctx, result)

	writeSeveritySummary(&sb, result.Findings)

	findingsByComponent, accountWide := partitionFindingsByComponent(result.Findings, result.Components)

	if len(result.Components) > 0 {
		sb.WriteString("## Components\n\n")
		for _, c := range result.Components {
			writeComponentSection(&sb, c, findingsByComponent[c.Name])
		}
	}

	sb.WriteString("## Account-wide Findings\n\n")
	if len(accountWide) == 0 {
		sb.WriteString("_No findings unattached to any component._\n\n")
	} else {
		writeFindingsBySeverity(&sb, accountWide)
	}

	return sb.String()
}

// writeAWSHeader emits the "Audited Account" stanza per plan §7.7.
// EventCount is rendered with the leading "~" the plan calls for since
// it's a structural estimate, not an atomic counter.
func writeAWSHeader(sb *strings.Builder, ctx AWSAuditContext, result *Result) {
	sb.WriteString("## Audited Account\n\n")
	if ctx.AccountID != "" {
		sb.WriteString(fmt.Sprintf("- **Account ID:** %s\n", ctx.AccountID))
	}
	if ctx.Identity != "" {
		sb.WriteString(fmt.Sprintf("- **Identity:** %s\n", ctx.Identity))
	}
	if len(ctx.Regions) > 0 {
		sb.WriteString(fmt.Sprintf("- **Regions:** %s\n", strings.Join(ctx.Regions, ", ")))
	}
	sb.WriteString(fmt.Sprintf("- **CloudTrail Read events (approx.):** ~%d\n", ctx.EventCount))
	sb.WriteString(fmt.Sprintf("- **Findings:** %d\n", len(result.Findings)))
	sb.WriteString(fmt.Sprintf("- **Components:** %d\n\n", len(result.Components)))
}

// writeSeveritySummary mirrors the severity table from RenderMarkdown
// so the AWS report header stays familiar.
func writeSeveritySummary(sb *strings.Builder, findings []Finding) {
	counts := countBySeverity(findings)
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		if c := counts[sev]; c > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(sev), c))
		}
	}
	sb.WriteString("\n")
}

// writeComponentSection renders one component subsection with its
// member URNs and (if any) matched findings. Findings inside the
// section are severity-grouped to match the global rendering.
func writeComponentSection(sb *strings.Builder, c group.Component, matched []Finding) {
	sb.WriteString(fmt.Sprintf("### %s: %s\n\n", c.Kind, c.Name))
	if len(c.Resources) > 0 {
		sb.WriteString("**Resources:**\n")
		for _, urn := range c.Resources {
			sb.WriteString("- ")
			sb.WriteString(urn)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
	if len(matched) == 0 {
		sb.WriteString("_No findings._\n\n")
		return
	}
	sb.WriteString(fmt.Sprintf("**Findings (%d):**\n\n", len(matched)))
	writeFindingsBySeverity(sb, matched)
}

// writeFindingsBySeverity emits findings in severity order with the
// same per-finding block format the source/state mode reports use.
func writeFindingsBySeverity(sb *strings.Builder, findings []Finding) {
	grouped := groupBySeverity(findings)
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		list := grouped[sev]
		if len(list) == 0 {
			continue
		}
		for _, f := range list {
			sb.WriteString(fmt.Sprintf("#### %s — %s\n\n", f.RuleID, f.Title))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(f.Severity)))
			sb.WriteString(fmt.Sprintf("- **Resource:** %s\n", f.Resource))
			sb.WriteString(fmt.Sprintf("- **Service:** %s\n", f.Service))
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("\n**Remediation:** %s\n", f.Remediation))
			}
			sb.WriteString("\n")
		}
	}
}

// partitionFindingsByComponent assigns each finding to at most one
// component — the first (by sorted component order) whose Resources
// list contains the finding's Resource — and returns the leftover
// findings as the account-wide set. Findings with an empty Resource
// always land in the account-wide set, which is the v1 outcome for any
// finding that names a non-resource subject (e.g. LLM-CB-COST-CAP).
func partitionFindingsByComponent(findings []Finding, components []group.Component) (map[string][]Finding, []Finding) {
	if len(components) == 0 {
		return nil, findings
	}

	// Pre-sort component pointers by Name so the first-match is
	// deterministic across runs. The grouping pass already sorts, but
	// this function is reused in tests with hand-built fixtures.
	ordered := make([]group.Component, len(components))
	copy(ordered, components)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Kind != ordered[j].Kind {
			return ordered[i].Kind < ordered[j].Kind
		}
		return ordered[i].Name < ordered[j].Name
	})

	byComponent := make(map[string][]Finding, len(components))
	matched := make([]bool, len(findings))

	for _, c := range ordered {
		set := make(map[string]struct{}, len(c.Resources))
		for _, urn := range c.Resources {
			set[urn] = struct{}{}
		}
		for i, f := range findings {
			if matched[i] || f.Resource == "" {
				continue
			}
			if _, ok := set[f.Resource]; ok {
				byComponent[c.Name] = append(byComponent[c.Name], f)
				matched[i] = true
			}
		}
	}

	var accountWide []Finding
	for i, f := range findings {
		if !matched[i] {
			accountWide = append(accountWide, f)
		}
	}
	return byComponent, accountWide
}
