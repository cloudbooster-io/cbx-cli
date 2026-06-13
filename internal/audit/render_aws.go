package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
)

// AWSAuditContext carries the live-AWS audit metadata RenderAWSMarkdown
// needs at the top of the report — values the discover layer already
// resolved (account / identity / regions) plus the event-count estimate
// (plan §7.7). State and source mode runs don't have an equivalent
// context, so they keep using the mode-agnostic RenderMarkdown.
type AWSAuditContext struct {
	AccountID string
	Identity  string
	// CallerARN is the raw ARN of the identity the audit ran as
	// (discResult.Identity.ARN). Distinct from Identity, which may be a
	// rendered display string. Threaded through so the post-LLM severity
	// post-process can drop the auditor's own IAM-user finding (the
	// recurring #1 false positive). Empty disables that drop.
	CallerARN  string
	Regions    []string
	EventCount int

	// AccountPosture carries account-level configuration the prompt
	// builder renders as an `==== ACCOUNT POSTURE ====` block.
	// Populated by the AWS discovery layer (see discover/aws/account_posture.go).
	AccountPosture *AccountPosture

	// DiscoveryIntegrityFindings are deterministic `warning` findings
	// the discovery-integrity probe produced (see DiscoveryIntegrityFinding
	// and discover/aws/integrity.go). They're carried on the context — not
	// appended to the returned Result — because RunFromResources renders the
	// report inline, so the findings must be merged BEFORE rendering. Empty
	// on a healthy run.
	DiscoveryIntegrityFindings []Finding

	// RulePack records which rung of the rulepack resolve ladder served
	// the rules that grounded this audit (pack version, source, content
	// hash — see rulesbundle.Provenance). Rendered into the report
	// header and serialized into the .state.json sidecar; a sweep
	// verdict that can't name its pack is unscoreable. Nil when unknown
	// (state/source-mode audits, older state files).
	RulePack *rulesbundle.Provenance `json:"rule_pack,omitempty"`
}

// RenderAWSMarkdown emits the AWS-mode report shape per plan §7.7 +
// §7.12 with a documentation-style layout:
//
//   - Title + GitHub alert block with run metadata
//   - Executive summary table (severity counts + actions)
//   - TL;DR alert (CAUTION/WARNING/NOTE depending on worst severity)
//   - Table of contents linking to severity sections
//   - Severity-grouped finding cards (CRITICAL → INFO), each card has:
//   - Title
//   - GitHub alert block keyed to severity (CAUTION/WARNING/IMPORTANT/NOTE)
//   - Resource as a code block (not inline) so long URNs wrap cleanly
//   - Service / Rule / Component as a metadata line
//   - Description as prose
//   - Remediation in a quoted callout with a wrench icon
//
// GitHub-flavoured alerts (`> [!CAUTION]`) render as colored callouts
// in GitHub, VS Code, Obsidian, and most modern Markdown viewers; they
// degrade to a quoted block in plainer renderers. Critically, no raw
// HTML is emitted — every primitive used here is real Markdown so the
// file renders identically in any pipeline.
//
// "Primary component" assignment matches partitionFindingsByComponent
// — findings inherit the first component (by sorted order) whose
// Resources set contains them, then surface as a metadata pill on the
// finding card.
func RenderAWSMarkdown(result *Result, ctx AWSAuditContext) string {
	var sb strings.Builder

	writeReportHeader(&sb, ctx, result)
	writeExecutiveBrief(&sb, ctx, result)
	writeArchitectureDiagram(&sb, result.DiagramSVGFile, result.DiagramSVG, result.Diagram)
	writeExecutiveSummary(&sb, result.Findings)
	writeTLDR(&sb, result.Findings)
	writeTableOfContents(&sb, result.Findings)

	urnToComponent := componentLabelByURN(result.Components)
	writeFindingsBySeverity(&sb, result.Findings, urnToComponent)

	writeComponentsSection(&sb, result.Components)

	writeFooter(&sb, ctx)

	return sb.String()
}

// writeExecutiveBrief is a prose-style top-of-report summary aimed at
// a stakeholder who won't scroll past the first page: one paragraph
// of context, a one-line posture rating, and a numbered list of the
// top critical-or-high titles with their resource names. The data
// driving the prose is purely the findings list — no LLM is needed —
// but the framing reads like a human-written brief.
func writeExecutiveBrief(sb *strings.Builder, ctx AWSAuditContext, result *Result) {
	sb.WriteString("## Executive Summary\n\n")

	region := firstOrEmpty(ctx.Regions)
	if region == "<region>" || region == "" {
		region = "the audited region"
	} else {
		region = "`" + region + "`"
	}
	fmt.Fprintf(sb,
		"This audit reviewed **%d component%s** in %s and identified **%d finding%s** grounded against CloudBooster's curated AWS knowledge.\n\n",
		len(result.Components), plural(len(result.Components)),
		region,
		len(result.Findings), plural(len(result.Findings)))

	// Posture rating — one-glance verdict before the breakdown.
	counts := countBySeverity(result.Findings)
	crit, high, warn := counts[SeverityCritical], counts[SeverityHigh], counts[SeverityWarning]
	posture, posturePrefix := posturePill(crit, high, warn, len(result.Findings))
	sb.WriteString("**Posture:** " + posture + ". " + posturePrefix + "\n\n")

	// Top concerns — first N critical+high titles with their resource
	// shortnames. Skips this block entirely on clean accounts.
	top := topConcerns(result.Findings, 5)
	if len(top) == 0 {
		return
	}
	sb.WriteString("**Top concerns:**\n\n")
	for i, t := range top {
		fmt.Fprintf(sb, "%d. %s %s — `%s`\n", i+1, severityEmoji(t.Severity), t.Title, shortResourceForBrief(t.Resource))
	}
	sb.WriteString("\nSee the severity sections below for full details and remediations.\n\n---\n\n")
}

// posturePill returns the verdict pill (emoji + label) plus a one-
// line follow-on sentence describing the urgency. Picks the worst
// category present so the verdict matches reader intuition.
func posturePill(crit, high, warn, total int) (string, string) {
	switch {
	case crit > 0:
		return "🔴 **Urgent**", fmt.Sprintf("%d critical issue%s need%s attention today, with %d high-severity follow-on%s for this sprint.",
			crit, plural(crit), pluralVerb(crit), high, plural(high))
	case high > 0:
		return "🟠 **Action required**", fmt.Sprintf("%d high-severity issue%s should be addressed this sprint.", high, plural(high))
	case warn > 0:
		return "🟡 **Watch**", fmt.Sprintf("%d warning%s — no critical or high findings, but worth scheduling.", warn, plural(warn))
	case total > 0:
		return "🟢 **Healthy**", "Only informational findings — posture is in good shape."
	default:
		return "🟢 **Clean**", "No findings — account posture is in good shape."
	}
}

// topConcernEntry is a slim view of a Finding used by topConcerns to
// avoid leaking the wider Finding shape into the brief renderer.
type topConcernEntry struct {
	Title    string
	Resource string
	Severity string
}

// topConcerns returns the worst-N findings (critical first, then
// high) for the executive brief. Stable order: as encountered, so a
// stakeholder sees the same ranking the LLM produced. Skips warning/
// info — they're surfaced lower in the report.
func topConcerns(findings []Finding, n int) []topConcernEntry {
	out := make([]topConcernEntry, 0, n)
	for _, f := range findings {
		if strings.EqualFold(f.Severity, SeverityCritical) {
			out = append(out, topConcernEntry{f.Title, f.Resource, f.Severity})
			if len(out) >= n {
				return out
			}
		}
	}
	for _, f := range findings {
		if strings.EqualFold(f.Severity, SeverityHigh) {
			out = append(out, topConcernEntry{f.Title, f.Resource, f.Severity})
			if len(out) >= n {
				return out
			}
		}
	}
	return out
}

// shortResourceForBrief trims a CB-style URN to its trailing ID — what
// a stakeholder cares about is the resource name, not the URN scheme.
func shortResourceForBrief(urn string) string {
	if urn == "" {
		return "—"
	}
	if i := strings.LastIndex(urn, "/"); i >= 0 && i < len(urn)-1 {
		return urn[i+1:]
	}
	return urn
}

// writeArchitectureDiagram emits the Architecture section of the
// markdown report. The SVG is the only diagram we ship.
//
// Strategy: prefer a markdown image link (`![alt](file.svg)`) to a
// sibling .svg file when one was written. That renders in every
// viewer (GitHub, GitLab, VS Code preview, mdBook, Pandoc, …)
// without inline-SVG sanitization issues. When no sibling file is
// available, fall back to inline `<svg>` which works in
// raw-HTML-aware viewers and degrades to source text in strict ones.
//
// Skipped entirely when no diagram was produced.
func writeArchitectureDiagram(sb *strings.Builder, svgFile, svg, _ string) {
	if strings.TrimSpace(svgFile) == "" && strings.TrimSpace(svg) == "" {
		return
	}
	sb.WriteString("## Architecture\n\n")
	switch {
	case strings.TrimSpace(svgFile) != "":
		sb.WriteString("![CloudBooster architecture diagram](")
		sb.WriteString(svgFile)
		sb.WriteString(")\n\n")
	case strings.TrimSpace(svg) != "":
		sb.WriteString(svg)
		sb.WriteString("\n\n")
	}
}

// writeReportHeader writes the title plus a GitHub-style NOTE block
// with the run metadata. Putting the metadata in an alert (rather than
// a bullet list) groups the values visually and avoids the "form-style
// label/value" feel the previous version had.
func writeReportHeader(sb *strings.Builder, ctx AWSAuditContext, result *Result) {
	sb.WriteString("# CloudBooster Audit\n\n")
	sb.WriteString("_Live AWS posture audit · grounded in CloudBooster knowledge_\n\n")

	sb.WriteString("> [!NOTE]\n")
	if ctx.AccountID != "" {
		sb.WriteString("> **Account** `" + ctx.AccountID + "`")
		if len(ctx.Regions) > 0 {
			sb.WriteString("  ·  **Region** `" + strings.Join(ctx.Regions, ", ") + "`")
		}
		sb.WriteString("  \n")
	}
	if ctx.Identity != "" {
		sb.WriteString("> **Identity** `" + ctx.Identity + "`  \n")
	}
	if p := ctx.RulePack; p != nil {
		short := p.ContentSHA256
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Fprintf(sb, "> **Rules** pack v%d (schema %d)  ·  source `%s`  ·  `%s`", p.PackVersion, p.SchemaVersion, p.Source, short)
		if p.Stale || p.Degraded {
			sb.WriteString("  ·  ⚠ degraded — see LLM-CB-RULES-STALE")
		}
		sb.WriteString("  \n")
	}
	fmt.Fprintf(sb, "> **Findings** %d  ·  **Components** %d  ·  **CloudTrail** ~%d Read events\n\n",
		len(result.Findings), len(result.Components), ctx.EventCount)
}

// writeExecutiveSummary renders the severity breakdown as a three-
// column table: emoji + name + count + suggested action. The action
// column gives the reader an immediate sense of urgency without
// scrolling to the TL;DR.
func writeExecutiveSummary(sb *strings.Builder, findings []Finding) {
	counts := countBySeverity(findings)
	// Rename the prior "Executive Summary" heading now that the new
	// prose brief above owns that title — this stays the breakdown
	// table users skim while the brief reads as the narrative intro.
	sb.WriteString("## Severity Breakdown\n\n")
	if len(findings) == 0 {
		sb.WriteString("_No findings — account posture is in good shape._\n\n")
		return
	}
	sb.WriteString("| | Severity | Count | Action |\n")
	sb.WriteString("|---|---|---|---|\n")
	actions := map[string]string{
		SeverityCritical: "Address immediately",
		SeverityHigh:     "Address this sprint",
		SeverityWarning:  "Schedule in backlog",
		SeverityInfo:     "Optional improvements",
	}
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		c := counts[sev]
		if c == 0 {
			continue
		}
		fmt.Fprintf(sb, "| %s | **%s** | %d | %s |\n",
			severityEmoji(sev), strings.ToUpper(sev), c, actions[sev])
	}
	sb.WriteString("\n")
}

// writeTLDR emits a single GitHub alert keyed to the worst severity
// present, with a one-line urgency summary. CAUTION for critical,
// WARNING for high, IMPORTANT for warning, NOTE for info-only or
// empty.
func writeTLDR(sb *strings.Builder, findings []Finding) {
	counts := countBySeverity(findings)
	crit, high, warn, info := counts[SeverityCritical], counts[SeverityHigh], counts[SeverityWarning], counts[SeverityInfo]

	if crit == 0 && high == 0 && warn == 0 && info == 0 {
		sb.WriteString("> [!TIP]\n> **No findings.** Account posture is in good shape.\n\n")
		return
	}

	var alert, line string
	switch {
	case crit > 0:
		alert = "CAUTION"
		line = fmt.Sprintf("**%d critical finding%s** require%s immediate attention.", crit, plural(crit), pluralVerb(crit))
		if high > 0 {
			line += fmt.Sprintf(" Plus %d high-severity follow-on%s.", high, plural(high))
		}
	case high > 0:
		alert = "WARNING"
		line = fmt.Sprintf("**%d high-severity finding%s** should be addressed this sprint.", high, plural(high))
	case warn > 0:
		alert = "IMPORTANT"
		line = fmt.Sprintf("**%d warning%s** — schedule for the backlog.", warn, plural(warn))
	default:
		alert = "NOTE"
		line = fmt.Sprintf("%d informational finding%s — review at leisure.", info, plural(info))
	}
	sb.WriteString("> [!" + alert + "]\n> " + line + "\n\n")
}

// writeTableOfContents lists the severity sections that have entries,
// each linking to the corresponding H2 below. Keeps the report
// navigable in long runs without making the reader scroll.
func writeTableOfContents(sb *strings.Builder, findings []Finding) {
	counts := countBySeverity(findings)
	if len(findings) == 0 {
		return
	}
	sb.WriteString("## Contents\n\n")
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		c := counts[sev]
		if c == 0 {
			continue
		}
		title := severityTitle(sev)
		anchor := strings.ToLower(strings.ReplaceAll(title, " ", "-"))
		fmt.Fprintf(sb, "- %s [%s](#%s) — %d\n", severityEmoji(sev), title, anchor, c)
	}
	sb.WriteString("\n")
}

// writeFindingsBySeverity emits one H2 section per non-empty severity.
// Findings within a section are rendered as card-style blocks with a
// GitHub alert + metadata + remediation callout.
func writeFindingsBySeverity(sb *strings.Builder, findings []Finding, urnToComponent map[string]string) {
	grouped := groupBySeverity(findings)
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		list := grouped[sev]
		if len(list) == 0 {
			continue
		}
		title := severityTitle(sev)
		fmt.Fprintf(sb, "## %s %s\n\n", severityEmoji(sev), title)
		for i, f := range list {
			writeFindingCard(sb, f, urnToComponent[f.Resource])
			if i < len(list)-1 {
				sb.WriteString("---\n\n")
			}
		}
		sb.WriteString("\n")
	}
}

// writeFindingCard renders one finding as a card-style block. Layout:
//
//	### Finding title
//	> [!ALERT-KIND]
//	> One-line severity + rule reference
//
//	**Resource**
//	```
//	aws://...
//	```
//
//	**Service** IAM  ·  **Component** cb-primitive: cb:aws:iam/role@v1
//
//	Description prose…
//
//	> 🔧 **Remediation**
//	> remediation prose…
func writeFindingCard(sb *strings.Builder, f Finding, component string) {
	sb.WriteString("### " + f.Title + "\n\n")

	// Severity callout keyed to the GitHub alert type that best
	// matches the urgency. CAUTION (red) for critical/high, IMPORTANT
	// (purple) for warning, NOTE (blue) for info.
	alert := alertKindFor(f.Severity)
	sb.WriteString("> [!" + alert + "]\n")
	sb.WriteString("> **" + strings.ToUpper(f.Severity) + "**")
	if f.RuleID != "" {
		sb.WriteString("  ·  Rule `" + f.RuleID + "`")
	}
	sb.WriteString("\n\n")

	if f.Resource != "" {
		sb.WriteString("**Resource**\n\n```\n" + f.Resource + "\n```\n\n")
	}

	var meta []string
	if f.Service != "" {
		meta = append(meta, "**Service** "+f.Service)
	}
	if component != "" {
		meta = append(meta, "**Component** `"+component+"`")
	}
	if len(meta) > 0 {
		sb.WriteString(strings.Join(meta, "  ·  ") + "\n\n")
	}

	if f.Description != "" {
		sb.WriteString(f.Description + "\n\n")
	}

	if f.Remediation != "" {
		// Multi-line remediations stay readable by quoting every line
		// rather than collapsing onto one >.
		sb.WriteString("> 🔧 **Remediation**\n>\n")
		for _, line := range strings.Split(strings.TrimSpace(f.Remediation), "\n") {
			sb.WriteString("> " + line + "\n")
		}
		sb.WriteString("\n")
	}
}

// writeComponentsSection renders the component inventory at the
// bottom of the report — useful as a flat resource map but kept out
// of the way of the urgency-driven finding list above. Components
// with no findings get the 🟢 chip so a clean component reads
// immediately as "OK".
func writeComponentsSection(sb *strings.Builder, components []group.Component) {
	if len(components) == 0 {
		return
	}
	sb.WriteString("---\n\n## Component Inventory\n\n")
	sb.WriteString("_Resources grouped by CB primitive or tag-based component. Findings are listed under each component for cross-reference._\n\n")

	for _, c := range components {
		fmt.Fprintf(sb, "- **%s** `%s` — %d resource%s\n",
			c.Kind, c.Name, len(c.Resources), plural(len(c.Resources)))
		for _, urn := range c.Resources {
			sb.WriteString("  - `" + urn + "`\n")
		}
	}
	sb.WriteString("\n")
}

// writeFooter is the closing meta block: re-run hint + a horizontal
// rule separator so the body doesn't bleed into adjacent doc content
// when pasted into a larger report.
func writeFooter(sb *strings.Builder, ctx AWSAuditContext) {
	sb.WriteString("---\n\n")
	region := firstOrEmpty(ctx.Regions)
	sb.WriteString("_Re-run with_ `cbx audit aws --region " + region + "` _to refresh this report._\n")
}

// alertKindFor maps a CB severity to a GitHub alert kind. CAUTION
// (red) covers critical + high so emergency-level findings share the
// strongest visual treatment. IMPORTANT (purple) for warning, NOTE
// (blue) for info.
func alertKindFor(sev string) string {
	switch strings.ToLower(sev) {
	case SeverityCritical, SeverityHigh:
		return "CAUTION"
	case SeverityWarning:
		return "IMPORTANT"
	default:
		return "NOTE"
	}
}

// severityTitle is the human heading for a severity section.
// Capitalised + "Findings" suffix to read well as an H2.
func severityTitle(sev string) string {
	switch strings.ToLower(sev) {
	case SeverityCritical:
		return "Critical Findings"
	case SeverityHigh:
		return "High-Severity Findings"
	case SeverityWarning:
		return "Warnings"
	case SeverityInfo:
		return "Informational"
	}
	return strings.ToUpper(sev)
}

// severityEmoji returns the badge glyph paired with a severity.
// Visual hierarchy: red > orange > yellow > white.
func severityEmoji(sev string) string {
	switch strings.ToLower(sev) {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityWarning:
		return "🟡"
	case SeverityInfo:
		return "⚪"
	}
	return "•"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func pluralVerb(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}

func firstOrEmpty(s []string) string {
	if len(s) == 0 {
		return "<region>"
	}
	return s[0]
}

// componentLabelByURN returns a "resource URN → component label" map
// matching partitionFindingsByComponent's first-match ordering. Used
// by writeFindingCard to render the component pill inline on each
// finding.
func componentLabelByURN(components []group.Component) map[string]string {
	if len(components) == 0 {
		return map[string]string{}
	}
	ordered := make([]group.Component, len(components))
	copy(ordered, components)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Kind != ordered[j].Kind {
			return ordered[i].Kind < ordered[j].Kind
		}
		return ordered[i].Name < ordered[j].Name
	})
	out := map[string]string{}
	for _, c := range ordered {
		label := c.Kind + ": " + c.Name
		for _, urn := range c.Resources {
			if _, exists := out[urn]; !exists {
				out[urn] = label
			}
		}
	}
	return out
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
