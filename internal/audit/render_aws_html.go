package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
)

// RenderAWSHTML emits a self-contained HTML report intended to be
// opened directly in a browser (file://) — no server, no external CSS
// or JS, no fonts pulled from CDNs. The layout mirrors a small SPA
// dashboard: a fixed left sidebar that lists every finding (with
// severity filters, search, and sort), and a scrollable main pane
// with the full finding cards. Clicking a sidebar row smooth-scrolls
// to the finding; scrolling the main pane updates which sidebar row
// is highlighted (scrollspy via IntersectionObserver).
//
// Design vocabulary is lifted from ../platform-app/fe (Inter, cyan
// accent, zinc surfaces, rounded-xl, translucent dark mode) so the
// report feels continuous with the web product. Buttons in the
// toolbar download the embedded markdown source and trigger
// browser-native Save-as-PDF via window.print().
//
// Design intent: a security reviewer opens the .html, narrows to
// critical only, walks the list top-to-bottom, exports a PDF for the
// stakeholder readout. No tooling install required.
func RenderAWSHTML(result *Result, ctx AWSAuditContext, markdownSource string) string {
	counts := countBySeverity(result.Findings)
	findingsByComponent, accountWide := partitionFindingsByComponent(result.Findings, result.Components)

	// Sort findings by severity so both the sidebar and the main pane
	// surface critical/high first. The sidebar uses the same order so
	// scrollspy aligns naturally.
	sortedFindings := append([]Finding(nil), result.Findings...)
	sort.SliceStable(sortedFindings, func(i, j int) bool {
		return severityRank(sortedFindings[i].Severity) > severityRank(sortedFindings[j].Severity)
	})

	// Assign every finding a stable DOM id so the sidebar can link to
	// it and the scrollspy can map back. RuleIDs aren't unique within
	// a run (e.g. the same EBS rule fires once per volume), so we
	// suffix with the position.
	ids := make([]string, len(sortedFindings))
	for i, f := range sortedFindings {
		ids[i] = makeFindingID(f, i)
	}

	var body strings.Builder
	renderHTMLBody(&body, result, ctx, counts, findingsByComponent, accountWide, sortedFindings, ids)

	mdName := defaultMarkdownFilename(ctx)
	return renderHTMLShell(body.String(), markdownSource, mdName, ctx)
}

// architectureDiagramHTMLBlueprint emits the diagram section with the
// Blueprint title block, a height-capped scrollable schematic, and
// an "Open in fullscreen" button. The NOTES keyed-findings table
// is no longer rendered — the sidebar finding list to the left of
// the report carries that information, with severity chips inside
// the SVG boxes acting as visual anchors.
func architectureDiagramHTMLBlueprint(sb *strings.Builder, svg, mermaid string, findings []Finding, ctx AWSAuditContext, components interface{}) {
	if svg == "" && mermaid == "" {
		return
	}
	sb.WriteString(`<section class="diagram-section bp-section" id="diagram-section">`)
	renderBlueprintTitleBlock(sb, ctx, findings)
	if svg != "" {
		sb.WriteString(`<div class="bp-toolbar">`)
		sb.WriteString(`<span class="bp-toolbar-hint">scroll inside the diagram to pan · click <strong>fullscreen</strong> for a closer look</span>`)
		sb.WriteString(`<button type="button" class="bp-fs-btn" id="bp-fullscreen-btn" aria-label="Open diagram in fullscreen">⛶ fullscreen</button>`)
		sb.WriteString(`</div>`)
		sb.WriteString(`<div class="diagram-wrap bp-wrap" id="bp-diagram-wrap">`)
		sb.WriteString(svg)
		sb.WriteString(`</div>`)
		// Fullscreen modal — hidden by default, populated by cloning
		// the SVG into it on click (avoids serving the SVG twice in
		// the page body).
		sb.WriteString(`<div class="bp-modal" id="bp-modal" role="dialog" aria-hidden="true" aria-label="Architecture diagram fullscreen">`)
		sb.WriteString(`<div class="bp-modal-bar"><span class="bp-modal-title">Architecture · ` + htmlEscape(ctx.AccountID) + `</span><button type="button" class="bp-modal-close" id="bp-modal-close" aria-label="Close fullscreen">✕</button></div>`)
		sb.WriteString(`<div class="bp-modal-body" id="bp-modal-body"></div>`)
		sb.WriteString(`</div>`)
		// Inline glue: clone the SVG into the modal on open and
		// drop it on close. Uses safe DOM APIs only (no innerHTML
		// assignment of untrusted text — the SVG node is already a
		// trusted element built by the renderer).
		sb.WriteString(`<script>(function(){var btn=document.getElementById('bp-fullscreen-btn');var modal=document.getElementById('bp-modal');var body=document.getElementById('bp-modal-body');var close=document.getElementById('bp-modal-close');var src=document.querySelector('#bp-diagram-wrap > svg');if(!btn||!modal||!body||!close||!src)return;function clear(node){while(node.firstChild)node.removeChild(node.firstChild);}function open(){clear(body);body.appendChild(src.cloneNode(true));modal.classList.add('open');modal.setAttribute('aria-hidden','false');document.body.style.overflow='hidden';}function shut(){modal.classList.remove('open');modal.setAttribute('aria-hidden','true');clear(body);document.body.style.overflow='';}btn.addEventListener('click',open);close.addEventListener('click',shut);modal.addEventListener('click',function(e){if(e.target===modal)shut();});document.addEventListener('keydown',function(e){if(e.key==='Escape'&&modal.classList.contains('open'))shut();});})();</script>`)
	}
	// Mermaid block intentionally omitted — the SVG is the only
	// architecture diagram. (The mermaid form was a duplicate that
	// added load weight + a CDN dependency without ever looking as
	// good as the SVG.)
	_ = mermaid
	sb.WriteString(`</section>`)
	_ = findings
}

// renderBlueprintTitleBlock prints the sheet header that sits above
// the schematic SVG: SHEET tag, big CBX AUDIT title, sub-line with
// the VPC + CIDR + discovery hint, and the meta cells on the right
// (DATE, REV, COMPS, FINDINGS chip summary).
func renderBlueprintTitleBlock(sb *strings.Builder, ctx AWSAuditContext, findings []Finding) {
	sb.WriteString(`<div class="bp-title">`)
	sb.WriteString(`<div class="bp-title-left">`)
	sb.WriteString(`<div class="bp-sheet-tag">SHEET A1 · INFRASTRUCTURE TOPOLOGY</div>`)
	title := "CBX AUDIT"
	if ctx.AccountID != "" {
		title += " · " + htmlEscape(ctx.AccountID)
	}
	if len(ctx.Regions) > 0 {
		title += " / " + htmlEscape(strings.Join(ctx.Regions, " · "))
	}
	sb.WriteString(`<h2 class="bp-title-main">` + title + `</h2>`)
	sb.WriteString(`<div class="bp-subline">drawn from live discovery</div>`)
	sb.WriteString(`</div>`)

	// Right-side meta cells.
	sb.WriteString(`<div class="bp-meta-row">`)
	renderBPCell(sb, "DATE", time.Now().Format("2006-01-02"), true)
	renderBPCell(sb, "REV", "r.01", true)
	if ctx.Identity != "" {
		renderBPCell(sb, "IDENTITY", htmlEscape(shortIdentity(ctx.Identity)), true)
	}
	// FINDINGS chips
	if len(findings) > 0 {
		_, keys := assignFindingKeys(findings)
		counts := map[string]int{}
		for _, k := range keys {
			counts[k.Severity]++
		}
		var chips strings.Builder
		writeChip := func(sev, letter string) {
			if c := counts[sev]; c > 0 {
				chips.WriteString(`<span class="bp-tag" style="background:` + severityChipColourBySeverity(sev) + `">` + letter + `·` + fmt.Sprint(c) + `</span>`)
			}
		}
		writeChip(SeverityCritical, "C")
		writeChip(SeverityHigh, "H")
		writeChip(SeverityWarning, "W")
		writeChip(SeverityInfo, "I")
		sb.WriteString(`<div class="bp-cell"><div class="bp-cell-label">FINDINGS</div><div class="bp-cell-chips">` + chips.String() + `</div></div>`)
	}
	sb.WriteString(`</div>`) // .bp-meta-row
	sb.WriteString(`</div>`) // .bp-title
}

// renderBPCell prints one of the right-side meta cells (DATE/REV/…).
func renderBPCell(sb *strings.Builder, label, value string, mono bool) {
	cls := "bp-cell"
	if mono {
		cls += " bp-cell-mono"
	}
	sb.WriteString(`<div class="` + cls + `"><div class="bp-cell-label">` + label + `</div><div class="bp-cell-value">` + value + `</div></div>`)
}

// shortIdentity trims an "arn:aws:sts::123:assumed-role/Role/foo" to
// just the trailing user identifier so it fits in the title meta cell.
func shortIdentity(id string) string {
	if idx := strings.LastIndex(id, "/"); idx >= 0 {
		id = id[idx+1:]
	}
	if len(id) > 26 {
		id = id[:25] + "…"
	}
	return id
}

func defaultMarkdownFilename(ctx AWSAuditContext) string {
	if ctx.AccountID != "" {
		return ctx.AccountID + "_audit_report.md"
	}
	return "audit_report.md"
}

// makeFindingID composes a CSS-safe anchor id for a finding. We pair
// the rule ID with the run-local index so duplicate-rule findings
// (e.g. "EBS volume is not encrypted" × 3) each get a unique anchor.
func makeFindingID(f Finding, idx int) string {
	rule := strings.ToLower(f.RuleID)
	if rule == "" {
		rule = "finding"
	}
	// Cheap CSS-id sanitiser: keep [a-z0-9-_], replace anything else.
	var b strings.Builder
	for _, r := range rule {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return fmt.Sprintf("f-%s-%d", b.String(), idx)
}

// severityRank turns a severity string into a sortable int (higher =
// more urgent). Kept local so this file can stand alone if extracted
// later.
func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// renderHTMLShell wraps the report body in the page chrome: meta tags,
// inline CSS, inline JS, and the embedded markdown source as a
// <script type="text/plain"> block so the "Download MD" button can
// hand a real file back to the user without needing the .md sibling
// on disk.
func renderHTMLShell(body, markdownSource, mdFileName string, ctx AWSAuditContext) string {
	mdJSON, _ := json.Marshal(markdownSource)
	mdNameJSON, _ := json.Marshal(mdFileName)
	titleSuffix := ""
	if ctx.AccountID != "" {
		titleSuffix = " · " + ctx.AccountID
	}
	_ = time.Now() // generated timestamp is rendered inside the body now

	return fmt.Sprintf(htmlShellTemplate,
		htmlEscape("CloudBooster Audit"+titleSuffix),
		body,
		string(mdJSON),
		string(mdNameJSON),
	)
}

func renderHTMLBody(sb *strings.Builder, result *Result, ctx AWSAuditContext, counts map[string]int, byComponent map[string][]Finding, accountWide []Finding, sortedFindings []Finding, ids []string) {
	// Build the chip-key map once so sidebar / diagram / detail card
	// can all show the same "C1" / "H7" / … id for the same finding.
	keyMap, _ := assignFindingKeys(result.Findings)
	chipKeys := make([]string, len(sortedFindings))
	for i, f := range sortedFindings {
		chipKeys[i] = keyMap[findingFingerprint(f)]
	}
	sb.WriteString(`<div class="app">`)
	renderSidebar(sb, ctx, result, counts, sortedFindings, ids, chipKeys)
	renderMain(sb, ctx, result, counts, byComponent, accountWide, sortedFindings, ids)
	sb.WriteString(`</div>`) // .app
}

// renderSidebar emits the navigation column: account chip, severity
// filters, sort dropdown, search, and the compact findings list.
func renderSidebar(sb *strings.Builder, ctx AWSAuditContext, result *Result, counts map[string]int, sortedFindings []Finding, ids []string, chipKeys []string) {
	sb.WriteString(`<aside class="sidebar">`)

	// Brand + account chip
	sb.WriteString(`<div class="sidebar-brand">`)
	sb.WriteString(`<span class="brand-mark"></span>`)
	sb.WriteString(`<div class="sidebar-brand-text"><div class="sidebar-brand-name">CloudBooster</div><div class="sidebar-brand-sub">AWS audit</div></div>`)
	sb.WriteString(`</div>`)

	if ctx.AccountID != "" {
		sb.WriteString(`<div class="sidebar-account">`)
		sb.WriteString(`<div class="sidebar-account-label">Account</div>`)
		sb.WriteString(`<div class="sidebar-account-id">` + htmlEscape(ctx.AccountID) + `</div>`)
		if len(ctx.Regions) > 0 {
			sb.WriteString(`<div class="sidebar-account-region">` + htmlEscape(strings.Join(ctx.Regions, ", ")) + `</div>`)
		}
		sb.WriteString(`</div>`)
	}

	// Severity filter pills
	sb.WriteString(`<div class="sidebar-filters">`)
	sb.WriteString(`<div class="sidebar-section-label">Filter by severity</div>`)
	sb.WriteString(`<div class="filter-grid">`)
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		count := counts[sev]
		extra := ""
		if count == 0 {
			extra = " disabled"
		}
		fmt.Fprintf(sb,
			`<button class="filter-pill sev-%s%s" data-sev-toggle="%s" type="button">`+
				`<span class="filter-dot"></span>`+
				`<span class="filter-label">%s</span>`+
				`<span class="filter-count">%d</span>`+
				`</button>`,
			sev, extra, sev, strings.ToUpper(sev), count)
	}
	sb.WriteString(`</div>`)
	sb.WriteString(`</div>`)

	// Sort + Search
	sb.WriteString(`<div class="sidebar-controls">`)
	sb.WriteString(`<div class="input-wrap"><svg class="input-icon" viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="9" cy="9" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M14 14L17 17" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`)
	sb.WriteString(`<input type="search" id="finding-search" placeholder="Search findings…" autocomplete="off" /></div>`)
	sb.WriteString(`<div class="control-row">`)
	sb.WriteString(`<label class="control-label" for="sort-select">Sort</label>`)
	sb.WriteString(`<select id="sort-select" class="control-select">`)
	sb.WriteString(`<option value="severity" selected>Severity</option>`)
	sb.WriteString(`<option value="service">Service</option>`)
	sb.WriteString(`<option value="resource">Resource</option>`)
	sb.WriteString(`<option value="rule">Rule ID</option>`)
	sb.WriteString(`</select>`)
	sb.WriteString(`<button type="button" id="reset-filters" class="control-reset" title="Reset filters">Reset</button>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`</div>`)

	// Findings list
	sb.WriteString(`<div class="sidebar-list-header"><span class="sidebar-list-title">Findings</span> <span class="sidebar-list-count" id="visible-count">` + fmt.Sprintf("%d", len(sortedFindings)) + `</span></div>`)
	sb.WriteString(`<nav class="sidebar-list" id="finding-nav">`)
	for i, f := range sortedFindings {
		key := ""
		if i < len(chipKeys) {
			key = chipKeys[i]
		}
		renderSidebarFindingRow(sb, f, ids[i], key)
	}
	if len(sortedFindings) == 0 {
		sb.WriteString(`<div class="empty-list">No findings</div>`)
	}
	sb.WriteString(`</nav>`)

	sb.WriteString(`<div class="sidebar-footer">Generated ` + htmlEscape(time.Now().UTC().Format("2006-01-02 15:04 UTC")) + `</div>`)
	sb.WriteString(`</aside>`)
}

func renderSidebarFindingRow(sb *strings.Builder, f Finding, id, chipKey string) {
	service := f.Service
	if service == "" {
		service = "—"
	}
	resourceShort := shortResource(f.Resource)
	searchText := strings.ToLower(strings.Join([]string{f.Title, f.Resource, f.Service, f.RuleID, f.Description, f.Remediation, chipKey}, " "))
	// Data attributes drive client-side filtering + sorting without
	// reparsing the DOM. data-rank holds the severity weight so the
	// JS sort doesn't have to re-look up.
	fmt.Fprintf(sb,
		`<a class="finding-row sev-%s" href="#%s" data-target="%s" data-sev="%s" data-rank="%d" data-service="%s" data-resource="%s" data-rule="%s" data-search="%s">`,
		f.Severity, id, id, f.Severity, severityRank(f.Severity),
		htmlEscape(strings.ToLower(service)), htmlEscape(strings.ToLower(resourceShort)),
		htmlEscape(strings.ToLower(f.RuleID)), htmlEscape(searchText))
	sb.WriteString(`<span class="row-bar"></span>`)
	if chipKey != "" {
		// Same coloured pill used in the SVG, so the eye can match
		// "C2 on the diagram" → "C2 in the sidebar" instantly.
		sb.WriteString(`<span class="row-key" style="background:` + severityChipColourBySeverity(f.Severity) + `">` + chipKey + `</span>`)
	}
	sb.WriteString(`<div class="row-body">`)
	sb.WriteString(`<div class="row-title">` + htmlEscape(f.Title) + `</div>`)
	sb.WriteString(`<div class="row-meta"><span class="row-service">` + htmlEscape(service) + `</span><span class="row-dot">·</span><span class="row-resource">` + htmlEscape(resourceShort) + `</span></div>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`</a>`)
}

// shortResource extracts the human-readable tail of a CB-style URN
// (`aws://eu-central-1/AWS::EC2::Instance/i-007e…`) so sidebar rows
// don't waste space repeating the URN scheme.
func shortResource(urn string) string {
	if urn == "" {
		return "—"
	}
	if i := strings.LastIndex(urn, "/"); i >= 0 && i < len(urn)-1 {
		tail := urn[i+1:]
		if len(tail) > 40 {
			return tail[:37] + "…"
		}
		return tail
	}
	if len(urn) > 40 {
		return urn[:37] + "…"
	}
	return urn
}

// renderMain emits the right pane: sticky toolbar, hero card with the
// account/region/CloudTrail summary, components accordion (preserves
// the rich grouping context from the MD report), and the full
// findings cards.
func renderMain(sb *strings.Builder, ctx AWSAuditContext, result *Result, counts map[string]int, byComponent map[string][]Finding, accountWide []Finding, sortedFindings []Finding, ids []string) {
	sb.WriteString(`<main class="main">`)

	// Toolbar
	sb.WriteString(`<header class="toolbar">`)
	sb.WriteString(`<div class="toolbar-stats">`)
	fmt.Fprintf(sb, `<div class="toolbar-stat"><div class="ts-count">%d</div><div class="ts-label">Findings</div></div>`, len(result.Findings))
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		c := counts[sev]
		if c == 0 {
			continue
		}
		fmt.Fprintf(sb,
			`<div class="toolbar-stat sev-%s"><div class="ts-count">%d</div><div class="ts-label">%s</div></div>`,
			sev, c, strings.ToUpper(sev))
	}
	sb.WriteString(`</div>`)
	sb.WriteString(`<div class="toolbar-actions">`)
	sb.WriteString(`<button type="button" class="btn btn-icon" id="theme-toggle" aria-label="Toggle theme" title="Toggle theme">`)
	sb.WriteString(`<svg class="theme-icon theme-icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>`)
	sb.WriteString(`<svg class="theme-icon theme-icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`)
	sb.WriteString(`</button>`)
	sb.WriteString(`<button type="button" class="btn btn-secondary" id="download-md">Download Markdown</button>`)
	sb.WriteString(`<button type="button" class="btn btn-primary" id="save-pdf">Save as PDF</button>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`</header>`)

	sb.WriteString(`<div class="main-content">`)

	// Hero
	sb.WriteString(`<section class="hero">`)
	sb.WriteString(`<div class="hero-tag">Grounded in CloudBooster knowledge</div>`)
	sb.WriteString(`<h1 class="hero-title">AWS Audit Report</h1>`)
	sb.WriteString(`<dl class="hero-meta">`)
	if ctx.AccountID != "" {
		sb.WriteString(`<div class="hero-meta-item"><dt>Account</dt><dd><code>` + htmlEscape(ctx.AccountID) + `</code></dd></div>`)
	}
	if ctx.Identity != "" {
		sb.WriteString(`<div class="hero-meta-item"><dt>Identity</dt><dd>` + htmlEscape(shortenIdentityForHTML(ctx.Identity)) + `</dd></div>`)
	}
	if len(ctx.Regions) > 0 {
		sb.WriteString(`<div class="hero-meta-item"><dt>Regions</dt><dd>` + htmlEscape(strings.Join(ctx.Regions, ", ")) + `</dd></div>`)
	}
	fmt.Fprintf(sb, `<div class="hero-meta-item"><dt>Components</dt><dd>%d</dd></div>`, len(result.Components))
	fmt.Fprintf(sb, `<div class="hero-meta-item"><dt>CloudTrail</dt><dd>~%d Read events</dd></div>`, ctx.EventCount)
	sb.WriteString(`</dl>`)
	sb.WriteString(`</section>`)

	architectureDiagramHTMLBlueprint(sb, result.DiagramSVG, result.Diagram, result.Findings, ctx, result.Components)

	// Empty-state
	if len(sortedFindings) == 0 {
		sb.WriteString(`<section class="empty-main"><div class="empty-emoji">🟢</div><h2>All clear</h2><p>No findings against this account.</p></section>`)
		sb.WriteString(`</div></main>`)
		return
	}

	// Findings (severity-sorted, each with a stable id for scrollspy
	// and sidebar links). Component context is rendered inline on each
	// card so the relationship is preserved without forcing the user
	// to scan two trees.
	sb.WriteString(`<section class="findings-section" id="findings-section">`)
	urnToComponent := buildURNToComponentMap(result.Components)
	for i, f := range sortedFindings {
		renderFindingCardHTML(sb, f, ids[i], urnToComponent[f.Resource])
	}
	sb.WriteString(`</section>`)

	sb.WriteString(`</div>`) // .main-content
	sb.WriteString(`</main>`)
	_ = byComponent
	_ = accountWide
}

// buildURNToComponentMap returns a "resource URN → component label"
// lookup using the same first-match ordering as
// partitionFindingsByComponent so per-card component pills match the
// markdown report's component groupings.
func buildURNToComponentMap(components []group.Component) map[string]string {
	ordered := append([]group.Component(nil), components...)
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

func renderFindingCardHTML(sb *strings.Builder, f Finding, id string, component string) {
	searchText := strings.ToLower(strings.Join([]string{f.Title, f.Resource, f.Service, f.RuleID, f.Description, f.Remediation}, " "))
	fmt.Fprintf(sb,
		`<article class="finding sev-%s" id="%s" data-sev="%s" data-rank="%d" data-service="%s" data-resource="%s" data-rule="%s" data-search="%s">`,
		f.Severity, id, f.Severity, severityRank(f.Severity),
		htmlEscape(strings.ToLower(f.Service)), htmlEscape(strings.ToLower(shortResource(f.Resource))),
		htmlEscape(strings.ToLower(f.RuleID)), htmlEscape(searchText))
	sb.WriteString(`<div class="finding-header">`)
	fmt.Fprintf(sb, `<span class="sev-chip sev-%s">%s</span>`, f.Severity, strings.ToUpper(f.Severity))
	if component != "" {
		sb.WriteString(`<span class="component-pill">` + htmlEscape(component) + `</span>`)
	}
	sb.WriteString(`</div>`)
	sb.WriteString(`<h3 class="finding-title">` + htmlEscape(f.Title) + `</h3>`)

	sb.WriteString(`<dl class="finding-meta">`)
	if f.Resource != "" {
		sb.WriteString(`<div class="fm-row"><dt>Resource</dt><dd><code>` + htmlEscape(f.Resource) + `</code></dd></div>`)
	}
	if f.Service != "" {
		sb.WriteString(`<div class="fm-row"><dt>Service</dt><dd>` + htmlEscape(f.Service) + `</dd></div>`)
	}
	if f.RuleID != "" && !isLLMRuleID(f.RuleID) {
		sb.WriteString(`<div class="fm-row"><dt>Rule</dt><dd><code>` + htmlEscape(f.RuleID) + `</code></dd></div>`)
	}
	sb.WriteString(`</dl>`)
	if f.Description != "" {
		sb.WriteString(`<p class="finding-description">` + htmlEscape(f.Description) + `</p>`)
	}
	if f.Remediation != "" {
		sb.WriteString(`<div class="finding-remediation">`)
		sb.WriteString(`<div class="remediation-label">Remediation</div>`)
		sb.WriteString(`<div class="remediation-body">` + htmlEscape(f.Remediation) + `</div>`)
		sb.WriteString(`</div>`)
	}
	sb.WriteString(`</article>`)
}

// isLLMRuleID reports whether a Finding.RuleID is the auto-generated
// LLM hash form (e.g. "LLM-claudecode-5d18d80c", "LLM-CB-UNGROUNDED",
// "LLM-ERROR"). These ids exist for internal de-dup / tracking and
// don't carry user-meaningful information, so the report hides them.
func isLLMRuleID(id string) bool {
	return strings.HasPrefix(id, "LLM-")
}

// shortenIdentityForHTML mirrors the CLI's truncation of long SSO ARNs
// — the trailing user/role is the only useful bit on a wide screen.
func shortenIdentityForHTML(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i < len(arn)-1 {
		return ".../" + arn[i+1:]
	}
	return arn
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// htmlShellTemplate is the standalone document scaffold. Inline CSS +
// JS so the file works under file:// with zero dependencies. Visual
// system mirrors platform-app/fe (Inter + cyan accent + zinc surfaces
// + translucent dark mode + rounded-xl corners + soft shadows) so the
// report feels like a continuation of the web product. The %% in CSS
// rules is the fmt-required escape for literal percent — keep both
// %% sequences intact when editing.
const htmlShellTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
  /* ---- Design tokens (lifted from ../platform-app/fe/src/index.css) ----
     Light is default. Dark is applied via [data-theme="dark"] (set
     explicitly by the toggle button) or via prefers-color-scheme when
     the theme is "auto". The toggle persists to localStorage so the
     reader's choice survives reloads. */
  :root, [data-theme="light"] {
    --bg-page: rgb(250 250 250);
    --bg-surface: rgb(255 255 255);
    --bg-surface-hover: rgb(244 244 245);
    --bg-code: rgb(244 244 245);
    --text-primary: rgb(24 24 27);
    --text-muted: rgb(82 82 91);
    --text-subtle: rgb(113 113 122);
    --border-default: rgb(228 228 231);
    --border-muted: rgb(244 244 245);
    --accent: rgb(8 145 178);
    --accent-muted: rgb(22 163 184);
    --accent-surface: rgb(236 254 255);
    --accent-border: rgb(165 243 252);
    --accent-strong: rgb(14 116 144);
    --ring-accent: rgba(8, 145, 178, 0.5);
    --btn-primary-bg: rgb(8 145 178);
    --btn-primary-text: rgb(255 255 255);

    --sev-crit-bg:  rgb(254 226 226); --sev-crit-text: rgb(153 27 27);  --sev-crit-bar: rgb(220 38 38);
    --sev-high-bg:  rgb(255 237 213); --sev-high-text: rgb(154 52 18);  --sev-high-bar: rgb(234 88 12);
    --sev-warn-bg:  rgb(254 249 195); --sev-warn-text: rgb(133 77 14);  --sev-warn-bar: rgb(202 138 4);
    --sev-info-bg:  rgb(219 234 254); --sev-info-text: rgb(30 64 175);  --sev-info-bar: rgb(37 99 235);

    --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
    --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.06), 0 2px 4px -2px rgb(0 0 0 / 0.06);
    --shadow-lg: 0 10px 24px -8px rgb(0 0 0 / 0.12), 0 4px 8px -4px rgb(0 0 0 / 0.08);
    --shadow-accent: 0 0 50px rgba(34, 211, 238, 0.10);

    --radius-sm: 0.5rem;
    --radius-md: 0.75rem;
    --radius-lg: 1rem;

    --sidebar-w: 320px;

    /* Blueprint diagram tokens — consumed by the .bp-* chrome below
       AND by the inlined architecture SVG, which references them as
       var(--bp-*, <light fallback>) from its embedded stylesheet (see
       internal/audit/diagram_svg.go, svgThemeStyle). Light values here
       must equal those fallbacks; keep all three theme blocks in sync. */
    --bp-paper: #FAF7F0;
    --bp-node: #FFFFFF;
    --bp-ink: #1C1917;
    --bp-subtle: #57534E;
    --bp-muted: #78716C;
    --bp-faint: #A8A29E;
    --bp-accent: #C2410C;
    --bp-red: #B91C1C;
    --bp-slate: #64748B;
    --bp-slate-strong: #475569;
    --bp-teal: #0D9488;
    --bp-lime: #65A30D;
    --bp-notes-bg: rgba(255,255,255,0.55);
  }
  [data-theme="dark"] {
    --bg-page: #07080b;
    --bg-surface: rgba(255 255 255 / 0.04);
    --bg-surface-hover: rgba(255 255 255 / 0.08);
    --bg-code: rgba(255 255 255 / 0.06);
    --text-primary: rgb(244 244 245);
    --text-muted: rgba(244 244 245 / 0.7);
    --text-subtle: rgba(244 244 245 / 0.5);
    --border-default: rgba(255 255 255 / 0.1);
    --border-muted: rgba(255 255 255 / 0.05);
    --accent: rgb(103 232 249);
    --accent-muted: rgb(165 243 252);
    --accent-surface: rgba(34 211 238 / 0.1);
    --accent-border: rgba(34 211 238 / 0.3);
    --accent-strong: rgb(165 243 252);
    --ring-accent: rgba(34, 211, 238, 0.6);
    --btn-primary-bg: rgba(34, 211, 238, 0.25);

    --sev-crit-bg:  rgba(220 38 38 / 0.15); --sev-crit-text: rgb(252 165 165); --sev-crit-bar: rgb(248 113 113);
    --sev-high-bg:  rgba(234 88 12 / 0.15); --sev-high-text: rgb(253 186 116); --sev-high-bar: rgb(251 146 60);
    --sev-warn-bg:  rgba(202 138 4 / 0.15); --sev-warn-text: rgb(253 224 71);  --sev-warn-bar: rgb(250 204 21);
    --sev-info-bg:  rgba(37 99 235 / 0.15); --sev-info-text: rgb(147 197 253); --sev-info-bar: rgb(96 165 250);

    --shadow-sm: 0 1px 2px rgba(0,0,0,0.4);
    --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.5), 0 2px 4px -2px rgba(0,0,0,0.3);
    --shadow-lg: 0 12px 24px -8px rgba(0,0,0,0.55);

    --bp-paper: #141210;
    --bp-node: #1C1917;
    --bp-ink: #E7E5E4;
    --bp-subtle: #D6D3D1;
    --bp-muted: #A8A29E;
    --bp-faint: #57534E;
    --bp-accent: #FB923C;
    --bp-red: #F87171;
    --bp-slate: #94A3B8;
    --bp-slate-strong: #CBD5E1;
    --bp-teal: #2DD4BF;
    --bp-lime: #A3E635;
    --bp-notes-bg: rgba(255,255,255,0.04);
  }
  /* Auto theme follows the OS preference when no explicit choice
     has been made. The toggle's third state ("auto") removes the
     [data-theme] attribute so this kicks in. */
  @media (prefers-color-scheme: dark) {
    [data-theme="auto"] {
      --bg-page: #07080b;
      --bg-surface: rgba(255 255 255 / 0.04);
      --bg-surface-hover: rgba(255 255 255 / 0.08);
      --bg-code: rgba(255 255 255 / 0.06);
      --text-primary: rgb(244 244 245);
      --text-muted: rgba(244 244 245 / 0.7);
      --text-subtle: rgba(244 244 245 / 0.5);
      --border-default: rgba(255 255 255 / 0.1);
      --border-muted: rgba(255 255 255 / 0.05);
      --accent: rgb(103 232 249);
      --accent-muted: rgb(165 243 252);
      --accent-surface: rgba(34 211 238 / 0.1);
      --accent-border: rgba(34 211 238 / 0.3);
      --accent-strong: rgb(165 243 252);
      --ring-accent: rgba(34, 211, 238, 0.6);
      --btn-primary-bg: rgba(34, 211, 238, 0.25);
      --sev-crit-bg:  rgba(220 38 38 / 0.15); --sev-crit-text: rgb(252 165 165); --sev-crit-bar: rgb(248 113 113);
      --sev-high-bg:  rgba(234 88 12 / 0.15); --sev-high-text: rgb(253 186 116); --sev-high-bar: rgb(251 146 60);
      --sev-warn-bg:  rgba(202 138 4 / 0.15); --sev-warn-text: rgb(253 224 71);  --sev-warn-bar: rgb(250 204 21);
      --sev-info-bg:  rgba(37 99 235 / 0.15); --sev-info-text: rgb(147 197 253); --sev-info-bar: rgb(96 165 250);
      --shadow-sm: 0 1px 2px rgba(0,0,0,0.4);
      --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.5), 0 2px 4px -2px rgba(0,0,0,0.3);
      --shadow-lg: 0 12px 24px -8px rgba(0,0,0,0.55);
      --bp-paper: #141210;
      --bp-node: #1C1917;
      --bp-ink: #E7E5E4;
      --bp-subtle: #D6D3D1;
      --bp-muted: #A8A29E;
      --bp-faint: #57534E;
      --bp-accent: #FB923C;
      --bp-red: #F87171;
      --bp-slate: #94A3B8;
      --bp-slate-strong: #CBD5E1;
      --bp-teal: #2DD4BF;
      --bp-lime: #A3E635;
      --bp-notes-bg: rgba(255,255,255,0.04);
    }
  }
  /* The architecture SVG ships its own prefers-color-scheme block so
     the standalone .svg artifact is dark-mode aware. Vars defined ON
     the svg element beat the inherited ones above, so when the reader
     forces LIGHT via the toggle while the OS is dark, this
     higher-specificity rule re-asserts the light palette on the
     element itself. (Forced dark needs no twin: the svg's own media
     block only ever sets the same dark values.) */
  [data-theme="light"] .cbx-arch {
    --bp-paper: #FAF7F0; --bp-node: #FFFFFF; --bp-ink: #1C1917;
    --bp-subtle: #57534E; --bp-muted: #78716C; --bp-faint: #A8A29E;
    --bp-accent: #C2410C; --bp-red: #B91C1C; --bp-slate: #64748B;
    --bp-slate-strong: #475569; --bp-teal: #0D9488; --bp-lime: #65A30D;
  }

  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: "Inter", ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: var(--bg-page);
    color: var(--text-primary);
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
    font-feature-settings: "ss01", "cv02", "cv11";
    overflow: hidden;
  }
  code, pre {
    font-family: "JetBrains Mono", "SF Mono", Menlo, Monaco, Consolas, monospace;
    font-size: 0.82em;
    background: var(--bg-code);
    padding: 0.15em 0.45em;
    border-radius: 0.375rem;
  }
  h1, h2, h3, h4 { font-weight: 600; letter-spacing: -0.012em; }
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb {
    background: var(--border-default);
    border-radius: 5px;
    border: 2px solid var(--bg-page);
  }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-subtle); }

  /* ---- App layout: sidebar + main ---- */
  .app {
    display: grid;
    grid-template-columns: var(--sidebar-w) 1fr;
    height: 100vh;
  }
  .sidebar {
    background: var(--bg-surface);
    border-right: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .main {
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: var(--bg-page);
  }
  .main-content {
    overflow-y: auto;
    padding: 1.75rem 2rem 4rem;
    scroll-behavior: smooth;
  }

  /* ---- Sidebar: brand ---- */
  .sidebar-brand {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1.25rem 1.25rem 1rem;
    border-bottom: 1px solid var(--border-muted);
  }
  .brand-mark {
    width: 28px; height: 28px;
    border-radius: 0.5rem;
    background: linear-gradient(135deg, var(--accent), var(--accent-muted));
    box-shadow: var(--shadow-accent);
    flex-shrink: 0;
  }
  .sidebar-brand-name {
    font-weight: 700;
    font-size: 0.92rem;
    letter-spacing: -0.005em;
  }
  .sidebar-brand-sub {
    font-size: 0.72rem;
    color: var(--text-muted);
  }

  /* ---- Sidebar: account chip ---- */
  .sidebar-account {
    padding: 0.85rem 1.25rem 1rem;
    border-bottom: 1px solid var(--border-muted);
  }
  .sidebar-account-label {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    font-weight: 600;
    margin-bottom: 0.3rem;
  }
  .sidebar-account-id {
    font-family: "JetBrains Mono", "SF Mono", Menlo, Monaco, monospace;
    font-size: 0.92rem;
    font-weight: 500;
    color: var(--text-primary);
  }
  .sidebar-account-region {
    font-size: 0.78rem;
    color: var(--text-muted);
    margin-top: 0.2rem;
  }

  /* ---- Sidebar: filters ---- */
  .sidebar-filters { padding: 0.85rem 1.25rem 0.5rem; }
  .sidebar-section-label {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    font-weight: 600;
    margin-bottom: 0.5rem;
  }
  .filter-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.4rem;
  }
  .filter-pill {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    padding: 0.45rem 0.6rem;
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    cursor: pointer;
    font: inherit;
    font-size: 0.78rem;
    color: var(--text-primary);
    transition: border-color 0.12s, background 0.12s;
    text-align: left;
  }
  .filter-pill:hover { border-color: var(--accent-border); background: var(--accent-surface); }
  .filter-pill.disabled { opacity: 0.35; cursor: default; }
  .filter-pill.disabled:hover { border-color: var(--border-default); background: var(--bg-surface); }
  .filter-pill.filtered-out { opacity: 0.5; }
  .filter-pill.filtered-out .filter-label { text-decoration: line-through; }
  .filter-dot {
    width: 8px; height: 8px;
    border-radius: 50%%;
    flex-shrink: 0;
  }
  .filter-pill.sev-critical .filter-dot { background: var(--sev-crit-bar); }
  .filter-pill.sev-high     .filter-dot { background: var(--sev-high-bar); }
  .filter-pill.sev-warning  .filter-dot { background: var(--sev-warn-bar); }
  .filter-pill.sev-info     .filter-dot { background: var(--sev-info-bar); }
  .filter-label { flex: 1; font-weight: 500; }
  .filter-count {
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
    font-size: 0.72rem;
  }

  /* ---- Sidebar: search + sort ---- */
  .sidebar-controls {
    padding: 0.75rem 1.25rem 0.85rem;
    border-bottom: 1px solid var(--border-muted);
  }
  .input-wrap { position: relative; margin-bottom: 0.5rem; }
  .input-icon {
    position: absolute;
    left: 0.65rem; top: 50%%;
    transform: translateY(-50%%);
    width: 14px; height: 14px;
    color: var(--text-muted);
    pointer-events: none;
  }
  #finding-search {
    width: 100%%;
    padding: 0.5rem 0.65rem 0.5rem 2rem;
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-primary);
    font: inherit;
    font-size: 0.86rem;
  }
  #finding-search::placeholder { color: var(--text-subtle); }
  #finding-search:focus {
    outline: 2px solid var(--ring-accent);
    outline-offset: -1px;
    border-color: transparent;
  }
  .control-row { display: flex; align-items: center; gap: 0.5rem; }
  .control-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    font-weight: 600;
  }
  .control-select {
    flex: 1;
    padding: 0.35rem 0.5rem;
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font: inherit;
    font-size: 0.82rem;
    cursor: pointer;
  }
  .control-reset {
    background: transparent;
    border: 1px solid var(--border-default);
    color: var(--text-muted);
    padding: 0.35rem 0.6rem;
    border-radius: var(--radius-sm);
    font: inherit;
    font-size: 0.78rem;
    cursor: pointer;
  }
  .control-reset:hover { color: var(--text-primary); border-color: var(--text-muted); }

  /* ---- Sidebar: findings list ---- */
  .sidebar-list-header {
    padding: 0.85rem 1.25rem 0.45rem;
    display: flex;
    align-items: baseline;
    justify-content: space-between;
  }
  .sidebar-list-title {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    font-weight: 600;
  }
  .sidebar-list-count {
    font-size: 0.72rem;
    background: var(--accent-surface);
    color: var(--accent);
    padding: 0.1rem 0.5rem;
    border-radius: 999px;
    font-variant-numeric: tabular-nums;
    font-weight: 600;
  }
  .sidebar-list {
    flex: 1;
    overflow-y: auto;
    padding: 0 0.65rem 1rem;
  }
  .finding-row {
    display: flex;
    gap: 0.55rem;
    padding: 0.55rem 0.65rem;
    border-radius: var(--radius-sm);
    text-decoration: none;
    color: var(--text-primary);
    transition: background 0.12s;
    position: relative;
    cursor: pointer;
  }
  .finding-row:hover { background: var(--bg-surface-hover); }
  .finding-row.active { background: var(--accent-surface); }
  .finding-row.active .row-title { color: var(--accent-strong); font-weight: 600; }
  .finding-row.hidden { display: none; }
  .row-bar {
    width: 3px;
    border-radius: 2px;
    flex-shrink: 0;
    background: var(--border-default);
  }
  .finding-row.sev-critical .row-bar { background: var(--sev-crit-bar); }
  .finding-row.sev-high     .row-bar { background: var(--sev-high-bar); }
  .finding-row.sev-warning  .row-bar { background: var(--sev-warn-bar); }
  .finding-row.sev-info     .row-bar { background: var(--sev-info-bar); }
  /* Chip-key pill, mirrors the box chip inside the SVG so the eye
     can match diagram → sidebar entries instantly. */
  .row-key {
    display: inline-block; flex-shrink: 0;
    align-self: flex-start; margin-top: 1px;
    min-width: 26px; padding: 1px 5px;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 0.66rem; font-weight: 800; letter-spacing: 0.02em;
    color: #fff; text-align: center;
  }
  .row-body { flex: 1; min-width: 0; }
  .row-title {
    font-size: 0.84rem;
    font-weight: 500;
    line-height: 1.35;
    color: var(--text-primary);
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .row-meta {
    font-size: 0.72rem;
    color: var(--text-muted);
    margin-top: 0.15rem;
    display: flex;
    gap: 0.35rem;
    align-items: center;
  }
  .row-service { text-transform: lowercase; }
  .row-resource {
    font-family: "JetBrains Mono", "SF Mono", Menlo, Monaco, monospace;
    font-size: 0.68rem;
    color: var(--text-subtle);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .row-dot { color: var(--text-subtle); }
  .empty-list {
    padding: 1.5rem 0.65rem;
    text-align: center;
    color: var(--text-muted);
    font-size: 0.85rem;
  }
  .sidebar-footer {
    padding: 0.75rem 1.25rem;
    border-top: 1px solid var(--border-muted);
    font-size: 0.7rem;
    color: var(--text-subtle);
    font-family: "JetBrains Mono", "SF Mono", Menlo, Monaco, monospace;
  }

  /* ---- Main: toolbar ---- */
  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 2rem;
    border-bottom: 1px solid var(--border-default);
    background: var(--bg-surface);
    backdrop-filter: saturate(180%%) blur(6px);
    -webkit-backdrop-filter: saturate(180%%) blur(6px);
    flex-shrink: 0;
    gap: 1rem;
  }
  .toolbar-stats { display: flex; gap: 0.5rem; flex-wrap: wrap; }
  .toolbar-stat {
    padding: 0.35rem 0.85rem;
    border-radius: 0.5rem;
    background: var(--bg-surface-hover);
    text-align: center;
    min-width: 64px;
    border: 1px solid var(--border-muted);
  }
  .toolbar-stat .ts-count {
    font-size: 1.15rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    line-height: 1.1;
    letter-spacing: -0.015em;
  }
  .toolbar-stat .ts-label {
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-top: 0.1rem;
    font-weight: 600;
  }
  .toolbar-stat.sev-critical .ts-count { color: var(--sev-crit-text); }
  .toolbar-stat.sev-high     .ts-count { color: var(--sev-high-text); }
  .toolbar-stat.sev-warning  .ts-count { color: var(--sev-warn-text); }
  .toolbar-stat.sev-info     .ts-count { color: var(--sev-info-text); }
  .toolbar-actions { display: flex; gap: 0.5rem; flex-shrink: 0; }
  .btn {
    border-radius: var(--radius-md);
    font: inherit;
    font-size: 0.85rem;
    font-weight: 500;
    padding: 0.45rem 0.95rem;
    cursor: pointer;
    transition: opacity 0.12s, background 0.12s;
  }
  .btn-primary { background: var(--btn-primary-bg); color: var(--btn-primary-text); border: none; }
  .btn-primary:hover { opacity: 0.9; }
  .btn-secondary {
    background: var(--accent-surface);
    color: var(--accent);
    border: 1px solid var(--accent-border);
  }
  .btn-secondary:hover { opacity: 0.85; }
  .btn:focus-visible { outline: 2px solid var(--ring-accent); outline-offset: 2px; }
  .btn-icon {
    background: transparent;
    color: var(--text-muted);
    border: 1px solid var(--border-default);
    width: 2.15rem;
    height: 2.15rem;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .btn-icon:hover { color: var(--text-primary); border-color: var(--text-muted); }
  .theme-icon { width: 1.05rem; height: 1.05rem; }
  /* Show sun in dark mode (click = switch to light) and moon in light
     mode (click = switch to dark). Auto-mode inherits via media query. */
  [data-theme="light"] .theme-icon-sun,
  [data-theme="auto"] .theme-icon-sun { display: none; }
  [data-theme="dark"] .theme-icon-moon { display: none; }
  @media (prefers-color-scheme: dark) {
    [data-theme="auto"] .theme-icon-sun { display: inline-block; }
    [data-theme="auto"] .theme-icon-moon { display: none; }
  }

  /* ---- Main: hero ---- */
  .hero {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-lg);
    padding: 1.5rem 1.75rem;
    margin-bottom: 1.75rem;
    box-shadow: var(--shadow-sm);
    position: relative;
    overflow: hidden;
  }
  .hero::after {
    content: "";
    position: absolute;
    inset: 0;
    pointer-events: none;
    background: radial-gradient(circle at top right, var(--accent-surface), transparent 65%%);
    opacity: 0.7;
  }
  .hero > * { position: relative; z-index: 1; }
  .hero-tag {
    display: inline-block;
    color: var(--accent);
    background: var(--accent-surface);
    border: 1px solid var(--accent-border);
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 0.2rem 0.55rem;
    border-radius: 999px;
    margin-bottom: 0.75rem;
  }
  .hero-title {
    margin: 0 0 1rem;
    font-size: 1.5rem;
    letter-spacing: -0.02em;
  }
  .hero-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 0.85rem 1.25rem;
    margin: 0;
  }
  .hero-meta-item dt {
    color: var(--text-muted);
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
    margin-bottom: 0.15rem;
  }
  .hero-meta-item dd { margin: 0; font-size: 0.88rem; word-break: break-word; color: var(--text-primary); }

  /* ---- Main: architecture diagram ----
     The SVG payload is fully self-contained — see
     internal/audit/diagram_svg.go. The CSS here is only about
     framing it nicely inside the report: matched border radius,
     subtle shadow, header bar above with a "share this" cue. */
  .diagram-section {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-lg);
    padding: 1.25rem 1.5rem 1.25rem;
    margin-bottom: 1.75rem;
    box-shadow: var(--shadow-sm);
  }
  .diagram-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .diagram-title {
    margin: 0;
    font-size: 1.15rem;
    letter-spacing: -0.015em;
  }
  .diagram-meta {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }
  .diagram-pill {
    background: var(--accent-surface);
    color: var(--accent);
    border: 1px solid var(--accent-border);
    border-radius: 999px;
    padding: 0.2rem 0.55rem;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .diagram-hint {
    font-size: 0.72rem;
    color: var(--text-muted);
    letter-spacing: 0.04em;
  }
  .diagram-wrap {
    border-radius: var(--radius-md);
    overflow: auto;
    /* Cap to ~80%% viewport height so the diagram never pushes the
       findings off-screen on smaller laptops. The SVG keeps its
       natural width via min-width so wide accounts scroll
       horizontally inside the card. */
    max-height: 80vh;
    background: #F8FAFC;
    box-shadow: inset 0 0 0 1px var(--border-muted);
    line-height: 0;
  }
  .diagram-wrap > svg {
    display: block;
    min-width: 1280px;
    width: 100%%;
    height: auto;
  }

  /* ---- Blueprint diagram chrome (title block + toolbar + modal) ----
     The entire section (title + toolbar + diagram) is capped at 60vh
     so the diagram never takes more than 60%% of the user's monitor.
     The diagram-wrap inside takes whatever vertical space is left
     after the title chrome, and preserveAspectRatio="meet" scales
     the artwork to fit. */
  .bp-section { background: var(--bp-paper); border-radius: 0; padding: 0.85rem 1.1rem 0.65rem; }
  .bp-section .bp-title { padding-bottom: 0.55rem; margin-bottom: 0.65rem; }
  .bp-section .bp-title-main { font-size: 17px; margin: 0.15rem 0 0.2rem; }
  .bp-section .bp-sheet-tag, .bp-section .bp-subline { font-size: 9.5px; }
  .bp-section .bp-toolbar { padding: 0.3rem 0.1rem 0.45rem; }
  .bp-section .bp-wrap {
    background: var(--bp-paper);
    border-radius: 0;
    box-shadow: none;
    line-height: 0;
    border-top: 1px solid var(--bp-ink);
    border-bottom: 1px solid var(--bp-ink);
    /* The whole section (title + toolbar + diagram) lands around
       45%% of the viewport because the diagram-wrap caps at 35vh.
       Calculation: title chrome ≈ 70-90px, toolbar ≈ 30px, and the
       wrap itself ≤ 35vh — together they sit comfortably above
       the first finding cards on a typical 900-1100px screen. */
    max-height: 35vh;
    overflow: hidden;
    text-align: center;
  }
  .bp-section .bp-wrap > svg {
    display: inline-block;
    width: auto;
    max-width: 100%%;
    height: 35vh;
    max-height: 35vh;
  }
  .bp-toolbar {
    display: flex; align-items: center; justify-content: space-between;
    gap: 0.75rem; padding: 0.4rem 0.1rem 0.55rem;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
  }
  .bp-toolbar-hint { font-size: 10.5px; color: var(--bp-muted); letter-spacing: 0.02em; }
  .bp-toolbar-hint strong { color: var(--bp-ink); font-weight: 700; }
  .bp-fs-btn {
    all: unset; cursor: pointer; padding: 4px 12px; font-size: 11px; font-weight: 700;
    letter-spacing: 0.06em; background: var(--bp-ink); color: var(--bp-paper);
    font-family: 'JetBrains Mono', ui-monospace, monospace; border: 1px solid var(--bp-ink);
  }
  .bp-fs-btn:hover { background: var(--bp-accent); border-color: var(--bp-accent); }
  /* Fullscreen modal */
  .bp-modal {
    display: none; position: fixed; inset: 0; background: rgba(28, 25, 23, 0.75);
    z-index: 9999; padding: 24px;
    flex-direction: column; align-items: stretch;
  }
  .bp-modal.open { display: flex; }
  .bp-modal-bar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 8px 12px; background: var(--bp-paper); border: 1.5px solid var(--bp-ink); border-bottom: 0;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
  }
  .bp-modal-title { font-size: 12px; font-weight: 700; letter-spacing: 0.06em; color: var(--bp-ink); }
  .bp-modal-close {
    all: unset; cursor: pointer; padding: 2px 10px; font-size: 14px; font-weight: 700;
    color: var(--bp-ink);
  }
  .bp-modal-close:hover { color: var(--bp-accent); }
  .bp-modal-body {
    flex: 1 1 auto; overflow: auto; background: var(--bp-paper);
    border: 1.5px solid var(--bp-ink); line-height: 0;
  }
  .bp-modal-body > svg { display: block; min-width: 1400px; width: 100%%; height: auto; }
  .bp-title { display: flex; justify-content: space-between; align-items: flex-start; gap: 1.25rem; padding-bottom: 0.75rem; border-bottom: 1.5px solid var(--bp-accent); margin-bottom: 1rem; }
  .bp-title-left { min-width: 0; flex: 1 1 auto; font-family: 'JetBrains Mono', ui-monospace, monospace; color: var(--bp-ink); }
  .bp-sheet-tag { font-size: 10px; letter-spacing: 0.18em; color: var(--bp-muted); font-weight: 700; }
  .bp-title-main { margin: 0.2rem 0 0.25rem; font-size: 20px; font-weight: 700; letter-spacing: -0.02em; font-family: 'JetBrains Mono', ui-monospace, monospace; line-height: 1.2; }
  .bp-subline { font-size: 11px; color: var(--bp-subtle); font-family: 'JetBrains Mono', ui-monospace, monospace; }
  .bp-meta-row { display: flex; gap: 0.9rem; font-family: 'JetBrains Mono', ui-monospace, monospace; flex: 0 0 auto; flex-wrap: wrap; }
  .bp-cell { border-left: 1px solid var(--bp-faint); padding-left: 0.625rem; min-width: 80px; }
  .bp-cell-label { font-size: 9px; letter-spacing: 0.18em; color: var(--bp-muted); font-weight: 700; }
  .bp-cell-value { font-size: 11px; font-weight: 600; color: var(--bp-ink); margin-top: 2px; }
  .bp-cell-mono .bp-cell-value { font-family: 'JetBrains Mono', ui-monospace, monospace; }
  .bp-cell-chips { display: inline-flex; gap: 6px; margin-top: 3px; }
  .bp-tag { color: #fff; padding: 1px 6px; font-size: 9px; font-weight: 800; font-family: 'JetBrains Mono', ui-monospace, monospace; letter-spacing: 0.04em; }
  .bp-notes { margin-top: 1.25rem; padding: 0.9rem 1rem; border: 1.5px solid var(--bp-ink); background: var(--bp-notes-bg); font-family: 'JetBrains Mono', ui-monospace, monospace; }
  .bp-notes-head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 0.6rem; }
  .bp-notes-title { font-size: 10px; font-weight: 700; letter-spacing: 0.18em; color: var(--bp-ink); }
  .bp-notes-hint { font-size: 10px; color: var(--bp-muted); letter-spacing: 0.06em; }
  .bp-notes-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px 28px; font-size: 10.5px; color: var(--bp-ink); }
  .bp-note { display: flex; gap: 8px; align-items: baseline; }
  .bp-note-key { color: #fff; padding: 1px 5px; font-size: 9.5px; font-weight: 800; font-family: 'JetBrains Mono', ui-monospace, monospace; min-width: 28px; text-align: center; display: inline-block; }
  .bp-note-txt { font-size: 10.5px; line-height: 1.35; }
  @media (max-width: 900px) { .bp-notes-grid { grid-template-columns: 1fr; } .bp-title { flex-direction: column; } }
  .diagram-source {
    margin-top: 0.85rem;
    font-size: 0.8rem;
  }
  .diagram-source summary {
    cursor: pointer;
    color: var(--text-muted);
    user-select: none;
  }
  .diagram-source summary:hover { color: var(--text-primary); }
  .diagram-source-pre {
    margin: 0.5rem 0 0;
    padding: 0.85rem 1rem;
    background: var(--bg-code);
    border-radius: var(--radius-sm);
    overflow-x: auto;
    font-size: 0.72rem;
    line-height: 1.5;
    max-height: 280px;
  }
  .diagram-source-pre code {
    background: none;
    padding: 0;
    border-radius: 0;
    font-size: inherit;
  }

  /* ---- Main: findings ---- */
  .findings-section { display: flex; flex-direction: column; gap: 0.85rem; }
  .finding {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
    padding: 1.1rem 1.35rem 1.25rem;
    box-shadow: var(--shadow-sm);
    transition: border-color 0.15s, box-shadow 0.15s, transform 0.12s;
    scroll-margin-top: 1rem;
  }
  .finding:hover { border-color: var(--accent-border); box-shadow: var(--shadow-md); }
  .finding.flash {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--ring-accent), var(--shadow-md);
  }
  .finding.hidden { display: none; }
  .finding-header {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    margin-bottom: 0.55rem;
    flex-wrap: wrap;
  }
  .sev-chip {
    display: inline-block;
    padding: 0.2rem 0.65rem;
    border-radius: 999px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    font-variant: all-small-caps;
  }
  .sev-chip.sev-critical { background: var(--sev-crit-bg); color: var(--sev-crit-text); }
  .sev-chip.sev-high     { background: var(--sev-high-bg); color: var(--sev-high-text); }
  .sev-chip.sev-warning  { background: var(--sev-warn-bg); color: var(--sev-warn-text); }
  .sev-chip.sev-info     { background: var(--sev-info-bg); color: var(--sev-info-text); }
  .component-pill {
    background: var(--bg-surface-hover);
    color: var(--text-muted);
    padding: 0.2rem 0.55rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 500;
  }
  .finding-title {
    margin: 0 0 0.65rem;
    font-size: 1.05rem;
    font-weight: 600;
    line-height: 1.4;
    color: var(--text-primary);
  }
  .finding-meta {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin: 0 0 0.85rem;
    font-size: 0.82rem;
  }
  .fm-row { display: grid; grid-template-columns: 80px 1fr; gap: 0.5rem; align-items: baseline; }
  .fm-row dt {
    color: var(--text-muted);
    font-weight: 500;
    text-transform: uppercase;
    font-size: 0.65rem;
    letter-spacing: 0.06em;
  }
  .fm-row dd { margin: 0; word-break: break-all; color: var(--text-primary); }
  .finding-description {
    margin: 0.5rem 0 0.85rem;
    font-size: 0.9rem;
    color: var(--text-primary);
  }
  .finding-remediation {
    background: var(--accent-surface);
    border: 1px solid var(--accent-border);
    padding: 0.85rem 1rem;
    border-radius: var(--radius-sm);
  }
  .remediation-label {
    font-weight: 600;
    color: var(--accent);
    text-transform: uppercase;
    font-size: 0.65rem;
    letter-spacing: 0.08em;
    margin-bottom: 0.35rem;
  }
  .remediation-body { font-size: 0.9rem; color: var(--text-primary); }

  /* ---- Main: empty state ---- */
  .empty-main {
    text-align: center;
    padding: 4rem 2rem;
    background: var(--bg-surface);
    border-radius: var(--radius-lg);
    border: 1px solid var(--border-default);
  }
  .empty-main .empty-emoji { font-size: 3rem; margin-bottom: 0.5rem; }
  .empty-main h2 { margin: 0 0 0.5rem; font-size: 1.4rem; }
  .empty-main p { margin: 0; color: var(--text-muted); }

  /* ---- Responsive: sidebar collapses below 900px ---- */
  @media (max-width: 900px) {
    body { overflow: auto; }
    .app { grid-template-columns: 1fr; height: auto; }
    .sidebar {
      border-right: none;
      border-bottom: 1px solid var(--border-default);
      height: auto;
    }
    .sidebar-list { max-height: 240px; }
    .main { overflow: visible; height: auto; }
    .main-content { overflow-y: visible; }
  }

  /* ---- Print stylesheet — properly paginated PDF export ----
     The screen layout (sidebar + scrolling main) doesn't translate
     to print, so we override aggressively: forced light palette for
     ink economy, paginated finding cards, a cover page assembled
     from the .pdf-cover injected by JS, an executive-summary page,
     and per-finding page-break-inside protection. */
  .pdf-cover, .pdf-page-footer { display: none; }
  @page {
    size: A4;
    margin: 18mm 14mm;
  }
  @media print {
    /* Force light palette so PDFs look right whether the viewer was
       in dark mode or not. Inline override beats [data-theme] cascade. */
    :root, [data-theme] {
      --bg-page: #ffffff;
      --bg-surface: #ffffff;
      --bg-surface-hover: #f4f4f5;
      --bg-code: #f4f4f5;
      --text-primary: #18181b;
      --text-muted: #52525b;
      --text-subtle: #71717a;
      --border-default: #e4e4e7;
      --border-muted: #f4f4f5;
      --accent: #0e7490;
      --accent-surface: #ecfeff;
      --accent-border: #a5f3fc;
      --accent-strong: #0e7490;
      --sev-crit-bg: #fee2e2; --sev-crit-text: #991b1b; --sev-crit-bar: #dc2626;
      --sev-high-bg: #ffedd5; --sev-high-text: #9a3412; --sev-high-bar: #ea580c;
      --sev-warn-bg: #fef9c5; --sev-warn-text: #854d0e; --sev-warn-bar: #ca8a04;
      --sev-info-bg: #dbeafe; --sev-info-text: #1e40af; --sev-info-bar: #2563eb;
      --bp-paper: #FAF7F0; --bp-node: #FFFFFF; --bp-ink: #1C1917;
      --bp-subtle: #57534E; --bp-muted: #78716C; --bp-faint: #A8A29E;
      --bp-accent: #C2410C; --bp-red: #B91C1C; --bp-slate: #64748B;
      --bp-slate-strong: #475569; --bp-teal: #0D9488; --bp-lime: #65A30D;
      --bp-notes-bg: rgba(255,255,255,0.55);
    }
    /* The architecture SVG defines its dark vars on itself under
       prefers-color-scheme; element-own definitions beat the inherited
       light values above, so re-assert light directly on the element.
       (Browsers usually evaluate print as light anyway — this is the
       belt to that suspender.) */
    html .cbx-arch {
      --bp-paper: #FAF7F0; --bp-node: #FFFFFF; --bp-ink: #1C1917;
      --bp-subtle: #57534E; --bp-muted: #78716C; --bp-faint: #A8A29E;
      --bp-accent: #C2410C; --bp-red: #B91C1C; --bp-slate: #64748B;
      --bp-slate-strong: #475569; --bp-teal: #0D9488; --bp-lime: #65A30D;
    }
    body {
      background: #fff;
      color: var(--text-primary);
      font-size: 10pt;
      overflow: visible;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    .app { display: block; height: auto; }
    .sidebar, .toolbar { display: none !important; }
    .main { overflow: visible; height: auto; display: block; }
    .main-content { overflow: visible; padding: 0; }
    .pdf-cover {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-height: 90vh;
      padding: 2rem 0 1rem;
      break-after: page;
      page-break-after: always;
    }
    .pdf-cover-top { display: flex; align-items: center; gap: 0.75rem; }
    .pdf-cover-top .brand-mark { width: 36px; height: 36px; }
    .pdf-cover-top-name { font-weight: 700; font-size: 1.1rem; }
    .pdf-cover-middle { margin: auto 0; }
    .pdf-cover-eyebrow {
      display: inline-block;
      color: var(--accent);
      background: var(--accent-surface);
      border: 1px solid var(--accent-border);
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      padding: 0.2rem 0.65rem;
      border-radius: 999px;
      margin-bottom: 1rem;
    }
    .pdf-cover-title {
      font-size: 2.4rem;
      letter-spacing: -0.025em;
      margin: 0.25rem 0 1.5rem;
      font-weight: 700;
    }
    .pdf-cover-meta {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.5rem 1.5rem;
      font-size: 0.95rem;
      max-width: 540px;
    }
    .pdf-cover-meta dt {
      color: var(--text-muted);
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 600;
      align-self: center;
    }
    .pdf-cover-meta dd {
      margin: 0;
      font-family: "JetBrains Mono", "SF Mono", Menlo, Monaco, monospace;
      font-size: 0.9rem;
    }
    .pdf-cover-bottom {
      font-size: 0.75rem;
      color: var(--text-muted);
      border-top: 1px solid var(--border-default);
      padding-top: 0.75rem;
    }

    /* Hide screen-only chrome */
    .hero::after { display: none; }
    .hero {
      border-radius: 0;
      border: 0;
      border-bottom: 2px solid var(--accent);
      padding: 0 0 1rem;
      margin-bottom: 1.5rem;
      box-shadow: none;
    }
    .hero-tag { display: none; }

    .findings-section { gap: 0.5rem; }
    .finding {
      background: #fff;
      box-shadow: none;
      border: 1px solid var(--border-default);
      border-left: 4px solid var(--border-default);
      border-radius: 4px;
      padding: 0.85rem 1rem;
      margin-bottom: 0.5rem;
      break-inside: avoid;
      page-break-inside: avoid;
    }
    .finding.sev-critical { border-left-color: var(--sev-crit-bar); }
    .finding.sev-high     { border-left-color: var(--sev-high-bar); }
    .finding.sev-warning  { border-left-color: var(--sev-warn-bar); }
    .finding.sev-info     { border-left-color: var(--sev-info-bar); }
    .finding.hidden { display: block !important; }
    .finding-title { font-size: 1rem; }
    .finding-remediation { background: #fafdfe; border: 1px solid #cce8ee; }

    /* Severity section headings start on a new page after the cover
       so each batch of cards gets clean pagination. */
    .findings-section > .pdf-severity-heading {
      font-size: 1.1rem;
      font-weight: 700;
      margin: 0 0 0.5rem;
      padding-top: 0.25rem;
      break-before: page;
      page-break-before: always;
    }
    .findings-section > .pdf-severity-heading:first-of-type {
      break-before: auto;
      page-break-before: auto;
    }
    .pdf-severity-heading[data-sev="critical"] { color: var(--sev-crit-text); }
    .pdf-severity-heading[data-sev="high"]     { color: var(--sev-high-text); }
    .pdf-severity-heading[data-sev="warning"]  { color: var(--sev-warn-text); }
    .pdf-severity-heading[data-sev="info"]     { color: var(--sev-info-text); }

    a { color: var(--accent); text-decoration: none; }

    /* Diagram prints between cover and findings. The SVG is
       deterministic so we just shrink it into the available width. */
    .diagram-section {
      box-shadow: none;
      border: 1px solid var(--border-default);
      border-radius: 4px;
      padding: 0.85rem 1rem;
      margin-bottom: 1rem;
      break-inside: avoid;
      page-break-inside: avoid;
    }
    .diagram-hint, .diagram-source { display: none; }
    /* Blueprint diagram chrome — hide screen-only affordances and
       collapsed JS-driven elements so they don't bleed into the
       printed page. */
    .bp-toolbar, .bp-modal { display: none !important; }
    .diagram-wrap, .bp-section .bp-wrap {
      background: #fff;
      box-shadow: none;
      max-height: none !important;
      overflow: visible !important;
    }
    /* Print-fit the schematic. The screen rules pin a 1280px min-width
       and a 35vh letterbox (built for scroll-and-pan); min-width beats
       max-width in CSS, so on an A4 page (~690px printable) the SVG
       overflowed right and the fixed height left dead space below.
       On paper the SVG must instead scale to page width — the root
       viewBox keeps the aspect ratio. */
    .diagram-wrap > svg, .bp-section .bp-wrap > svg {
      min-width: 0 !important;
      width: 100%% !important;
      max-width: 100%% !important;
      height: auto !important;
      max-height: none !important;
    }
    .bp-section { break-inside: avoid; page-break-inside: avoid; }
    /* Keep the first severity heading attached to its first card so
       the printed page doesn't end with an orphan "Critical Findings"
       title. The default break-before: auto already lets the heading
       flow after the diagram; this just guards against widow lines. */
    .pdf-severity-heading {
      break-after: avoid;
      page-break-after: avoid;
    }
    .pdf-severity-heading + .finding {
      break-before: avoid;
      page-break-before: avoid;
    }
  }
</style>
</head>
<body>
%s
<script id="md-source" type="text/plain">%s</script>
<script>
  (function() {
    'use strict';

    // Embedded markdown source for the Download button. The .md file
    // on disk is the authoritative copy; this is here so the HTML is
    // self-portable (emailable, archivable) without breaking the
    // download button if the .md is missing.
    const mdEl = document.getElementById('md-source');
    const mdText = mdEl ? mdEl.textContent : '';
    const mdFile = %s;

    // ---- Theme toggle (auto → light → dark → auto) ----
    // Persists via localStorage so the user's pick survives reloads.
    // "auto" follows the OS preference; explicit light/dark wins.
    const THEME_KEY = 'cbx-audit-theme';
    const html = document.documentElement;
    const themeBtn = document.getElementById('theme-toggle');
    function applyTheme(theme) {
      if (theme === 'light' || theme === 'dark') {
        html.setAttribute('data-theme', theme);
      } else {
        html.setAttribute('data-theme', 'auto');
      }
    }
    const stored = (function() { try { return localStorage.getItem(THEME_KEY); } catch (_) { return null; } })();
    applyTheme(stored || 'auto');
    themeBtn?.addEventListener('click', function() {
      const current = html.getAttribute('data-theme') || 'auto';
      const next = current === 'auto' ? 'light' : (current === 'light' ? 'dark' : 'auto');
      applyTheme(next);
      try { localStorage.setItem(THEME_KEY, next); } catch (_) {}
    });

    // ---- Toolbar actions ----
    document.getElementById('download-md')?.addEventListener('click', function() {
      const blob = new Blob([mdText], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = mdFile;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });

    // ---- Save as PDF: inject a cover page + per-severity headings
    // into the main flow before printing, then clean them up after.
    // Cover content is built via DOM APIs (no innerHTML) so the
    // generated HTML stays XSS-safe even when audit metadata is
    // operator-controlled. ----
    function el(tag, opts) {
      const node = document.createElement(tag);
      if (opts) {
        if (opts.cls) node.className = opts.cls;
        if (opts.text != null) node.textContent = opts.text;
        if (opts.attrs) Object.keys(opts.attrs).forEach(k => node.setAttribute(k, opts.attrs[k]));
      }
      return node;
    }
    function injectPrintChrome() {
      const main = document.querySelector('.main-content');
      if (!main) return;

      const cover = el('section', { cls: 'pdf-cover' });
      const top = el('div', { cls: 'pdf-cover-top' });
      top.appendChild(el('span', { cls: 'brand-mark' }));
      top.appendChild(el('span', { cls: 'pdf-cover-top-name', text: 'CloudBooster' }));
      cover.appendChild(top);

      const middle = el('div', { cls: 'pdf-cover-middle' });
      middle.appendChild(el('div', { cls: 'pdf-cover-eyebrow', text: 'AWS posture audit · grounded' }));
      middle.appendChild(el('h1', { cls: 'pdf-cover-title', text: 'Audit Report' }));
      const dl = el('dl', { cls: 'pdf-cover-meta' });
      const metaItems = document.querySelectorAll('.hero-meta .hero-meta-item');
      metaItems.forEach(item => {
        const dt = item.querySelector('dt');
        const dd = item.querySelector('dd');
        if (!dt || !dd) return;
        dl.appendChild(el('dt', { text: dt.textContent }));
        // Preserve <code> wrapping when present, otherwise plain text.
        const newDd = document.createElement('dd');
        const code = dd.querySelector('code');
        if (code) {
          const c = document.createElement('code');
          c.textContent = code.textContent;
          newDd.appendChild(c);
        } else {
          newDd.textContent = dd.textContent;
        }
        dl.appendChild(newDd);
      });
      middle.appendChild(dl);
      cover.appendChild(middle);

      const generated = new Date().toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short' });
      cover.appendChild(el('div', {
        cls: 'pdf-cover-bottom',
        text: 'Generated ' + generated + ' · cbx audit aws · CloudBooster',
      }));

      main.insertBefore(cover, main.firstChild);

      // Per-severity H2 headings (drive the per-section page break
      // in the print stylesheet).
      const findings = main.querySelectorAll('.findings-section .finding');
      let lastSev = '';
      findings.forEach(card => {
        const sev = card.dataset.sev;
        if (sev && sev !== lastSev) {
          const h = el('h2', {
            cls: 'pdf-severity-heading',
            text: sev.charAt(0).toUpperCase() + sev.slice(1) + ' Findings',
            attrs: { 'data-sev': sev },
          });
          card.parentNode.insertBefore(h, card);
          lastSev = sev;
        }
      });
    }
    function cleanupPrintChrome() {
      document.querySelectorAll('.pdf-cover, .pdf-severity-heading').forEach(n => n.remove());
    }
    document.getElementById('save-pdf')?.addEventListener('click', function() {
      injectPrintChrome();
      setTimeout(function() {
        window.print();
        setTimeout(cleanupPrintChrome, 200);
      }, 50);
    });
    window.addEventListener('afterprint', cleanupPrintChrome);

    // ---- Filtering & sorting ----
    const hidden = new Set();
    const rows = Array.from(document.querySelectorAll('.finding-row'));
    const findings = Array.from(document.querySelectorAll('.finding'));
    const findingsById = new Map(findings.map(f => [f.id, f]));
    const sidebarList = document.getElementById('finding-nav');
    const mainSection = document.getElementById('findings-section');
    const visibleCountEl = document.getElementById('visible-count');
    const searchInput = document.getElementById('finding-search');
    const sortSelect = document.getElementById('sort-select');
    const filterPills = document.querySelectorAll('[data-sev-toggle]');

    function applyFilters() {
      const term = (searchInput?.value || '').toLowerCase().trim();
      let visible = 0;
      rows.forEach(row => {
        const sev = row.dataset.sev;
        const matchSev = !hidden.has(sev);
        const matchText = !term || (row.dataset.search || '').includes(term);
        const show = matchSev && matchText;
        row.classList.toggle('hidden', !show);
        const card = findingsById.get(row.dataset.target);
        if (card) card.classList.toggle('hidden', !show);
        if (show) visible++;
      });
      if (visibleCountEl) visibleCountEl.textContent = String(visible);
    }

    function applySort() {
      const mode = sortSelect ? sortSelect.value : 'severity';
      const keyOf = function(el) {
        switch (mode) {
          case 'service':  return (el.dataset.service || '') + ' ' + (10 - Number(el.dataset.rank || 0));
          case 'resource': return (el.dataset.resource || '') + ' ' + (10 - Number(el.dataset.rank || 0));
          case 'rule':     return el.dataset.rule || '';
          case 'severity':
          default:         return String(10 - Number(el.dataset.rank || 0)).padStart(2, '0') + ' ' + (el.dataset.service || '');
        }
      };
      const sortedRows = rows.slice().sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
      const sortedCards = findings.slice().sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
      const rf = document.createDocumentFragment();
      sortedRows.forEach(r => rf.appendChild(r));
      sidebarList.appendChild(rf);
      const cf = document.createDocumentFragment();
      sortedCards.forEach(c => cf.appendChild(c));
      mainSection.appendChild(cf);
    }

    filterPills.forEach(p => {
      if (p.classList.contains('disabled')) return;
      p.addEventListener('click', function() {
        const sev = p.dataset.sevToggle;
        if (hidden.has(sev)) { hidden.delete(sev); p.classList.remove('filtered-out'); }
        else { hidden.add(sev); p.classList.add('filtered-out'); }
        applyFilters();
      });
    });
    searchInput?.addEventListener('input', applyFilters);
    sortSelect?.addEventListener('change', applySort);
    document.getElementById('reset-filters')?.addEventListener('click', function() {
      hidden.clear();
      filterPills.forEach(p => p.classList.remove('filtered-out'));
      if (searchInput) searchInput.value = '';
      if (sortSelect) sortSelect.value = 'severity';
      applyFilters();
      applySort();
    });

    // ---- Sidebar row click → smooth-scroll + flash highlight ----
    rows.forEach(row => {
      row.addEventListener('click', function(e) {
        e.preventDefault();
        const card = findingsById.get(row.dataset.target);
        if (!card) return;
        card.scrollIntoView({ behavior: 'smooth', block: 'start' });
        card.classList.add('flash');
        setTimeout(() => card.classList.remove('flash'), 1200);
        setActive(row);
      });
    });

    function setActive(activeRow) {
      rows.forEach(r => r.classList.toggle('active', r === activeRow));
      // Keep the active row in view in the sidebar list, but only
      // when the user reached it via scrollspy (i.e. not when they
      // clicked it — clicks already moved it into view).
      if (activeRow && !activeRow.matches(':hover')) {
        activeRow.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }

    // ---- Scrollspy via IntersectionObserver ----
    // Threshold tuned so a card is "active" when its top is within
    // the upper third of the viewport. Tracks the topmost intersecting
    // card to handle dense lists where multiple cards are visible.
    const rowByCardId = new Map(rows.map(r => [r.dataset.target, r]));
    const obs = new IntersectionObserver(function(entries) {
      const visible = entries
        .filter(e => e.isIntersecting)
        .map(e => ({ id: e.target.id, top: e.boundingClientRect.top }))
        .sort((a, b) => a.top - b.top);
      if (visible.length === 0) return;
      const topId = visible[0].id;
      const row = rowByCardId.get(topId);
      if (row) setActive(row);
    }, {
      root: document.querySelector('.main-content'),
      rootMargin: '-10%% 0px -70%% 0px',
      threshold: 0,
    });
    findings.forEach(f => obs.observe(f));

    // Initial state
    if (rows.length > 0) setActive(rows[0]);
  })();
</script>
</body>
</html>
`
