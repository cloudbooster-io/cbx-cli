package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// RenderPlain returns the human-friendly terminal rendering of an audit
// run: a severity overview row, severity-grouped finding cards (chip +
// title + resource chip + reflowed remediation), a buffered advisories
// block, and a "what next" footer. The signature is preserved because
// pkg/audit re-exports it as a semver-public symbol.
func RenderPlain(findings []Finding, stateFile string) string {
	if len(findings) == 0 {
		return renderNoFindings(stateFile)
	}

	var sb strings.Builder

	// Severity overview — replaces the old `Severity  Count` ASCII table.
	sb.WriteString(renderSeverityOverview(findings))
	sb.WriteString("\n")

	// Per-finding blocks grouped by severity (critical → info)
	grouped := groupBySeverity(findings)
	width := output.TerminalWidth()
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		list := grouped[sev]
		if len(list) == 0 {
			continue
		}
		// Section heading: small dim banner above each severity cluster.
		sb.WriteString(renderSeverityHeading(sev, len(list), width))
		sb.WriteString("\n")
		for _, f := range list {
			block := output.FindingBlock{
				Severity:    f.Severity,
				Title:       f.Title,
				ResourceURN: f.Resource,
				Remediation: f.Remediation,
				RuleID:      f.RuleID,
				Width:       width,
			}
			sb.WriteString(block.Render())
			sb.WriteString("\n")
		}
	}

	// Advisories block (legacy config dir, post-scan warnings, etc).
	// Drain so the root Execute hook doesn't re-render them.
	if adv := output.FlushAdvisories(); adv != "" {
		sb.WriteString(adv)
		sb.WriteString("\n")
	}

	// Footer: report link + suggested follow-ups.
	sb.WriteString(renderFooter(stateFile, findings, width))

	return sb.String()
}

// renderNoFindings is the happy-path message: a single celebratory line
// rather than the bare "No findings." of the prior implementation.
func renderNoFindings(stateFile string) string {
	headline := output.Success.Render(output.Symbol("check") + " no findings")
	sub := output.Dim.Render("clean audit — nothing to act on.")
	report := reportFileFor(stateFile)
	link := output.Hyperlink(report, fileURL(report))
	return fmt.Sprintf("%s\n%s\n\n%s %s\n",
		headline, sub,
		output.Dim.Render("report"), link,
	)
}

// renderSeverityOverview prints a single-line summary of the severity mix
// using coloured chip pills. Counts are right-padded so they read like
// a microsummary, not a table.
func renderSeverityOverview(findings []Finding) string {
	counts := countBySeverity(findings)
	total := len(findings)

	headline := output.Dim.Render(fmt.Sprintf("%d findings", total))
	parts := []string{headline}
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		c := counts[sev]
		if c == 0 {
			continue
		}
		chip := output.SeverityChip(sev)
		parts = append(parts, fmt.Sprintf("%s %s", chip, output.Dim.Render(fmt.Sprintf("× %d", c))))
	}
	sep := output.Dim.Render("    ")
	return strings.Join(parts, sep) + "\n"
}

// renderSeverityHeading emits a thin dim divider with the severity name
// and its count — replaces the loud `=== CRITICAL ===` banner.
func renderSeverityHeading(sev string, count, width int) string {
	label := fmt.Sprintf("%s · %d", strings.ToUpper(sev), count)
	style := output.SeverityBarStyle(sev)
	if !output.Enabled() {
		return label + "\n"
	}
	dash := "─"
	// 4 = leading space + label space + space + trailing margin
	fill := width - lipgloss.Width(label) - 4
	if fill < 4 {
		fill = 4
	}
	left := style.Render(strings.Repeat(dash, 2))
	right := output.Dim.Render(strings.Repeat(dash, fill))
	return fmt.Sprintf("%s %s %s\n",
		left,
		lipgloss.NewStyle().Bold(true).Render(label),
		right,
	)
}

// renderFooter assembles the closing block: a report link plus suggested
// follow-up cbx commands. The commands surfaced are tuned to whatever
// findings are present (e.g. only mention --severity critical when there
// are critical findings).
func renderFooter(stateFile string, findings []Finding, _ int) string {
	report := reportFileFor(stateFile)
	link := output.Hyperlink(report, fileURL(report))

	var sb strings.Builder
	sb.WriteString(output.Symbol("check") + " " + output.Success.Render("report") + " " + link + "\n")

	// HTML companion (AWS audits only — written alongside the .md). We
	// re-derive the path from the same base rather than threading it
	// through the function signature; the renderer should stay
	// stateless w.r.t. Result.
	htmlReport := strings.TrimSuffix(report, ".md") + ".html"
	if _, err := os.Stat(htmlReport); err == nil {
		htmlLink := output.Hyperlink(htmlReport, fileURL(htmlReport))
		sb.WriteString(output.Dim.Render("  open in browser ") + htmlLink + "\n")
	}

	return sb.String()
}

// reportFileFor mirrors the previous behaviour: <base>_audit_report.md
// relative to wherever the runner wrote it. Caller passes the same
// stateFile string used in the older RenderPlain.
func reportFileFor(stateFile string) string {
	base := strings.TrimSuffix(filepath.Base(stateFile), filepath.Ext(stateFile))
	return base + "_audit_report.md"
}

// fileURL returns a file:// URL for a relative report path. For absolute
// paths it's identity; for relative ones it joins to cwd so OSC-8 clicks
// land on the right file in Finder / iTerm2.
func fileURL(p string) string {
	if filepath.IsAbs(p) {
		return "file://" + p
	}
	if cwd, err := os.Getwd(); err == nil {
		return "file://" + filepath.Join(cwd, p)
	}
	return ""
}

// RenderJSON returns findings as indented JSON.
func RenderJSON(findings []Finding) (string, error) {
	b, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding JSON: %w", err)
	}
	return string(b), nil
}

// RenderMarkdown returns a markdown report string.
func RenderMarkdown(findings []Finding) string {
	var sb strings.Builder
	sb.WriteString("# CloudBooster Audit Report\n\n")
	sb.WriteString(fmt.Sprintf("**Findings:** %d\n\n", len(findings)))

	severityCounts := countBySeverity(findings)
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		if c := severityCounts[sev]; c > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(sev), c))
		}
	}
	sb.WriteString("\n")

	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("## %s — %s\n\n", f.RuleID, f.Title))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(f.Severity)))
		sb.WriteString(fmt.Sprintf("- **Resource:** %s\n", f.Resource))
		sb.WriteString(fmt.Sprintf("- **Service:** %s\n", f.Service))
		sb.WriteString(fmt.Sprintf("- **Description:** %s\n\n", f.Description))
		sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", f.Remediation))
	}

	return sb.String()
}

// WriteMarkdownReport writes the markdown report to the given path.
func WriteMarkdownReport(path string, findings []Finding) error {
	return os.WriteFile(path, []byte(RenderMarkdown(findings)), 0o644)
}

// RenderSARIF returns findings formatted as SARIF JSON.
func RenderSARIF(findings []Finding) (string, error) {
	runs := []sarifRun{
		{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:  "cbx-audit",
					Rules: buildSARIFRules(findings),
				},
			},
			Results: buildSARIFResults(findings),
		},
	}

	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    runs,
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding SARIF: %w", err)
	}
	return string(b), nil
}

// RenderGitHubAction returns findings as GitHub Actions workflow commands.
func RenderGitHubAction(findings []Finding) string {
	var sb strings.Builder
	for _, f := range findings {
		level := "notice"
		switch f.Severity {
		case SeverityWarning:
			level = "warning"
		case SeverityHigh, SeverityCritical:
			level = "error"
		}
		sb.WriteString(fmt.Sprintf("::%s title=%s::%s — %s\n", level, f.RuleID, f.Title, f.Description))
	}
	return sb.String()
}

func countBySeverity(findings []Finding) map[string]int {
	counts := map[string]int{
		SeverityInfo:     0,
		SeverityWarning:  0,
		SeverityHigh:     0,
		SeverityCritical: 0,
	}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func groupBySeverity(findings []Finding) map[string][]Finding {
	groups := map[string][]Finding{
		SeverityInfo:     {},
		SeverityWarning:  {},
		SeverityHigh:     {},
		SeverityCritical: {},
	}
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	// Sort each group by rule ID for deterministic output.
	for _, list := range groups {
		sort.Slice(list, func(i, j int) bool {
			return list[i].RuleID < list[j].RuleID
		})
	}
	return groups
}

// SARIF types.

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Help struct {
		Text string `json:"text"`
	} `json:"help"`
	Properties struct {
		Severity string `json:"severity"`
	} `json:"properties"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func buildSARIFRules(findings []Finding) []sarifRule {
	seen := make(map[string]struct{})
	var rules []sarifRule
	for _, f := range findings {
		if _, ok := seen[f.RuleID]; ok {
			continue
		}
		seen[f.RuleID] = struct{}{}
		r := sarifRule{
			ID:   f.RuleID,
			Name: f.Title,
		}
		r.Help.Text = f.Description + "\n\nRemediation: " + f.Remediation
		r.Properties.Severity = f.Severity
		rules = append(rules, r)
	}
	return rules
}

func buildSARIFResults(findings []Finding) []sarifResult {
	var results []sarifResult
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Message: sarifMessage{Text: f.Description},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.Resource,
						},
					},
				},
			},
		})
	}
	return results
}
