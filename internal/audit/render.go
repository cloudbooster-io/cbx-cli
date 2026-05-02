package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RenderPlain returns a severity-grouped plain text representation of
// findings with a summary table followed by per-finding three-line
// blocks (what / why / what-to-do).
func RenderPlain(findings []Finding, stateFile string) string {
	if len(findings) == 0 {
		return "No findings.\n"
	}

	var sb strings.Builder

	// Summary table
	severityCounts := countBySeverity(findings)
	sb.WriteString("Severity  Count\n")
	sb.WriteString("--------  -----\n")
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		if c := severityCounts[sev]; c > 0 {
			sb.WriteString(fmt.Sprintf("%-8s  %d\n", strings.ToUpper(sev), c))
		}
	}
	sb.WriteString("\n")

	// Per-finding blocks grouped by severity (high → info)
	grouped := groupBySeverity(findings)
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo} {
		list := grouped[sev]
		if len(list) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("=== %s ===\n\n", strings.ToUpper(sev)))
		for _, f := range list {
			sb.WriteString(fmt.Sprintf("[%s] %s — %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Title))
			sb.WriteString(fmt.Sprintf("  Resource: %s (%s)\n", f.Resource, f.Service))
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", f.Remediation))
		}
	}

	// Report path
	base := strings.TrimSuffix(filepath.Base(stateFile), filepath.Ext(stateFile))
	reportFile := base + "_audit_report.md"
	sb.WriteString(fmt.Sprintf("Report written to: %s\n", reportFile))

	return sb.String()
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
