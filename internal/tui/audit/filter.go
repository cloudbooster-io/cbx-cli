package audit

import (
	"sort"
	"strings"

	auditcore "github.com/cloudbooster-io/cbx-cli/internal/audit"
)

// severityRank maps severity strings to numeric ranks for sorting.
// Lower number = higher severity (appears first).
func severityRank(sev string) int {
	switch sev {
	case auditcore.SeverityCritical:
		return 0
	case auditcore.SeverityHigh:
		return 1
	case auditcore.SeverityWarning:
		return 2
	case auditcore.SeverityInfo:
		return 3
	default:
		return 4
	}
}

// FilterState holds the active filter criteria.
type FilterState struct {
	Search   string // substring match on RuleID, Title, Description
	Severity string // empty = all, otherwise one of auditcore.Severity*
	Service  string // empty = all, otherwise exact service name
}

// IsZero reports whether no filters are active.
func (f FilterState) IsZero() bool {
	return f.Search == "" && f.Severity == "" && f.Service == ""
}

// SortFindings sorts findings by severity (critical→info) then by RuleID.
func SortFindings(findings []auditcore.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri := severityRank(findings[i].Severity)
		rj := severityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

// ApplyFilters returns the indices of findings that match the filter state.
func ApplyFilters(findings []auditcore.Finding, filter FilterState) []int {
	var result []int
	search := strings.ToLower(filter.Search)
	for i, f := range findings {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if filter.Service != "" && f.Service != filter.Service {
			continue
		}
		if search != "" {
			combined := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Description)
			if !strings.Contains(combined, search) {
				continue
			}
		}
		result = append(result, i)
	}
	return result
}

// UniqueServices returns all unique service names from findings, sorted.
func UniqueServices(findings []auditcore.Finding) []string {
	seen := make(map[string]struct{})
	for _, f := range findings {
		seen[f.Service] = struct{}{}
	}
	var services []string
	for s := range seen {
		services = append(services, s)
	}
	sort.Strings(services)
	return services
}
