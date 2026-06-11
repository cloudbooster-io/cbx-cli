package audit

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	auditcore "github.com/cloudbooster-io/cbx-cli/internal/audit"
)

func TestNewModelSortsFindings(t *testing.T) {
	findings := []auditcore.Finding{
		{RuleID: "A", Severity: auditcore.SeverityInfo},
		{RuleID: "B", Severity: auditcore.SeverityCritical},
		{RuleID: "C", Severity: auditcore.SeverityHigh},
	}
	m := NewModel(findings)
	if len(m.findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(m.findings))
	}
	if m.findings[0].RuleID != "B" {
		t.Fatalf("expected critical first, got %s", m.findings[0].RuleID)
	}
	if m.findings[1].RuleID != "C" {
		t.Fatalf("expected high second, got %s", m.findings[1].RuleID)
	}
	if m.findings[2].RuleID != "A" {
		t.Fatalf("expected info third, got %s", m.findings[2].RuleID)
	}
}

func TestNewModelDoesNotMutateInput(t *testing.T) {
	findings := []auditcore.Finding{
		{RuleID: "A", Severity: auditcore.SeverityInfo},
		{RuleID: "B", Severity: auditcore.SeverityCritical},
	}
	_ = NewModel(findings)
	// Caller's slice ordering must survive — NewModel sorts a copy.
	if findings[0].RuleID != "A" {
		t.Fatalf("input slice was mutated; first RuleID = %q, want %q", findings[0].RuleID, "A")
	}
}

func TestCycleSeverityFilter(t *testing.T) {
	findings := []auditcore.Finding{
		{RuleID: "S3-001", Severity: auditcore.SeverityHigh, Service: "S3"},
		{RuleID: "EC2-001", Severity: auditcore.SeverityWarning, Service: "EC2"},
	}
	m := NewModel(findings)
	m.SetSize(120, 30)

	if len(m.filtered) != 2 {
		t.Fatalf("expected 2 filtered, got %d", len(m.filtered))
	}

	// s → critical (no matches)
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 0 || m.filter.Severity != auditcore.SeverityCritical {
		t.Fatalf("expected 0 critical, sev=critical; got %d, sev=%q", len(m.filtered), m.filter.Severity)
	}

	// s → high
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 1 || m.filter.Severity != auditcore.SeverityHigh {
		t.Fatalf("expected 1 high, sev=high; got %d, sev=%q", len(m.filtered), m.filter.Severity)
	}

	// s → warning, info, then back to all
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 1 || m.filter.Severity != auditcore.SeverityWarning {
		t.Fatalf("expected 1 warning; got %d, sev=%q", len(m.filtered), m.filter.Severity)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 0 || m.filter.Severity != auditcore.SeverityInfo {
		t.Fatalf("expected 0 info; got %d, sev=%q", len(m.filtered), m.filter.Severity)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 2 || m.filter.Severity != "" {
		t.Fatalf("expected all-reset; got %d, sev=%q", len(m.filtered), m.filter.Severity)
	}
}

func TestSearchLiveFilter(t *testing.T) {
	findings := []auditcore.Finding{
		{RuleID: "S3-001", Title: "S3 issue", Severity: auditcore.SeverityHigh, Service: "S3"},
		{RuleID: "EC2-001", Title: "EC2 issue", Severity: auditcore.SeverityWarning, Service: "EC2"},
	}
	m := NewModel(findings)
	m.SetSize(120, 30)

	// Enter search mode
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updated.(Model)
	if !m.searchMode {
		t.Fatal("expected search mode after /")
	}

	// Type "S3" — list narrows live (no need to press enter).
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	m = updated.(Model)
	if len(m.filtered) != 1 {
		t.Fatalf("expected 1 filtered after live search, got %d", len(m.filtered))
	}

	// Enter commits and exits search mode.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.searchMode {
		t.Fatal("expected search mode to exit on enter")
	}
	if m.filter.Search != "S3" {
		t.Fatalf("expected filter.Search=S3, got %q", m.filter.Search)
	}
}

func TestResetClearsFilters(t *testing.T) {
	findings := []auditcore.Finding{
		{RuleID: "S3-001", Severity: auditcore.SeverityHigh, Service: "S3"},
		{RuleID: "EC2-001", Severity: auditcore.SeverityWarning, Service: "EC2"},
	}
	m := NewModel(findings)
	m.SetSize(120, 30)

	// Apply a severity filter, then reset.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if m.filter.Severity == "" {
		t.Fatal("expected severity filter set after s")
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	if !m.filter.IsZero() {
		t.Fatalf("expected filters cleared, got %+v", m.filter)
	}
	if len(m.filtered) != 2 {
		t.Fatalf("expected all findings restored after reset, got %d", len(m.filtered))
	}
}

func TestQuitBindings(t *testing.T) {
	for name, key := range map[string]tea.KeyMsg{
		"ctrl+c": {Type: tea.KeyCtrlC},
		"q":      {Type: tea.KeyRunes, Runes: []rune{'q'}},
		"esc":    {Type: tea.KeyEsc},
	} {
		t.Run(name, func(t *testing.T) {
			m := NewModel(nil)
			m.SetSize(120, 30)
			updated, cmd := m.Update(key)
			model := updated.(Model)
			if !model.quitting {
				t.Fatal("expected quitting flag")
			}
			if cmd == nil {
				t.Fatal("expected quit command")
			}
		})
	}
}

func TestWithContextAndReportPath(t *testing.T) {
	m := NewModel([]auditcore.Finding{
		{RuleID: "X-1", Severity: auditcore.SeverityCritical, Service: "X", Title: "x"},
	}).WithContext("AWS · 123 · eu-central-1").WithReportPath("/tmp/report.md")
	m.SetSize(140, 40)

	view := m.View()
	if !strings.Contains(view, "AWS · 123 · eu-central-1") {
		t.Fatalf("header missing context line, view=\n%s", view)
	}
	// `o open report` should appear in the keymap footer because reportPath is set.
	if !strings.Contains(view, "open report") {
		t.Fatalf("expected `open report` hint in keymap, view=\n%s", view)
	}
}

func TestNarrowModeHidesDetailPane(t *testing.T) {
	m := NewModel([]auditcore.Finding{
		{RuleID: "X-1", Severity: auditcore.SeverityCritical, Service: "X", Title: "x"},
	})
	m.SetSize(80, 30) // below wideMode threshold (110)
	if m.wideMode {
		t.Fatal("expected narrow mode at width 80")
	}
	m.SetSize(140, 30)
	if !m.wideMode {
		t.Fatal("expected wide mode at width 140")
	}
}
