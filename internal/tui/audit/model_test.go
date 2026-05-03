package audit

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	auditcore "gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
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

func TestCycleSeverityFilter(t *testing.T) {
	findings := []auditcore.Finding{
		{RuleID: "S3-001", Severity: auditcore.SeverityHigh, Service: "S3"},
		{RuleID: "EC2-001", Severity: auditcore.SeverityWarning, Service: "EC2"},
	}
	m := NewModel(findings)
	m.SetSize(80, 24)

	// Initial: all 2 findings
	if len(m.filtered) != 2 {
		t.Fatalf("expected 2 filtered, got %d", len(m.filtered))
	}

	// Cycle to critical (none)
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 0 {
		t.Fatalf("expected 0 critical findings, got %d", len(m.filtered))
	}

	// Cycle to high
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 1 {
		t.Fatalf("expected 1 high finding, got %d", len(m.filtered))
	}

	// Cycle to warning
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 1 {
		t.Fatalf("expected 1 warning finding, got %d", len(m.filtered))
	}

	// Cycle to info (none)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 0 {
		t.Fatalf("expected 0 info findings, got %d", len(m.filtered))
	}

	// Cycle back to all
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = updated.(Model)
	if len(m.filtered) != 2 {
		t.Fatalf("expected 2 findings after reset, got %d", len(m.filtered))
	}
}

func TestSearchFilter(t *testing.T) {
	findings := []auditcore.Finding{
		{RuleID: "S3-001", Title: "S3 issue", Severity: auditcore.SeverityHigh, Service: "S3"},
		{RuleID: "EC2-001", Title: "EC2 issue", Severity: auditcore.SeverityWarning, Service: "EC2"},
	}
	m := NewModel(findings)
	m.SetSize(80, 24)

	// Enter search mode
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updated.(Model)
	if !m.searchMode {
		t.Fatal("expected search mode")
	}

	// Type "S3"
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	m = updated.(Model)
	if m.searchBuffer != "S3" {
		t.Fatalf("expected search buffer S3, got %s", m.searchBuffer)
	}

	// Apply search
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if len(m.filtered) != 1 {
		t.Fatalf("expected 1 filtered finding, got %d", len(m.filtered))
	}
	if m.findings[m.filtered[0]].RuleID != "S3-001" {
		t.Fatalf("expected S3-001, got %s", m.findings[m.filtered[0]].RuleID)
	}
}

func TestDrilldownAndBack(t *testing.T) {
	findings := []auditcore.Finding{
		{RuleID: "S3-001", Title: "S3 issue", Severity: auditcore.SeverityHigh, Service: "S3"},
	}
	m := NewModel(findings)
	m.SetSize(80, 24)

	// Enter detail mode
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(Model)
	if model.mode != detailMode {
		t.Fatal("expected detail mode after enter")
	}

	// Back to list
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(Model)
	if model.mode != listMode {
		t.Fatal("expected list mode after esc")
	}
}

func TestQuit(t *testing.T) {
	m := NewModel([]auditcore.Finding{})
	m.SetSize(80, 24)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model := updated.(Model)
	if !model.quitting {
		t.Fatal("expected quitting flag")
	}
	if cmd == nil {
		t.Fatal("expected quit command")
	}
}
