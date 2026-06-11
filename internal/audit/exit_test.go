package audit

import "testing"

func TestExitWithSeverityNone(t *testing.T) {
	err := ExitWithSeverity([]Finding{})
	if err != nil {
		t.Fatalf("expected nil for empty findings, got: %v", err)
	}
}

func TestExitWithSeverityInfo(t *testing.T) {
	err := ExitWithSeverity([]Finding{{Severity: SeverityInfo}})
	if err == nil {
		t.Fatal("expected error for info severity")
	}
	if ec, ok := err.(*ExitCodeError); !ok || ec.Code != 1 {
		t.Fatalf("expected exit code 1, got: %v", err)
	}
}

func TestExitWithSeverityWarning(t *testing.T) {
	err := ExitWithSeverity([]Finding{{Severity: SeverityWarning}})
	if err == nil {
		t.Fatal("expected error for warning severity")
	}
	if ec, ok := err.(*ExitCodeError); !ok || ec.Code != 2 {
		t.Fatalf("expected exit code 2, got: %v", err)
	}
}

func TestExitWithSeverityHigh(t *testing.T) {
	err := ExitWithSeverity([]Finding{{Severity: SeverityHigh}})
	if err == nil {
		t.Fatal("expected error for high severity")
	}
	if ec, ok := err.(*ExitCodeError); !ok || ec.Code != 3 {
		t.Fatalf("expected exit code 3, got: %v", err)
	}
}

func TestExitWithSeverityCritical(t *testing.T) {
	err := ExitWithSeverity([]Finding{{Severity: SeverityCritical}})
	if err == nil {
		t.Fatal("expected error for critical severity")
	}
	if ec, ok := err.(*ExitCodeError); !ok || ec.Code != 3 {
		t.Fatalf("expected exit code 3, got: %v", err)
	}
}

func TestExitWithSeverityMax(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityInfo},
		{Severity: SeverityHigh},
		{Severity: SeverityWarning},
	}
	err := ExitWithSeverity(findings)
	if ec, ok := err.(*ExitCodeError); !ok || ec.Code != 3 {
		t.Fatalf("expected exit code 3 (max), got: %v", err)
	}
}
