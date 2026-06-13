package audit

import (
	"strings"
	"testing"
)

// TestWriteAccountPosture_RendersConsoleUsersWithoutMFA asserts the
// credential-report console-MFA block lands in the posture render: the
// offender list (in sorted order) plus the derived "(evaluated N; without
// MFA M)" count line.
func TestWriteAccountPosture_RendersConsoleUsersWithoutMFA(t *testing.T) {
	posture := &AccountPosture{
		CredentialReport: &CredentialReportPosture{
			ConsolePasswordUsersEvaluated: 3,
			ConsoleUsersWithoutMFA:        []string{"bob", "charlie"},
		},
	}
	var sb strings.Builder
	writeAccountPosture(&sb, posture)
	out := sb.String()

	for _, want := range []string{
		"IAM console users WITHOUT MFA",
		"  - bob",
		"  - charlie",
		"evaluated for MFA: 3; without MFA: 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("posture render missing %q\n---\n%s", want, out)
		}
	}

	// Sorted order: bob must render before charlie.
	if strings.Index(out, "- bob") > strings.Index(out, "- charlie") {
		t.Errorf("console-MFA offenders not rendered in sorted order:\n%s", out)
	}
}

// TestWriteAccountPosture_ConsoleMFAAllCompliant: when the probe ran and
// every console user has MFA, the count line still renders (positive
// confirmation) but there is NO offender list — the model must read this as
// "checked, compliant", not silence.
func TestWriteAccountPosture_ConsoleMFAAllCompliant(t *testing.T) {
	posture := &AccountPosture{
		CredentialReport: &CredentialReportPosture{ConsolePasswordUsersEvaluated: 4},
	}
	var sb strings.Builder
	writeAccountPosture(&sb, posture)
	out := sb.String()

	if strings.Contains(out, "IAM console users WITHOUT MFA") {
		t.Errorf("offender header rendered with no offenders:\n%s", out)
	}
	if !strings.Contains(out, "evaluated for MFA: 4; without MFA: 0") {
		t.Errorf("compliant count line missing:\n%s", out)
	}
}

// TestWriteAccountPosture_OmitsConsoleMFAWhenProbeDidNotRun: a nil
// CredentialReport (probe failed / didn't run, recorded in Errors) renders
// NOTHING — the gap must read as UNKNOWN, never a false "all console users
// have MFA".
func TestWriteAccountPosture_OmitsConsoleMFAWhenProbeDidNotRun(t *testing.T) {
	var sb strings.Builder
	writeAccountPosture(&sb, &AccountPosture{}) // CredentialReport is nil
	if strings.Contains(sb.String(), "evaluated for MFA") {
		t.Errorf("console-MFA block rendered when the probe did not run:\n%s", sb.String())
	}
}
