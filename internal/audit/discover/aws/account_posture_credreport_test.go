package aws

import (
	"reflect"
	"testing"
)

// TestParseCredentialReportConsoleNoMFA covers the credential-report
// console-MFA gate: a finding is a user with password_enabled=true AND
// mfa_active=false, excluding the <root_account> row and any
// programmatic-only (password_enabled=false) user. Columns are resolved by
// header NAME, not position (the header here is deliberately not the
// AWS-canonical order to prove that), and the offender list is sorted for a
// deterministic render.
func TestParseCredentialReportConsoleNoMFA(t *testing.T) {
	csv := "arn,mfa_active,user,access_key_1_active,password_enabled\n" +
		"arn:aws:iam::111122223333:root,false,<root_account>,false,not_supported\n" + // root → skipped
		"arn:aws:iam::111122223333:user/charlie,false,charlie,false,true\n" + // PLANT: console pw, no MFA
		"arn:aws:iam::111122223333:user/alice,true,alice,true,false\n" + // programmatic-only (no console pw) → skipped
		"arn:aws:iam::111122223333:user/dave,true,dave,false,true\n" + // console pw WITH MFA → evaluated, compliant
		"arn:aws:iam::111122223333:user/bob,false,bob,false,true\n" // PLANT: console pw, no MFA

	rep, err := parseCredentialReportConsoleNoMFA([]byte(csv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// charlie + dave + bob have console passwords → 3 evaluated. alice has no
	// console password → skipped, not counted. root → skipped.
	if rep.ConsolePasswordUsersEvaluated != 3 {
		t.Errorf("ConsolePasswordUsersEvaluated = %d, want 3", rep.ConsolePasswordUsersEvaluated)
	}
	// Offenders are the console-password users without MFA, sorted.
	if want := []string{"bob", "charlie"}; !reflect.DeepEqual(rep.ConsoleUsersWithoutMFA, want) {
		t.Errorf("ConsoleUsersWithoutMFA = %v, want %v", rep.ConsoleUsersWithoutMFA, want)
	}
}

// TestParseCredentialReportConsoleNoMFA_AllCompliant is the positive-
// confirmation signal: console users exist and all have MFA → a non-nil
// result with N>0 evaluated and an EMPTY offender list (the "ran, all
// compliant" case — NOT silence).
func TestParseCredentialReportConsoleNoMFA_AllCompliant(t *testing.T) {
	csv := "user,password_enabled,mfa_active\n" +
		"<root_account>,not_supported,true\n" +
		"alice,true,true\n" +
		"svc,false,false\n" // programmatic-only, skipped
	rep, err := parseCredentialReportConsoleNoMFA([]byte(csv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.ConsolePasswordUsersEvaluated != 1 {
		t.Errorf("evaluated = %d, want 1", rep.ConsolePasswordUsersEvaluated)
	}
	if len(rep.ConsoleUsersWithoutMFA) != 0 {
		t.Errorf("expected no offenders, got %v", rep.ConsoleUsersWithoutMFA)
	}
}

// TestParseCredentialReportConsoleNoMFA_NoUsers: a header-only report
// (no IAM users) is a valid "probe ran" result — non-nil, zero evaluated,
// no error.
func TestParseCredentialReportConsoleNoMFA_NoUsers(t *testing.T) {
	rep, err := parseCredentialReportConsoleNoMFA([]byte("user,password_enabled,mfa_active\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep == nil {
		t.Fatal("expected non-nil result (probe ran), got nil")
	}
	if rep.ConsolePasswordUsersEvaluated != 0 || len(rep.ConsoleUsersWithoutMFA) != 0 {
		t.Errorf("expected empty result, got %+v", rep)
	}
}

// TestParseCredentialReportConsoleNoMFA_Errors covers the malformed-input
// paths that must surface an error (→ posture.Errors → UNKNOWN), never a
// false "all compliant" silence.
func TestParseCredentialReportConsoleNoMFA_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"empty input":            "",
		"missing mfa_active col": "user,password_enabled\nalice,true\n",
		"missing password col":   "user,mfa_active\nalice,false\n",
	} {
		if _, err := parseCredentialReportConsoleNoMFA([]byte(in)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
