package audit

import (
	"strings"
	"testing"
)

// TestWriteAccountPosture_RendersRootCredentialCounters asserts the
// root-account credential facts derived from iam:GetAccountSummary land in
// the posture render as bare booleans — true for a present root access key,
// false for disabled root MFA — mirroring the IAM password-policy line. The
// firing/severity decision lives in the API-distributed rule pack (its
// content is exercised by the e2e_staging tier, not unit tests); here we
// only prove the data reaches the prompt with the exact `> 0` reading.
func TestWriteAccountPosture_RendersRootCredentialCounters(t *testing.T) {
	posture := &AccountPosture{
		IAMSummary: map[string]int32{
			"AccountAccessKeysPresent": 1, // non-compliant: root has access keys
			"AccountMFAEnabled":        0, // non-compliant: root MFA off
		},
	}
	var sb strings.Builder
	writeAccountPosture(&sb, posture)
	out := sb.String()

	for _, want := range []string{
		"Root account access keys present: true",
		"Root account MFA enabled: false",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("posture render missing %q\n---\n%s", want, out)
		}
	}
}

// TestWriteAccountPosture_RootCredentialsFPSafeWhenCompliant asserts the
// compliant posture renders the GOOD values (no keys, MFA on) so the LLM
// sees the fact and does NOT flag — the lines are always present, polarity
// carries the meaning, exactly like the GuardDuty/Config posture blocks.
func TestWriteAccountPosture_RootCredentialsFPSafeWhenCompliant(t *testing.T) {
	posture := &AccountPosture{
		IAMSummary: map[string]int32{
			"AccountAccessKeysPresent": 0, // compliant: no root access keys
			"AccountMFAEnabled":        1, // compliant: root MFA enabled
		},
	}
	var sb strings.Builder
	writeAccountPosture(&sb, posture)
	out := sb.String()

	for _, want := range []string{
		"Root account access keys present: false",
		"Root account MFA enabled: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("posture render missing %q\n---\n%s", want, out)
		}
	}
}

// TestWriteAccountPosture_OmitsRootCredentialsWhenCounterAbsent is the
// load-bearing FP-safety guard: when a counter is NOT present in the summary
// map (e.g. iam:GetAccountSummary failed, or AWS didn't return that key), the
// corresponding labelled line must be omitted entirely so the model treats
// it as UNKNOWN rather than inferring a compliant default. A populated-but-
// missing-the-keys summary still exercises the raw IAMSummary dump path.
func TestWriteAccountPosture_OmitsRootCredentialsWhenCounterAbsent(t *testing.T) {
	posture := &AccountPosture{
		IAMSummary: map[string]int32{
			"Users": 5, // some other counter present; root keys absent
		},
	}
	var sb strings.Builder
	writeAccountPosture(&sb, posture)
	out := sb.String()

	for _, unwanted := range []string{
		"Root account access keys present",
		"Root account MFA enabled",
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("posture render leaked %q for an account whose summary lacked the counter — absent must mean unknown, not compliant:\n%s", unwanted, out)
		}
	}
}
