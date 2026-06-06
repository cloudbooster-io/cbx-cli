package aws

import (
	"errors"
	"testing"

	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

func int64p(i int64) *int64 { return &i }

// backupKeyIsAwsManaged is the FP gate for vault-aws-managed-key. The
// load-bearing property: a CUSTOMER_MANAGED key must NOT be reported as
// AWS-managed (no false alarm), and an unknown/empty enum must report
// known==false so the caller leaves the hint absent rather than guessing.
func TestBackupKeyIsAwsManaged(t *testing.T) {
	cases := []struct {
		name      string
		in        backuptypes.EncryptionKeyType
		wantAws   bool
		wantKnown bool
	}{
		{"aws-owned", backuptypes.EncryptionKeyTypeAwsOwnedKmsKey, true, true},
		{"customer-managed", backuptypes.EncryptionKeyTypeCustomerManagedKmsKey, false, true},
		{"empty", backuptypes.EncryptionKeyType(""), false, false},
		{"unrecognised", backuptypes.EncryptionKeyType("SOMETHING_NEW"), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAws, gotKnown := backupKeyIsAwsManaged(tc.in)
			if gotAws != tc.wantAws || gotKnown != tc.wantKnown {
				t.Errorf("backupKeyIsAwsManaged(%q) = (%v, %v), want (%v, %v)",
					tc.in, gotAws, gotKnown, tc.wantAws, tc.wantKnown)
			}
		})
	}
}

// backupPlanHasCrossRegionCopy is the FP gate for plan-no-secondary-region-copy.
// A same-region copy must NOT count as cross-region (the finding is specifically
// about a *secondary region* copy), and no copy actions at all must report
// false (the planted "no cross-region copy" posture) — but only the absence is
// asserted; a real cross-region copy must flip it to true so a correctly
// configured plan is never flagged.
func TestBackupPlanHasCrossRegionCopy(t *testing.T) {
	const plan = "eu-central-1"
	cases := []struct {
		name  string
		dests []string
		want  bool
	}{
		{"no-copy-actions", nil, false},
		{"same-region-copy", []string{"arn:aws:backup:eu-central-1:111122223333:backup-vault:dr"}, false},
		{"cross-region-copy", []string{"arn:aws:backup:us-east-1:111122223333:backup-vault:dr"}, true},
		{"mixed-same-and-cross", []string{
			"arn:aws:backup:eu-central-1:111122223333:backup-vault:local",
			"arn:aws:backup:us-east-1:111122223333:backup-vault:dr",
		}, true},
		{"malformed-arn-ignored", []string{"not-an-arn"}, false},
		{"case-insensitive-same-region", []string{"arn:aws:backup:EU-CENTRAL-1:111122223333:backup-vault:dr"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := backupPlanHasCrossRegionCopy(plan, tc.dests); got != tc.want {
				t.Errorf("backupPlanHasCrossRegionCopy(%q, %v) = %v, want %v", plan, tc.dests, got, tc.want)
			}
		})
	}

	// An empty plan region can't be adjudicated → must not raise a false alarm.
	if backupPlanHasCrossRegionCopy("", []string{"arn:aws:backup:us-east-1:1:backup-vault:dr"}) {
		t.Error("empty planRegion must return false (cannot adjudicate)")
	}
}

func TestRegionFromARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:backup:us-east-1:111122223333:backup-vault:dr": "us-east-1",
		"arn:aws-cn:backup:cn-north-1:1:backup-vault:x":         "cn-north-1",
		"not-an-arn": "",
		"arn:aws:s3": "",
		"":           "",
	}
	for in, want := range cases {
		if got := regionFromARN(in); got != want {
			t.Errorf("regionFromARN(%q) = %q, want %q", in, got, want)
		}
	}
}

// isBackupResourceNotFound is the gate that distinguishes "AWS confirms there is
// no access policy" (assert absent) from "we couldn't read it" (leave absent).
func TestIsBackupResourceNotFound(t *testing.T) {
	if !isBackupResourceNotFound(&backuptypes.ResourceNotFoundException{}) {
		t.Error("ResourceNotFoundException must be recognised as not-found")
	}
	if isBackupResourceNotFound(errors.New("AccessDenied")) {
		t.Error("a generic error must NOT be treated as not-found (would falsely assert 'no policy')")
	}
	if isBackupResourceNotFound(nil) {
		t.Error("nil must not be treated as not-found")
	}
}
