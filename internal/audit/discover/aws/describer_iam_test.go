package aws

import "testing"

// TestHasPowerUserManagedPolicy pins the FP gate for the power-user-group
// bullet. The load-bearing cases are the two NON-matches that keep the MEDIUM
// finding off the wrong groups:
//   - AdministratorAccess must NOT match — a full-admin group is a separate
//     (CRITICAL) concern and must never double-fire as the power-user MEDIUM;
//   - a customer-managed policy coincidentally named "PowerUserAccess" (its ARN
//     carries the account id, not the literal `aws`) must NOT match — this is
//     why the helper does exact-ARN matching, not a `:policy/PowerUserAccess`
//     suffix.
//
// PowerUserAccess itself — alone or among other attachments — must match so the
// planted group is caught.
func TestHasPowerUserManagedPolicy(t *testing.T) {
	cases := []struct {
		name string
		arns []string
		want bool
	}{
		{"power-user-attached", []string{"arn:aws:iam::aws:policy/PowerUserAccess"}, true},
		{"power-user-among-others", []string{"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess", "arn:aws:iam::aws:policy/PowerUserAccess"}, true},
		{"admin-only-does-not-match", []string{"arn:aws:iam::aws:policy/AdministratorAccess"}, false},
		{"customer-policy-named-poweruser-does-not-match", []string{"arn:aws:iam::123456789012:policy/PowerUserAccess"}, false},
		{"other-managed-policy", []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasPowerUserManagedPolicy(tc.arns); got != tc.want {
				t.Errorf("hasPowerUserManagedPolicy(%v) = %v, want %v", tc.arns, got, tc.want)
			}
		})
	}
}
