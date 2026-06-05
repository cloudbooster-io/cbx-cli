package audit

import "testing"

// helpers ---------------------------------------------------------------------

const (
	callerARN      = "arn:aws:iam::123456789012:user/cbx-audit-fixtures"
	harnessURN     = "aws://global/AWS::IAM::User/cbx-audit-fixtures"
	siblingURN     = "aws://global/AWS::IAM::User/other-admin"
	wildcardURN    = "aws://global/AWS::IAM::Role/cbx-wildcard-role"
	bpaBucketURN   = "aws://us-east-1/AWS::S3::Bucket/origin-bucket"
	trailURN       = "aws://us-east-1/AWS::CloudTrail::Trail/org-trail"
	taskRoleURN    = "aws://global/AWS::IAM::Role/cbx-ecs-task-role"
	benignSGURN    = "aws://us-east-1/AWS::EC2::SecurityGroup/sg-internet"
	accountFinding = "account:123456789012"
)

func adminUserRes(urn string) DiscoveredResource {
	return DiscoveredResource{
		Type: "AWS::IAM::User", URN: urn, ID: lastSeg(urn),
		Inputs: map[string]any{
			"cb_describer_admin_managed_policy_attached": true,
			"cb_describer_active_access_key_count":       1,
			"cb_describer_has_mfa":                       false,
		},
	}
}

func wildcardRoleRes(urn string) DiscoveredResource {
	return DiscoveredResource{
		Type: "AWS::IAM::Role", URN: urn, ID: lastSeg(urn),
		Inputs: map[string]any{
			"cb_describer_role_has_wildcard_inline_policy":  true,
			"cb_describer_inline_policy_has_wildcard_allow": true,
		},
	}
}

func bpaAllDisabledRes(urn string) DiscoveredResource {
	return DiscoveredResource{
		Type: "AWS::S3::Bucket", URN: urn, ID: lastSeg(urn),
		Inputs: map[string]any{
			"cb_describer_public_access_block": map[string]any{
				"block_public_acls":       false,
				"block_public_policy":     false,
				"ignore_public_acls":      false,
				"restrict_public_buckets": false,
			},
		},
	}
}

func lastSeg(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}

func sevOf(findings []Finding, resource string) (string, bool) {
	for _, f := range findings {
		if f.Resource == resource {
			return f.Severity, true
		}
	}
	return "", false
}

// T1 — the headline safety test: the auditor's own IAM-user finding is dropped
// by step (A) and never reaches `critical`, while a *different* admin-no-MFA
// user IS pinned to critical — proving the drop is identity-scoped, not
// class-scoped, and that the floor's promotion mechanism is real (so step A is
// load-bearing, not a no-op).
func TestSeverityFloor_HarnessFPNotPromoted(t *testing.T) {
	resources := []DiscoveredResource{
		adminUserRes(harnessURN),
		adminUserRes(siblingURN),
	}
	findings := []Finding{
		{RuleID: "LLM-a", Title: "admin user no MFA", Resource: harnessURN, Severity: SeverityHigh},
		{RuleID: "LLM-b", Title: "admin user no MFA", Resource: siblingURN, Severity: SeverityHigh},
	}

	// Step (A) then (B), exactly as RunFromResources wires them.
	out := applySeverityFloor(dropSelfIdentityFindings(findings, callerARN), resources)

	if _, present := sevOf(out, harnessURN); present {
		t.Fatalf("harness self-identity finding must be dropped, but it is present")
	}
	if got, present := sevOf(out, siblingURN); !present || got != SeverityCritical {
		t.Fatalf("sibling admin user: want critical present, got %q present=%v", got, present)
	}
	if len(out) != 1 {
		t.Fatalf("want exactly 1 finding after drop, got %d", len(out))
	}
}

// T2 — non-determinism is collapsed. The analysis proved the variant-02 wildcard
// role landed high/high/critical/high across four runs of the same build. Feed a
// finding at each of those severities; assert all four normalize to critical.
func TestSeverityFloor_Variant02DeterministicCritical(t *testing.T) {
	resources := []DiscoveredResource{wildcardRoleRes(wildcardURN)}
	for _, in := range []string{SeverityHigh, SeverityHigh, SeverityCritical, SeverityHigh} {
		out := applySeverityFloor([]Finding{
			{RuleID: "LLM-x", Title: "wildcard role", Resource: wildcardURN, Severity: in},
		}, resources)
		if out[0].Severity != SeverityCritical {
			t.Fatalf("wildcard role from %q: want critical, got %q", in, out[0].Severity)
		}
	}
}

// b1 structural pins + their negatives, plus the raise-only / over-rate
// preservation invariant, in one table.
func TestSeverityFloor_Pins(t *testing.T) {
	trailNoKMS := DiscoveredResource{Type: "AWS::CloudTrail::Trail", URN: trailURN, Inputs: map[string]any{}}
	trailWithKMS := DiscoveredResource{Type: "AWS::CloudTrail::Trail", URN: trailURN, Inputs: map[string]any{
		"KMSKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
	}}
	bpaOneEnabled := bpaAllDisabledRes(bpaBucketURN)
	bpaOneEnabled.Inputs["cb_describer_public_access_block"].(map[string]any)["block_public_acls"] = true
	// service-wildcard-only role (s3:* + dynamodb:* on Resource:*) — the
	// `08 task-role` shape: deliberately NOT pinned (out of scope, see floor doc).
	taskRole := DiscoveredResource{Type: "AWS::IAM::Role", URN: taskRoleURN, Inputs: map[string]any{
		"cb_describer_inline_policy_has_wildcard_allow": false,
	}}
	benignSG := DiscoveredResource{Type: "AWS::EC2::SecurityGroup", URN: benignSGURN, Inputs: map[string]any{}}

	cases := []struct {
		name    string
		res     DiscoveredResource
		finding Finding
		wantSev string
	}{
		{"bpa-all-disabled→critical", bpaAllDisabledRes(bpaBucketURN),
			Finding{Resource: bpaBucketURN, Severity: SeverityWarning}, SeverityCritical},
		{"bpa-one-enabled→unchanged", bpaOneEnabled,
			Finding{Resource: bpaBucketURN, Severity: SeverityWarning}, SeverityWarning},
		{"cloudtrail-no-kms→high", trailNoKMS,
			Finding{Resource: trailURN, Severity: SeverityInfo}, SeverityHigh},
		{"cloudtrail-with-kms→unchanged", trailWithKMS,
			Finding{Resource: trailURN, Severity: SeverityInfo}, SeverityInfo},
		{"full-admin-user→critical", adminUserRes(siblingURN),
			Finding{Resource: siblingURN, Severity: SeverityHigh}, SeverityCritical},
		{"service-wildcard-task-role→unchanged (deferred)", taskRole,
			Finding{Resource: taskRoleURN, Severity: SeverityWarning}, SeverityWarning},
		{"over-rate critical on unrelated resource preserved", benignSG,
			Finding{Resource: benignSGURN, Severity: SeverityCritical}, SeverityCritical},
		{"benign info on unrelated resource unchanged", benignSG,
			Finding{Resource: benignSGURN, Severity: SeverityInfo}, SeverityInfo},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := applySeverityFloor([]Finding{tc.finding}, []DiscoveredResource{tc.res})
			if out[0].Severity != tc.wantSev {
				t.Fatalf("%s: want %q, got %q", tc.name, tc.wantSev, out[0].Severity)
			}
		})
	}
}

// ECS-Exec-no-logging is a TEXT heuristic (no structured attribute). Confirm it
// raises the right finding to high and does not mis-fire on near-misses.
func TestSeverityFloor_ECSExecTextHeuristic(t *testing.T) {
	cases := []struct {
		name    string
		f       Finding
		wantSev string
	}{
		{"ecs exec no session logging",
			Finding{Title: "ECS Exec enabled", Description: "no session logging configured", Severity: SeverityInfo}, SeverityHigh},
		{"unrelated lambda exec mention not raised",
			Finding{Title: "Lambda execution role", Description: "broad permissions", Severity: SeverityInfo}, SeverityInfo},
		{"ecs without exec not raised",
			Finding{Title: "ECS task definition", Description: "no log group", Severity: SeverityInfo}, SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := applySeverityFloor([]Finding{tc.f}, nil)
			if out[0].Severity != tc.wantSev {
				t.Fatalf("%s: want %q, got %q", tc.name, tc.wantSev, out[0].Severity)
			}
		})
	}
}

// T6 — account-level findings skip the structural floor (no URN match).
func TestSeverityFloor_AccountScopedSkips(t *testing.T) {
	resources := []DiscoveredResource{adminUserRes(siblingURN)}
	out := applySeverityFloor([]Finding{
		{RuleID: "LLM-acct", Title: "root has no MFA", Resource: accountFinding, Severity: SeverityHigh},
	}, resources)
	if out[0].Severity != SeverityHigh {
		t.Fatalf("account-scoped finding must be unchanged, got %q", out[0].Severity)
	}
}

// T7 — recall neutrality. The floor adds/removes nothing; the only set change is
// step (A)'s self-identity drop. (RuleID, Resource) pairs are otherwise stable.
func TestSeverityFloor_RecallNeutral(t *testing.T) {
	resources := []DiscoveredResource{
		adminUserRes(harnessURN),
		adminUserRes(siblingURN),
		wildcardRoleRes(wildcardURN),
		bpaAllDisabledRes(bpaBucketURN),
	}
	in := []Finding{
		{RuleID: "LLM-1", Resource: harnessURN, Severity: SeverityHigh},
		{RuleID: "LLM-2", Resource: siblingURN, Severity: SeverityHigh},
		{RuleID: "LLM-3", Resource: wildcardURN, Severity: SeverityHigh},
		{RuleID: "LLM-4", Resource: bpaBucketURN, Severity: SeverityWarning},
		{RuleID: "LLM-5", Resource: accountFinding, Severity: SeverityInfo},
	}

	dropped := dropSelfIdentityFindings(in, callerARN)
	if len(dropped) != len(in)-1 {
		t.Fatalf("drop should remove exactly 1 (the self-identity), got len %d from %d", len(dropped), len(in))
	}
	floored := applySeverityFloor(dropped, resources)
	if len(floored) != len(dropped) {
		t.Fatalf("floor must not add/remove findings: got %d, want %d", len(floored), len(dropped))
	}

	// Every surviving (RuleID, Resource) from the post-drop set is preserved.
	want := map[string]string{}
	for _, f := range dropped {
		want[f.RuleID] = f.Resource
	}
	for _, f := range floored {
		if want[f.RuleID] != f.Resource {
			t.Fatalf("finding %s resource changed: %q", f.RuleID, f.Resource)
		}
		delete(want, f.RuleID)
	}
	if len(want) != 0 {
		t.Fatalf("findings disappeared from the set: %v", want)
	}
}

// dropSelfIdentityFindings matching matrix.
func TestDropSelfIdentityFindings(t *testing.T) {
	base := []Finding{
		{RuleID: "self-urn", Resource: harnessURN, Severity: SeverityHigh},
		{RuleID: "self-arn", Resource: callerARN, Severity: SeverityHigh},
		{RuleID: "other-user", Resource: siblingURN, Severity: SeverityHigh},
		{RuleID: "role", Resource: wildcardURN, Severity: SeverityHigh},
	}

	t.Run("drops caller URN and exact ARN, keeps others", func(t *testing.T) {
		out := dropSelfIdentityFindings(base, callerARN)
		if _, ok := sevOf(out, harnessURN); ok {
			t.Errorf("caller URN finding should be dropped")
		}
		if _, ok := sevOf(out, callerARN); ok {
			t.Errorf("caller exact-ARN finding should be dropped")
		}
		if _, ok := sevOf(out, siblingURN); !ok {
			t.Errorf("a different user must NOT be dropped")
		}
		if _, ok := sevOf(out, wildcardURN); !ok {
			t.Errorf("a role must NOT be dropped")
		}
		if len(out) != 2 {
			t.Fatalf("want 2 survivors, got %d", len(out))
		}
	})

	t.Run("empty callerARN is a no-op", func(t *testing.T) {
		out := dropSelfIdentityFindings(base, "")
		if len(out) != len(base) {
			t.Fatalf("empty callerARN must drop nothing, got %d", len(out))
		}
	})

	t.Run("assumed-role caller only drops on exact ARN match", func(t *testing.T) {
		role := "arn:aws:sts::123456789012:assumed-role/AuditRole/session"
		out := dropSelfIdentityFindings([]Finding{
			{RuleID: "user", Resource: harnessURN, Severity: SeverityHigh},
			{RuleID: "exact", Resource: role, Severity: SeverityHigh},
		}, role)
		if _, ok := sevOf(out, harnessURN); !ok {
			t.Errorf("assumed-role caller must not drop unrelated IAM-user findings")
		}
		if _, ok := sevOf(out, role); ok {
			t.Errorf("assumed-role caller should drop its own exact-ARN finding")
		}
	})

	t.Run("does not drop a name-prefixed lookalike user", func(t *testing.T) {
		look := "aws://global/AWS::IAM::User/not-cbx-audit-fixtures"
		out := dropSelfIdentityFindings([]Finding{
			{RuleID: "look", Resource: look, Severity: SeverityHigh},
		}, callerARN)
		if _, ok := sevOf(out, look); !ok {
			t.Errorf("a different user whose name merely ends with the caller name must NOT be dropped")
		}
	})
}
