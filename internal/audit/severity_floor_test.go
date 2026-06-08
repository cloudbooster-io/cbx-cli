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
	ecrRepoURN     = "aws://us-east-1/AWS::ECR::Repository/cbx-ecs-app"
	accountFinding = "account:123456789012"
)

// ecrRepoRes builds an ECR repository carrying the raw CloudFormation
// `ImageTagMutability` prop (the value CloudControl/the native lister surface),
// the shape isECRMutableTags reads.
func ecrRepoRes(urn, mutability string) DiscoveredResource {
	return DiscoveredResource{
		Type: "AWS::ECR::Repository", URN: urn, ID: lastSeg(urn),
		Inputs: map[string]any{"ImageTagMutability": mutability},
	}
}

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
	out := applySeverityFloor(dropSelfIdentityFindings(findings, callerARN), resources, "")

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
		}, resources, "")
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
		{"ecr-mutable-tags→high", ecrRepoRes(ecrRepoURN, "MUTABLE"),
			Finding{Resource: ecrRepoURN, Title: "ECR repository allows mutable image tags",
				Description: "ImageTagMutability=MUTABLE — tags can be overwritten", Severity: SeverityInfo}, SeverityHigh},
		{"ecr-mutable-lowercase-value→high (case-insensitive)", ecrRepoRes(ecrRepoURN, "mutable"),
			Finding{Resource: ecrRepoURN, Title: "ECR mutable image tags", Severity: SeverityInfo}, SeverityHigh},
		{"ecr-immutable→unchanged", ecrRepoRes(ecrRepoURN, "IMMUTABLE"),
			Finding{Resource: ecrRepoURN, Title: "ECR mutable image tags", Severity: SeverityInfo}, SeverityInfo},
		{"ecr-mutability-absent→unchanged (no infer from missing key)",
			DiscoveredResource{Type: "AWS::ECR::Repository", URN: ecrRepoURN, Inputs: map[string]any{}},
			Finding{Resource: ecrRepoURN, Title: "ECR mutable image tags", Severity: SeverityInfo}, SeverityInfo},
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
			out := applySeverityFloor([]Finding{tc.finding}, []DiscoveredResource{tc.res}, "")
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
			out := applySeverityFloor([]Finding{tc.f}, nil, "")
			if out[0].Severity != tc.wantSev {
				t.Fatalf("%s: want %q, got %q", tc.name, tc.wantSev, out[0].Severity)
			}
		})
	}
}

// The ECR MUTABLE-tags floor is STRUCT-backed (raw ImageTagMutability) AND
// text-gated. The text gate is what stops the structural URN join from raising
// the OTHER findings the same repo draws — scan-on-push (already HIGH, so a
// no-op) and lifecycle (spec MEDIUM, the real over-raise risk). Only the
// mutability finding may move.
func TestSeverityFloor_ECRMutableTextGate(t *testing.T) {
	mutableRepo := []DiscoveredResource{ecrRepoRes(ecrRepoURN, "MUTABLE")}

	t.Run("only the mutability finding is promoted on a MUTABLE repo", func(t *testing.T) {
		out := applySeverityFloor([]Finding{
			{RuleID: "LLM-mutab", Title: "ECR repository allows mutable image tags",
				Description: "ImageTagMutability=MUTABLE lets a release tag be overwritten",
				Resource:    ecrRepoURN, Severity: SeverityInfo},
			// Orthogonal MEDIUM lifecycle finding — no "mutab" in its text; must stay.
			{RuleID: "LLM-lifecycle", Title: "ECR repository has no lifecycle policy",
				Description: "untagged images accumulate and are never expired",
				Resource:    ecrRepoURN, Severity: SeverityWarning},
			// Orthogonal scan-on-push finding (already high) — must stay high, not be lowered.
			{RuleID: "LLM-scan", Title: "ECR image scanning on push disabled",
				Description: "scanOnPush=false — vulnerabilities are not detected at push time",
				Resource:    ecrRepoURN, Severity: SeverityHigh},
		}, mutableRepo, "")

		for _, f := range out {
			switch f.RuleID {
			case "LLM-mutab":
				if f.Severity != SeverityHigh {
					t.Fatalf("mutability finding: want high, got %q", f.Severity)
				}
			case "LLM-lifecycle":
				if f.Severity != SeverityWarning {
					t.Fatalf("orthogonal lifecycle finding must keep warning, got %q", f.Severity)
				}
			case "LLM-scan":
				if f.Severity != SeverityHigh {
					t.Fatalf("orthogonal scan-on-push finding must keep high, got %q", f.Severity)
				}
			}
		}
	})

	t.Run("a non-ECR resource with \"mutable\" in the text is not promoted (structural gate holds)", func(t *testing.T) {
		out := applySeverityFloor([]Finding{
			{RuleID: "LLM-x", Title: "S3 object lock allows mutable retention",
				Resource: bpaBucketURN, Severity: SeverityInfo},
		}, []DiscoveredResource{{Type: "AWS::S3::Bucket", URN: bpaBucketURN, Inputs: map[string]any{}}}, "")
		if out[0].Severity != SeverityInfo {
			t.Fatalf("non-ECR resource must not be promoted by mutability text alone, got %q", out[0].Severity)
		}
	})
}

// T5b — the regression for the resource-keyed over-promotion defect: when a
// single resource carries BOTH the condition-bearing finding AND an orthogonal
// finding, ONLY the condition-bearing one is promoted; the orthogonal finding
// keeps its own rule severity. Before the fix the floor keyed on the resource
// URN alone and raised EVERY finding on the resource (e.g. an S3 lifecycle
// finding on a BPA-all-disabled bucket → wrongly critical).
func TestSeverityFloor_OrthogonalFindingNotPromoted(t *testing.T) {
	t.Run("BPA-all-disabled bucket: only the public-access finding is promoted", func(t *testing.T) {
		out := applySeverityFloor([]Finding{
			{RuleID: "LLM-bpa", Title: "S3 Block Public Access disabled",
				Description: "all four block-public-access controls are turned off",
				Resource:    bpaBucketURN, Severity: SeverityWarning},
			{RuleID: "LLM-lifecycle", Title: "S3 bucket has no lifecycle policy",
				Description: "objects are never transitioned to cheaper storage or expired",
				Resource:    bpaBucketURN, Severity: SeverityInfo},
			// !31 regression: a hygiene INFO whose text contains the bare token
			// "public" ("public-facing") but is NOT the BPA finding (no "block
			// public access" / "publicly accessible" / "bpa"). The old gate keyed
			// on bare "public" and promoted this INFO→CRITICAL; the tightened gate
			// must leave it at info.
			{RuleID: "LLM-hygiene", Title: "S3 server access logging not enabled",
				Description: "enable access logging to audit requests to this public-facing bucket",
				Resource:    bpaBucketURN, Severity: SeverityInfo},
		}, []DiscoveredResource{bpaAllDisabledRes(bpaBucketURN)}, "")

		for _, f := range out {
			switch f.RuleID {
			case "LLM-bpa":
				if f.Severity != SeverityCritical {
					t.Fatalf("condition-bearing BPA finding: want critical, got %q", f.Severity)
				}
			case "LLM-lifecycle":
				if f.Severity != SeverityInfo {
					t.Fatalf("orthogonal lifecycle finding must keep info, got %q", f.Severity)
				}
			case "LLM-hygiene":
				if f.Severity != SeverityInfo {
					t.Fatalf("hygiene finding mentioning \"public\" must keep info, got %q", f.Severity)
				}
			}
		}
	})

	t.Run("admin-equivalent user: only the admin-grant finding is promoted", func(t *testing.T) {
		out := applySeverityFloor([]Finding{
			{RuleID: "LLM-admin", Title: "User has AdministratorAccess attached",
				Description: "the managed admin policy grants full account access",
				Resource:    siblingURN, Severity: SeverityHigh},
			// Orthogonal: text dodges admin/wildcard/full access/privilege/*:*.
			{RuleID: "LLM-keyrot", Title: "IAM access key not rotated",
				Description: "the active access key is older than 365 days",
				Resource:    siblingURN, Severity: SeverityWarning},
		}, []DiscoveredResource{adminUserRes(siblingURN)}, "")

		for _, f := range out {
			switch f.RuleID {
			case "LLM-admin":
				if f.Severity != SeverityCritical {
					t.Fatalf("condition-bearing admin finding: want critical, got %q", f.Severity)
				}
			case "LLM-keyrot":
				if f.Severity != SeverityWarning {
					t.Fatalf("orthogonal key-rotation finding must keep warning, got %q", f.Severity)
				}
			}
		}
	})
}

// T5c — the admin-grant text gate widened beyond admin/wildcard/full-access to
// the phrasings the LLM actually uses for an admin-equivalent grant: IAM policy
// JSON writes Action/Resource separately so "*:*" almost never appears, and the
// finding says "full control" / "unrestricted" / "all actions" / "permissive"
// rather than "full access". On an admin-equivalent resource (structural gate
// true) each new phrasing now promotes a below-critical finding to critical; on
// a NON-admin resource the very same wording promotes nothing — proof the
// widening only relaxes WHICH findings the promotion can reach, while the
// structural isFullAdminWildcardGrant predicate still decides IF it fires.
func TestSeverityFloor_AdminGrantWideKeywords(t *testing.T) {
	// admin-equivalent user — isFullAdminWildcardGrant(res) == true.
	adminRes := adminUserRes(siblingURN)
	// plain role with no admin/wildcard signal — isFullAdminWildcardGrant == false.
	nonAdminRole := DiscoveredResource{
		Type: "AWS::IAM::Role", URN: taskRoleURN, ID: lastSeg(taskRoleURN),
		Inputs: map[string]any{
			"cb_describer_inline_policy_has_wildcard_allow": false,
		},
	}

	// Each description exercises a keyword the OLD gate MISSED — none contain
	// admin / wildcard / full access / fullaccess / privilege / "*:*".
	cases := []struct {
		name string
		desc string
	}{
		{"unrestricted", "the attached policy grants unrestricted permissions to every API"},
		{"all actions", "the policy statement allows all actions on all resources"},
		{"full control", "this role grants full control over all resources in the account"},
		{"permissive", "an overly permissive policy is attached to this role"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/admin-equivalent→critical", func(t *testing.T) {
			out := applySeverityFloor([]Finding{
				{RuleID: "LLM-new", Title: "IAM policy too broad", Description: tc.desc,
					Resource: siblingURN, Severity: SeverityHigh},
			}, []DiscoveredResource{adminRes}, "")
			if out[0].Severity != SeverityCritical {
				t.Fatalf("%q on admin-equivalent resource: want critical, got %q", tc.desc, out[0].Severity)
			}
		})
		t.Run(tc.name+"/non-admin→unchanged", func(t *testing.T) {
			out := applySeverityFloor([]Finding{
				{RuleID: "LLM-new", Title: "IAM policy too broad", Description: tc.desc,
					Resource: taskRoleURN, Severity: SeverityHigh},
			}, []DiscoveredResource{nonAdminRole}, "")
			if out[0].Severity != SeverityHigh {
				t.Fatalf("%q on NON-admin resource must not promote (structural gate holds): want high, got %q", tc.desc, out[0].Severity)
			}
		})
	}
}

// T6 — account-level findings skip the structural floor (no URN match).
func TestSeverityFloor_AccountScopedSkips(t *testing.T) {
	resources := []DiscoveredResource{adminUserRes(siblingURN)}
	out := applySeverityFloor([]Finding{
		{RuleID: "LLM-acct", Title: "root has no MFA", Resource: accountFinding, Severity: SeverityHigh},
	}, resources, "")
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
	floored := applySeverityFloor(dropped, resources, "")
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

// ===========================================================================
// §4.2 structural HIGH floors — RDS/EBS at-rest encryption, IMDSv1, cross-account
// trust without ExternalId. Pure-function table tests (no AWS, no LLM), each with
// the absent-default / over-raise / raise-only guards the FP discipline requires.
// ===========================================================================

const (
	rdsURN       = "aws://us-east-1/AWS::RDS::DBInstance/cbx-db"
	ebsURN       = "aws://us-east-1/AWS::EC2::Volume/vol-0abc"
	ec2URN       = "aws://us-east-1/AWS::EC2::Instance/i-0abc"
	trustRoleURN = "aws://global/AWS::IAM::Role/cbx-cross-acct-role"
	auditedAcct  = "111111111111"
)

func rdsInstanceRes(urn string, storageEncrypted any) DiscoveredResource {
	in := map[string]any{}
	if storageEncrypted != nil {
		in["cb_describer_storage_encrypted"] = storageEncrypted
	}
	return DiscoveredResource{Type: "AWS::RDS::DBInstance", URN: urn, ID: lastSeg(urn), Inputs: in}
}

func ebsVolRes(urn string, encrypted, attached any) DiscoveredResource {
	in := map[string]any{}
	if encrypted != nil {
		in["Encrypted"] = encrypted
	}
	if attached != nil {
		in["cb_describer_is_attached"] = attached
	}
	return DiscoveredResource{Type: "AWS::EC2::Volume", URN: urn, ID: lastSeg(urn), Inputs: in}
}

func ec2InstanceRes(urn string, metadataOptions map[string]any) DiscoveredResource {
	in := map[string]any{}
	if metadataOptions != nil {
		in["MetadataOptions"] = metadataOptions
	}
	return DiscoveredResource{Type: "AWS::EC2::Instance", URN: urn, ID: lastSeg(urn), Inputs: in}
}

func roleWithTrust(urn, trustJSON string) DiscoveredResource {
	in := map[string]any{}
	if trustJSON != "" {
		in["cb_describer_assume_role_policy_raw"] = trustJSON
	}
	return DiscoveredResource{Type: "AWS::IAM::Role", URN: urn, ID: lastSeg(urn), Inputs: in}
}

// Rule 1 — RDS storage / attached-EBS at-rest encryption off → HIGH.
func TestSeverityFloor_EncryptionAtRest(t *testing.T) {
	encFinding := func(urn, sev string) Finding {
		return Finding{RuleID: "LLM-enc", Title: "storage unencrypted at rest",
			Description: "the volume is not encrypted", Resource: urn, Severity: sev}
	}
	rdsCluster := rdsInstanceRes(rdsURN, false)
	rdsCluster.Type = "AWS::RDS::DBCluster"

	cases := []struct {
		name    string
		res     DiscoveredResource
		finding Finding
		wantSev string
	}{
		{"rds-instance-unencrypted→high", rdsInstanceRes(rdsURN, false), encFinding(rdsURN, SeverityWarning), SeverityHigh},
		{"rds-cluster-unencrypted→high", rdsCluster, encFinding(rdsURN, SeverityWarning), SeverityHigh},
		{"rds-encrypted→unchanged", rdsInstanceRes(rdsURN, true), encFinding(rdsURN, SeverityWarning), SeverityWarning},
		{"rds-encryption-absent→unchanged (no infer from missing key)", rdsInstanceRes(rdsURN, nil), encFinding(rdsURN, SeverityWarning), SeverityWarning},
		{"ebs-attached-unencrypted→high", ebsVolRes(ebsURN, false, true), encFinding(ebsURN, SeverityInfo), SeverityHigh},
		{"ebs-unattached-unencrypted→unchanged (cost/hygiene, not this HIGH)", ebsVolRes(ebsURN, false, false), encFinding(ebsURN, SeverityInfo), SeverityInfo},
		{"ebs-encrypted→unchanged", ebsVolRes(ebsURN, true, true), encFinding(ebsURN, SeverityInfo), SeverityInfo},
		{"ebs-encrypted-absent→unchanged (no infer; unconditional describer key would default false)", ebsVolRes(ebsURN, nil, true), encFinding(ebsURN, SeverityInfo), SeverityInfo},
		{"raise-only: already-critical encryption finding not lowered", rdsInstanceRes(rdsURN, false), encFinding(rdsURN, SeverityCritical), SeverityCritical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := applySeverityFloor([]Finding{tc.finding}, []DiscoveredResource{tc.res}, auditedAcct)
			if out[0].Severity != tc.wantSev {
				t.Fatalf("%s: want %q, got %q", tc.name, tc.wantSev, out[0].Severity)
			}
		})
	}
}

// Rule 1 over-raise guard — only the encryption finding on an unencrypted RDS is
// raised; an orthogonal backup-retention finding sharing the URN keeps its sev.
func TestSeverityFloor_EncryptionOverRaiseGuard(t *testing.T) {
	out := applySeverityFloor([]Finding{
		{RuleID: "LLM-enc", Title: "RDS storage unencrypted at rest",
			Description: "enable KMS storage encryption", Resource: rdsURN, Severity: SeverityWarning},
		{RuleID: "LLM-backup", Title: "RDS automated backup retention too low",
			Description: "retention is 1 day, below the workload RPO", Resource: rdsURN, Severity: SeverityWarning},
	}, []DiscoveredResource{rdsInstanceRes(rdsURN, false)}, auditedAcct)
	for _, f := range out {
		switch f.RuleID {
		case "LLM-enc":
			if f.Severity != SeverityHigh {
				t.Fatalf("encryption finding: want high, got %q", f.Severity)
			}
		case "LLM-backup":
			if f.Severity != SeverityWarning {
				t.Fatalf("orthogonal backup finding must keep warning, got %q", f.Severity)
			}
		}
	}
}

// Rule 2 — EC2 instance still allowing IMDSv1 → HIGH.
func TestSeverityFloor_IMDSv1(t *testing.T) {
	imdsFinding := func(urn, sev string) Finding {
		return Finding{RuleID: "LLM-imds", Title: "EC2 instance allows IMDSv1",
			Description: "HttpTokens is optional; IMDSv2 is not enforced", Resource: urn, Severity: sev}
	}
	cases := []struct {
		name    string
		res     DiscoveredResource
		finding Finding
		wantSev string
	}{
		{"imds-optional→high", ec2InstanceRes(ec2URN, map[string]any{"HttpTokens": "optional"}), imdsFinding(ec2URN, SeverityWarning), SeverityHigh},
		{"options-present-tokens-unset→high (AWS default is optional)", ec2InstanceRes(ec2URN, map[string]any{"HttpEndpoint": "enabled"}), imdsFinding(ec2URN, SeverityWarning), SeverityHigh},
		{"imds-required→unchanged", ec2InstanceRes(ec2URN, map[string]any{"HttpTokens": "required"}), imdsFinding(ec2URN, SeverityWarning), SeverityWarning},
		{"metadata-options-absent→unchanged (no infer from missing key)", ec2InstanceRes(ec2URN, nil), imdsFinding(ec2URN, SeverityWarning), SeverityWarning},
		{"raise-only: already-critical not lowered", ec2InstanceRes(ec2URN, map[string]any{"HttpTokens": "optional"}), imdsFinding(ec2URN, SeverityCritical), SeverityCritical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := applySeverityFloor([]Finding{tc.finding}, []DiscoveredResource{tc.res}, auditedAcct)
			if out[0].Severity != tc.wantSev {
				t.Fatalf("%s: want %q, got %q", tc.name, tc.wantSev, out[0].Severity)
			}
		})
	}
}

// Rule 2 over-raise guard — an IMDSv1-allowing instance also draws an orthogonal
// public-IP finding (no IMDS/metadata phrasing); only the IMDS finding is raised.
func TestSeverityFloor_IMDSv1OverRaiseGuard(t *testing.T) {
	out := applySeverityFloor([]Finding{
		{RuleID: "LLM-imds", Title: "Instance Metadata Service v1 still enabled",
			Description: "set HttpTokens=required to enforce IMDSv2", Resource: ec2URN, Severity: SeverityWarning},
		{RuleID: "LLM-pubip", Title: "EC2 instance has a public IP",
			Description: "the instance is directly addressable from the internet", Resource: ec2URN, Severity: SeverityInfo},
	}, []DiscoveredResource{ec2InstanceRes(ec2URN, map[string]any{"HttpTokens": "optional"})}, auditedAcct)
	for _, f := range out {
		switch f.RuleID {
		case "LLM-imds":
			if f.Severity != SeverityHigh {
				t.Fatalf("imds finding: want high, got %q", f.Severity)
			}
		case "LLM-pubip":
			if f.Severity != SeverityInfo {
				t.Fatalf("orthogonal public-IP finding must keep info, got %q", f.Severity)
			}
		}
	}
}

// Rule 4 — IAM role cross-account trust with no sts:ExternalId → HIGH.
func TestSeverityFloor_CrossAccountTrustNoExternalID(t *testing.T) {
	const (
		crossRoot = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`
		sameRoot  = `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}}`
		withExtID = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"shared-secret"}}}]}`
		svc       = `{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
		wildcard  = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`
		bareAcct  = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"sts:AssumeRole"}]}`
		mixedList = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::222222222222:role/Other"]},"Action":"sts:AssumeRole"}]}`
		denyCross = `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`
	)
	trustFinding := func(sev string) Finding {
		return Finding{RuleID: "LLM-trust", Title: "IAM role allows cross-account AssumeRole without ExternalId",
			Description: "the trust policy grants assume-role to another account with no external id", Resource: trustRoleURN, Severity: sev}
	}
	cases := []struct {
		name    string
		trust   string
		audited string
		wantSev string
	}{
		{"cross-account-root→high", crossRoot, auditedAcct, SeverityHigh},
		{"same-account→unchanged", sameRoot, auditedAcct, SeverityWarning},
		{"cross-account-with-externalid→unchanged", withExtID, auditedAcct, SeverityWarning},
		{"service-principal→unchanged (not an AWS principal)", svc, auditedAcct, SeverityWarning},
		{"wildcard-principal→high", wildcard, auditedAcct, SeverityHigh},
		{"bare-account-id→high", bareAcct, auditedAcct, SeverityHigh},
		{"mixed-list-one-cross-account→high", mixedList, auditedAcct, SeverityHigh},
		{"deny-statement→unchanged", denyCross, auditedAcct, SeverityWarning},
		{"empty-audited-account→unchanged (pin disabled, no guess)", crossRoot, "", SeverityWarning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := applySeverityFloor([]Finding{trustFinding(SeverityWarning)},
				[]DiscoveredResource{roleWithTrust(trustRoleURN, tc.trust)}, tc.audited)
			if out[0].Severity != tc.wantSev {
				t.Fatalf("%s: want %q, got %q", tc.name, tc.wantSev, out[0].Severity)
			}
		})
	}

	t.Run("trust-policy-absent→unchanged (no infer from missing key)", func(t *testing.T) {
		out := applySeverityFloor([]Finding{trustFinding(SeverityWarning)},
			[]DiscoveredResource{roleWithTrust(trustRoleURN, "")}, auditedAcct)
		if out[0].Severity != SeverityWarning {
			t.Fatalf("absent trust policy must not fire, got %q", out[0].Severity)
		}
	})

	t.Run("raise-only: already-critical not lowered", func(t *testing.T) {
		out := applySeverityFloor([]Finding{trustFinding(SeverityCritical)},
			[]DiscoveredResource{roleWithTrust(trustRoleURN, crossRoot)}, auditedAcct)
		if out[0].Severity != SeverityCritical {
			t.Fatalf("raise-only: want critical, got %q", out[0].Severity)
		}
	})
}

// Rule 4 over-raise guard — a cross-account-trust role also draws an orthogonal
// unused-role finding (no trust/external-id/assume phrasing); only the trust
// finding is raised.
func TestSeverityFloor_CrossAccountTrustOverRaiseGuard(t *testing.T) {
	const crossRoot = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`
	out := applySeverityFloor([]Finding{
		{RuleID: "LLM-trust", Title: "Role trusts another account with no ExternalId",
			Description: "add an sts:ExternalId condition to the trust policy", Resource: trustRoleURN, Severity: SeverityWarning},
		{RuleID: "LLM-unused", Title: "IAM role not used in 90 days",
			Description: "the role has no recent activity and may be removable", Resource: trustRoleURN, Severity: SeverityInfo},
	}, []DiscoveredResource{roleWithTrust(trustRoleURN, crossRoot)}, auditedAcct)
	for _, f := range out {
		switch f.RuleID {
		case "LLM-trust":
			if f.Severity != SeverityHigh {
				t.Fatalf("trust finding: want high, got %q", f.Severity)
			}
		case "LLM-unused":
			if f.Severity != SeverityInfo {
				t.Fatalf("orthogonal unused-role finding must keep info, got %q", f.Severity)
			}
		}
	}
}

// Ordering guard — a role that is BOTH admin-equivalent AND a cross-account trust
// lands its admin-grant finding at critical (the admin case is evaluated before
// the cross-account HIGH case), never capped at high.
func TestSeverityFloor_AdminCrossAccountRoleGetsCritical(t *testing.T) {
	const crossRoot = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`
	role := DiscoveredResource{
		Type: "AWS::IAM::Role", URN: trustRoleURN, ID: lastSeg(trustRoleURN),
		Inputs: map[string]any{
			"cb_describer_admin_managed_policy_attached": true,
			"cb_describer_assume_role_policy_raw":        crossRoot,
		},
	}
	out := applySeverityFloor([]Finding{
		{RuleID: "LLM-admin", Title: "Role has AdministratorAccess and full control",
			Description: "the role grants unrestricted admin access to the account", Resource: trustRoleURN, Severity: SeverityHigh},
	}, []DiscoveredResource{role}, auditedAcct)
	if out[0].Severity != SeverityCritical {
		t.Fatalf("admin+cross-account role: want critical (admin wins), got %q", out[0].Severity)
	}
}
