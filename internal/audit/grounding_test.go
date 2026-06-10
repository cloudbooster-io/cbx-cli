package audit

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
)

// newFakeKnowledgeServer stands up an httptest server that answers the
// three CB knowledge endpoints with predictable, content-stable bodies.
func newFakeKnowledgeServer(t *testing.T) *httptest.Server {
	t.Helper()
	envelope := func(data map[string]interface{}) string {
		body, _ := json.Marshal(map[string]interface{}{
			"schema_version": "1",
			"data":           data,
			"meta":           map[string]interface{}{"request_id": "req_t"},
		})
		return string(body)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/knowledge/aws/primitives/"):
			typeID := strings.TrimPrefix(r.URL.Path, "/v1/knowledge/aws/primitives/")
			_, _ = w.Write([]byte(envelope(map[string]interface{}{
				"kb_version": 1,
				"chunks": []map[string]interface{}{
					{
						"doc_path":    "aws/" + typeID + ".md",
						"chunk_text":  "Posture for " + typeID,
						"chunk_index": 0,
						"category":    "primitive",
					},
				},
			})))
		case r.URL.Path == "/v1/knowledge/aws/practices":
			workload := r.URL.Query().Get("workload")
			_, _ = w.Write([]byte(envelope(map[string]interface{}{
				"kb_version": 1,
				"chunks": []map[string]interface{}{
					{
						"doc_path":    "aws/practices/" + workload + ".md",
						"chunk_text":  "Best practices for " + workload,
						"chunk_index": 0,
						"category":    "practices",
					},
				},
			})))
		case r.URL.Path == "/v1/knowledge/aws/composition":
			_, _ = w.Write([]byte(envelope(map[string]interface{}{
				"kb_version": 1,
				"chunks": []map[string]interface{}{
					{
						"doc_path":    "aws/composition/rules.md",
						"chunk_text":  "Composition rules apply.",
						"chunk_index": 0,
						"category":    "composition",
					},
				},
			})))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv
}

// fakeKnowledgeServer returns a knowledge.Client bound to a fresh fake
// server plus its cleanup func, for tests that call BuildGrounding directly.
func fakeKnowledgeServer(t *testing.T) (*knowledge.Client, func()) {
	t.Helper()
	srv := newFakeKnowledgeServer(t)
	return knowledge.New(srv.URL), srv.Close
}

// useFakeKnowledgeBackend points CB_API_URL at a fresh fake knowledge
// server for the duration of the test, so analyzer paths that resolve the
// backend via resolvedCBAPIURL() stay hermetic (no real network).
func useFakeKnowledgeBackend(t *testing.T) {
	t.Helper()
	srv := newFakeKnowledgeServer(t)
	t.Cleanup(srv.Close)
	t.Setenv(cbAPIURLEnv, srv.URL)
}

// TestBuildGrounding_StableAcrossInputShuffle is the load-bearing
// determinism test: the same resources in shuffled order must produce
// byte-identical bundles. If this test fails, the prompt will drift
// between runs and we lose the whole point of the rewrite.
func TestBuildGrounding_StableAcrossInputShuffle(t *testing.T) {
	client, closeSrv := fakeKnowledgeServer(t)
	defer closeSrv()

	original := []DiscoveredResource{
		{Type: "aws_s3_bucket", URN: "aws_s3_bucket.a"},
		{Type: "aws_cloudfront_distribution", URN: "aws_cf.b"},
		{Type: "aws_lambda_function", URN: "aws_lambda.c"},
		{Type: "aws_s3_bucket", URN: "aws_s3_bucket.d"}, // duplicate primitive
	}
	shuffled := append([]DiscoveredResource(nil), original...)
	rng := rand.New(rand.NewSource(42))
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	workloadsOriginal := []string{"static-site", "secure-s3-bucket"}
	workloadsShuffled := []string{"secure-s3-bucket", "static-site"}

	b1, _, err := BuildGrounding(context.Background(), client, original, workloadsOriginal, 4)
	if err != nil {
		t.Fatalf("first BuildGrounding: %v", err)
	}
	b2, _, err := BuildGrounding(context.Background(), client, shuffled, workloadsShuffled, 4)
	if err != nil {
		t.Fatalf("second BuildGrounding: %v", err)
	}

	// Compare the JSON serialisations — easy way to catch any ordering
	// or content drift in the nested structs.
	j1, _ := json.Marshal(b1)
	j2, _ := json.Marshal(b2)
	if string(j1) != string(j2) {
		t.Errorf("bundles differ across shuffled input:\n  a=%s\n  b=%s", j1, j2)
	}
}

// TestBuildGroundedPrompt_StableAcrossResourceShuffle pins the prompt
// builder's output: shuffling the resource slice cannot change a single
// byte of the rendered prompt. Together with the BuildGrounding test
// this covers the whole deterministic pipeline.
func TestBuildGroundedPrompt_StableAcrossResourceShuffle(t *testing.T) {
	bundle := &GroundingBundle{
		Primitives: []PrimitiveKnowledge{
			{TypeID: "aws:cdn/distribution@v1", Missing: true},
			{TypeID: "aws:compute/lambda@v1", Missing: true},
			{TypeID: "aws:s3/bucket@v1", Missing: true},
		},
		Practices: []WorkloadKnowledge{
			{Workload: "static-site", Missing: true},
		},
		Composition: &CompositionKnowledge{
			TypeIDs: []string{"aws:cdn/distribution@v1", "aws:compute/lambda@v1", "aws:s3/bucket@v1"},
			Missing: true,
		},
	}
	resources := []DiscoveredResource{
		{Type: "aws_s3_bucket", URN: "urn:a", Region: "us-east-1"},
		{Type: "aws_cloudfront_distribution", URN: "urn:b", Region: "us-east-1"},
		{Type: "aws_lambda_function", URN: "urn:c", Region: "us-west-2"},
	}
	shuffled := append([]DiscoveredResource(nil), resources...)
	rng := rand.New(rand.NewSource(7))
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	p1 := buildGroundedPrompt(IaCTypeTerraform, nil, resources, bundle, nil)
	p2 := buildGroundedPrompt(IaCTypeTerraform, nil, shuffled, bundle, nil)
	if p1 != p2 {
		t.Errorf("prompt differs across shuffled resources:\n  a=%s\n  b=%s", p1, p2)
	}
}

// TestBuildGroundedPrompt_RendersAccountPosture asserts the account
// posture block lands in the prompt with the LLM-readable per-region
// EBS-encryption table, the IAM summary, and the probe-errors list.
// Without this the LLM has no signal for account-wide gaps like
// "default EBS encryption disabled in eu-central-1".
func TestBuildGroundedPrompt_RendersAccountPosture(t *testing.T) {
	hasPolicy := false
	posture := &AccountPosture{
		EBSEncryptionByDefault: map[string]bool{
			"eu-central-1": false,
			"us-east-1":    true,
		},
		IAMSummary: map[string]int32{
			"AccountMFAEnabled": 0,
			"Users":             3,
		},
		PasswordPolicyPresent: &hasPolicy,
		Errors:                []string{"iam:ListVirtualMFADevices: AccessDenied"},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, posture)
	for _, want := range []string{
		"ACCOUNT POSTURE",
		"eu-central-1: false",
		"us-east-1: true",
		"AccountMFAEnabled: 0",
		"IAM password policy configured: false",
		"AccessDenied",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

// TestBuildGroundedPrompt_IncludesLambdaApigwHygieneRules pins the
// baseline cues for the Lambda DLQ / reserved-concurrency and APIGW
// access-logging findings into the grounded prompt. Without these the
// describer booleans would land in the resource table but the model
// would have no instruction to act on them — these three operational
// gaps were MISSED on the 03-serverless-api fixture for exactly that
// reason.
func TestBuildGroundedPrompt_IncludesLambdaApigwHygieneRules(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		"cb_describer_dlq_configured",
		"cb_describer_reserved_concurrency_set",
		"cb_describer_access_logging_enabled",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing baseline cue %q", want)
		}
	}
}

// TestBuildGroundedPrompt_SeverityCalibration pins the 5-bucket SEVERITY SCALE
// rubric and the two prompt-side severity calibrations into the grounded
// prompt. The AWS-Config-globals reconcile (WARNING→HIGH) has NO deterministic
// floor (it is an account-level finding that skips the URN floor by design), so
// this substring assertion is its only regression guard — without it a later
// prompt edit could silently revert the HIGH back to WARNING and every other
// test would still pass.
func TestBuildGroundedPrompt_SeverityCalibration(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// the 5-bucket rubric marker and its wire-value mapping
		"SEVERITY SCALE",
		"`MEDIUM` maps to `warning`",
		// Config recorder excluding IAM/global types → HIGH (06 capstone drift)
		"emit ONE HIGH account-level finding `account:<accountId>` titled `AWS Config not recording global (IAM) resource types`",
		// ECR MUTABLE image tags → HIGH (08 capstone drift)
		"`AWS::ECR::Repository` has `ImageTagMutability` == `MUTABLE`, emit a HIGH finding",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing severity-calibration text %q", want)
		}
	}
	// The absent-Config case is DELIBERATELY left at WARNING (account-baseline
	// noise; no spec HIGH anchor). Guard that decision so a well-meaning later
	// edit doesn't sweep it up to HIGH along with the globals-excluded case.
	if !strings.Contains(prompt, "emit ONE WARNING `account:<accountId>` finding that AWS Config is not enabled") {
		t.Errorf("grounded prompt must keep the Config-absent case at WARNING")
	}
}

// TestBuildGroundedPrompt_IncludesNextRoundRuleGaps pins the batch-1
// next-round recall bullets (CloudTrail→CW-Logs, ECS writable-root,
// DynamoDB deletion-protection) into the grounded prompt. Each was a
// code-confirmed gap on a healthy variant (06/08/03): the signal lands
// in the resource table but, without these cues, the model has no
// instruction to act on it. The ECS guard substring is asserted
// separately because the explicit-`false`-only behaviour is the
// load-bearing FP control for that HIGH-FP-risk rule — a later edit that
// loosened it to fire on absent/unset would silently regress the "a bare
// container with the field unset is NOT a finding" contract.
func TestBuildGroundedPrompt_IncludesNextRoundRuleGaps(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// CloudTrail no CloudWatch Logs → WARNING (06)
		"`AWS::CloudTrail::Trail` has no `CloudWatchLogsLogGroupArn`",
		// ECS writable container root filesystem → WARNING, scoped (08)
		"whose `ReadonlyRootFilesystem` is explicitly `false`",
		// the FP guard: explicit-false-only, never infer from a missing key
		"fire ONLY on an EXPLICIT `false`",
		// DynamoDB no deletion protection → WARNING, scoped (03)
		"`AWS::DynamoDB::Table` has `DeletionProtectionEnabled: false`",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing next-round rule-gap cue %q", want)
		}
	}
}

// TestBuildGroundedPrompt_IncludesBulletBatch pins the next bullet batch
// (RDS deletion-protection + single-AZ on 07, EC2 no-instance-profile on
// 04, ALB access-logs on 07 via the !53 enrichment) into the grounded
// prompt. Each fires off a PRESENT cb_describer_* field — none is
// absence-inferred. Beyond the four identity cues, the load-bearing
// FALSE-POSITIVE guards are asserted explicitly, because those are what a
// later edit could silently loosen:
//   - the prod-intent gate vocabulary shared by both RDS bullets (these
//     conditions are default-common, so blanket-firing is the FP class);
//   - the instance-scope carve-out — pinned via this batch's UNIQUE
//     "AWS::RDS::DBCluster carries neither carve-out signal" phrase, because
//     bare "AWS::RDS::DBInstance" and the "SUPPRESS when
//     cb_describer_is_cluster_member is true" clause both already appear on
//     the L518 backup-retention bullet and so don't discriminate;
//   - the ALB positive-field / explicit-false-only + skip-when-absent guard,
//     so the bullet can never read a probe error as "logging disabled".
func TestBuildGroundedPrompt_IncludesBulletBatch(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// #3 RDS no deletion protection → WARNING, instance-scoped, prod-intent (07)
		"`cb_describer_deletion_protection: false`",
		// #4 RDS single-AZ → WARNING, instance-scoped, prod-intent (07)
		"`cb_describer_multi_az: false`",
		// prod-intent gate shared by both RDS bullets — the FP control for these
		// default-common conditions (mirrors the S3-hygiene intent gate)
		"production / stateful / primary / critical intent",
		// instance-scope carve-out, discriminating (see doc comment)
		"instance-scoped; an `AWS::RDS::DBCluster` carries neither carve-out signal",
		// #5 EC2 with no IAM instance profile → WARNING, no-profile (empty-string) detection (04)
		"whose `cb_describer_instance_profile_arn` is the empty string",
		// M1 ratification: the bullet's fire-on-ALL (no intent scope) is a
		// COORDINATOR DECISION, not an oversight. Pin the load-bearing imperative
		// — an intent gate directly contradicts it, so a future reviewer who
		// "fixes" the asymmetry by adding a prod-intent/dev-test-sandbox gate (as
		// the RDS siblings carry) breaks this test rather than silently diverging
		// from the ratified behaviour. "intent-scoped" alone recurs in the prompt
		// and would not discriminate; this exact imperative is unique.
		"do NOT add a prod-intent gate here",
		// #1 ALB access logging disabled → WARNING (07, via the !53 attributes enrichment)
		"`cb_describer_alb_access_logs_enabled: false`",
		// the ALB FP guard: positive field, explicit-false-only, never inferred from absence
		"is a POSITIVE field (`true` iff enabled, `false` iff explicitly disabled)",
		"Skip when the field is absent (the LB's attributes weren't read",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing bullet-batch cue %q", want)
		}
	}
}

// TestBuildGroundedPrompt_IncludesEKSNoIRSABullet pins the EKS
// "no pod-level IAM mechanism" bullet (variant 10, HIGH) into the grounded
// prompt. This bullet is the round's hardest case: it fires only when a
// cluster has NEITHER scoped-role mechanism, gated on TWO describer fields
// (`cb_describer_eks_irsa_oidc_provider_present` via the IRSA enrichment AND
// `cb_describer_eks_pod_identity_present` via the Pod-Identity probe). Each
// pinned substring guards a property a later edit could silently break:
//   - the BOTH/AND clause — a loosening to EITHER/OR would reintroduce the
//     Pod-Identity false positive (firing HIGH on a cluster that uses Pod
//     Identity but no OIDC provider), the exact FP this gate exists to kill;
//   - "Skip when EITHER field is ABSENT" — this is what keeps the bullet
//     DORMANT until BOTH enrichments land (an absent field reads as UNKNOWN,
//     never as the gap), so authoring it before the fields are plumbed is
//     FP-safe and it cannot false-fire in the IRSA-only window;
//   - the unique "no pod-level IAM mechanism → HIGH" title fragment — guards
//     the explicit per-rule HIGH severity against a future edit that drops it
//     and lets the general rubric default it to `warning` (a severity miss on
//     variant 10). Bare "Emit a HIGH finding" is non-unique (IMDSv1,
//     backup-retention, … all use it) and would not discriminate.
func TestBuildGroundedPrompt_IncludesEKSNoIRSABullet(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// unique title + explicit HIGH severity (guards the per-rule override)
		"EKS cluster with no pod-level IAM mechanism → HIGH",
		// both-absent gate — fire ONLY on explicit false×2, never EITHER/OR
		"where BOTH `cb_describer_eks_irsa_oidc_provider_present: false` AND `cb_describer_eks_pod_identity_present: false`",
		// FP guard: a present `true` on either field means the mechanism exists
		"SUPPRESS when EITHER field is `true`",
		// FP guard + dormancy: an absent field is UNKNOWN, never the gap
		"Skip when EITHER field is ABSENT",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing EKS no-IRSA bullet cue %q", want)
		}
	}
}

// TestBuildGroundedPrompt_IncludesBackupVaultBullets pins the three AWS
// Backup vault hygiene bullets (no-Vault-Lock → warning, AWS-managed-key →
// info, no-access-policy → info) into the grounded prompt. Each fires off a
// PRESENT cb_describer_* field — none is absence-inferred. Beyond the three
// field+severity identity cues and one key phrase per bullet, the
// load-bearing PRESENT-FIELD guard ("skip when absent") is asserted, because
// that is the FP control a later edit could silently loosen, and the
// "encrypted at rest, not unencrypted" framing is pinned so the AWS-managed-key
// item is never mis-escalated into a storage-unencrypted HIGH.
func TestBuildGroundedPrompt_IncludesBackupVaultBullets(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// #1 no Vault Lock → warning (field + severity)
		"`cb_describer_vault_locked: false`) → `warning`",
		// #1 key phrase
		"no immutability / ransomware floor",
		// #2 AWS-managed key (non-CMK) → info (field + severity)
		"`cb_describer_vault_uses_aws_managed_key: true`) → `info`",
		// #2 key phrase — and the "encrypted, not unencrypted" framing
		"Backup analog of the S3 SSE-S3→SSE-KMS upgrade item",
		// #3 no access policy → info (field + severity)
		"`cb_describer_vault_access_policy_present: false`) → `info`",
		// #3 key phrase
		"explicit `Deny` on `backup:DeleteRecoveryPoint`",
		// the present-field discipline guard shared by all three bullets
		"SKIP when the field is ABSENT",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing backup-vault-hygiene cue %q", want)
		}
	}
}

// TestBuildGroundedPrompt_IncludesIAMPowerUserGroupBullet pins the
// power-user-group bullet (an AWS::IAM::Group carrying AWS-managed
// PowerUserAccess → MEDIUM) into the grounded prompt. It fires off a PRESENT
// positive cb_describer_* field — never absence-inferred. Beyond the
// field+severity identity cues, the two load-bearing FP guards a later edit
// could silently loosen are asserted: the admin-EXCLUSION clause (the field is
// true only for PowerUserAccess, so a full-admin group can't double-fire as
// this MEDIUM) and the present-field skip-when-absent guard.
func TestBuildGroundedPrompt_IncludesIAMPowerUserGroupBullet(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// field + severity identity
		"`cb_describer_power_user_managed_policy_attached: true`",
		"Emit a MEDIUM finding (wire value `warning`",
		// key phrase
		"persistent full access to nearly all AWS services",
		// admin-exclusion guard (the double-fire FP control)
		"never for AdministratorAccess, so a full-admin group does NOT trip this bullet",
		// present-field discipline guard
		"Skip when `cb_describer_power_user_managed_policy_attached` is absent",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing power-user-group cue %q", want)
		}
	}
}

// TestBuildGroundedPrompt_IncludesS3KMSExposureBullets pins the CIS/FSBP
// bucket-A batch — S3 Block Public Access disabled (HIGH), public KMS
// key-policy (CRITICAL), and KMS customer-CMK rotation off (info) — into the
// grounded prompt. These are BEYOND-FIXTURES (planted in no variant) and
// detection-only: with no live-val and no compliant control, the bullet design
// itself is the only FP guard, so each bullet's load-bearing guard is pinned
// here, not just its identity cue:
//   - S3 BPA fires off a PRESENT object with an explicit `false` flag; the
//     null/absent → SKIP clause is the FP control (a bucket with no bucket-level
//     PAB may be covered by ACCOUNT-level BPA — firing HIGH on `null` would
//     over-fire on a protected bucket), pinned via the unique account-level
//     rationale phrase. It is HIGH data-exposure, NOT an `info` hygiene item, so
//     the "do NOT downgrade it to `info`" imperative is pinned too.
//   - public KMS key-policy reuses the S3/Glue wildcard-principal logic over the
//     raw `KeyPolicy`; the load-bearing FP guard is that the UBIQUITOUS default
//     key policy grants the account-root ARN (NOT a wildcard) — a loosening that
//     flagged it would false-fire on essentially every CMK in the account.
//   - KMS rotation fires only on an explicit-false customer CMK; the
//     AWS-managed suppression (AWS rotates those itself) is the FP control.
//
// Severities are pinned via each bullet's unique title fragment (the HIGH /
// CRITICAL / info arrow in each title), because a bare "Emit a HIGH/CRITICAL
// finding" recurs across other bullets and would not discriminate a dropped
// override.
func TestBuildGroundedPrompt_IncludesS3KMSExposureBullets(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// #1 S3 BPA disabled — unique title + explicit HIGH severity
		"S3 Block Public Access disabled → HIGH",
		// #1 field identity — the four BPA flags read off the present object
		"`block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`",
		// #1 load-bearing FP guard: null/absent → skip, account-level-BPA rationale
		"it may be covered by account-level Block Public Access",
		// #1 the public-intent suppression carve-out (the legitimate disable case)
		"public static-site / CloudFront-origin / public-website bucket",
		// #1 do-not-downgrade imperative (guards the HIGH against an info fold-in)
		"do NOT downgrade it to `info`",
		// #2 public KMS key policy — unique title + explicit CRITICAL severity
		"Public KMS key policy → CRITICAL",
		// #2 field identity — the raw KeyPolicy (KeyPolicy appears nowhere else)
		"an `AWS::KMS::Key`'s raw `KeyPolicy`",
		// #2 a scoping condition unique to this bullet
		"`kms:CallerAccount`",
		// #2 load-bearing FP guard: the default root-account grant is NOT a wildcard
		"which is an account-root ARN, NOT a wildcard",
		// #3 KMS rotation off — field + severity identity
		"`cb_describer_key_rotation_enabled: false`",
		"rotation disabled → `info` (key hygiene)",
		// #3 load-bearing FP guard: suppress AWS-managed keys
		"AWS rotates those on its own schedule, outside operator control",
		// #3 symmetric-key scoping (belt-and-suspenders, field in hand)
		"`cb_describer_key_spec: SYMMETRIC_DEFAULT`",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing S3/KMS exposure-bullet cue %q", want)
		}
	}
}

// TestBuildGrounding_404IsPlaceholder verifies that a knowledge gap
// surfaces as a Missing entry — not as an error and not as a silently
// dropped slot. Required by advisor flag #3.
func TestBuildGrounding_404IsPlaceholder(t *testing.T) {
	envelope := func(data map[string]interface{}) []byte {
		body, _ := json.Marshal(map[string]interface{}{
			"schema_version": "1",
			"data":           data,
			"meta":           map[string]interface{}{"request_id": "req_t"},
		})
		return body
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "missing") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(envelope(map[string]interface{}{
			"kb_version": 1,
			"chunks":     []map[string]interface{}{{"doc_path": "ok.md", "chunk_text": "ok"}},
		}))
	}))
	defer srv.Close()

	client := knowledge.New(srv.URL)
	resources := []DiscoveredResource{
		{Type: "aws_s3_bucket", URN: "urn:a"}, // resolves to aws:s3/bucket@v1
	}
	// Inject a synthetic primitive that the fake server will 404 by
	// inserting a fake Inputs override the resolver picks up.
	resources[0].Inputs = map[string]any{"cb_describer_primitive_resolved": "aws:fake/missing@v1"}

	bundle, _, err := BuildGrounding(context.Background(), client, resources, nil, 1)
	if err != nil {
		t.Fatalf("BuildGrounding: %v", err)
	}
	if len(bundle.Primitives) != 1 {
		t.Fatalf("expected 1 primitive, got %d", len(bundle.Primitives))
	}
	if !bundle.Primitives[0].Missing {
		t.Errorf("expected Missing=true for 404'd primitive, got %+v", bundle.Primitives[0])
	}
}

// TestBuildGroundedPrompt_RendersObservabilityPosture asserts the
// GuardDuty and AWS Config posture blocks reach the prompt — including
// the derived aggregate lines the FP-safe rules key on (per-region facts
// alone aren't enough: the LLM must not flag a single-region absence /
// global-types gap when another region covers it).
func TestBuildGroundedPrompt_RendersObservabilityPosture(t *testing.T) {
	posture := &AccountPosture{
		GuardDutyByRegion: map[string]string{
			"us-east-1":    "disabled",
			"eu-central-1": "absent",
		},
		ConfigRecorderByRegion: map[string]ConfigRecorderState{
			"us-east-1":    {Present: true, RecordsGlobalTypes: false},
			"eu-central-1": {Present: false, RecordsGlobalTypes: false},
		},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, posture)
	for _, want := range []string{
		"GuardDuty detector",
		"us-east-1: disabled",
		"eu-central-1: absent",
		// us-east-1 holds a DISABLED detector, so a detector IS present
		// account-wide → present-anywhere is true even though no region is
		// "enabled". This is the gate that stops the absent-everywhere
		// WARNING from double-firing alongside the per-region disabled HIGH.
		"GuardDuty detector present in at least one audited region: true",
		"AWS Config recorder",
		"us-east-1: present=true records_global_types=false",
		"AWS Config recorder present in at least one audited region: true",
		"global resource types recorded in at least one audited region: false",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

// TestBuildGroundedPrompt_GuardDutyDisabledIsNotAbsent locks the
// disabled↔absent distinction that the absent-everywhere WARNING keys on.
// Live validation of the observability rules found that WARNING
// double-firing on a DISABLED detector: the old aggregate was true only
// for exactly "enabled", so a disabled-everywhere account derived
// enabled-anywhere=false and the LLM read "no GuardDuty in the account"
// — even though a detector demonstrably exists. The fix mirrors the AWS
// Config recorder gate: present-anywhere counts a disabled detector as
// present, so only a TRUE no-detector-anywhere account trips the warning.
//
// This asserts the deterministic render GATE (the present-anywhere line
// the rule tells the LLM to key on), not the LLM's finding emission —
// that's the layer a unit test can pin. A disabled-only account must
// render present=true (no absent-everywhere warning; the per-region HIGH
// still fires off its own "disabled" line); an all-absent account must
// render present=false (warning preserved).
func TestBuildGroundedPrompt_GuardDutyDisabledIsNotAbsent(t *testing.T) {
	disabledOnly := &AccountPosture{
		GuardDutyByRegion: map[string]string{
			"us-east-1":    "disabled",
			"eu-central-1": "absent",
		},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, disabledOnly)
	if !strings.Contains(prompt, "GuardDuty detector present in at least one audited region: true") {
		t.Errorf("a disabled detector must keep present-anywhere=true (a detector exists; only the per-region HIGH should fire, not the account-wide absent warning)")
	}
	if strings.Contains(prompt, "GuardDuty detector present in at least one audited region: false") {
		t.Errorf("present-anywhere must not be false while a disabled detector exists")
	}

	absentEverywhere := &AccountPosture{
		GuardDutyByRegion: map[string]string{
			"us-east-1":    "absent",
			"eu-central-1": "absent",
		},
	}
	prompt = buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, absentEverywhere)
	if !strings.Contains(prompt, "GuardDuty detector present in at least one audited region: false") {
		t.Errorf("a genuinely no-detector-anywhere account must render present-anywhere=false so the absent-everywhere WARNING still fires")
	}
}

// TestBuildGroundedPrompt_RendersVPCFlowLogsEnrichment guards the link
// the annotateVPCFlowLogs unit test can't see: that
// cb_describer_flow_logs_enabled actually reaches the DISCOVERED
// RESOURCES table the LLM reads (writeResourceTable → serialiseInputs
// dumps the whole Inputs map as JSON). If a refactor ever curated that
// to an allow-list, the VPC flow-logs rule would fire on a field the LLM
// never sees — a silent recall miss — and this test catches it. We
// assert the JSON form ("...": false) so a match can only come from the
// resource table, never the rule prose (which uses the backtick form).
func TestBuildGroundedPrompt_RendersVPCFlowLogsEnrichment(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type:   "AWS::EC2::VPC",
			URN:    "aws://us-east-1/AWS::EC2::VPC/vpc-nolog",
			ID:     "vpc-nolog",
			Region: "us-east-1",
			Inputs: map[string]any{"cb_describer_flow_logs_enabled": false},
		},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, resources, nil, nil)
	table := prompt[strings.Index(prompt, "==== DISCOVERED RESOURCES ===="):]
	if !strings.Contains(table, `"cb_describer_flow_logs_enabled": false`) {
		t.Errorf("resource table missing rendered cb_describer_flow_logs_enabled=false")
	}
}

// TestBuildGroundedPrompt_ObservabilityPostureDeterministic guards the
// sorted-key rendering of the new maps. Map iteration order is random,
// so an unsorted render would diverge across builds — and the existing
// determinism test passes a nil posture, so it can't catch this.
func TestBuildGroundedPrompt_ObservabilityPostureDeterministic(t *testing.T) {
	posture := &AccountPosture{
		GuardDutyByRegion: map[string]string{
			"us-east-1": "enabled", "eu-central-1": "disabled",
			"ap-south-1": "absent", "us-west-2": "enabled",
		},
		ConfigRecorderByRegion: map[string]ConfigRecorderState{
			"us-east-1":    {Present: true, RecordsGlobalTypes: true},
			"eu-central-1": {Present: true, RecordsGlobalTypes: false},
			"ap-south-1":   {Present: false}, "us-west-2": {Present: true, RecordsGlobalTypes: true},
		},
	}
	first := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, posture)
	for i := 0; i < 20; i++ {
		if got := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, posture); got != first {
			t.Fatalf("observability posture render not deterministic across builds")
		}
	}
}

// TestBuildGroundedPrompt_IncludesECSLambdaSecretsBullets pins the bucket-A
// ECS task-definition + Lambda posture bullets (CIS/FSBP coverage-gap batch:
// ECS.4 privileged, ECS.8 plaintext-secrets-in-env, ECS.9 no-log-driver,
// Lambda plaintext-secrets) into the grounded prompt. These read RAW
// synthesised `ContainerDefinitions[*]` fields (the native ECS lister surfaces
// Privileged / Environment / Secrets / LogConfiguration directly — no
// `cb_describer_*` probe) and, for Lambda, the already-set-but-unconsumed
// `cb_describer_env_has_plaintext_secrets`. The two secret bullets are
// HEURISTICS with no compliant-control live-validation yet, so beyond the four
// identity cues this test pins the load-bearing FALSE-POSITIVE controls a later
// edit could silently loosen:
//   - the privileged rule's explicit-`true`-only / skip-on-absent guard — the
//     AWS default is non-privileged, and the lister emits the field only when
//     set, so firing on absent/unset would invent a finding from a missing key;
//   - the ECS env-secret bullet's "NEVER assert the value IS a leaked secret"
//     framing — it must stay a key-NAME-shape review nudge at `warning`, never a
//     certainty claim, or the heuristic ships as noisy accusation;
//   - the Lambda bullet's `info` severity + the exact "review whether…" framing
//     the brief mandated — a future edit that promotes it past `info` or drops
//     the hedge reintroduces the FP risk the field was left unconsumed over.
func TestBuildGroundedPrompt_IncludesECSLambdaSecretsBullets(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// ECS.4 privileged container → HIGH (unique title + explicit per-rule severity)
		"Privileged container → HIGH",
		// fire condition: explicit `true` only
		"whose `Privileged` is explicitly `true`",
		// load-bearing FP guard: skip absent/unset (AWS default non-privileged)
		"SKIP when `Privileged` is ABSENT/unset",
		// ECS.8 plaintext secrets in env → warning, FP-aware (unique title)
		"Secret-shaped plaintext `Environment` vars → `warning`",
		// load-bearing FP framing: heuristic, never a certainty claim
		"NEVER assert the value IS a leaked secret",
		// ECS.9 no log driver → warning (unique title + raw-field condition)
		"No container log driver → `warning`",
		"has no `LogConfiguration.LogDriver`",
		// Lambda plaintext secrets → info, FP-aware (unique title + field identity)
		"Lambda functions with secret-shaped plaintext env vars → `info`",
		"`cb_describer_env_has_plaintext_secrets: true`",
		// the brief-mandated review framing (keeps it a nudge, not an accusation)
		"review whether these env vars hold plaintext secrets",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing ECS/Lambda secrets bullet cue %q", want)
		}
	}
}

// TestBuildGroundedPrompt_IncludesRound2BucketARules pins the round-2
// bucket-A batch (CIS/FSBP Tier-2): CloudTrail log-file-validation,
// EKS Secrets envelope-encryption, S3 SSL-only bucket policy, and
// RDS auto-minor-version-upgrade — all four recommended at WARNING. Three
// ride on RAW CFN / native-lister fields dumped by writeResourceTable
// (`EnableLogFileValidation`, `EncryptionConfigPresent`/`EncryptionConfig`,
// `AutoMinorVersionUpgrade`); the S3 one rides on the existing
// `cb_describer_bucket_policy_*` describer fields. For each bullet this pins
// the unique title (the `→ WARNING` suffix alone is non-discriminating — it
// recurs across the CWL / RDS / ALB bullets — so the full title phrase is the
// real guard) plus the load-bearing FP guard a later edit could silently
// loosen:
//   - CloudTrail: the no-`cb_describer_*`-probe / raw-field framing, so the
//     fire-on-explicit-false / skip-on-absent contract can't be inverted into
//     an absence-inference;
//   - EKS: the dual-shape SUPPRESS clause, so a present `true` boolean OR a
//     non-empty CC `EncryptionConfig` array both correctly suppress;
//   - S3: the intentionally-public SUPPRESS clause — almost no bucket carries an
//     explicit SecureTransport deny, so the intent gate is what stops this from
//     firing on nearly every bucket in the account;
//   - RDS: the instance-scope carve-out via the UNIQUE "carries cluster-level
//     patching" phrase (bare "instance-scoped" recurs on the del-prot / single-AZ
//     bullets and would not discriminate).
func TestBuildGroundedPrompt_IncludesRound2BucketARules(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil)
	for _, want := range []string{
		// #1 CloudTrail log-file-validation → WARNING (unique title + raw field)
		"CloudTrail trail without log-file validation → WARNING (audit integrity)",
		"`EnableLogFileValidation` is explicitly `false`",
		// #1 FP guard: raw CFN field, no describer probe (fire-on-false/skip-on-absent)
		"there is no `cb_describer_*` probe for trails",
		// #2 EKS Secrets envelope-encryption → WARNING (unique title + native bool)
		"EKS cluster without envelope encryption for Kubernetes Secrets → WARNING",
		"`EncryptionConfigPresent: false`",
		// #2 FP guard: dual-shape suppress (present bool OR non-empty CC array)
		"SUPPRESS when `EncryptionConfigPresent` is `true` OR `EncryptionConfig` is a non-empty array",
		// #3 S3 SSL-only bucket policy → info-block sub-bullet (unique title + describer field)
		"No SSL-only / TLS-enforcing bucket policy",
		"`cb_describer_bucket_policy_present: false`",
		// #3 FP guard: intent gate — suppress public/static-site (the noise control)
		"SUPPRESS generic / static-website-origin / already-public buckets",
		// #4 RDS auto-minor-version-upgrade → WARNING (unique title + raw field)
		"RDS DB instance with automatic minor-version upgrades disabled → WARNING (patch hygiene)",
		"`AutoMinorVersionUpgrade` is explicitly `false`",
		// #4 FP guard: instance-scope carve-out, discriminating (see doc comment)
		"carries cluster-level patching and is out of scope",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing round-2 bucket-A cue %q", want)
		}
	}
}
