package audit

import (
	"encoding/json"
	"strings"
)

// This file implements the two-step, deterministic severity post-process that
// runs over the final LLM findings of an `cbx audit aws` pass, just before
// grouping / rendering / exit-code computation (wired in RunFromResources):
//
//	(A) dropSelfIdentityFindings — remove the auditor's own IAM-user finding
//	    (the recurring #1 false positive). MUST run first.
//	(B) applySeverityFloor       — RAISE (never lower) the severity of findings
//	    whose joined resource matches an unambiguous account-takeover / audit-
//	    integrity pattern, imposing a stable spine on top of the LLM's run-to-run
//	    variable severity choices.
//
// Scope is the scale-INDEPENDENT subset: the ≥2-bucket "b1" bugs that are wrong
// under any severity scale, plus the full-admin/wildcard determinism spine. The
// broader systematic CRITICAL→high calibration cluster ("b2") is intentionally
// NOT pinned here — it depends on a maintainer decision about the canonical
// severity scale and would change display-tier values for cases that are within
// the fixtures' own ±1 tolerance.
//
// Both steps are pure functions over their inputs (no AWS, no LLM), so they are
// trivially unit-testable — see severity_floor_test.go.

// raiseTo returns target when it is strictly more severe than current,
// otherwise current — the floor's raise-only invariant in one place. Severity
// order is the package-level severityRank (render_aws_html.go).
func raiseTo(current, target string) string {
	if severityRank(target) > severityRank(current) {
		return target
	}
	return current
}

// dropSelfIdentityFindings removes findings whose subject resource is the
// auditor's OWN IAM user — the recurring #1 false positive across the fixture
// sweep (the harness identity `cbx-audit-fixtures`: admin + active key + no
// MFA). It implements the `data.identity.ARN` allowlist the recall baseline
// asked for, and MUST run BEFORE applySeverityFloor: the caller's own admin
// user is the exact shape the full-admin floor promotes to `critical`, so
// dropping it first prevents the floor from amplifying the sweep's noisiest FP.
//
// Matching is scoped to IAM-user callers. The caller ARN
// (arn:aws:iam::<acct>:user/<path>/<name>) yields a user name joined against
// each finding's resource — either an exact ARN match or an IAM-user URN
// (aws://<region>/AWS::IAM::User/<name>). Assumed-role / non-user callers only
// drop on an exact ARN match (there is no IAM user to allowlist), the
// conservative choice. An empty callerARN is a no-op. The input slice is not
// mutated; a fresh slice is returned.
func dropSelfIdentityFindings(findings []Finding, callerARN string) []Finding {
	callerARN = strings.TrimSpace(callerARN)
	if callerARN == "" {
		return findings
	}
	userName := iamUserNameFromARN(callerARN)

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if isSelfIdentityResource(f.Resource, callerARN, userName) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// iamUserNameFromARN extracts the user name from an IAM-user ARN
// (arn:aws:iam::<acct>:user/<optional/path>/<name>). Returns "" for any other
// ARN shape (e.g. an assumed-role ARN), signalling "no IAM user to allowlist".
func iamUserNameFromARN(arn string) string {
	const marker = ":user/"
	i := strings.Index(arn, marker)
	if i < 0 {
		return ""
	}
	rest := arn[i+len(marker):]
	// IAM user ARNs may carry a path; the user name is the final segment.
	if j := strings.LastIndex(rest, "/"); j >= 0 {
		rest = rest[j+1:]
	}
	return rest
}

// isSelfIdentityResource reports whether a finding's resource string refers to
// the caller's own identity: an exact ARN match, or — for IAM-user callers —
// the caller's IAM-user URN/ARN matched by user name.
func isSelfIdentityResource(resource, callerARN, userName string) bool {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return false
	}
	if resource == callerARN {
		return true
	}
	if userName == "" {
		return false
	}
	// IAM-user URN form: aws://<region>/AWS::IAM::User/<name>.
	if strings.HasSuffix(resource, "/AWS::IAM::User/"+userName) {
		return true
	}
	// IAM-user ARN form (single-account audit ⇒ a user-name match is the
	// caller). The leading ":user/" guard avoids matching role/other ARNs.
	if strings.Contains(resource, ":user/") && iamUserNameFromARN(resource) == userName {
		return true
	}
	return false
}

// applySeverityFloor deterministically RAISES (never lowers) the severity of a
// finding when (a) its joined resource matches one of the unambiguous, scale-
// independent patterns below AND (b) the finding's own text shows it is the
// finding REPORTING that condition. It joins findings to resources by URN
// (Finding.Resource is the resource URN; account-scoped `account:<id>` findings
// and any unmatched URN skip the structural pins). The structural half keys on
// the resource attributes cbx's describers already compute (cb_describer_*) and
// raw CloudFormation fields; the finding-scoping half keys on Title+Description
// — never on LLM-generated rule_ids, which drift run-to-run. Scoping to the
// condition-bearing finding is what keeps the floor from over-promoting an
// orthogonal finding (lifecycle, DLQ, …) that merely shares the resource URN.
// The input slice is not mutated; a fresh slice is returned.
//
//	critical:
//	  - full-admin / wildcard IAM grant (Action:* Resource:* / AdministratorAccess
//	    / admin-equivalent role) on any role or user
//	  - S3 bucket with Block-Public-Access all four controls disabled
//	high:
//	  - CloudTrail trail with no SSE-KMS encryption
//	  - ECR repository permitting MUTABLE image tags (raw CFN ImageTagMutability)
//	  - ECS Exec enabled with no session logging (TEXT heuristic; no structured
//	    attribute exists)
//	  - RDS storage / attached EBS volume unencrypted at rest (§4.2)
//	  - EC2 instance still allowing IMDSv1 (§4.2)
//	  - IAM role with cross-account trust and no scoping condition (ExternalId /
//	    OrgID / Source*) or enforcing Deny (§4.2)
//
// auditedAccount is the AWS account the audit ran as (AWSAuditContext.AccountID,
// a single-account audit). It is used ONLY by the cross-account-trust pin to tell
// a same-account principal from a cross-account one; an empty value disables that
// one pin (we never guess "cross-account" without knowing our own account).
func applySeverityFloor(findings []Finding, resources []DiscoveredResource, auditedAccount string) []Finding {
	if len(findings) == 0 {
		return findings
	}
	byURN := make(map[string]DiscoveredResource, len(resources))
	for _, r := range resources {
		byURN[r.URN] = r
	}

	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		f := &out[i]
		if res, ok := byURN[f.Resource]; ok {
			// Each structural condition is ANDed with a finding-scoping text
			// gate so the promotion fires ONLY on the finding that actually
			// REPORTS that condition — not on every orthogonal finding that
			// merely shares the resource URN (e.g. a lifecycle finding on a
			// BPA-all-disabled bucket, or a DLQ/reserved-concurrency finding on
			// an admin-equivalent role). The structural predicate proves the
			// resource genuinely has the condition (drift-free cb_describer_*
			// signals); the text gate proves this is the finding about it. This
			// mirrors isECSExecWithoutLogging, which already keys on the finding.
			switch {
			case isFullAdminWildcardGrant(res) && findingConcernsAdminGrant(f):
				f.Severity = raiseTo(f.Severity, SeverityCritical)
			case isPublicAccessBlockAllDisabled(res) && findingConcernsPublicAccess(f):
				f.Severity = raiseTo(f.Severity, SeverityCritical)
			case isCloudTrailWithoutKMS(res) && findingConcernsEncryption(f):
				f.Severity = raiseTo(f.Severity, SeverityHigh)
			case isECRMutableTags(res) && findingConcernsImageTagMutability(f):
				f.Severity = raiseTo(f.Severity, SeverityHigh)
			// §4.2 structural HIGH floors. Each is resource-type-scoped and
			// mutually exclusive with the cases above by type — except the IAM
			// role, which the full-admin CRITICAL case handles FIRST, so a role
			// that is BOTH admin-equivalent AND a cross-account trust lands
			// critical (the admin case wins), never downgraded to high here.
			case isRDSStorageUnencrypted(res) && findingConcernsEncryption(f):
				f.Severity = raiseTo(f.Severity, SeverityHigh)
			case isEBSAttachedUnencrypted(res) && findingConcernsEncryption(f):
				f.Severity = raiseTo(f.Severity, SeverityHigh)
			case isIMDSv1Allowed(res) && findingConcernsIMDSv1(f):
				f.Severity = raiseTo(f.Severity, SeverityHigh)
			case isCrossAccountTrustWithoutExternalID(res, auditedAccount) && findingConcernsCrossAccountTrust(f):
				f.Severity = raiseTo(f.Severity, SeverityHigh)
			}
		}
		// TEXT heuristic — runs per-finding because no structured attribute
		// exists for ECS-Exec session logging. raiseTo keeps it raise-only.
		if isECSExecWithoutLogging(f) {
			f.Severity = raiseTo(f.Severity, SeverityHigh)
		}
	}
	return out
}

// findingConcernsAdminGrant / findingConcernsPublicAccess / findingConcernsEncryption
// are the finding-scoping text gates that pair with the resource-keyed structural
// predicates in applySeverityFloor. The structural predicate proves the resource
// genuinely HAS the condition; the gate proves THIS finding is the one reporting
// it, so an orthogonal finding sharing the same resource URN is left untouched.
//
// They key on the finding's own Title+Description text — the same signal
// isECSExecWithoutLogging uses — deliberately NOT on RuleID, which the LLM
// generates (and which cbx itself derives from a hash of the title), so it
// drifts run-to-run and cannot identify a rule.
func findingConcernsAdminGrant(f *Finding) bool {
	// IAM policy JSON writes Action and Resource separately, so the literal
	// "*:*" almost never appears in an LLM finding, and an admin-equivalent
	// grant is more often phrased "full control" / "unrestricted" / "all
	// actions on all resources" / "(overly) permissive" than "full access".
	// These widen which findings the promotion CAN reach; the structural
	// isFullAdminWildcardGrant(res) gate still proves the resource genuinely
	// has the grant, so a non-admin resource is never promoted (no over-fire).
	return findingTextHasAny(f,
		"admin", "wildcard", "full access", "fullaccess", "privilege", "*:*",
		"unrestricted", "all actions", "full control", "permissive")
}

// findingConcernsPublicAccess gates the S3 Block-Public-Access promotion on
// BPA-SPECIFIC phrasing only — deliberately NOT the bare token "public". The
// LLM sprinkles "public" across orthogonal S3-hygiene recs ("public-facing
// bucket", "publicly listed prefix", …); on a BPA-all-disabled bucket the floor
// joins by URN over the full finding set, so gating on bare "public" promoted
// those INFO hygiene findings to CRITICAL — inverting the "hygiene = info"
// contract. The real BPA-all-disabled finding always says "block public access"
// / "publicly accessible", so the tighter phrase set keeps it matched while
// leaving the hygiene findings at their own severity. This is the one gate where
// over-permissiveness is NOT benign (see the findingTextHasAny note).
func findingConcernsPublicAccess(f *Finding) bool {
	return findingTextHasAny(f, "block public access", "public access block", "publicly accessible", "bpa")
}

func findingConcernsEncryption(f *Finding) bool {
	return findingTextHasAny(f, "kms", "encrypt", "cmk", "sse")
}

// findingConcernsImageTagMutability gates the ECR promotion on
// mutability-SPECIFIC phrasing — the "mutab" stem covers the finding the LLM
// actually emits ("ECR repository allows mutable image tags" /
// "ImageTagMutability=MUTABLE"). The same repo also draws orthogonal
// scan-on-push and lifecycle findings; neither says "mutab", so the gate leaves
// them at their own severity. Lifecycle in particular is the real over-raise
// risk (spec MEDIUM) — the structural isECRMutableTags(res) join alone would
// reach it; the text gate is what keeps it untouched.
func findingConcernsImageTagMutability(f *Finding) bool {
	return findingTextHasAny(f, "mutab")
}

// findingTextHasAny lower-cases the finding's Title+Description and reports
// whether any keyword is present.
//
// An EMPTY text (no Title and no Description) matches conservatively: the gate
// cannot discriminate, so it defers to the structural signal and allows the
// promotion — preserving the pre-fix behavior for that case. This branch has no
// production footprint: every analyzer-emitted Finding carries a Title (the LLM
// JSON `title`, from which RuleID itself is derived in parseLLMFindings), so the
// orthogonal-finding case the gate guards against always has discriminating
// text in practice. The fallback exists only so the floor's unit fixtures, which
// assert promotion on text-less findings, keep passing.
//
// Keyword lists are deliberately permissive: these gates only RESTRICT a
// raise-only promotion, so a false positive is at worst the pre-fix behavior,
// whereas a false negative would silently drop a real promotion.
func findingTextHasAny(f *Finding, keywords ...string) bool {
	text := strings.ToLower(strings.TrimSpace(f.Title + " " + f.Description))
	if text == "" {
		return true
	}
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

// isFullAdminWildcardGrant reports whether an IAM role/user carries a full-
// administrative or admin-equivalent grant — the unambiguous account-takeover
// shape every framework (CIS, AWS FSBP) rates CRITICAL. Keys on the booleans
// the IAM describer + Lambda-role cross-reference precompute.
//
// IMPORTANT — deliberately matches only FULL wildcard (Action:* AND Resource:*,
// per cbx's matchesWildcard, which requires the literal "*"), AdministratorAccess
// / admin-equivalent. It does NOT match service-level wildcards such as
// `s3:*`+`dynamodb:*` on Resource:* (e.g. the `08 ecs-task-role-s3-ddb-star`
// fixture): those are structurally indistinguishable from the HIGH-band overbroad
// roles (`02 custom-overbroad`, `05 glue-crawler`, `07 asg-instance-profile`),
// so pinning them critical here would over-rate those siblings. That distinction
// is contextual (is the role assumed by a running workload?) and needs either a
// new cross-reference signal or the maintainer's scale decision — out of scope.
func isFullAdminWildcardGrant(r DiscoveredResource) bool {
	for _, key := range []string{
		"cb_describer_role_is_admin_equivalent",
		"cb_describer_role_has_wildcard_inline_policy",
		"cb_describer_admin_managed_policy_attached",
		"cb_describer_inline_policy_has_wildcard_allow",
		"cb_describer_policy_has_wildcard_allow",
	} {
		if b, ok := r.Inputs[key].(bool); ok && b {
			return true
		}
	}
	return false
}

// isPublicAccessBlockAllDisabled reports whether an S3 bucket has all four
// Block-Public-Access controls explicitly disabled — the b1 `bpa-all-disabled`
// bug cbx under-rated to `warning`. The describer emits the config as a
// map[string]any of four bools; all-four-false is the critical misconfiguration.
// A nil/absent map (no PAB config at all) is NOT pinned here — that is a
// distinct, more common case the b1 evidence does not cover.
func isPublicAccessBlockAllDisabled(r DiscoveredResource) bool {
	pab, ok := r.Inputs["cb_describer_public_access_block"].(map[string]any)
	if !ok || pab == nil {
		return false
	}
	for _, k := range []string{
		"block_public_acls",
		"block_public_policy",
		"ignore_public_acls",
		"restrict_public_buckets",
	} {
		b, ok := pab[k].(bool)
		if !ok || b {
			// A missing control or any enabled control ⇒ not all-disabled.
			return false
		}
	}
	return true
}

// isCloudTrailWithoutKMS reports whether a CloudTrail trail has no SSE-KMS
// encryption configured (SSE-S3 only) — the b1 `cloudtrail-no-kms` bug cbx
// under-rated to `info`. There is NO cb_describer key for this (the CloudTrail
// cross-reference computes only region coverage), so it keys on the raw
// CloudFormation `KMSKeyId` property CloudControl returns in Inputs.
func isCloudTrailWithoutKMS(r DiscoveredResource) bool {
	if r.Type != "AWS::CloudTrail::Trail" {
		return false
	}
	return strings.TrimSpace(inputsStringCI(r.Inputs, "kmskeyid")) == ""
}

// isECRMutableTags reports whether an ECR repository permits MUTABLE image tags
// — the `08 ecr-image-tag-mutability-mutable` case the capstone under-rated to
// `info` (spec: HIGH; a published release/deploy tag can be overwritten with
// different image content, undermining supply-chain integrity, provenance, and
// reproducible deploys). Like isCloudTrailWithoutKMS there is NO cb_describer_*
// key — the value is the raw CloudFormation `ImageTagMutability` property
// CloudControl returns inline (and the native ECR lister synthesises verbatim),
// an SDK enum string ("MUTABLE"/"IMMUTABLE"). An absent value is NOT pinned (the
// repo wasn't enriched — never infer the gap from a missing key).
func isECRMutableTags(r DiscoveredResource) bool {
	if r.Type != "AWS::ECR::Repository" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(inputsStringCI(r.Inputs, "imagetagmutability")), "MUTABLE")
}

// inputsStringCI does a case-insensitive lookup of a string-valued raw input,
// tolerating CloudFormation/CloudControl casing variance (KMSKeyId vs KmsKeyId).
func inputsStringCI(inputs map[string]any, lowerKey string) string {
	for k, v := range inputs {
		if strings.ToLower(k) == lowerKey {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// isECSExecWithoutLogging is a TEXT heuristic (no structured attribute exists)
// for the b1 `ecs-exec-no-log` bug: ECS Exec enabled with no session logging,
// cbx under-rated to `info`. Matched conservatively on the finding's own text
// to avoid mis-firing on unrelated findings that merely mention "exec".
func isECSExecWithoutLogging(f *Finding) bool {
	text := strings.ToLower(f.Title + " " + f.Description)
	if !strings.Contains(text, "exec") {
		return false
	}
	if !strings.Contains(text, "log") && !strings.Contains(text, "audit") {
		return false
	}
	return strings.Contains(text, "ecs") || strings.Contains(text, "session") || strings.Contains(text, "ssm")
}

// ===========================================================================
// §4.2 structural HIGH floors (RDS/EBS at-rest encryption, IMDSv1, cross-account
// trust). Each follows the same shape as the b1 pins above: a drift-free,
// type-scoped structural predicate over cb_describer_* / raw CFN fields, ANDed in
// applySeverityFloor with a finding-text gate so only the finding REPORTING the
// condition is raised — never an orthogonal finding sharing the resource URN.
// All three deliberately treat an ABSENT signal as "not read", never as the
// finding (no infer-from-missing-key), mirroring the RDS describer's documented
// "false != not-read" philosophy.
// ===========================================================================

// findingConcernsEncryption already gates the RDS / EBS at-rest pins (it keys on
// "kms"/"encrypt"/"cmk"/"sse", which the unencrypted-storage finding always
// carries); the two new gates below pair with the IMDSv1 and cross-account pins.

// findingConcernsIMDSv1 gates the IMDSv1 pin on instance-metadata-service
// phrasing. Permissive by design (it only RESTRICTS a raise-only promotion that
// the structural isIMDSv1Allowed already proved), but tight enough not to reach
// orthogonal EC2 findings: it deliberately avoids the bare token "metadata".
func findingConcernsIMDSv1(f *Finding) bool {
	return findingTextHasAny(f, "imds", "instance metadata", "metadata service", "http tokens", "httptokens")
}

// findingConcernsCrossAccountTrust gates the cross-account-trust pin on
// trust/assume-role/external-id phrasing — not on bare "role", so an orthogonal
// finding on the same role (unused role, key rotation, …) is left untouched.
func findingConcernsCrossAccountTrust(f *Finding) bool {
	return findingTextHasAny(f,
		"externalid", "external id", "cross-account", "cross account",
		"assume role", "assumerole", "trust policy", "trust relationship", "confused deputy")
}

// isRDSStorageUnencrypted reports whether an RDS instance/cluster has storage
// encryption-at-rest explicitly disabled. The RDS describer lifts StorageEncrypted
// into cb_describer_storage_encrypted ONLY when CloudControl returned the field
// (copyBool leaves it absent otherwise — describer_rds.go deliberately keeps
// "false" distinct from "not read"), so a present-and-false read is a genuine
// unencrypted-at-rest signal, never a not-enriched default.
func isRDSStorageUnencrypted(r DiscoveredResource) bool {
	if !strings.HasPrefix(r.Type, "AWS::RDS::") {
		return false
	}
	enc, ok := r.Inputs["cb_describer_storage_encrypted"].(bool)
	return ok && !enc
}

// isEBSAttachedUnencrypted reports whether an ATTACHED EBS volume is unencrypted
// at rest. Unlike RDS, the EBS describer sets cb_describer_encrypted
// unconditionally (an absent raw Encrypted defaults it to false), so this gates
// on the RAW Encrypted being explicitly present-and-false — restoring the RDS
// "absent != false" guarantee and avoiding a not-read false positive. Scoped to
// attached volumes: an unattached unencrypted volume is the cost/hygiene item the
// prompt already covers separately, not this HIGH data-confidentiality finding.
func isEBSAttachedUnencrypted(r DiscoveredResource) bool {
	if r.Type != "AWS::EC2::Volume" {
		return false
	}
	enc, ok := r.Inputs["Encrypted"].(bool)
	if !ok || enc {
		return false
	}
	attached, _ := r.Inputs["cb_describer_is_attached"].(bool)
	return attached
}

// isIMDSv1Allowed reports whether an EC2 instance still answers unauthenticated
// IMDSv1 requests: MetadataOptions present AND HttpTokens != "required". The
// describer's cb_describer_imdsv2_required key collapses "MetadataOptions absent"
// and "HttpTokens optional" both to false, so this reads the raw nested
// MetadataOptions directly and REQUIRES it present — an instance CloudControl
// didn't enrich with metadata options is "not read", not "IMDSv1 allowed", and
// must not fire. (When MetadataOptions IS present, an unset/empty HttpTokens means
// AWS's default of "optional", i.e. IMDSv1 still accepted — correctly flagged.)
func isIMDSv1Allowed(r DiscoveredResource) bool {
	if r.Type != "AWS::EC2::Instance" {
		return false
	}
	opts, ok := r.Inputs["MetadataOptions"].(map[string]any)
	if !ok {
		return false
	}
	tokens, _ := opts["HttpTokens"].(string)
	return tokens != "required"
}

// isCrossAccountTrustWithoutExternalID reports whether an IAM role's trust
// (assume-role) policy Allows a DIFFERENT-account AWS principal — or the wildcard
// "*" — to assume it with no sts:ExternalId condition: the confused-deputy
// exposure. auditedAccount is the account the audit ran as (single-account); an
// empty value disables the pin (we cannot tell same- from cross-account without
// it). It reads cb_describer_assume_role_policy_raw (the decoded trust policy the
// IAM describer emits) and is conservative throughout — a malformed document, an
// unparseable principal account, a service principal, a same-account principal,
// a present scoping condition (sts:ExternalId / aws:PrincipalOrgID /
// aws:SourceAccount / aws:SourceArn), or an enforcing Deny all leave it untouched.
func isCrossAccountTrustWithoutExternalID(r DiscoveredResource, auditedAccount string) bool {
	if r.Type != "AWS::IAM::Role" {
		return false
	}
	auditedAccount = strings.TrimSpace(auditedAccount)
	if auditedAccount == "" {
		return false
	}
	raw, ok := r.Inputs["cb_describer_assume_role_policy_raw"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return false
	}
	return trustPolicyExposesCrossAccount(raw, auditedAccount)
}

// trustPolicyExposesCrossAccount parses a decoded JSON IAM trust policy and
// reports whether any Allow statement grants an sts:AssumeRole-class action to a
// cross-account AWS principal (account != auditedAccount, or the wildcard "*")
// without a mitigating scoping control. A scoping control is EITHER a mitigating
// Allow-condition (one of the keys in isMitigatingConditionKey, required-present
// under a positive operator — see conditionHasMitigatingScope) OR an explicit
// Deny that blocks assume-role precisely when that control is absent (see
// denyEnforcesMitigationFor). Either defuses the confused-deputy exposure this
// floor targets. The floor is raise-only, so a mitigated trust simply keeps its
// LLM-assigned severity — the finding is not deleted.
func trustPolicyExposesCrossAccount(raw, auditedAccount string) bool {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return false
	}
	stmts := decodePolicyStatements(doc.Statement)
	for _, st := range stmts {
		if !strings.EqualFold(strings.TrimSpace(st.Effect), "Allow") {
			continue
		}
		if !actionsIncludeAssumeRole(st.Action) {
			continue
		}
		if conditionHasMitigatingScope(st.Condition) {
			continue
		}
		for _, p := range awsPrincipalARNs(st.Principal) {
			if !principalIsCrossAccount(p, auditedAccount) {
				continue
			}
			// An explicit Deny that enforces the scoping control for this
			// principal overrides the Allow in IAM evaluation, so the role is
			// not exposed even when the Allow itself carries no condition.
			if denyEnforcesMitigationFor(stmts, p) {
				continue
			}
			return true
		}
	}
	return false
}

// denyEnforcesMitigationFor reports whether an explicit Deny statement protects
// cross-account principal p by blocking sts:AssumeRole precisely when the scoping
// control is ABSENT — the canonical `Deny + Null:{"sts:ExternalId":"true"}` guard,
// or a `Deny + StringNotEquals:{"aws:PrincipalOrgID":…}` org fence. An explicit
// Deny always overrides an Allow in IAM policy evaluation, so such a Deny defuses
// the exposure. The Deny must cover p (its Principal is "*", or names p's
// account) — a Deny scoped to some OTHER account does not protect this principal.
func denyEnforcesMitigationFor(stmts []policyStatement, p string) bool {
	for _, st := range stmts {
		if !strings.EqualFold(strings.TrimSpace(st.Effect), "Deny") {
			continue
		}
		if !actionsIncludeAssumeRole(st.Action) {
			continue
		}
		if !denyConditionEnforcesScope(st.Condition) {
			continue
		}
		if denyCoversPrincipal(st.Principal, p) {
			return true
		}
	}
	return false
}

// denyCoversPrincipal reports whether a Deny statement's Principal applies to the
// exposed principal p: a "*" / {"AWS":"*"} Deny covers everyone, otherwise the
// Deny must name p exactly or share p's account (by bare id or ARN). A Deny that
// lists only an unrelated account does not protect p.
func denyCoversPrincipal(denyPrincipalRaw json.RawMessage, p string) bool {
	pAcct := accountIDFromPrincipal(p)
	for _, dp := range awsPrincipalARNs(denyPrincipalRaw) {
		dp = strings.TrimSpace(dp)
		if dp == "*" || strings.EqualFold(dp, strings.TrimSpace(p)) {
			return true
		}
		if pAcct != "" && accountIDFromPrincipal(dp) == pAcct {
			return true
		}
	}
	return false
}

// policyStatement is the narrow slice of an IAM statement the trust parse reads.
type policyStatement struct {
	Effect    string          `json:"Effect"`
	Action    json.RawMessage `json:"Action"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
}

// decodePolicyStatements tolerates Statement being a single object OR an array.
func decodePolicyStatements(raw json.RawMessage) []policyStatement {
	if len(raw) == 0 {
		return nil
	}
	var arr []policyStatement
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var one policyStatement
	if json.Unmarshal(raw, &one) == nil {
		return []policyStatement{one}
	}
	return nil
}

// actionsIncludeAssumeRole reports whether the statement's Action (string or
// []string) includes an sts:AssumeRole-class action or a wildcard. A trust
// policy's action is always sts:AssumeRole*, but gating defends against a
// malformed document that an attacker can't exploit anyway.
func actionsIncludeAssumeRole(raw json.RawMessage) bool {
	for _, a := range stringOrStringSlice(raw) {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "*" || a == "sts:*" || strings.HasPrefix(a, "sts:assumerole") {
			return true
		}
	}
	return false
}

// awsPrincipalARNs extracts the AWS-principal values from a statement's
// Principal. It returns entries ONLY for the "AWS" key (string or []string) and
// for a bare "*". Principal.Service / Principal.Federated yield nothing — they
// are not account principals and must never be treated as cross-account.
//
// (D, out of scope) An Allow that uses NotPrincipal — "everyone EXCEPT these" —
// is an effective cross-account wildcard, but this reads only Principal and so
// under-fires on it. Left unhandled deliberately: a NotPrincipal trust policy is
// vanishingly rare, and the miss is a false negative (never a false positive).
func awsPrincipalARNs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	// Principal: "*"  (any principal, any account).
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if strings.TrimSpace(s) == "*" {
			return []string{"*"}
		}
		return nil
	}
	// Principal: {"AWS": "...", "Service": "...", ...}.
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		if awsRaw, ok := obj["AWS"]; ok {
			return stringOrStringSlice(awsRaw)
		}
	}
	return nil
}

// principalIsCrossAccount reports whether an AWS-principal value targets an
// account other than auditedAccount. "*" is cross-account by definition (anyone);
// otherwise the account is extracted from a bare 12-digit id or an ARN's account
// field, and an unparseable principal is conservatively NOT cross-account.
func principalIsCrossAccount(principal, auditedAccount string) bool {
	principal = strings.TrimSpace(principal)
	if principal == "*" {
		return true
	}
	acct := accountIDFromPrincipal(principal)
	return acct != "" && acct != auditedAccount
}

// accountIDFromPrincipal pulls the 12-digit account id out of a principal value:
// a bare account id, or an ARN (arn:aws:iam::<acct>:root|user/…|role/…). Returns
// "" when no account can be determined.
func accountIDFromPrincipal(p string) string {
	p = strings.TrimSpace(p)
	if len(p) == 12 && isAllDigits(p) {
		return p
	}
	if strings.HasPrefix(p, "arn:") {
		if parts := strings.Split(p, ":"); len(parts) >= 5 {
			return parts[4]
		}
	}
	return ""
}

// isMitigatingConditionKey reports whether an IAM condition key scopes an
// assume-role trust to a known org/account and so defuses the cross-account
// confused-deputy exposure: the per-integration shared secret (sts:ExternalId),
// the organization fence (aws:PrincipalOrgID), and the calling-service scope
// (aws:SourceAccount / aws:SourceArn, set by AWS services that assume the role on
// your behalf — exactly the confused-deputy vector this floor targets).
func isMitigatingConditionKey(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "sts:externalid", "aws:principalorgid", "aws:sourceaccount", "aws:sourcearn":
		return true
	}
	return false
}

// conditionHasMitigatingScope reports whether an Allow statement's Condition
// REQUIRES one of the mitigating scoping keys under a POSITIVE operator —
// StringEquals / StringLike / ArnLike (incl. ForAnyValue:/ForAllValues:
// qualifiers) or Null:"false" (require-present). The negated variants
// (StringNotEquals, …) and Null:"true" (require-ABSENT) do NOT scope the trust
// and must NOT count as mitigating — reading a require-absent condition as
// mitigating is exactly the operator-polarity bug that masked a real exposure.
// ...IfExists is also rejected: it makes the key optional, so it does not enforce
// the scope.
func conditionHasMitigatingScope(raw json.RawMessage) bool {
	return conditionMatches(raw, operatorIsMitigating)
}

// denyConditionEnforcesScope is the Deny-side mirror of
// conditionHasMitigatingScope: a Deny that fires when the scoping control is
// absent enforces it. The polarity is INVERTED relative to an Allow — Null:"true"
// (deny when key absent) and a negated string/ARN match (deny when key != the
// allowed value) are the enforcing operators here.
func denyConditionEnforcesScope(raw json.RawMessage) bool {
	return conditionMatches(raw, denyOperatorEnforces)
}

// conditionMatches walks a Condition block ({operator: {key: value}}) and reports
// whether any (operator, mitigating-key, value) triple satisfies want.
func conditionMatches(raw json.RawMessage, want func(op string, valueRaw json.RawMessage) bool) bool {
	if len(raw) == 0 {
		return false
	}
	var byOp map[string]json.RawMessage
	if json.Unmarshal(raw, &byOp) != nil {
		return false
	}
	for op, opRaw := range byOp {
		var kv map[string]json.RawMessage
		if json.Unmarshal(opRaw, &kv) != nil {
			continue
		}
		for k, vRaw := range kv {
			if isMitigatingConditionKey(k) && want(op, vRaw) {
				return true
			}
		}
	}
	return false
}

// operatorIsMitigating reports whether an Allow-side operator REQUIRES the
// scoping key present with an allowed value: a positive string/ARN match, or
// Null:"false". Negated (...Not...), require-absent (Null:"true"), and ...IfExists
// (optional) operators are not mitigating.
func operatorIsMitigating(op string, valueRaw json.RawMessage) bool {
	op = normalizeOperator(op)
	if op == "null" {
		return nullValueRequiresPresent(valueRaw)
	}
	if strings.Contains(op, "ifexists") || strings.Contains(op, "not") {
		return false
	}
	return strings.HasPrefix(op, "string") || strings.HasPrefix(op, "arn")
}

// denyOperatorEnforces reports whether a Deny-side operator blocks assume-role
// when the scoping key is absent or wrong: Null:"true" (deny when absent) or a
// negated string/ARN match (deny when key != the allowed value).
func denyOperatorEnforces(op string, valueRaw json.RawMessage) bool {
	op = normalizeOperator(op)
	if op == "null" {
		return nullValueRequiresAbsent(valueRaw)
	}
	if strings.Contains(op, "ifexists") {
		return false
	}
	return strings.Contains(op, "not") && (strings.HasPrefix(op, "string") || strings.HasPrefix(op, "arn"))
}

// normalizeOperator lowercases a condition operator and strips a ForAnyValue:/
// ForAllValues: set-qualifier prefix, leaving the bare comparison name
// ("stringequals", "null", "arnlike", …).
func normalizeOperator(op string) string {
	op = strings.ToLower(strings.TrimSpace(op))
	if i := strings.LastIndex(op, ":"); i >= 0 {
		op = op[i+1:]
	}
	return op
}

// nullValueRequiresPresent / nullValueRequiresAbsent decode a Null condition
// value (JSON string "true"/"false" or bool): Null:"false" means the key must be
// PRESENT, Null:"true" means it must be ABSENT.
func nullValueRequiresPresent(valueRaw json.RawMessage) bool {
	v, ok := nullBool(valueRaw)
	return ok && !v
}

func nullValueRequiresAbsent(valueRaw json.RawMessage) bool {
	v, ok := nullBool(valueRaw)
	return ok && v
}

func nullBool(valueRaw json.RawMessage) (val, ok bool) {
	var s string
	if json.Unmarshal(valueRaw, &s) == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
		return false, false
	}
	var b bool
	if json.Unmarshal(valueRaw, &b) == nil {
		return b, true
	}
	return false, false
}

// stringOrStringSlice unmarshals a JSON value that may be a single string or an
// array of strings into a []string (nil for neither).
func stringOrStringSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ===========================================================================
// Canonical AWS-Organizations org-access-role downgrade (FP discipline).
//
// AWS Organizations auto-creates `OrganizationAccountAccessRole` in EVERY member
// account: a cross-account admin trust to the management account root, carrying
// AdministratorAccess. It is expected, unavoidable, and cannot be removed while the
// account is an Org member — yet it lands at the TOP of the report because it is
// exactly the shape two raise paths target (the full-admin floor → critical, the
// cross-account-trust floor → high) layered on an LLM the prompt instructs to emit a
// HIGH cross-account-no-ExternalId finding (buildGroundedPrompt, off-limits this
// round). In a real Org member account that is a guaranteed top-severity false
// positive.
//
// A guard INSIDE the raise-only floor cannot fix this: the LLM rates the role HIGH
// on its own, so suppressing the floor still leaves a HIGH FP. This pass instead
// DOWNGRADES (caps to info) the role's cross-account-admin trust finding. It runs
// AFTER applySeverityFloor (wired in RunFromResources) so it overrides BOTH the
// floor's raise AND the LLM's base severity — robust to the model's run-to-run
// severity choices. It caps rather than DROPs (unlike dropSelfIdentityFindings,
// which removes the auditor's own identity as pure noise): a powerful cross-account
// admin role is worth an informational note, so the finding stays visible — just not
// at a tier that demands action.
//
// Because it LOWERS severity, its match must be conservative in the OPPOSITE
// direction to the floor: a floor over-match is benign (worst case = pre-fix
// severity), but a downgrade over-match SILENTLY BURIES a real finding. So the
// recognizer demands the exact canonical NAME *and* the exact canonical TRUST SHAPE
// (account-root-only principals), and the finding-text gate fires ONLY on a positive
// keyword hit — a text-less or orthogonal finding sharing the role's URN is left
// untouched (the inverse of the raise-side gates' empty-text default).

// orgAccessRoleName is the canonical name AWS Organizations gives the role it
// auto-creates in every member account. Matched case-sensitively: AWS always
// creates it with this exact casing, and an exact match is the tightest guard
// against a look-alike spoof.
const orgAccessRoleName = "OrganizationAccountAccessRole"

// downgradeCanonicalOrgRoleFindings caps to info the severity of the finding that
// reports the cross-account-admin trust on a canonical AWS-managed
// OrganizationAccountAccessRole. It joins findings to resources by URN (like
// applySeverityFloor) and edits only findings whose resource is the canonical role
// AND whose text is the trust/admin finding (findingIsCanonicalOrgRoleTrust) — an
// orthogonal finding sharing the role's URN keeps its own severity. The input slice
// is not mutated; a fresh slice is returned. MUST run after applySeverityFloor so it
// overrides the floor's raise.
func downgradeCanonicalOrgRoleFindings(findings []Finding, resources []DiscoveredResource) []Finding {
	if len(findings) == 0 {
		return findings
	}
	byURN := make(map[string]DiscoveredResource, len(resources))
	for _, r := range resources {
		byURN[r.URN] = r
	}
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		f := &out[i]
		res, ok := byURN[f.Resource]
		if !ok || !isCanonicalOrgAccessRole(res) {
			continue
		}
		if findingIsCanonicalOrgRoleTrust(f) {
			f.Severity = capTo(f.Severity, SeverityInfo)
		}
	}
	return out
}

// capTo returns target when it is strictly LESS severe than current, otherwise
// current — the downgrade's lower-only mirror of raiseTo. It never raises a finding
// already below the cap.
func capTo(current, target string) string {
	if severityRank(target) < severityRank(current) {
		return target
	}
	return current
}

// isCanonicalOrgAccessRole reports whether a discovered role is the genuine,
// AWS-Organizations-created OrganizationAccountAccessRole: the exact canonical NAME
// (its CloudControl primary identifier, surfaced as DiscoveredResource.ID, with a
// RoleName input fallback) AND the canonical TRUST SHAPE — every assume-role Allow
// statement trusts ONLY AWS-account-root principal(s). The name alone is spoofable,
// so a role merely NAMED OrganizationAccountAccessRole that trusts a foreign
// user/role ARN, the `*` wildcard, or an AWS service is NOT recognized and keeps
// firing. Conditions are deliberately NOT policed: a trust condition only RESTRICTS
// who may assume the role, so it cannot make root-trust more dangerous (and an
// ExternalId-scoped role never reaches the floor anyway).
//
// We cannot tell the real management account from an attacker's account without the
// Organizations API (not called here), so a single-account-root trust is recognized
// regardless of which account it names — the downgrade is to info (not a drop), so
// even a hypothetical look-alike persistence role stays visible in the report.
func isCanonicalOrgAccessRole(r DiscoveredResource) bool {
	if r.Type != "AWS::IAM::Role" {
		return false
	}
	name := strings.TrimSpace(r.ID)
	if name == "" {
		name = strings.TrimSpace(inputsStringCI(r.Inputs, "rolename"))
	}
	if name != orgAccessRoleName {
		return false
	}
	raw, ok := r.Inputs["cb_describer_assume_role_policy_raw"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return false
	}
	return trustIsAccountRootOnly(raw)
}

// trustIsAccountRootOnly reports whether a decoded JSON trust policy matches the
// canonical org-role shape: at least one statement, and EVERY statement is an Allow
// of an sts:AssumeRole-class action whose Principal trusts ONLY AWS-account-root
// principal(s). Any deviation — a Deny, a non-assume-role action, a `*`, a service/
// federated principal, or a non-root AWS ARN — makes it NOT canonical (so it keeps
// firing). Strictness here is the safe direction for a downgrade.
func trustIsAccountRootOnly(raw string) bool {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return false
	}
	stmts := decodePolicyStatements(doc.Statement)
	if len(stmts) == 0 {
		return false
	}
	for _, st := range stmts {
		if !strings.EqualFold(strings.TrimSpace(st.Effect), "Allow") {
			return false
		}
		if !actionsIncludeAssumeRole(st.Action) {
			return false
		}
		if !principalIsAccountRootOnly(st.Principal) {
			return false
		}
	}
	return true
}

// principalIsAccountRootOnly reports whether a statement's Principal trusts ONLY
// AWS-account-root principal(s): the Principal must be an object whose SOLE key is
// "AWS", and every "AWS" value an account-root form. A bare-string Principal (only
// ever "*" in practice), any additional key (Service / Federated / CanonicalUser),
// or any non-root AWS ARN (`:user/`, `:role/`, …) makes it NOT root-only.
func principalIsAccountRootOnly(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	// Principal: "*" (or any bare string) — never account-root-only.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	if len(obj) != 1 {
		return false
	}
	awsRaw, ok := obj["AWS"]
	if !ok {
		return false
	}
	vals := stringOrStringSlice(awsRaw)
	if len(vals) == 0 {
		return false
	}
	for _, v := range vals {
		if !isAccountRootPrincipal(v) {
			return false
		}
	}
	return true
}

// isAccountRootPrincipal reports whether an AWS-principal value names an ENTIRE
// account root: a bare 12-digit account id, or an `arn:<partition>:iam::<acct>:root`
// ARN. A non-root ARN (`:user/<name>`, `:role/<name>`) or the `*` wildcard returns
// false.
func isAccountRootPrincipal(p string) bool {
	p = strings.TrimSpace(p)
	if len(p) == 12 && isAllDigits(p) {
		return true
	}
	if strings.HasPrefix(p, "arn:") {
		parts := strings.Split(p, ":")
		return len(parts) == 6 && parts[2] == "iam" && parts[5] == "root"
	}
	return false
}

// findingIsCanonicalOrgRoleTrust reports whether a finding is the one REPORTING the
// canonical org-role's cross-account-admin trust — the FP downgradeCanonicalOrgRoleFindings
// caps. Unlike the raise-side text gates (which default to TRUE on empty text — safe
// because they only widen a raise-only promotion), this gate defaults to FALSE: it
// RESTRICTS a downgrade, and an over-match would silently bury a real finding sharing
// the role's URN. So it fires ONLY on a positive cross-account-trust / admin-grant
// keyword hit; a text-less or orthogonal finding is left at its own severity.
func findingIsCanonicalOrgRoleTrust(f *Finding) bool {
	text := strings.ToLower(strings.TrimSpace(f.Title + " " + f.Description))
	if text == "" {
		return false
	}
	for _, kw := range []string{
		"cross-account", "cross account", "assume role", "assumerole",
		"trust policy", "trust relationship", "externalid", "external id",
		"confused deputy", "admin", "administratoraccess",
	} {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}
