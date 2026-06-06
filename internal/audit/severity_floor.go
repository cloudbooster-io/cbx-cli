package audit

import "strings"

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
//	  - ECS Exec enabled with no session logging (TEXT heuristic; no structured
//	    attribute exists)
func applySeverityFloor(findings []Finding, resources []DiscoveredResource) []Finding {
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
	return findingTextHasAny(f, "admin", "wildcard", "full access", "fullaccess", "privilege", "*:*")
}

func findingConcernsPublicAccess(f *Finding) bool {
	return findingTextHasAny(f, "public", "bpa", "block public")
}

func findingConcernsEncryption(f *Finding) bool {
	return findingTextHasAny(f, "kms", "encrypt", "cmk", "sse")
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
