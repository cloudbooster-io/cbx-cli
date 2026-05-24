package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
)

// iamRoleDescriber enriches AWS::IAM::Role with the LastUsedDate that
// CloudControl never returns — it's the single most useful signal for
// "is this role orphaned?" — and decodes AssumeRolePolicyDocument from
// its CloudControl-mangled URL-encoded form into a proper map. Without
// the decode, the grounded analyzer can't reason about trust policies.
type iamRoleDescriber struct{}

func (iamRoleDescriber) CFNType() string { return "AWS::IAM::Role" }

func (iamRoleDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	roleName := r.ID
	if roleName == "" {
		return fmt.Errorf("iam describer: empty role name")
	}

	// IAM is global; the SDK accepts any region. CC tagged Region as
	// "" for global services so just use whatever cfg has.
	client := iam.NewFromConfig(c.cfg)

	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	// GetRole — surfaces LastUsedDate plus the trust-policy doc.
	role, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
	if err != nil {
		return classifyIAMError(err, roleName, "iam:GetRole")
	}

	if role.Role != nil {
		if role.Role.RoleLastUsed != nil && role.Role.RoleLastUsed.LastUsedDate != nil {
			r.Inputs["cb_describer_last_used"] = role.Role.RoleLastUsed.LastUsedDate.UTC().Format("2006-01-02T15:04:05Z")
			if role.Role.RoleLastUsed.Region != nil {
				r.Inputs["cb_describer_last_used_region"] = *role.Role.RoleLastUsed.Region
			}
		} else {
			// Distinct from "we don't know" — the IAM service reports
			// no use ever, which IS the orphan signal.
			r.Inputs["cb_describer_last_used"] = nil
		}

		// AssumeRolePolicyDocument comes URL-encoded as a string. Decode
		// it so downstream analyzers see structured policy.
		if role.Role.AssumeRolePolicyDocument != nil {
			decoded, decodeErr := url.QueryUnescape(*role.Role.AssumeRolePolicyDocument)
			if decodeErr == nil {
				r.Inputs["cb_describer_assume_role_policy_raw"] = decoded
			}
		}
	}

	// AttachedRolePolicies — names of managed policies attached. The
	// grounded analyzer pairs these with iam:GetPolicy to evaluate
	// scope-of-grants, but listing alone is the orphan / least-priv
	// signal v1 needs.
	pols, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &roleName})
	if err != nil {
		// Don't fail the whole enrichment for this — the role data
		// already collected is still useful.
		return classifyIAMError(err, roleName, "iam:ListAttachedRolePolicies")
	}
	if len(pols.AttachedPolicies) > 0 {
		arns := make([]string, 0, len(pols.AttachedPolicies))
		for _, p := range pols.AttachedPolicies {
			if p.PolicyArn != nil {
				arns = append(arns, *p.PolicyArn)
			}
		}
		r.Inputs["cb_describer_attached_managed_policies"] = arns
		// Surface the well-known AWS-managed "danger" policies as a
		// top-level boolean so the LLM doesn't have to recognise the
		// ARN itself. AdministratorAccess + PowerUserAccess are the two
		// the audit's verification flagged as load-bearing.
		r.Inputs["cb_describer_admin_managed_policy_attached"] = hasAdminManagedPolicy(arns)
	}

	// Inline policies are where ad-hoc wildcard grants hide — they're
	// not visible from ListAttachedRolePolicies, so we go fetch them
	// explicitly. Without this the LLM never sees `Action:"*"
	// Resource:"*"` on a role like cbx-audit-overprivileged because the
	// document doesn't exist in CloudControl's response either.
	inline, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: &roleName})
	if err != nil {
		return classifyIAMError(err, roleName, "iam:ListRolePolicies")
	}
	if len(inline.PolicyNames) > 0 {
		docs := make([]map[string]any, 0, len(inline.PolicyNames))
		hasWildcard := false
		for _, name := range inline.PolicyNames {
			n := name
			out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: &n})
			if err != nil {
				return classifyIAMError(err, roleName, "iam:GetRolePolicy")
			}
			if out.PolicyDocument == nil {
				continue
			}
			decoded, decodeErr := url.QueryUnescape(*out.PolicyDocument)
			if decodeErr != nil {
				continue
			}
			docs = append(docs, map[string]any{
				"name":     n,
				"document": decoded,
			})
			if policyHasWildcardAllow(decoded) {
				hasWildcard = true
			}
		}
		r.Inputs["cb_describer_inline_policies"] = docs
		r.Inputs["cb_describer_inline_policy_has_wildcard_allow"] = hasWildcard
	}

	return nil
}

// hasAdminManagedPolicy returns true when one of the AWS-managed
// "danger" policies is attached. Names recognised: AdministratorAccess,
// PowerUserAccess, IAMFullAccess. Kept narrow on purpose; the LLM still
// evaluates other managed policies on its own.
func hasAdminManagedPolicy(arns []string) bool {
	danger := map[string]bool{
		"arn:aws:iam::aws:policy/AdministratorAccess":  true,
		"arn:aws:iam::aws:policy/PowerUserAccess":      true,
		"arn:aws:iam::aws:policy/IAMFullAccess":        true,
	}
	for _, a := range arns {
		if danger[a] {
			return true
		}
	}
	return false
}

// policyHasWildcardAllow decodes the IAM policy JSON and reports
// whether any Statement with Effect=Allow has Action `*` AND Resource
// `*` (or list-of-strings containing `*`). The classic "give me
// everything" grant — surfaced as a top-level boolean so the LLM has a
// crisp signal instead of having to parse JSON nested in a string.
func policyHasWildcardAllow(doc string) bool {
	var parsed struct {
		Statement []struct {
			Effect   string `json:"Effect"`
			Action   any    `json:"Action"`
			Resource any    `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
	}
	for _, s := range parsed.Statement {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if matchesWildcard(s.Action) && matchesWildcard(s.Resource) {
			return true
		}
	}
	return false
}

// matchesWildcard reports whether the value (string or []string) is
// "*" or contains "*" in a list.
func matchesWildcard(v any) bool {
	switch t := v.(type) {
	case string:
		return t == "*"
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

func classifyIAMError(err error, roleName, action string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "AccessDeniedException":
			return &PermissionError{
				Service: "iam",
				Action:  action,
				Cause:   fmt.Errorf("on role %s: %w", roleName, err),
			}
		case "NoSuchEntity":
			// Race: CC listed it, role deleted between list+describe.
			// Treat as soft-skip; the resource will still be in the
			// output with whatever CC data was collected.
			return nil
		}
	}
	return fmt.Errorf("%s on role %s: %w", action, roleName, err)
}

// iamUserDescriber enriches AWS::IAM::User with the security signals
// CloudControl doesn't return: active access-key count + ids + ages,
// MFA-device presence, and the attached managed-policy list. Without
// these, a planted "IAM user with admin access key and no MFA" cannot
// be flagged — CloudControl returns the user but not its credentials.
//
// Per-user API cost: 3 calls (ListAccessKeys + ListMFADevices +
// ListAttachedUserPolicies). Linear in the user count; acceptable for
// the small populations real-world AWS accounts run with.
type iamUserDescriber struct{}

func (iamUserDescriber) CFNType() string { return "AWS::IAM::User" }

func (iamUserDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	userName := r.ID
	if userName == "" {
		return fmt.Errorf("iam user describer: empty user name")
	}
	client := iam.NewFromConfig(c.cfg)

	// Access keys — count, ids, age. A user with an Active key and no
	// MFA is the single most common IAM finding in real audits.
	keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &userName})
	if err != nil {
		return classifyIAMError(err, userName, "iam:ListAccessKeys")
	}
	activeKeys := 0
	keyIDs := make([]string, 0, len(keys.AccessKeyMetadata))
	keyMeta := make([]map[string]any, 0, len(keys.AccessKeyMetadata))
	for _, k := range keys.AccessKeyMetadata {
		entry := map[string]any{}
		if k.AccessKeyId != nil {
			entry["access_key_id"] = *k.AccessKeyId
			keyIDs = append(keyIDs, *k.AccessKeyId)
		}
		entry["status"] = string(k.Status)
		if k.CreateDate != nil {
			entry["create_date"] = k.CreateDate.UTC().Format("2006-01-02T15:04:05Z")
		}
		keyMeta = append(keyMeta, entry)
		if string(k.Status) == "Active" {
			activeKeys++
		}
	}
	r.Inputs["cb_describer_access_keys"] = keyMeta
	r.Inputs["cb_describer_access_key_ids"] = keyIDs
	r.Inputs["cb_describer_active_access_key_count"] = activeKeys

	// MFA devices — presence. Boolean signal so the LLM has a crisp
	// "has_mfa=false + active_access_key_count>0" pattern to match.
	mfas, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: &userName})
	if err != nil {
		return classifyIAMError(err, userName, "iam:ListMFADevices")
	}
	r.Inputs["cb_describer_has_mfa"] = len(mfas.MFADevices) > 0
	r.Inputs["cb_describer_mfa_device_count"] = len(mfas.MFADevices)

	// Attached managed policies — same shape as the role describer so
	// the LLM applies one rule to both. Surfaces the admin-managed-
	// policy flag at the top level for crisp grounding.
	pols, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &userName})
	if err != nil {
		return classifyIAMError(err, userName, "iam:ListAttachedUserPolicies")
	}
	if len(pols.AttachedPolicies) > 0 {
		arns := make([]string, 0, len(pols.AttachedPolicies))
		for _, p := range pols.AttachedPolicies {
			if p.PolicyArn != nil {
				arns = append(arns, *p.PolicyArn)
			}
		}
		r.Inputs["cb_describer_attached_managed_policies"] = arns
		r.Inputs["cb_describer_admin_managed_policy_attached"] = hasAdminManagedPolicy(arns)
	}

	return nil
}

// iamManagedPolicyDescriber fetches the actual policy document for
// customer-managed managed policies. The CloudControl AWS::IAM::ManagedPolicy
// schema exposes PolicyDocument, but the field is URL-encoded JSON
// nested under PolicyVersion; surfacing a decoded copy + a wildcard
// flag at the top level lets the LLM reason about least-privilege
// without re-parsing CFN-shape payloads.
//
// AWS-managed policies are filtered out at the listAndGet layer (see
// keepCustomerIAMPolicy), so this describer only ever runs on
// customer policies.
type iamManagedPolicyDescriber struct{}

func (iamManagedPolicyDescriber) CFNType() string { return "AWS::IAM::ManagedPolicy" }

func (iamManagedPolicyDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	// CC nests the document under PolicyDocument as a URL-encoded JSON
	// string. Decode and parse for wildcards in one pass.
	raw, _ := r.Inputs["PolicyDocument"].(string)
	if raw == "" {
		return nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return nil
	}
	r.Inputs["cb_describer_policy_document"] = decoded
	r.Inputs["cb_describer_policy_has_wildcard_allow"] = policyHasWildcardAllow(decoded)
	return nil
}
