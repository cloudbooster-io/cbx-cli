package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"

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
	}

	return nil
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
