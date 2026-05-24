package aws

import "strings"

// crossReferenceLambdaRole copies the relevant "is this role
// privileged?" flags from each Lambda's execution role onto the
// Lambda itself, so the LLM has a one-step signal for the canonical
// "unauthenticated API + admin-Lambda" CRITICAL pattern instead of
// having to walk Lambda → Role ARN → IAM Role → admin policy check
// (multi-hop reasoning the LLM does inconsistently).
//
// Annotations written on AWS::Lambda::Function resources:
//
//   - cb_describer_role_arn                         (string)
//   - cb_describer_role_is_admin_equivalent         (bool)
//   - cb_describer_role_has_wildcard_inline_policy  (bool)
//
// "Admin equivalent" = the role has AdministratorAccess / PowerUserAccess
// / IAMFullAccess attached, OR an inline policy with Action:* Resource:*
// under an Allow statement. Both signals are already lifted by the IAM
// role describer; we copy them onto the Lambda for crisp grounding.
//
// Roles that aren't in the discovered inventory (e.g. cross-account
// roles) leave the flags as defaults (false) — the LLM is told in the
// prompt that absence means "not provably admin," not "definitely
// not admin."
func crossReferenceLambdaRole(resources []DiscoveredResource) {
	// Index discovered IAM roles by both their ARN and their RoleName
	// — CFN's Lambda.Role property can be either form depending on
	// who deployed it.
	roleByARN := map[string]int{}
	roleByName := map[string]int{}
	for i, r := range resources {
		if r.Type != "AWS::IAM::Role" {
			continue
		}
		if arn := stringInput(r.Inputs, "Arn"); arn != "" {
			roleByARN[arn] = i
		}
		if name := stringInput(r.Inputs, "RoleName"); name != "" {
			roleByName[name] = i
		}
		// IAM role primary identifier is RoleName, so r.ID is the name.
		if r.ID != "" {
			roleByName[r.ID] = i
		}
	}

	for i, r := range resources {
		if r.Type != "AWS::Lambda::Function" {
			continue
		}
		if r.Inputs == nil {
			resources[i].Inputs = map[string]any{}
		}
		roleRef := stringInput(r.Inputs, "Role")
		if roleRef == "" {
			continue
		}
		resources[i].Inputs["cb_describer_role_arn"] = roleRef

		idx := -1
		if v, ok := roleByARN[roleRef]; ok {
			idx = v
		} else {
			// Role can be the bare name (CFN canonical) or an ARN. If
			// it's an ARN, the role name is the trailing path
			// component.
			name := roleRef
			if strings.Contains(roleRef, ":role/") {
				if cut := strings.LastIndex(roleRef, "/"); cut >= 0 && cut+1 < len(roleRef) {
					name = roleRef[cut+1:]
				}
			}
			if v, ok := roleByName[name]; ok {
				idx = v
			}
		}
		if idx < 0 {
			// Role not in inventory — leave the flags unset so the
			// LLM doesn't conflate "unknown" with "not admin."
			continue
		}

		role := resources[idx]
		if v, ok := role.Inputs["cb_describer_admin_managed_policy_attached"].(bool); ok {
			resources[i].Inputs["cb_describer_role_is_admin_equivalent"] = v
		}
		if v, ok := role.Inputs["cb_describer_inline_policy_has_wildcard_allow"].(bool); ok {
			resources[i].Inputs["cb_describer_role_has_wildcard_inline_policy"] = v
		}
	}
}
