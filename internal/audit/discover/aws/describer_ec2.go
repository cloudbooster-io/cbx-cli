package aws

import "context"

// ec2InstanceDescriber lifts the security-posture signals the audit
// cares about on AWS::EC2::Instance out of CloudControl's CFN-shape
// Properties into top-level cb_describer_* keys. CC's response already
// includes MetadataOptions, IamInstanceProfile, State, PublicIpAddress,
// KeyName, and the security-group / subnet identifiers — we don't need
// an ec2:DescribeInstances call here.
//
// The describer exists despite being pure normalization because the
// resulting keys are the contract downstream native rules and the
// grounded analyzer read. Pushing CFN nesting depth into every rule
// would couple them to AWS schema details that the cb_describer_*
// namespace deliberately hides.
type ec2InstanceDescriber struct{}

func (ec2InstanceDescriber) CFNType() string { return "AWS::EC2::Instance" }

func (ec2InstanceDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	// IMDSv2 is "required" only when HttpTokens explicitly equals
	// "required". The default for a CFN-managed instance is "optional"
	// (IMDSv1 still allowed), so an absent / different value means
	// IMDSv2 is NOT enforced and should be reported as such.
	r.Inputs["cb_describer_imdsv2_required"] = imdsv2Required(r.Inputs)

	// Instance profile presence is a coarse "does this instance have an
	// IAM identity at all?" signal. The ARN goes into the resolved field;
	// callers that want to walk policies can fetch by ARN themselves.
	r.Inputs["cb_describer_instance_profile_arn"] = instanceProfileARN(r.Inputs)

	// State.Name is nested one level deep in CC's response.
	r.Inputs["cb_describer_state"] = readNested(r.Inputs, "State", "Name")

	// PublicIpAddress is a string in CC's response; treat its presence
	// as the binary signal (empty / missing → no public IP).
	r.Inputs["cb_describer_public_ip_present"] = readStr(r.Inputs, "PublicIpAddress") != ""

	return nil
}

// imdsv2Required returns true iff MetadataOptions.HttpTokens explicitly
// equals "required". Any other value (including missing) means the
// instance still accepts IMDSv1, which is the v1 reportable state.
func imdsv2Required(m map[string]any) bool {
	opts, ok := m["MetadataOptions"].(map[string]any)
	if !ok {
		return false
	}
	tokens, _ := opts["HttpTokens"].(string)
	return tokens == "required"
}

// instanceProfileARN extracts IamInstanceProfile.Arn from CC's nested
// shape. CC encodes the field as an object even though many AWS
// surfaces return it as a bare string; we accept either to be safe.
func instanceProfileARN(m map[string]any) string {
	switch v := m["IamInstanceProfile"].(type) {
	case map[string]any:
		if s, ok := v["Arn"].(string); ok {
			return s
		}
	case string:
		return v
	}
	return ""
}

// readNested fetches m[outer][inner] when both lookups succeed and the
// inner value is a string. Returns "" otherwise — pairs naturally with
// the "store presence-or-absence, not unknown-vs-false" convention.
func readNested(m map[string]any, outer, inner string) string {
	nested, ok := m[outer].(map[string]any)
	if !ok {
		return ""
	}
	v, _ := nested[inner].(string)
	return v
}
