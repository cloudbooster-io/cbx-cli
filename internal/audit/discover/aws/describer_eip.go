package aws

import "context"

// eipDescriber lifts attachment posture out of CloudControl's
// AWS::EC2::EIP Properties into a crisp top-level boolean. The LLM
// was inconsistently flagging unattached EIPs because the signal
// hides in multiple optional fields (AssociationId, InstanceId,
// NetworkInterfaceId) — any one of them being non-empty means the
// EIP is in use. Without the lift, the model only saw "two of these
// fields are missing, the third is missing-ish" and shrugged.
//
// No AWS API calls — CloudControl already returns the relevant
// fields on AWS::EC2::EIP.
type eipDescriber struct{}

func (eipDescriber) CFNType() string { return "AWS::EC2::EIP" }

func (eipDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	assoc, _ := r.Inputs["AssociationId"].(string)
	inst, _ := r.Inputs["InstanceId"].(string)
	eni, _ := r.Inputs["NetworkInterfaceId"].(string)

	attached := assoc != "" || inst != "" || eni != ""
	r.Inputs["cb_describer_is_attached"] = attached
	r.Inputs["cb_describer_association_id"] = assoc
	return nil
}
