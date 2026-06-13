package aws

import "context"

// ebsVolumeDescriber lifts encryption + attachment posture out of
// CloudControl's AWS::EC2::Volume Properties into top-level
// cb_describer_* keys. Without the lift, "Encrypted: false" sits
// nested in CFN shape and the LLM repeatedly misses it (the audit
// verification flagged 3 unencrypted volumes including 2 root disks).
//
// No AWS API calls — CC already returns Encrypted, KmsKeyId, State,
// Attachments, Size, and VolumeType.
type ebsVolumeDescriber struct{}

func (ebsVolumeDescriber) CFNType() string { return "AWS::EC2::Volume" }

func (ebsVolumeDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	encrypted, _ := r.Inputs["Encrypted"].(bool)
	r.Inputs["cb_describer_encrypted"] = encrypted

	kms, _ := r.Inputs["KmsKeyId"].(string)
	r.Inputs["cb_describer_kms_key_arn"] = kms

	// State.Name tells us "in-use" vs "available" — an "available"
	// volume that's unencrypted is the classic orphan + at-rest-data
	// double finding the audit should always raise.
	state, _ := r.Inputs["State"].(string)
	r.Inputs["cb_describer_state"] = state

	// Attachment presence (CC returns the Attachments list flattened on
	// the volume). Boolean signal so the LLM can distinguish "root disk
	// of a running instance" from "unattached leftover".
	r.Inputs["cb_describer_is_attached"] = volumeIsAttached(r.Inputs)

	return nil
}

func volumeIsAttached(m map[string]any) bool {
	list, ok := m["Attachments"].([]any)
	if !ok {
		return false
	}
	return len(list) > 0
}
