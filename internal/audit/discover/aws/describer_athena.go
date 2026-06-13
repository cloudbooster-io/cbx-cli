package aws

import "context"

// athenaDefaultWorkGroupName is the AWS-reserved name of the Athena
// default workgroup. Every account has exactly one, it cannot be
// deleted, and it ships with EnforceWorkGroupConfiguration unset and no
// ResultConfiguration.EncryptionConfiguration — i.e. it trips BOTH
// halves of the workgroup hardening rule by AWS default, on every
// account, with zero user involvement. That makes it a guaranteed
// false-positive on every audited account (it even fires on accounts
// with no user Athena usage at all).
const athenaDefaultWorkGroupName = "primary"

// cbDescriberIsDefaultWorkGroup is the Inputs key the describer sets to
// true on the reserved `primary` workgroup. The baseline rule in
// buildGroundedPrompt keys its carve-out on this flag — the "is this
// the AWS-managed default?" decision is made here in Go, deterministicly,
// so the LLM only has to honor a boolean rather than re-derive the
// reserved name on every run. This mirrors the KMS describer's
// cb_describer_key_manager flag, which lets the same rule block carve
// AWS-managed keys out of unused-key findings.
const cbDescriberIsDefaultWorkGroup = "cb_describer_is_default_workgroup"

// athenaWorkGroupDescriber is a pure-normalization describer (no SDK
// call): CloudControl already returns the workgroup Name and the full
// WorkGroupConfiguration through the read handler, so all this does is
// mark the AWS-managed default. The reserved name `primary` is the
// signal — it is fixed and undeletable, so an exact-match is a safe,
// deterministic test. USER-created workgroups (any other name) are left
// untouched, preserving the real unenforced / unencrypted signal the
// rule is meant to catch.
type athenaWorkGroupDescriber struct{}

func (athenaWorkGroupDescriber) CFNType() string { return "AWS::Athena::WorkGroup" }

func (athenaWorkGroupDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	// The workgroup name arrives both as the CloudControl primary
	// identifier (r.ID) and, redundantly, as the CFN `Name` property.
	// Prefer the property and fall back to the identifier so the flag
	// lands whether or not CC populated Properties.Name.
	name := readStr(r.Inputs, "Name")
	if name == "" {
		name = r.ID
	}
	if name == athenaDefaultWorkGroupName {
		r.Inputs[cbDescriberIsDefaultWorkGroup] = true
	}
	return nil
}
