package aws

import (
	"sort"
	"strings"
)

// crossReferenceKMS annotates every AWS::KMS::Key resource with the
// set of other resources that reference it (cb_describer_referenced_by)
// and a derived "is this key unused?" boolean (cb_describer_is_unused).
//
// Why a post-discovery pass instead of a per-resource describer: the
// answer to "is this key used" depends on EVERY other resource in the
// inventory — a describer that only sees its own resource can't
// compute it. We accept the extra walk in exchange for catching the
// most common KMS cost-waste finding (customer-managed keys created
// for one project, then orphaned) without buying CloudTrail data
// events or a usage-telemetry layer.
//
// Reference fields walked (depth-1 + a few known nested paths):
//   - KmsKeyId            EBS Volume, EFS, RDS, Lambda env, Secret
//   - KMSMasterKeyID      SNS, S3 SSE rules
//   - KMSMasterKeyId      DynamoDB SSESpecification (nested; upper KMS + "Id")
//   - KMSKeyId            CloudTrail Trail (top-level CFN property)
//   - KeyArn              EKS EncryptionConfig provider (nested)
//   - KmsKeyArn           some services
//   - KmsKey              some services
//   - EncryptionKeyArn    AWS::Backup::BackupVault (vault → CMK link)
//   - TargetKeyId         AWS::KMS::Alias (handled separately for alias→arn map)
//
// Matching is "the value contains the key ARN OR the alias name." We
// don't try to handle every possible field name — the false-negative
// cost is "key flagged as unused when it isn't"; the user can refute
// on the finding card. The far worse failure mode is missing a finding
// that exists.
func crossReferenceKMS(resources []DiscoveredResource) {
	keyByARN := map[string]int{} // ARN → index into resources
	keyByID := map[string]int{}  // bare KeyId (uuid) → index
	aliasToARN := map[string]string{}

	for i, r := range resources {
		switch r.Type {
		case "AWS::KMS::Key":
			arn := stringInput(r.Inputs, "Arn")
			if arn != "" {
				keyByARN[arn] = i
			}
			id := stringInput(r.Inputs, "KeyId")
			if id != "" {
				keyByID[id] = i
			}
		case "AWS::KMS::Alias":
			name := stringInput(r.Inputs, "AliasName")
			target := stringInput(r.Inputs, "TargetKeyId")
			if name != "" && target != "" {
				// TargetKeyId can be either the bare uuid or an ARN.
				aliasToARN[name] = target
			}
		}
	}

	// referenced[i] is the set of URNs referencing resources[i] (a
	// KMS key). Using a map collapses dupes when a single resource
	// references the same key via both alias and arn.
	referenced := make([]map[string]struct{}, len(resources))

	noteRef := func(keyIdx int, fromURN string) {
		if referenced[keyIdx] == nil {
			referenced[keyIdx] = map[string]struct{}{}
		}
		if fromURN != "" {
			referenced[keyIdx][fromURN] = struct{}{}
		}
	}

	// resolveRef takes a string value (some encryption-field value) and
	// returns the index of the KMS key resource it points at, or -1.
	resolveRef := func(v string) int {
		if v == "" {
			return -1
		}
		// Direct ARN match
		if idx, ok := keyByARN[v]; ok {
			return idx
		}
		// Bare KeyId match
		if idx, ok := keyByID[v]; ok {
			return idx
		}
		// Alias match — value can be "alias/foo" directly, or an ARN
		// like "arn:aws:kms:us-east-1:123:alias/foo"
		alias := v
		if strings.Contains(v, ":alias/") {
			if i := strings.Index(v, ":alias/"); i >= 0 {
				alias = "alias/" + v[i+len(":alias/"):]
			}
		}
		if target, ok := aliasToARN[alias]; ok {
			if idx, ok := keyByARN[target]; ok {
				return idx
			}
			if idx, ok := keyByID[target]; ok {
				return idx
			}
		}
		return -1
	}

	for _, r := range resources {
		if r.Type == "AWS::KMS::Key" || r.Type == "AWS::KMS::Alias" {
			continue
		}
		walkKMSReferences(r.Inputs, func(val string) {
			if idx := resolveRef(val); idx >= 0 {
				noteRef(idx, r.URN)
			}
		})
	}

	// Apply results back to the KMS Key resources. Empty referenced
	// set + customer-managed (non-aws-managed) key = "unused" — the
	// LLM is told this in the prompt's baseline-pattern list.
	for i := range resources {
		if resources[i].Type != "AWS::KMS::Key" {
			continue
		}
		if resources[i].Inputs == nil {
			resources[i].Inputs = map[string]any{}
		}
		refs := referenced[i]
		urns := make([]string, 0, len(refs))
		for u := range refs {
			urns = append(urns, u)
		}
		sort.Strings(urns)
		resources[i].Inputs["cb_describer_referenced_by"] = urns
		resources[i].Inputs["cb_describer_is_unused"] = len(urns) == 0 && !isAWSManagedKMSKey(resources[i].Inputs)
	}
}

// walkKMSReferences invokes onValue for every string in m that could
// plausibly be a KMS reference — values under known encryption field
// names plus a depth-2 walk of nested maps so SSE-style nested
// configs (S3 SSE rules, RDS storage config) get picked up.
func walkKMSReferences(m map[string]any, onValue func(string)) {
	if m == nil {
		return
	}
	for k, v := range m {
		if isKMSFieldName(k) {
			if s, ok := v.(string); ok {
				onValue(s)
			}
		}
		switch t := v.(type) {
		case map[string]any:
			walkKMSReferences(t, onValue)
		case []any:
			for _, item := range t {
				if mm, ok := item.(map[string]any); ok {
					walkKMSReferences(mm, onValue)
				}
			}
		}
	}
}

// isKMSFieldName matches the set of CFN Property names that carry a
// KMS key reference. Conservative on purpose — extending the set is
// cheaper than chasing false positives.
func isKMSFieldName(name string) bool {
	switch name {
	case "KmsKeyId", "KMSMasterKeyID", "KmsKeyArn", "KmsKey",
		"KmsMasterKeyId", "KmsMasterKeyID", "SseKmsKeyId",
		"EncryptionKeyArn":
		return true
	// Class-1 cross-ref gaps: DynamoDB's nested SSESpecification.KMSMasterKeyId
	// (upper KMS + "Id" — distinct from the SNS/S3 KMSMasterKeyID above),
	// CloudTrail's top-level KMSKeyId (cf. severity_floor.go isCloudTrailWithoutKMS),
	// and the EKS EncryptionConfig[].Provider.KeyArn the EKS lister now surfaces.
	// KeyArn is generic but FP-safe by direction: resolveRef only notes a
	// reference when the value resolves to a DISCOVERED key.
	case "KMSMasterKeyId", "KMSKeyId", "KeyArn":
		return true
	}
	return false
}

// isAWSManagedKMSKey returns true when the key looks AWS-managed
// (KeyManager=AWS, surfaced by the KMS describer via kms:DescribeKey
// — CloudControl's CFN Properties for AWS::KMS::Key don't carry the
// field). AWS-managed keys are created and reaped by AWS itself, so
// they should NEVER be flagged as unused by the cross-reference
// pass even when no customer resource references them by ARN.
func isAWSManagedKMSKey(in map[string]any) bool {
	if mgr, ok := in["cb_describer_key_manager"].(string); ok && strings.EqualFold(mgr, "AWS") {
		return true
	}
	// Legacy fallback: some CC responses MAY surface KeyManager
	// directly (newer CFN schema). Keep this for forward compat.
	if mgr, ok := in["KeyManager"].(string); ok && strings.EqualFold(mgr, "AWS") {
		return true
	}
	return false
}

// stringInput is a small helper for "read a top-level string from
// Inputs, or empty when missing / wrong type." Avoids 4-line type
// assertions every time crossReferenceKMS reads a CFN field.
func stringInput(in map[string]any, key string) string {
	if in == nil {
		return ""
	}
	s, _ := in[key].(string)
	return s
}
