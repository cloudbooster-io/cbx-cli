package aws

import "testing"

func TestCrossReferenceKMS_DetectsUnusedKey(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://us-east-1/AWS::KMS::Key/used-key",
			ID:   "used-key",
			Inputs: map[string]any{
				"Arn":   "arn:aws:kms:us-east-1:123:key/used-key",
				"KeyId": "used-key",
			},
		},
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://us-east-1/AWS::KMS::Key/orphan-key",
			ID:   "orphan-key",
			Inputs: map[string]any{
				"Arn":   "arn:aws:kms:us-east-1:123:key/orphan-key",
				"KeyId": "orphan-key",
			},
		},
		{
			Type: "AWS::KMS::Alias",
			URN:  "aws://us-east-1/AWS::KMS::Alias/alias-used",
			Inputs: map[string]any{
				"AliasName":   "alias/cbx-audit-used",
				"TargetKeyId": "arn:aws:kms:us-east-1:123:key/used-key",
			},
		},
		{
			Type: "AWS::EC2::Volume",
			URN:  "aws://us-east-1/AWS::EC2::Volume/vol-1",
			Inputs: map[string]any{
				"Encrypted": true,
				"KmsKeyId":  "arn:aws:kms:us-east-1:123:key/used-key",
			},
		},
		// Reference by alias should also count.
		{
			Type: "AWS::RDS::DBInstance",
			URN:  "aws://us-east-1/AWS::RDS::DBInstance/db1",
			Inputs: map[string]any{
				"KmsKeyId": "alias/cbx-audit-used",
			},
		},
	}

	crossReferenceKMS(resources)

	usedKey := findResource(t, resources, "aws://us-east-1/AWS::KMS::Key/used-key")
	orphan := findResource(t, resources, "aws://us-east-1/AWS::KMS::Key/orphan-key")

	if usedKey.Inputs["cb_describer_is_unused"] != false {
		t.Errorf("used-key: cb_describer_is_unused = %v, want false", usedKey.Inputs["cb_describer_is_unused"])
	}
	refs, _ := usedKey.Inputs["cb_describer_referenced_by"].([]string)
	if len(refs) != 2 {
		t.Errorf("used-key: expected 2 referencers (vol + db), got %d (%v)", len(refs), refs)
	}

	if orphan.Inputs["cb_describer_is_unused"] != true {
		t.Errorf("orphan-key: cb_describer_is_unused = %v, want true", orphan.Inputs["cb_describer_is_unused"])
	}
	orphanRefs, _ := orphan.Inputs["cb_describer_referenced_by"].([]string)
	if len(orphanRefs) != 0 {
		t.Errorf("orphan-key: expected 0 referencers, got %v", orphanRefs)
	}
}

func TestCrossReferenceKMS_NestedSSEConfig(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://us-east-1/AWS::KMS::Key/sse-key",
			Inputs: map[string]any{
				"Arn":   "arn:aws:kms:us-east-1:123:key/sse-key",
				"KeyId": "sse-key",
			},
		},
		{
			Type: "AWS::S3::Bucket",
			URN:  "aws://us-east-1/AWS::S3::Bucket/my-bucket",
			Inputs: map[string]any{
				"BucketEncryption": map[string]any{
					"ServerSideEncryptionConfiguration": []any{
						map[string]any{
							"ServerSideEncryptionByDefault": map[string]any{
								"KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/sse-key",
								"SSEAlgorithm":   "aws:kms",
							},
						},
					},
				},
			},
		},
	}

	crossReferenceKMS(resources)

	key := findResource(t, resources, "aws://us-east-1/AWS::KMS::Key/sse-key")
	if key.Inputs["cb_describer_is_unused"] != false {
		t.Errorf("sse-key: should be referenced by S3 bucket, got is_unused=%v", key.Inputs["cb_describer_is_unused"])
	}
}

func findResource(t *testing.T, rs []DiscoveredResource, urn string) DiscoveredResource {
	t.Helper()
	for _, r := range rs {
		if r.URN == urn {
			return r
		}
	}
	t.Fatalf("no resource with URN %q", urn)
	return DiscoveredResource{}
}
