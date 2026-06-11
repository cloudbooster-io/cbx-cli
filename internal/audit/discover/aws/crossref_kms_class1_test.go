package aws

import (
	"testing"

	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

// These three tests close the Class-1 KMS cross-reference gaps: a customer CMK
// used ONLY by a DynamoDB table / CloudTrail trail / EKS cluster was mis-flagged
// cb_describer_is_unused=true because its key-reference field name was not walked
// by isKMSFieldName (or, for EKS, the ARN was dropped by the lister). Each test
// pairs a referenced ("used") CMK with an unreferenced orphan and asserts only
// the orphan is flagged — and, for the two that have a lister, drives the real
// lister → mapToDiscovered → crossReferenceKMS so the test pins the EXACT field
// casing the lister emits (a hand-built Inputs map would pass even if the lister
// later drifted, masking the very mismatch these fixes close — cf. the RDS
// round-trip rationale in lister_rds_native_test.go).

const (
	class1UsedKeyARN   = "arn:aws:kms:us-east-1:123:key/class1-used"
	class1OrphanKeyARN = "arn:aws:kms:us-east-1:123:key/class1-orphan"
)

// class1Keys returns a referenced ("used") customer CMK plus an unreferenced
// orphan, both customer-managed (no cb_describer_key_manager=AWS guard). After
// crossReferenceKMS only the orphan must read is_unused=true.
func class1Keys() []DiscoveredResource {
	return []DiscoveredResource{
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://us-east-1/AWS::KMS::Key/class1-used",
			Inputs: map[string]any{
				"Arn":   class1UsedKeyARN,
				"KeyId": "class1-used",
			},
		},
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://us-east-1/AWS::KMS::Key/class1-orphan",
			Inputs: map[string]any{
				"Arn":   class1OrphanKeyARN,
				"KeyId": "class1-orphan",
			},
		},
	}
}

func assertClass1Refs(t *testing.T, resources []DiscoveredResource) {
	t.Helper()
	used := findResource(t, resources, "aws://us-east-1/AWS::KMS::Key/class1-used")
	if used.Inputs["cb_describer_is_unused"] != false {
		t.Errorf("used CMK: cb_describer_is_unused = %v, want false (a resource references it)", used.Inputs["cb_describer_is_unused"])
	}
	orphan := findResource(t, resources, "aws://us-east-1/AWS::KMS::Key/class1-orphan")
	if orphan.Inputs["cb_describer_is_unused"] != true {
		t.Errorf("orphan CMK: cb_describer_is_unused = %v, want true (nothing references it)", orphan.Inputs["cb_describer_is_unused"])
	}
}

func dynamoToDiscovered(t *testing.T, td dynamodbtypes.TableDescription) DiscoveredResource {
	t.Helper()
	raw, ok := dynamoTableToRaw(td, nil, "us-east-1")
	if !ok {
		t.Fatal("dynamoTableToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	return dr
}

func eksToDiscovered(t *testing.T, cl ekstypes.Cluster) DiscoveredResource {
	t.Helper()
	raw, ok := eksClusterToRaw(cl, "us-east-1")
	if !ok {
		t.Fatal("eksClusterToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	return dr
}

// #1 DynamoDB — the strongest of the three. The lister stores the CMK ARN under
// the nested SSESpecification.KMSMasterKeyId (upper KMS + "Id"); the switch only
// had KMSMasterKeyID / KmsMasterKeyId, so a CMK-only DynamoDB key read as unused.
// An AWS-owned-key table (no SSEDescription) carries no SSESpecification, so it
// must reference nothing — the orphan stays flagged.
func TestCrossReferenceKMS_DynamoDBCMK(t *testing.T) {
	cmkTable := dynamoToDiscovered(t, dynamodbtypes.TableDescription{
		TableName: strp("class1-cmk-table"),
		SSEDescription: &dynamodbtypes.SSEDescription{
			SSEType:         dynamodbtypes.SSETypeKms,
			KMSMasterKeyArn: strp(class1UsedKeyARN),
		},
	})
	awsOwnedTable := dynamoToDiscovered(t, dynamodbtypes.TableDescription{
		TableName: strp("class1-aws-owned-table"), // no SSEDescription → no KMS ref
	})

	resources := append(class1Keys(), cmkTable, awsOwnedTable)
	crossReferenceKMS(resources)
	assertClass1Refs(t, resources)
}

// #2 CloudTrail — there is no native trail lister, so a hand-built resource is
// the correct shape: CloudControl returns the SSE-KMS key inline under the
// top-level CFN KMSKeyId property (the same field severity_floor.go's
// isCloudTrailWithoutKMS reads). A trail with no KMSKeyId is SSE-S3 only and
// references nothing — the orphan stays flagged.
func TestCrossReferenceKMS_CloudTrailCMK(t *testing.T) {
	cmkTrail := DiscoveredResource{
		Type:   "AWS::CloudTrail::Trail",
		URN:    "aws://us-east-1/AWS::CloudTrail::Trail/class1-trail",
		Inputs: map[string]any{"KMSKeyId": class1UsedKeyARN},
	}
	plainTrail := DiscoveredResource{
		Type:   "AWS::CloudTrail::Trail",
		URN:    "aws://us-east-1/AWS::CloudTrail::Trail/class1-plain-trail",
		Inputs: map[string]any{}, // SSE-S3 only, no KMSKeyId
	}

	resources := append(class1Keys(), cmkTrail, plainTrail)
	crossReferenceKMS(resources)
	assertClass1Refs(t, resources)
}

// #3 EKS — the lister previously kept only EncryptionConfigPresent and DROPPED
// EncryptionConfig[].Provider.KeyArn, so a CMK used only for EKS secrets
// encryption was invisible to the cross-ref. There is no other EKS lister test,
// so this round-trip is the sole guard that the new lister code emits the ARN at
// all. A cluster with no EncryptionConfig must not fabricate the field, so its
// orphan stays flagged.
func TestCrossReferenceKMS_EKSSecretsCMK(t *testing.T) {
	cmkCluster := eksToDiscovered(t, ekstypes.Cluster{
		Name: strp("class1-cmk-cluster"),
		EncryptionConfig: []ekstypes.EncryptionConfig{
			{Provider: &ekstypes.Provider{KeyArn: strp(class1UsedKeyARN)}},
		},
	})
	plainCluster := eksToDiscovered(t, ekstypes.Cluster{
		Name: strp("class1-plain-cluster"), // no EncryptionConfig → no KMS ref
	})

	// Guard the lister edit directly: the CMK ARN surfaces nested, and a cluster
	// without secrets encryption must not emit EncryptionConfig at all.
	ec, _ := cmkCluster.Inputs["EncryptionConfig"].([]any)
	if len(ec) != 1 {
		t.Fatalf("EncryptionConfig: got %v, want one entry carrying the CMK ARN", cmkCluster.Inputs["EncryptionConfig"])
	}
	if _, present := plainCluster.Inputs["EncryptionConfig"]; present {
		t.Errorf("plain cluster: EncryptionConfig present, want absent (no provider key)")
	}

	resources := append(class1Keys(), cmkCluster, plainCluster)
	crossReferenceKMS(resources)
	assertClass1Refs(t, resources)
}
