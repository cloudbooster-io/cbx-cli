package aws

import (
	"testing"

	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// rdsClusterToRaw must carry KmsKeyId under the exact CFN property name
// crossReferenceKMS walks (isKMSFieldName) — the field the instance path
// already carries but the cluster path silently dropped. Stored only when set,
// so a non-encrypted cluster (the AWS default) leaves it absent.
func TestRDSClusterToRaw_CarriesKmsKeyId(t *testing.T) {
	cases := []struct {
		name    string
		kms     *string
		wantKey any // expected Inputs["KmsKeyId"], or nil for "absent"
	}{
		{
			name:    "customer cmk → stored under KmsKeyId",
			kms:     strp("arn:aws:kms:eu-central-1:123:key/cluster-cmk"),
			wantKey: "arn:aws:kms:eu-central-1:123:key/cluster-cmk",
		},
		{
			name:    "no key (default encryption / unencrypted) → absent",
			kms:     nil,
			wantKey: nil,
		},
		{
			name:    "empty key → absent (putStr discipline)",
			kms:     strp(""),
			wantKey: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, ok := rdsClusterToRaw(rdstypes.DBCluster{
				DBClusterIdentifier: strp("aurora-prod"),
				KmsKeyId:            tc.kms,
				StorageEncrypted:    boolp(true),
			}, "eu-central-1")
			if !ok {
				t.Fatal("rdsClusterToRaw !ok for a valid cluster")
			}
			dr, err := raw.mapToDiscovered()
			if err != nil {
				t.Fatalf("mapToDiscovered: %v", err)
			}
			got, present := dr.Inputs["KmsKeyId"]
			if tc.wantKey == nil {
				if present {
					t.Errorf("KmsKeyId = %v, want absent", got)
				}
				return
			}
			if !present {
				t.Fatalf("KmsKeyId absent, want %v", tc.wantKey)
			}
			if got != tc.wantKey {
				t.Errorf("KmsKeyId = %v, want %v", got, tc.wantKey)
			}
		})
	}
}

// The gating assertion: a customer CMK used ONLY as a fallback-discovered RDS
// cluster's storage-encryption key must resolve to is_unused=false. This goes
// through the full toRaw → mapToDiscovered (JSON round-trip) → crossReferenceKMS
// path, so a wrong-cased store ("KMSKeyId" etc.) that a naive presence check
// would pass still fails here — the round-trip key name must be walked.
func TestRDSClusterToRaw_CrossRefCountsCluster(t *testing.T) {
	keyARN := "arn:aws:kms:eu-central-1:123:key/cluster-only-key"
	raw, ok := rdsClusterToRaw(rdstypes.DBCluster{
		DBClusterIdentifier: strp("aurora-only-ref"),
		KmsKeyId:            strp(keyARN),
		StorageEncrypted:    boolp(true),
	}, "eu-central-1")
	if !ok {
		t.Fatal("rdsClusterToRaw !ok")
	}
	cluster, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}

	resources := []DiscoveredResource{
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://eu-central-1/AWS::KMS::Key/cluster-only-key",
			Inputs: map[string]any{
				"Arn":   keyARN,
				"KeyId": "cluster-only-key",
			},
		},
		cluster,
	}

	crossReferenceKMS(resources)

	key := findResource(t, resources, "aws://eu-central-1/AWS::KMS::Key/cluster-only-key")
	if key.Inputs["cb_describer_is_unused"] != false {
		t.Errorf("CMK used only as RDS cluster storage key flagged is_unused=%v, want false (the FP this fix closes)", key.Inputs["cb_describer_is_unused"])
	}
}
