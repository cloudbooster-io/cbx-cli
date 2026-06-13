package aws

import (
	"testing"

	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ecrRepositoryToRaw must carry the encryption CMK under the nested CFN shape
// crossReferenceKMS walks (EncryptionConfiguration.KmsKey — "KmsKey" is in
// isKMSFieldName and the walk recurses into nested maps). Emitted ONLY for the
// KMS encryption type with an explicit key; SSE-S3/AES256 and the AWS-managed
// aws/ecr key (KMS type, no key id) leave it absent.
func TestECRRepositoryToRaw_CarriesEncryptionKey(t *testing.T) {
	keyOf := func(in map[string]any) any {
		enc, ok := in["EncryptionConfiguration"].(map[string]any)
		if !ok {
			return nil
		}
		return enc["KmsKey"]
	}
	cases := []struct {
		name    string
		cfg     *ecrtypes.EncryptionConfiguration
		wantKey any // expected EncryptionConfiguration.KmsKey, or nil for "absent"
	}{
		{
			name:    "kms cmk with key → stored under EncryptionConfiguration.KmsKey",
			cfg:     &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeKms, KmsKey: strp("arn:aws:kms:eu-central-1:123:key/ecr-cmk")},
			wantKey: "arn:aws:kms:eu-central-1:123:key/ecr-cmk",
		},
		{
			name:    "AES256 (SSE-S3) → no key",
			cfg:     &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeAes256},
			wantKey: nil,
		},
		{
			name:    "kms type with no key id (aws/ecr managed) → no key, FP-safe",
			cfg:     &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeKms},
			wantKey: nil,
		},
		{
			name:    "nil encryption config → no key",
			cfg:     nil,
			wantKey: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, ok := ecrRepositoryToRaw(ecrtypes.Repository{
				RepositoryName:          strp("payments-svc"),
				EncryptionConfiguration: tc.cfg,
			}, "eu-central-1")
			if !ok {
				t.Fatal("ecrRepositoryToRaw !ok")
			}
			dr, err := raw.mapToDiscovered()
			if err != nil {
				t.Fatalf("mapToDiscovered: %v", err)
			}
			got := keyOf(dr.Inputs)
			if tc.wantKey == nil {
				if got != nil {
					t.Errorf("EncryptionConfiguration.KmsKey = %v, want absent", got)
				}
				return
			}
			if got != tc.wantKey {
				t.Errorf("EncryptionConfiguration.KmsKey = %v, want %v", got, tc.wantKey)
			}
		})
	}
}

// Gating assertion: a customer CMK used ONLY as a fallback-discovered ECR repo's
// encryption key resolves to is_unused=false. Proves the nested KmsKey survives
// the toRaw → mapToDiscovered JSON round-trip and is reached by the recursive walk.
func TestECRRepositoryToRaw_CrossRefCountsRepository(t *testing.T) {
	keyARN := "arn:aws:kms:eu-central-1:123:key/ecr-only-key"
	raw, ok := ecrRepositoryToRaw(ecrtypes.Repository{
		RepositoryName: strp("repo-only-ref"),
		EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
			EncryptionType: ecrtypes.EncryptionTypeKms,
			KmsKey:         strp(keyARN),
		},
	}, "eu-central-1")
	if !ok {
		t.Fatal("ecrRepositoryToRaw !ok")
	}
	repo, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}

	resources := []DiscoveredResource{
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://eu-central-1/AWS::KMS::Key/ecr-only-key",
			Inputs: map[string]any{
				"Arn":   keyARN,
				"KeyId": "ecr-only-key",
			},
		},
		repo,
	}

	crossReferenceKMS(resources)

	key := findResource(t, resources, "aws://eu-central-1/AWS::KMS::Key/ecr-only-key")
	if key.Inputs["cb_describer_is_unused"] != false {
		t.Errorf("CMK used only as ECR repo encryption key flagged is_unused=%v, want false (the FP this fix closes)", key.Inputs["cb_describer_is_unused"])
	}
}
