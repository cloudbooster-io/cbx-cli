package aws

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

func TestVersioningEnabled(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"Enabled", true},
		{"Suspended", false},
		{"", false}, // never configured — AWS omits the element
	}
	for _, tc := range cases {
		if got := versioningEnabled(tc.status); got != tc.want {
			t.Errorf("versioningEnabled(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestMFADeleteEnabled(t *testing.T) {
	cases := []struct {
		mfa  string
		want bool
	}{
		{"Enabled", true},
		{"Disabled", false},
		{"", false}, // never configured == not enabled (the common case)
	}
	for _, tc := range cases {
		if got := mfaDeleteEnabled(tc.mfa); got != tc.want {
			t.Errorf("mfaDeleteEnabled(%q) = %v, want %v", tc.mfa, got, tc.want)
		}
	}
}

func TestSSEIsKMS(t *testing.T) {
	cases := []struct {
		name  string
		algos []string
		want  bool
	}{
		{"sse-s3 only", []string{"AES256"}, false},
		{"kms cmk", []string{"aws:kms"}, true},
		{"dual-layer kms", []string{"aws:kms:dsse"}, true},
		{"mixed, kms present", []string{"AES256", "aws:kms"}, true},
		{"empty (encryption present but no default algo)", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sseIsKMS(tc.algos); got != tc.want {
				t.Errorf("sseIsKMS(%v) = %v, want %v", tc.algos, got, tc.want)
			}
		})
	}
}

func TestApplyEncryptionInputs(t *testing.T) {
	sp := func(s string) *string { return &s }
	rule := func(algo types.ServerSideEncryption, keyID *string) types.ServerSideEncryptionRule {
		return types.ServerSideEncryptionRule{
			ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
				SSEAlgorithm:   algo,
				KMSMasterKeyID: keyID,
			},
		}
	}
	cases := []struct {
		name       string
		rules      []types.ServerSideEncryptionRule
		wantKeyRef any // expected KMSMasterKeyID value, or nil for "field absent"
		wantIsKMS  bool
	}{
		{
			name:       "kms cmk with key arn → stored under KMSMasterKeyID",
			rules:      []types.ServerSideEncryptionRule{rule(types.ServerSideEncryptionAwsKms, sp("arn:aws:kms:us-east-1:123:key/abc"))},
			wantKeyRef: "arn:aws:kms:us-east-1:123:key/abc",
			wantIsKMS:  true,
		},
		{
			name:       "dual-layer kms with key alias → stored",
			rules:      []types.ServerSideEncryptionRule{rule(types.ServerSideEncryptionAwsKmsDsse, sp("alias/cbx"))},
			wantKeyRef: "alias/cbx",
			wantIsKMS:  true,
		},
		{
			name:       "sse-s3 AES256 → no key ref",
			rules:      []types.ServerSideEncryptionRule{rule(types.ServerSideEncryptionAes256, nil)},
			wantKeyRef: nil,
			wantIsKMS:  false,
		},
		{
			name:       "kms with nil key id (aws/s3 managed) → no key ref, FP-safe",
			rules:      []types.ServerSideEncryptionRule{rule(types.ServerSideEncryptionAwsKms, nil)},
			wantKeyRef: nil,
			wantIsKMS:  true,
		},
		{
			name:       "kms with empty key id → no key ref, FP-safe",
			rules:      []types.ServerSideEncryptionRule{rule(types.ServerSideEncryptionAwsKms, sp(""))},
			wantKeyRef: nil,
			wantIsKMS:  true,
		},
		{
			name:       "rule with no default block → no key ref, not kms",
			rules:      []types.ServerSideEncryptionRule{{}},
			wantKeyRef: nil,
			wantIsKMS:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := map[string]any{}
			applyEncryptionInputs(in, &types.ServerSideEncryptionConfiguration{Rules: tc.rules})

			got, present := in["KMSMasterKeyID"]
			if tc.wantKeyRef == nil {
				if present {
					t.Errorf("KMSMasterKeyID = %v, want absent", got)
				}
			} else {
				if !present {
					t.Fatalf("KMSMasterKeyID absent, want %v", tc.wantKeyRef)
				}
				if got != tc.wantKeyRef {
					t.Errorf("KMSMasterKeyID = %v, want %v", got, tc.wantKeyRef)
				}
			}
			if in["cb_describer_sse_is_kms"] != tc.wantIsKMS {
				t.Errorf("cb_describer_sse_is_kms = %v, want %v", in["cb_describer_sse_is_kms"], tc.wantIsKMS)
			}
			// cb_describer_encryption is always set on the present branch.
			if _, ok := in["cb_describer_encryption"]; !ok {
				t.Error("cb_describer_encryption not set")
			}
		})
	}
}

// TestApplyEncryptionInputs_CrossRefCountsBucket proves the actual production
// shape: the describer emits KMSMasterKeyID at the TOP level of Inputs (the
// crossref_kms_test fixture covers the nested BucketEncryption shape that
// CloudControl would carry — which it doesn't for live buckets). A CMK used
// ONLY as a bucket's SSE-KMS key must therefore resolve to is_unused=false.
func TestApplyEncryptionInputs_CrossRefCountsBucket(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:123:key/s3-only-key"
	bucket := DiscoveredResource{
		Type:   "AWS::S3::Bucket",
		URN:    "aws://us-east-1/AWS::S3::Bucket/sse-bucket",
		Inputs: map[string]any{},
	}
	applyEncryptionInputs(bucket.Inputs, &types.ServerSideEncryptionConfiguration{
		Rules: []types.ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
				SSEAlgorithm:   types.ServerSideEncryptionAwsKms,
				KMSMasterKeyID: &keyARN,
			},
		}},
	})

	resources := []DiscoveredResource{
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://us-east-1/AWS::KMS::Key/s3-only-key",
			Inputs: map[string]any{
				"Arn":   keyARN,
				"KeyId": "s3-only-key",
			},
		},
		bucket,
	}

	crossReferenceKMS(resources)

	key := findResource(t, resources, "aws://us-east-1/AWS::KMS::Key/s3-only-key")
	if key.Inputs["cb_describer_is_unused"] != false {
		t.Errorf("CMK used only as S3 SSE-KMS key flagged is_unused=%v, want false (the FP this fix closes)", key.Inputs["cb_describer_is_unused"])
	}
}

func TestObjectLockEnabled(t *testing.T) {
	cases := []struct {
		name string
		cfg  *types.ObjectLockConfiguration
		want bool
	}{
		{"nil config (not enabled at creation)", nil, false},
		{"enabled", &types.ObjectLockConfiguration{ObjectLockEnabled: types.ObjectLockEnabledEnabled}, true},
		{"empty config object", &types.ObjectLockConfiguration{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := objectLockEnabled(tc.cfg); got != tc.want {
				t.Errorf("objectLockEnabled(%v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestS3AbsenceErrorClassifiers(t *testing.T) {
	apiErr := func(code string) error { return &smithy.GenericAPIError{Code: code} }

	t.Run("isNoSuchLifecycleConfiguration", func(t *testing.T) {
		if !isNoSuchLifecycleConfiguration(apiErr("NoSuchLifecycleConfiguration")) {
			t.Error("expected true for NoSuchLifecycleConfiguration")
		}
		if isNoSuchLifecycleConfiguration(apiErr("AccessDenied")) {
			t.Error("expected false for an unrelated API error code")
		}
		if isNoSuchLifecycleConfiguration(errors.New("plain error")) {
			t.Error("expected false for a non-API error")
		}
		if isNoSuchLifecycleConfiguration(nil) {
			t.Error("expected false for nil")
		}
	})

	t.Run("isObjectLockNotFound", func(t *testing.T) {
		if !isObjectLockNotFound(apiErr("ObjectLockConfigurationNotFoundError")) {
			t.Error("expected true for ObjectLockConfigurationNotFoundError")
		}
		if isObjectLockNotFound(apiErr("NoSuchBucket")) {
			t.Error("expected false for an unrelated API error code")
		}
		if isObjectLockNotFound(errors.New("plain error")) {
			t.Error("expected false for a non-API error")
		}
	})
}
