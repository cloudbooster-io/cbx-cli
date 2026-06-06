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
