package aws

import (
	"errors"
	"fmt"
	"testing"
)

func TestPermissionError_Error(t *testing.T) {
	cause := errors.New("access denied")
	pe := &PermissionError{Service: "s3", Action: "s3:ListBuckets", Cause: cause}
	if got := pe.Error(); got != "s3:ListBuckets denied: access denied" {
		t.Errorf("got %q", got)
	}
	pe.Region = "us-east-1"
	if got := pe.Error(); got != "s3:ListBuckets denied in us-east-1: access denied" {
		t.Errorf("got %q", got)
	}
}

func TestPermissionError_Unwrap(t *testing.T) {
	cause := errors.New("access denied")
	pe := &PermissionError{Service: "s3", Action: "s3:ListBuckets", Cause: cause}
	if !errors.Is(pe, cause) {
		t.Errorf("expected errors.Is to chain through Unwrap")
	}
}

func TestIsPermissionError(t *testing.T) {
	pe := &PermissionError{Service: "iam", Action: "iam:ListRoles", Cause: errors.New("nope")}
	wrapped := fmt.Errorf("during discovery: %w", pe)
	if !IsPermissionError(wrapped) {
		t.Errorf("expected IsPermissionError to detect wrapped PermissionError")
	}
	if IsPermissionError(errors.New("plain error")) {
		t.Errorf("expected IsPermissionError to be false for non-PermissionError")
	}
}

func TestIdentity_String(t *testing.T) {
	i := Identity{AccountID: "123", ARN: "arn:aws:iam::123:user/alice"}
	want := "account=123 arn=arn:aws:iam::123:user/alice"
	if got := i.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
