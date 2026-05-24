package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
)

// kmsKeyDescriber enriches AWS::KMS::Key with the fields CloudControl
// doesn't return: KeyManager (AWS vs CUSTOMER), KeyState (Enabled /
// PendingDeletion / etc.), and the per-key rotation status. The most
// load-bearing of these is KeyManager — without it, AWS-managed keys
// (alias/aws/rds, alias/aws/ebs, etc.) get flagged as `is_unused`
// because the customer's resources don't reference them by ARN, even
// though AWS itself is using them implicitly.
//
// One kms:DescribeKey + one kms:GetKeyRotationStatus per key. Cheap.
type kmsKeyDescriber struct{}

func (kmsKeyDescriber) CFNType() string { return "AWS::KMS::Key" }

func (kmsKeyDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	keyID := r.ID
	if keyID == "" {
		// CloudControl's primary identifier for AWS::KMS::Key is the
		// KeyId (a uuid), but some shapes return the ARN. DescribeKey
		// accepts either.
		if arn, ok := r.Inputs["Arn"].(string); ok && arn != "" {
			keyID = arn
		}
	}
	if keyID == "" {
		return fmt.Errorf("kms describer: empty key id")
	}

	client := kms.NewFromConfig(c.cfg)
	desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return classifyKMSError(err, keyID, "kms:DescribeKey")
	}
	if desc.KeyMetadata != nil {
		// KeyManager is the load-bearing field — "AWS" means the key
		// is created and reaped by AWS itself, and shouldn't be
		// flagged as unused by the cross-reference pass.
		r.Inputs["cb_describer_key_manager"] = string(desc.KeyMetadata.KeyManager)
		r.Inputs["cb_describer_key_state"] = string(desc.KeyMetadata.KeyState)
		r.Inputs["cb_describer_key_spec"] = string(desc.KeyMetadata.KeySpec)
		r.Inputs["cb_describer_key_usage"] = string(desc.KeyMetadata.KeyUsage)
		if desc.KeyMetadata.MultiRegion != nil {
			r.Inputs["cb_describer_multi_region"] = *desc.KeyMetadata.MultiRegion
		}
	}

	// Rotation status — separate API call. Only meaningful for
	// CUSTOMER-managed symmetric keys (AWS-managed keys auto-rotate
	// on a separate schedule the customer doesn't control).
	rot, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: aws.String(keyID)})
	if err != nil {
		// AccessDenied here is common for AWS-managed keys; classify
		// as a permission error but don't fail the whole enrichment —
		// the DescribeKey data is already attached.
		return classifyKMSError(err, keyID, "kms:GetKeyRotationStatus")
	}
	r.Inputs["cb_describer_key_rotation_enabled"] = rot.KeyRotationEnabled
	return nil
}

func classifyKMSError(err error, keyID, action string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "AccessDeniedException":
			return &PermissionError{
				Service: "kms",
				Action:  action,
				Cause:   fmt.Errorf("on key %s: %w", keyID, err),
			}
		case "NotFoundException":
			// Race: CC listed the key, it got deleted before describe.
			return nil
		}
	}
	return fmt.Errorf("%s on key %s: %w", action, keyID, err)
}
