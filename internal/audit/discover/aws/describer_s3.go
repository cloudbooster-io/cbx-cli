package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// s3BucketDescriber enriches AWS::S3::Bucket resources with the security
// posture data the CloudControl API doesn't surface in ListResources /
// GetResource. CloudControl returns the base CFN-shape Properties but
// not PublicAccessBlock state, encryption config, or bucket policy
// presence — which are exactly the fields CB best-practices checks care
// about for S3.
type s3BucketDescriber struct{}

func (s3BucketDescriber) CFNType() string { return "AWS::S3::Bucket" }

func (s3BucketDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	bucket := r.ID
	if bucket == "" {
		return fmt.Errorf("s3 describer: empty bucket name")
	}

	// S3 calls don't require c.region() to match the bucket's region —
	// the SDK auto-redirects. But making the call against the bucket's
	// home region (when known) is cheaper. CloudControl's region is
	// already on r.Region.
	if r.Region != "" {
		c = c.withRegion(r.Region)
	}
	client := s3.NewFromConfig(c.cfg)

	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	// PublicAccessBlock — the single most important S3 security control.
	// Bucket without it set is the "public S3" footgun.
	pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &bucket})
	switch {
	case err == nil && pab.PublicAccessBlockConfiguration != nil:
		r.Inputs["cb_describer_public_access_block"] = map[string]any{
			"block_public_acls":         deref(pab.PublicAccessBlockConfiguration.BlockPublicAcls),
			"block_public_policy":       deref(pab.PublicAccessBlockConfiguration.BlockPublicPolicy),
			"ignore_public_acls":        deref(pab.PublicAccessBlockConfiguration.IgnorePublicAcls),
			"restrict_public_buckets":   deref(pab.PublicAccessBlockConfiguration.RestrictPublicBuckets),
		}
	case isNoSuchPublicAccessBlock(err):
		// Distinct signal from "we don't know" — the bucket genuinely
		// has no PAB config, which IS a finding for CB rules.
		r.Inputs["cb_describer_public_access_block"] = nil
	default:
		return classifyS3Error(err, bucket, r.Region, "s3:GetPublicAccessBlock")
	}

	// Versioning — data-protection signal.
	vers, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bucket})
	if err == nil {
		r.Inputs["cb_describer_versioning"] = map[string]any{
			"status":     string(vers.Status),
			"mfa_delete": string(vers.MFADelete),
		}
	} else if !isS3NotFound(err) {
		return classifyS3Error(err, bucket, r.Region, "s3:GetBucketVersioning")
	}

	// Encryption — compliance signal. NoSuchBucketEncryption is the
	// "no SSE configured" case worth flagging.
	enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bucket})
	switch {
	case err == nil && enc.ServerSideEncryptionConfiguration != nil:
		rules := enc.ServerSideEncryptionConfiguration.Rules
		algos := make([]string, 0, len(rules))
		for _, ru := range rules {
			if ru.ApplyServerSideEncryptionByDefault != nil {
				algos = append(algos, string(ru.ApplyServerSideEncryptionByDefault.SSEAlgorithm))
			}
		}
		r.Inputs["cb_describer_encryption"] = map[string]any{"algorithms": algos}
	case isNoSuchBucketEncryption(err):
		r.Inputs["cb_describer_encryption"] = nil
	default:
		return classifyS3Error(err, bucket, r.Region, "s3:GetBucketEncryption")
	}

	// Bucket policy presence — coarse signal. We don't parse the
	// document here; the grounded analyzer can do that downstream.
	pol, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
	switch {
	case err == nil:
		r.Inputs["cb_describer_bucket_policy_present"] = pol.Policy != nil && *pol.Policy != ""
	case isS3NotFound(err):
		r.Inputs["cb_describer_bucket_policy_present"] = false
	default:
		return classifyS3Error(err, bucket, r.Region, "s3:GetBucketPolicy")
	}

	return nil
}

func isNoSuchPublicAccessBlock(err error) bool {
	return s3ErrorCode(err) == "NoSuchPublicAccessBlockConfiguration"
}

func isNoSuchBucketEncryption(err error) bool {
	return s3ErrorCode(err) == "ServerSideEncryptionConfigurationNotFoundError"
}

func isS3NotFound(err error) bool {
	switch s3ErrorCode(err) {
	case "NoSuchBucket", "NoSuchBucketPolicy", "NoSuchTagSet":
		return true
	}
	return false
}

func s3ErrorCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// classifyS3Error wraps AccessDenied as *PermissionError so --diagnose
// picks it up; other S3 errors pass through with context.
func classifyS3Error(err error, bucket, region, action string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "AccessDeniedException":
			return &PermissionError{
				Service: "s3",
				Action:  action,
				Region:  region,
				Cause:   fmt.Errorf("on bucket %s: %w", bucket, err),
			}
		}
	}
	return fmt.Errorf("%s on bucket %s [%s]: %w", action, bucket, region, err)
}

// _ asserts s3 types is referenced so future field types resolve;
// remove when a concrete reference replaces it.
var _ = types.ObjectStorageClassStandard
