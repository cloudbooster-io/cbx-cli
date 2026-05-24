package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// CloudControl's AWS::S3::Bucket schema does NOT expose CreationDate as
// a read-only property — only Arn, DomainName, RegionalDomainName,
// DualStackDomainName, WebsiteURL. The orphan provider needs creation
// time to gate "empty bucket" findings to genuinely-stale buckets, so we
// hydrate it from a single account-wide ListBuckets call, cached for the
// process lifetime. Tests reset via resetBucketCreationCacheForTest.
var (
	bucketCreationOnce  sync.Once
	bucketCreationCache map[string]time.Time
	bucketCreationErr   error
	bucketCreationMu    sync.Mutex // guards reset; Once handles the populate race
)

// fetchBucketCreationDates returns the creation date for the named
// bucket, sourced from a once-per-process ListBuckets. The bool reports
// "we found this bucket in the list" — when false, the caller should
// skip the cb_describer_creation_date field rather than guess.
func fetchBucketCreationDate(ctx context.Context, c awsCfg, name string) (time.Time, bool, error) {
	bucketCreationOnce.Do(func() {
		client := s3.NewFromConfig(c.cfg)
		out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			bucketCreationErr = err
			return
		}
		bucketCreationCache = make(map[string]time.Time, len(out.Buckets))
		for _, b := range out.Buckets {
			if b.Name != nil && b.CreationDate != nil {
				bucketCreationCache[*b.Name] = b.CreationDate.UTC()
			}
		}
	})
	if bucketCreationErr != nil {
		return time.Time{}, false, bucketCreationErr
	}
	t, ok := bucketCreationCache[name]
	return t, ok, nil
}

// resetBucketCreationCacheForTest is exported via the _test.go file so
// describer tests in this package can re-prime the sync.Once between
// table cases. Kept colocated with the cache to make the link obvious.
func resetBucketCreationCacheForTest() {
	bucketCreationMu.Lock()
	defer bucketCreationMu.Unlock()
	bucketCreationOnce = sync.Once{}
	bucketCreationCache = nil
	bucketCreationErr = nil
}

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

	// Bucket policy — presence + raw JSON document. The document is
	// the load-bearing signal for the most critical S3 finding
	// (Principal: "*" with no condition restricting the principal); a
	// bare "policy_present: true" wasn't enough for the LLM to flag
	// public-access policies. We surface the decoded JSON so the
	// grounded analyzer can reason about Principal / Condition
	// without re-parsing escape-encoded forms.
	pol, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
	switch {
	case err == nil:
		present := pol.Policy != nil && *pol.Policy != ""
		r.Inputs["cb_describer_bucket_policy_present"] = present
		if present {
			r.Inputs["cb_describer_bucket_policy_document"] = *pol.Policy
			r.Inputs["cb_describer_bucket_policy_has_wildcard_principal"] = bucketPolicyHasWildcardPrincipal(*pol.Policy)
		}
	case isS3NotFound(err):
		r.Inputs["cb_describer_bucket_policy_present"] = false
	default:
		return classifyS3Error(err, bucket, r.Region, "s3:GetBucketPolicy")
	}

	// Object-count probe — single-key list is the cheapest signal for
	// "is this bucket empty?", which the orphan provider consumes. We
	// only resolve presence/absence; an actual count isn't worth a
	// paginated walk. Versioned buckets containing only delete markers
	// still report as non-empty here, which is the correct conservative
	// behaviour — orphan-flagging shouldn't race ahead of versioning state.
	one := int32(1)
	objs, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket, MaxKeys: &one})
	switch {
	case err == nil:
		r.Inputs["cb_describer_has_objects"] = len(objs.Contents) > 0
	case isS3NotFound(err):
		r.Inputs["cb_describer_has_objects"] = false
	default:
		return classifyS3Error(err, bucket, r.Region, "s3:ListObjectsV2")
	}

	// Creation date — sourced from the once-cached ListBuckets, since CC
	// doesn't surface it for AWS::S3::Bucket. We don't fail the whole
	// describer if the cache fetch errored (AccessDenied on
	// s3:ListAllMyBuckets is the most common cause and is already a
	// preflight failure mode); we just skip the field and let the orphan
	// detector's "missing-date skip" branch handle it.
	if t, ok, ferr := fetchBucketCreationDate(ctx, c, bucket); ferr == nil && ok {
		r.Inputs["cb_describer_creation_date"] = t.Format("2006-01-02T15:04:05Z")
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

// bucketPolicyHasWildcardPrincipal returns true when any Statement
// with Effect=Allow has Principal `*` or `{"AWS":"*"}` AND no
// Condition restricting `aws:PrincipalAccount` / `aws:PrincipalOrgID`
// / `aws:PrincipalArn` / `aws:SourceVpc` / `aws:SourceIp`. The
// classic "open to the entire internet" S3 policy — surfaced as a
// crisp boolean so the LLM doesn't need to parse the policy JSON.
//
// This is intentionally a conservative match: the absence of any
// scoping condition under an `Effect: Allow` + `Principal: *`
// statement is treated as the public-access pattern. False positives
// (e.g. an `aws:SourceIp` allowlist of every IP under the sun) are
// the user's problem to refute on the finding card.
func bucketPolicyHasWildcardPrincipal(doc string) bool {
	var parsed struct {
		Statement []struct {
			Effect    string         `json:"Effect"`
			Principal any            `json:"Principal"`
			Condition map[string]any `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
	}
	for _, s := range parsed.Statement {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if !principalIsWildcard(s.Principal) {
			continue
		}
		if hasScopingCondition(s.Condition) {
			continue
		}
		return true
	}
	return false
}

func principalIsWildcard(p any) bool {
	switch t := p.(type) {
	case string:
		return t == "*"
	case map[string]any:
		// {"AWS": "*"} or {"AWS": ["*"]}
		for _, v := range t {
			switch vv := v.(type) {
			case string:
				if vv == "*" {
					return true
				}
			case []any:
				for _, item := range vv {
					if s, ok := item.(string); ok && s == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func hasScopingCondition(cond map[string]any) bool {
	if len(cond) == 0 {
		return false
	}
	// Any of these condition keys narrows the wildcard principal to a
	// scoped set, so the statement isn't unconditionally public.
	scopingKeys := []string{
		"aws:PrincipalAccount", "aws:PrincipalOrgID", "aws:PrincipalOrgPaths",
		"aws:PrincipalArn", "aws:SourceVpc", "aws:SourceVpce", "aws:SourceIp",
		"aws:SourceArn", "aws:SourceAccount", "aws:UserId",
	}
	for _, op := range cond {
		opMap, ok := op.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range scopingKeys {
			if _, present := opMap[k]; present {
				return true
			}
		}
	}
	return false
}
