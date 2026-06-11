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
// process lifetime.
var (
	bucketCreationOnce  sync.Once
	bucketCreationCache map[string]time.Time
	bucketCreationErr   error
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
			"block_public_acls":       deref(pab.PublicAccessBlockConfiguration.BlockPublicAcls),
			"block_public_policy":     deref(pab.PublicAccessBlockConfiguration.BlockPublicPolicy),
			"ignore_public_acls":      deref(pab.PublicAccessBlockConfiguration.IgnorePublicAcls),
			"restrict_public_buckets": deref(pab.PublicAccessBlockConfiguration.RestrictPublicBuckets),
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
		// Crisp derived booleans so a posture rule has an unambiguous hook
		// instead of string-matching the raw status (the same de-risking
		// the wildcard-principal boolean applies, L243+). AWS omits the
		// MFADelete element entirely until it is configured, so an empty
		// string is treated identically to "Disabled" — not enabled.
		r.Inputs["cb_describer_versioning_enabled"] = versioningEnabled(string(vers.Status))
		r.Inputs["cb_describer_mfa_delete_enabled"] = mfaDeleteEnabled(string(vers.MFADelete))
	} else if !isS3NotFound(err) {
		return classifyS3Error(err, bucket, r.Region, "s3:GetBucketVersioning")
	}

	// Encryption — compliance signal. NoSuchBucketEncryption is the
	// "no SSE configured" case worth flagging.
	enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bucket})
	switch {
	case err == nil && enc.ServerSideEncryptionConfiguration != nil:
		applyEncryptionInputs(r.Inputs, enc.ServerSideEncryptionConfiguration)
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

	// Lifecycle configuration — cost/retention hygiene. Like PAB/encryption,
	// the ABSENCE is the signal: NoSuchLifecycleConfiguration is the explicit
	// "no lifecycle rules" case worth flagging for data/ingest buckets, so we
	// emit cb_describer_lifecycle_present=false rather than silently skipping.
	lc, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: &bucket})
	switch {
	case err == nil:
		r.Inputs["cb_describer_lifecycle_present"] = len(lc.Rules) > 0
		r.Inputs["cb_describer_lifecycle_rule_count"] = len(lc.Rules)
	case isNoSuchLifecycleConfiguration(err):
		r.Inputs["cb_describer_lifecycle_present"] = false
		r.Inputs["cb_describer_lifecycle_rule_count"] = 0
	default:
		return classifyS3Error(err, bucket, r.Region, "s3:GetBucketLifecycleConfiguration")
	}

	// Server-access logging — audit signal. There is NO not-found error code
	// here: GetBucketLogging succeeds with LoggingEnabled==nil when logging is
	// off, which is the "off" case. When on, surface the target bucket so the
	// grounded analyzer can suppress the finding on a bucket that is itself an
	// access-log destination (a log target logging to itself is recursion, not
	// a gap).
	lg, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &bucket})
	switch {
	case err == nil:
		on := lg.LoggingEnabled != nil
		r.Inputs["cb_describer_access_logging_enabled"] = on
		if on && lg.LoggingEnabled.TargetBucket != nil {
			r.Inputs["cb_describer_access_logging_target_bucket"] = *lg.LoggingEnabled.TargetBucket
		}
	case isS3NotFound(err):
		r.Inputs["cb_describer_access_logging_enabled"] = false
	default:
		return classifyS3Error(err, bucket, r.Region, "s3:GetBucketLogging")
	}

	// Object Lock — WORM/immutability signal for backup/compliance buckets.
	// A bucket that was NOT created with ObjectLockEnabledForBucket=true
	// returns ObjectLockConfigurationNotFoundError — that error IS the
	// finding's absence signal (object lock genuinely off), not a failure, so
	// it maps to cb_describer_object_lock_enabled=false.
	ol, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: &bucket})
	switch {
	case err == nil:
		r.Inputs["cb_describer_object_lock_enabled"] = objectLockEnabled(ol.ObjectLockConfiguration)
	case isObjectLockNotFound(err):
		r.Inputs["cb_describer_object_lock_enabled"] = false
	default:
		return classifyS3Error(err, bucket, r.Region, "s3:GetObjectLockConfiguration")
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

func isNoSuchLifecycleConfiguration(err error) bool {
	return s3ErrorCode(err) == "NoSuchLifecycleConfiguration"
}

func isObjectLockNotFound(err error) bool {
	return s3ErrorCode(err) == "ObjectLockConfigurationNotFoundError"
}

// versioningEnabled reports whether the bucket's versioning Status is the
// AWS "Enabled" value (vs "Suspended" or the empty never-configured case).
func versioningEnabled(status string) bool {
	return status == "Enabled"
}

// mfaDeleteEnabled reports whether MFA-Delete is on. AWS omits the MFADelete
// element entirely until it has been configured, so an empty string is
// treated identically to "Disabled" — not enabled.
func mfaDeleteEnabled(mfaDelete string) bool {
	return mfaDelete == "Enabled"
}

// applyEncryptionInputs populates the encryption-related cb_describer_*
// fields from a bucket's server-side-encryption configuration, and — when
// the default algorithm is a KMS CMK with an explicit key — surfaces that
// key reference so the KMS cross-reference pass can count it.
//
// The key is stored under the bare, UN-prefixed "KMSMasterKeyID" name (NOT
// a cb_describer_* name) on purpose: that is the exact CFN property name
// crossReferenceKMS walks (isKMSFieldName), so a CMK used ONLY as this
// bucket's SSE-KMS key is counted as referenced instead of being mis-flagged
// "unused". Do NOT rename it to a cb_describer_* form for sibling-field
// consistency — doing so would silently reintroduce that false positive.
// CloudControl omits BucketEncryption entirely (the reason Enrich calls
// GetBucketEncryption at all), so this describer is the only place the
// reference can be recovered for a live bucket. FP-safe by direction: it can
// only add a real reference (flip is_unused true→false), never create a
// spurious unused=true.
func applyEncryptionInputs(in map[string]any, cfg *types.ServerSideEncryptionConfiguration) {
	rules := cfg.Rules
	algos := make([]string, 0, len(rules))
	for _, ru := range rules {
		def := ru.ApplyServerSideEncryptionByDefault
		if def == nil {
			continue
		}
		algos = append(algos, string(def.SSEAlgorithm))
		// Store the CMK reference ONLY when the default is genuinely KMS and
		// an explicit key id is present. SSE-S3/AES256 carries no key, and an
		// aws:kms rule with no KMSMasterKeyID is the AWS-managed aws/s3 key —
		// never a customer key the unused-pass would flag — so leave the field
		// absent in both cases (present-field discipline).
		if sseAlgoIsKMS(def.SSEAlgorithm) && def.KMSMasterKeyID != nil && *def.KMSMasterKeyID != "" {
			in["KMSMasterKeyID"] = *def.KMSMasterKeyID
		}
	}
	in["cb_describer_encryption"] = map[string]any{"algorithms": algos}
	// Derived hook: true only when a KMS CMK is the default algorithm
	// (vs SSE-S3/AES256). Deliberately set ONLY on the present branch —
	// the no-encryption case stays nil so "no SSE at all" (a distinct,
	// stronger finding) never collapses into "SSE-S3-not-KMS".
	in["cb_describer_sse_is_kms"] = sseIsKMS(algos)
}

// sseAlgoIsKMS reports whether a single default SSE algorithm is a KMS CMK
// ("aws:kms" or dual-layer "aws:kms:dsse") as opposed to SSE-S3 ("AES256").
func sseAlgoIsKMS(a types.ServerSideEncryption) bool {
	return a == types.ServerSideEncryptionAwsKms || a == types.ServerSideEncryptionAwsKmsDsse
}

// sseIsKMS reports whether any default SSE algorithm is a KMS CMK ("aws:kms"
// or dual-layer "aws:kms:dsse") as opposed to SSE-S3 ("AES256"). Only
// meaningful when encryption is present — the no-encryption case is handled
// separately (a stronger, distinct finding) and must not reach here.
func sseIsKMS(algorithms []string) bool {
	for _, a := range algorithms {
		if sseAlgoIsKMS(types.ServerSideEncryption(a)) {
			return true
		}
	}
	return false
}

// objectLockEnabled reports whether a bucket's Object Lock configuration has
// WORM protection turned on. nil config (or any non-"Enabled" state) is
// not-enabled — the absence signal finding 6 grounds on.
func objectLockEnabled(cfg *types.ObjectLockConfiguration) bool {
	return cfg != nil && cfg.ObjectLockEnabled == types.ObjectLockEnabledEnabled
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
