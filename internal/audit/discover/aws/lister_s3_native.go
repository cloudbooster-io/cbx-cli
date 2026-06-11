package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// listS3BucketsNative is the FallbackLister for AWS::S3::Bucket. CloudControl
// is the one workload type that was still WITHOUT a fallback: fixtures variant
// 01 (static-site, S3-heavy) measured 2/9 recall twice because its buckets were
// silently dropped at discovery — the same flaky silent-empty failure mode the
// other native fallbacks cover, just on the last uncovered type. s3:ListBuckets
// is the authoritative, strongly-consistent enumeration and only fires when
// CloudControl returned nothing for AWS::S3::Bucket in this region.
//
// GLOBAL-SERVICE region scoping (the load-bearing design point): S3 is a global
// service — s3:ListBuckets returns EVERY bucket in the account regardless of
// region. The audit is region-scoped and the synthetic URN is region-qualified
// (aws://<region>/<type>/<id>), so dedupeByURN would NOT collapse the same
// bucket synthesized under two different regions. Returning the whole account
// per region would therefore flood cross-region buckets into every single-region
// job. We resolve each bucket's home region with s3:GetBucketLocation and keep
// only the buckets whose home region matches the audited region, producing
// exactly the set a region-scoped CloudControl list would.
//
// We deliberately use the plain (unparameterised) ListBuckets — the same proven
// call s3BucketDescriber already makes for creation dates — plus the legacy
// GetBucketLocation, rather than the newer ListBuckets BucketRegion filter: the
// no-AWS unit test can't exercise a live call, so grounding the fallback on the
// already-validated call family keeps it from shipping an unverified code path.
func listS3BucketsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	// NewFromConfig(c.cfg) — NOT c.withRegion(region): S3 is a global service, so
	// ListBuckets returns the whole account regardless of the client's region and
	// each bucket's home region is resolved per-bucket below. (The other native
	// listers pin a regional client; this one deliberately must not.)
	return collectInRegionS3Buckets(ctx, s3.NewFromConfig(c.cfg), region)
}

// s3FallbackAPI is the narrow slice of the S3 client collectInRegionS3Buckets
// needs — just the two already-validated calls (ListBuckets + the legacy
// GetBucketLocation). The concrete *s3.Client satisfies it, and the seam lets
// the per-bucket region-resolution loop (and its partial-failure handling) be
// unit-tested with a fake instead of a live call.
type s3FallbackAPI interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

// collectInRegionS3Buckets enumerates buckets via ListBuckets and keeps only the
// ones whose home region matches the audited region (see the listS3BucketsNative
// doc for why global-service scoping matters).
//
// A ListBuckets failure is fatal — we have nothing to recover. But a single
// bucket's GetBucketLocation failing must NOT black out the whole fallback. Two
// real triggers: an SCP / permission-boundary denying s3:GetBucketLocation
// (fails every run for a restricted org), and a TOCTOU NoSuchBucket from a
// bucket deleted between ListBuckets and the lookup. Aborting on the first such
// error would discard every already-collected in-region bucket and reintroduce
// the exact silent-empty miss this fallback exists to kill. So we skip the
// offending bucket and continue (partial recovery), recording the first failure
// in locErr.
//
// The tail `return results, locErr` mirrors listDynamoDBTablesNative's
// `return results, pitrErr` and the runJob fallback contract (discover.go:421):
//   - any in-region buckets collected  → runJob keeps them and clears the
//     primary's emptiness; locErr (if any) is still surfaced to --diagnose so a
//     denied lookup isn't silently swallowed.
//   - zero results but a lookup failed → the error surfaces alone, so an
//     all-deny shows up in --diagnose instead of masquerading as a clean empty
//     account.
//   - zero results, no error           → a genuinely empty account.
func collectInRegionS3Buckets(ctx context.Context, client s3FallbackAPI, region string) ([]rawResource, error) {
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, classifyAWSError(err, "s3", "s3:ListBuckets", region)
	}

	var results []rawResource
	var locErr error
	for _, b := range out.Buckets {
		if b.Name == nil || *b.Name == "" {
			continue
		}
		loc, lerr := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: b.Name})
		if lerr != nil {
			if locErr == nil {
				locErr = classifyAWSError(lerr, "s3", "s3:GetBucketLocation", region)
			}
			continue
		}
		if normalizeBucketLocation(string(loc.LocationConstraint)) != region {
			continue
		}
		if raw, ok := s3BucketToRaw(*b.Name, region); ok {
			results = append(results, raw)
		}
	}
	return results, locErr
}

// normalizeBucketLocation maps GetBucketLocation's LocationConstraint to a real
// region code. S3 carries two legacy quirks: a bucket in us-east-1 returns an
// empty constraint, and a bucket in the original EU region returns "EU" (an
// alias for eu-west-1). Every other region returns its own code verbatim. We
// normalise before comparing to the audited region so a us-east-1 / eu-west-1
// bucket isn't silently excluded.
func normalizeBucketLocation(loc string) string {
	switch loc {
	case "":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	default:
		return loc
	}
}

// s3BucketToRaw synthesises CloudControl's AWS::S3::Bucket CFN shape from a
// bucket name. The bucket name is CloudControl's primary identifier for this
// type and is the ONLY field s3BucketDescriber reads off the resource — it
// fetches PublicAccessBlock / encryption / versioning / bucket-policy state live
// off r.ID + r.Region — so a minimal {BucketName} props map is sufficient for
// the s3-hygiene findings to fire identically to the CloudControl path. Pure (no
// SDK client) for unit testing. Mirrors ecrRepositoryToRaw.
func s3BucketToRaw(name, region string) (rawResource, bool) {
	if name == "" {
		return rawResource{}, false
	}
	props := map[string]any{"BucketName": name}
	return marshalRaw("AWS::S3::Bucket", name, region, props)
}
