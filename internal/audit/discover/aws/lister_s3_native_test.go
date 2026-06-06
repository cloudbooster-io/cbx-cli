package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// s3BucketToRaw must synthesise the CloudControl AWS::S3::Bucket shape: the
// bucket name is both the primary identifier (→ DiscoveredResource.ID, which is
// the only field s3BucketDescriber reads) and the BucketName prop, with the
// audited region carried through so the region-qualified URN is correct.
func TestS3BucketToRaw_RoundTrip(t *testing.T) {
	raw, ok := s3BucketToRaw("static-site-assets", "eu-central-1")
	if !ok {
		t.Fatal("s3BucketToRaw !ok for a valid bucket name")
	}
	if raw.CFNType != "AWS::S3::Bucket" || raw.Identifier != "static-site-assets" {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}
	if raw.Region != "eu-central-1" {
		t.Fatalf("Region: got %q, want eu-central-1", raw.Region)
	}

	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if dr.ID != "static-site-assets" {
		t.Errorf("ID: got %q, want static-site-assets (the name s3BucketDescriber keys off)", dr.ID)
	}
	if dr.Inputs["BucketName"] != "static-site-assets" {
		t.Errorf("BucketName: got %v, want static-site-assets", dr.Inputs["BucketName"])
	}
	if dr.URN != "aws://eu-central-1/AWS::S3::Bucket/static-site-assets" {
		t.Errorf("URN: got %q (region-qualified URN is why cross-region scoping matters)", dr.URN)
	}
}

func TestS3BucketToRaw_EmptyName(t *testing.T) {
	if _, ok := s3BucketToRaw("", "eu-central-1"); ok {
		t.Error("s3BucketToRaw returned ok for an empty bucket name")
	}
}

// normalizeBucketLocation must absorb S3's two legacy region quirks so a
// us-east-1 / eu-west-1 bucket isn't silently excluded by the region filter.
func TestNormalizeBucketLocation(t *testing.T) {
	cases := map[string]string{
		"":             "us-east-1",    // null LocationConstraint == us-east-1
		"EU":           "eu-west-1",    // legacy alias
		"eu-central-1": "eu-central-1", // verbatim
		"us-west-2":    "us-west-2",
	}
	for in, want := range cases {
		if got := normalizeBucketLocation(in); got != want {
			t.Errorf("normalizeBucketLocation(%q) = %q, want %q", in, got, want)
		}
	}
}

// Empty primary (CloudControl's silent-empty for S3) must trigger the fallback,
// and the synthesised bucket must flow through runJob into the resource set.
// The real s3BucketDescriber makes live AWS calls, so we swap the describer
// registry out — the wiring under test is the fallback-on-empty path, not the
// describer's network calls (mirrors TestRunJob_BackupVaultFallbackFires).
func TestRunJob_S3BucketFallbackFires(t *testing.T) {
	saved := allDescribers
	allDescribers = []Describer{}
	defer func() { allDescribers = saved }()

	fallbackRaw, ok := s3BucketToRaw("static-site-assets", "eu-central-1")
	if !ok {
		t.Fatal("s3BucketToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type:         "AWS::S3::Bucket",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 bucket from the fallback, got %d", len(res.resources))
	}
	if got := res.resources[0]; got.Type != "AWS::S3::Bucket" || got.ID != "static-site-assets" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
}

// When CloudControl lists the bucket, the fallback must NOT fire — CC's richer
// payload wins and there's no double-counting.
func TestRunJob_S3BucketFallbackNotFiredWhenPrimaryReturns(t *testing.T) {
	saved := allDescribers
	allDescribers = []Describer{}
	defer func() { allDescribers = saved }()

	primaryRaw, ok := s3BucketToRaw("cc-listed-bucket", "eu-central-1")
	if !ok {
		t.Fatal("s3BucketToRaw !ok")
	}

	fallbackCalled := false
	spec := cfnTypeSpec{
		Type:         "AWS::S3::Bucket",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return []rawResource{primaryRaw}, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			fallbackCalled = true
			return []rawResource{{CFNType: "AWS::S3::Bucket", Identifier: "should-not-appear"}}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if fallbackCalled {
		t.Error("FallbackLister fired even though CloudControl returned a bucket")
	}
	if len(res.resources) != 1 || res.resources[0].ID != "cc-listed-bucket" {
		t.Fatalf("expected only the CloudControl bucket, got %+v", res.resources)
	}
}

// fakeS3Fallback implements s3FallbackAPI so the per-bucket region-resolution
// loop can be exercised without a live call. ListBuckets always returns the
// configured buckets; GetBucketLocation reports loc[name] unless failLoc[name],
// in which case it returns an AccessDenied APIError — the SCP/permission-boundary
// deny (or a TOCTOU NoSuchBucket) the partial-recovery path exists for.
type fakeS3Fallback struct {
	buckets []s3types.Bucket
	loc     map[string]string // bucket name → LocationConstraint to report
	failLoc map[string]bool   // bucket name → GetBucketLocation returns AccessDenied
}

func (f *fakeS3Fallback) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.buckets}, nil
}

func (f *fakeS3Fallback) GetBucketLocation(_ context.Context, in *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	name := ""
	if in.Bucket != nil {
		name = *in.Bucket
	}
	if f.failLoc[name] {
		return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied by SCP"}
	}
	return &s3.GetBucketLocationOutput{LocationConstraint: s3types.BucketLocationConstraint(f.loc[name])}, nil
}

func bucketNames(raws []rawResource) map[string]bool {
	m := make(map[string]bool, len(raws))
	for _, r := range raws {
		m[r.Identifier] = true
	}
	return m
}

// One bucket's GetBucketLocation failing (an SCP deny, or a TOCTOU NoSuchBucket
// from a bucket deleted between ListBuckets and the lookup) must NOT black out
// the whole S3 fallback: the buckets whose region DID resolve are still returned,
// so a single bad lookup can't reintroduce the silent-empty miss this lister
// exists to kill. The error is still handed back — partial recovery, so runJob
// keeps the resources and surfaces the denied lookup to --diagnose.
func TestCollectInRegionS3Buckets_PartialRecoveryOnLocationError(t *testing.T) {
	client := &fakeS3Fallback{
		buckets: []s3types.Bucket{
			{Name: strp("alpha")},
			{Name: strp("bravo")}, // middle bucket's location lookup is denied
			{Name: strp("charlie")},
		},
		loc: map[string]string{
			"alpha":   "eu-central-1",
			"charlie": "eu-central-1",
		},
		failLoc: map[string]bool{"bravo": true},
	}

	results, err := collectInRegionS3Buckets(context.Background(), client, "eu-central-1")

	if results == nil {
		t.Fatal("results nil — one bad GetBucketLocation blacked out the whole fallback")
	}
	if len(results) != 2 {
		t.Fatalf("expected the 2 resolvable in-region buckets, got %d", len(results))
	}
	names := bucketNames(results)
	if !names["alpha"] || !names["charlie"] {
		t.Errorf("expected alpha+charlie recovered, got %v", names)
	}
	if names["bravo"] {
		t.Error("bravo (denied lookup) must be skipped, not synthesised")
	}
	// Partial recovery still surfaces the denied lookup for --diagnose (the
	// listDynamoDBTablesNative pitrErr idiom: keep the resources, return the error).
	if err == nil {
		t.Error("expected the GetBucketLocation error surfaced alongside the recovered buckets")
	}
}

// When EVERY bucket's location lookup is denied (a fully restricted org), the
// fallback recovers nothing — and that total failure must surface as an error so
// --diagnose flags the permission gap instead of it looking like a clean empty
// account. The error classifies as *PermissionError, the same shape the
// CloudControl path collects.
func TestCollectInRegionS3Buckets_AllLocationErrorsSurface(t *testing.T) {
	client := &fakeS3Fallback{
		buckets: []s3types.Bucket{
			{Name: strp("alpha")},
			{Name: strp("bravo")},
		},
		failLoc: map[string]bool{"alpha": true, "bravo": true},
	}

	results, err := collectInRegionS3Buckets(context.Background(), client, "eu-central-1")

	if len(results) != 0 {
		t.Fatalf("expected no resources when every location lookup failed, got %d", len(results))
	}
	if err == nil {
		t.Fatal("expected a non-nil error so the all-deny surfaces in --diagnose")
	}
	if _, ok := asPermissionError(err); !ok {
		t.Errorf("expected the AccessDenied to classify as *PermissionError, got %T", err)
	}
}

// The region filter (the load-bearing global-service scoping) drops cross-region
// buckets so a single-region audit doesn't flood every other region's buckets in.
// Exercises normalizeBucketLocation through the loop — a null constraint ("") is
// us-east-1 and stays out of an eu-central-1 audit; an empty-name bucket is
// skipped; the verbatim region match stays in — all with no error.
func TestCollectInRegionS3Buckets_RegionFilter(t *testing.T) {
	client := &fakeS3Fallback{
		buckets: []s3types.Bucket{
			{Name: strp("in-region")},
			{Name: strp("other-region")},
			{Name: strp("us-east-1-bucket")},
			{Name: nil}, // skipped: no name
		},
		loc: map[string]string{
			"in-region":        "eu-central-1",
			"other-region":     "us-west-2",
			"us-east-1-bucket": "", // null constraint == us-east-1
		},
	}

	results, err := collectInRegionS3Buckets(context.Background(), client, "eu-central-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected only the in-region bucket, got %d", len(results))
	}
	if results[0].Identifier != "in-region" {
		t.Errorf("expected in-region bucket, got %q", results[0].Identifier)
	}
}
