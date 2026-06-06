package aws

import (
	"context"
	"testing"
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
