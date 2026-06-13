package aws

import (
	"context"
	"errors"
	"testing"
)

// noopFallback is a stand-in FallbackLister/CustomLister used only to assert
// that wiring either one makes a type ineligible for the integrity reprobe.
func noopFallback(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil }

// --- scope: integrityProbeEligible ---------------------------------------

func TestIntegrityProbeEligible(t *testing.T) {
	cases := []struct {
		name string
		spec cfnTypeSpec
		want bool
	}{
		{
			// CB-curated (AWS::S3::Bucket → aws:s3/bucket@v1) with no
			// fallback: the bare tail the probe exists for.
			name: "curated bare type is eligible",
			spec: cfnTypeSpec{Type: "AWS::S3::Bucket"},
			want: true,
		},
		{
			// A type that already self-heals via FallbackLister must be
			// skipped — reprobing it is redundant.
			name: "curated type with fallback is not eligible",
			spec: cfnTypeSpec{Type: "AWS::S3::Bucket", FallbackLister: noopFallback},
			want: false,
		},
		{
			name: "curated type with custom lister is not eligible",
			spec: cfnTypeSpec{Type: "AWS::S3::Bucket", CustomLister: noopFallback},
			want: false,
		},
		{
			// No CB primitive → a silent miss darkens no finding, so the
			// type is out of scope.
			name: "non-curated type is not eligible",
			spec: cfnTypeSpec{Type: "AWS::Fake::Type"},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := integrityProbeEligible(tc.spec); got != tc.want {
				t.Errorf("integrityProbeEligible(%s) = %v, want %v", tc.spec.Type, got, tc.want)
			}
		})
	}
}

// --- candidate detection: isIntegrityCandidate ---------------------------

func TestIsIntegrityCandidate(t *testing.T) {
	bare := cfnTypeSpec{Type: "AWS::S3::Bucket"} // curated, no fallback
	withFallback := cfnTypeSpec{Type: "AWS::S3::Bucket", FallbackLister: noopFallback}
	someResource := DiscoveredResource{Type: "AWS::S3::Bucket", ID: "b1"}

	cases := []struct {
		name string
		r    jobResult
		want bool
	}{
		{
			// The exact silent-empty shape: eligible, no error, zero found.
			name: "clean-empty eligible is a candidate",
			r:    jobResult{spec: bare, resources: nil, listErr: nil},
			want: true,
		},
		{
			// An errored list is already an advisory — a reprobe failure
			// there is not a disagreement, so don't double-warn.
			name: "errored list is not a candidate",
			r:    jobResult{spec: bare, resources: nil, listErr: errors.New("throttled")},
			want: false,
		},
		{
			// Discovery already has the type — asymmetric rule means it
			// could never warn, so it's not a candidate.
			name: "non-empty list is not a candidate",
			r:    jobResult{spec: bare, resources: []DiscoveredResource{someResource}, listErr: nil},
			want: false,
		},
		{
			name: "ineligible type is not a candidate",
			r:    jobResult{spec: withFallback, resources: nil, listErr: nil},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isIntegrityCandidate(tc.r); got != tc.want {
				t.Errorf("isIntegrityCandidate = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- the probe: probeDiscoveryIntegrity ----------------------------------

// fakeReprobe returns a canned count/error keyed by CFN type, standing in for
// the live CloudControl re-list (whose flakiness can't be forced in a unit
// test, by design).
func fakeReprobe(counts map[string]int, errs map[string]error) reprobeFunc {
	return func(_ context.Context, _ awsCfg, _ string, spec cfnTypeSpec) (int, error) {
		if err, ok := errs[spec.Type]; ok {
			return 0, err
		}
		return counts[spec.Type], nil
	}
}

// The headline behaviour: when the independent re-list sees a resource the
// discovery set missed, the probe emits exactly one warning carrying the type,
// region, and missed count.
func TestProbeDiscoveryIntegrity_WarnsOnDisagreement(t *testing.T) {
	candidates := []integrityCandidate{
		{region: "eu-central-1", spec: cfnTypeSpec{Type: "AWS::S3::Bucket"}},
	}
	got := probeDiscoveryIntegrity(context.Background(), awsCfg{}, candidates, 2,
		fakeReprobe(map[string]int{"AWS::S3::Bucket": 3}, nil))

	if len(got) != 1 {
		t.Fatalf("expected 1 warning, got %d (%v)", len(got), got)
	}
	w := got[0]
	if w.Type != "AWS::S3::Bucket" || w.Region != "eu-central-1" || w.Count != 3 {
		t.Errorf("warning = %+v, want {AWS::S3::Bucket eu-central-1 3}", w)
	}
}

// When the re-list agrees with discovery (also sees zero — the type is
// genuinely absent, or both reads flaked), the probe stays silent. This is the
// no-false-alarms guarantee.
func TestProbeDiscoveryIntegrity_SilentWhenGenuinelyAbsent(t *testing.T) {
	candidates := []integrityCandidate{
		{region: "eu-central-1", spec: cfnTypeSpec{Type: "AWS::S3::Bucket"}},
	}
	got := probeDiscoveryIntegrity(context.Background(), awsCfg{}, candidates, 2,
		fakeReprobe(map[string]int{"AWS::S3::Bucket": 0}, nil))

	if len(got) != 0 {
		t.Errorf("expected no warnings when the re-list also sees 0, got %v", got)
	}
}

// A reprobe error is "no signal", not a disagreement — it must not warn.
func TestProbeDiscoveryIntegrity_SilentOnReprobeError(t *testing.T) {
	candidates := []integrityCandidate{
		{region: "eu-central-1", spec: cfnTypeSpec{Type: "AWS::S3::Bucket"}},
	}
	got := probeDiscoveryIntegrity(context.Background(), awsCfg{}, candidates, 2,
		fakeReprobe(nil, map[string]error{"AWS::S3::Bucket": errors.New("throttled")}))

	if len(got) != 0 {
		t.Errorf("expected no warnings on reprobe error, got %v", got)
	}
}

// A Global type's warning carries an empty region (it renders as "global")
// rather than the arbitrary region the global list was issued from.
func TestProbeDiscoveryIntegrity_GlobalRegionBlanked(t *testing.T) {
	candidates := []integrityCandidate{
		{region: "us-east-1", spec: cfnTypeSpec{Type: "AWS::IAM::Role", Global: true}},
	}
	got := probeDiscoveryIntegrity(context.Background(), awsCfg{}, candidates, 2,
		fakeReprobe(map[string]int{"AWS::IAM::Role": 2}, nil))

	if len(got) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(got))
	}
	if got[0].Region != "" {
		t.Errorf("global warning region = %q, want \"\"", got[0].Region)
	}
}

// Mixed candidates: only the ones whose re-list disagrees (positive count, no
// error) warn, and the output is sorted deterministically by (type, region).
func TestProbeDiscoveryIntegrity_MixedAndSorted(t *testing.T) {
	candidates := []integrityCandidate{
		{region: "us-east-1", spec: cfnTypeSpec{Type: "AWS::SNS::Topic"}},      // count 1 → warn
		{region: "us-east-1", spec: cfnTypeSpec{Type: "AWS::KMS::Key"}},        // count 0 → silent
		{region: "us-east-1", spec: cfnTypeSpec{Type: "AWS::DynamoDB::Table"}}, // error → silent
		{region: "eu-west-1", spec: cfnTypeSpec{Type: "AWS::SQS::Queue"}},      // count 5 → warn
	}
	got := probeDiscoveryIntegrity(context.Background(), awsCfg{}, candidates, 3,
		fakeReprobe(
			map[string]int{"AWS::SNS::Topic": 1, "AWS::KMS::Key": 0, "AWS::SQS::Queue": 5},
			map[string]error{"AWS::DynamoDB::Table": errors.New("boom")},
		))

	if len(got) != 2 {
		t.Fatalf("expected 2 warnings, got %d (%v)", len(got), got)
	}
	// Sorted by Type: "AWS::SNS::Topic" < "AWS::SQS::Queue".
	if got[0].Type != "AWS::SNS::Topic" || got[1].Type != "AWS::SQS::Queue" {
		t.Errorf("warnings not sorted by type: %+v", got)
	}
	if got[1].Count != 5 {
		t.Errorf("SQS count = %d, want 5", got[1].Count)
	}
}

func TestProbeDiscoveryIntegrity_NoCandidates(t *testing.T) {
	if got := probeDiscoveryIntegrity(context.Background(), awsCfg{}, nil, 2, fakeReprobe(nil, nil)); got != nil {
		t.Errorf("expected nil for no candidates, got %v", got)
	}
}
