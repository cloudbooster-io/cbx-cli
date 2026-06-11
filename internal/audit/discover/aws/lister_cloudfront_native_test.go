package aws

import (
	"context"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/smithy-go"
)

// cfInputs maps a synthesised raw through mapToDiscovered and returns the Inputs
// the grounded LLM pass reads. CloudFront has NO describer, so the synthesised
// props ARE the finding-bearing data the analyzer sees — this exercises exactly
// the path runJob feeds the prompt (no live call).
func cfInputs(t *testing.T, raw rawResource) map[string]any {
	t.Helper()
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	return dr.Inputs
}

// cfgOf pulls the DistributionConfig sub-map (the shape the prompt bullets and
// diagram_svg.go read: DistributionConfig.{ViewerCertificate, WebACLId, Logging,
// Origins[]}).
func cfgOf(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	cfg, ok := in["DistributionConfig"].(map[string]any)
	if !ok {
		t.Fatalf("DistributionConfig missing or wrong type: %T", in["DistributionConfig"])
	}
	return cfg
}

// The variant-01 posture every CloudFront rule should fire on: default viewer
// cert (forces TLSv1), no WAF, access logging off, and an S3 GLOBAL-endpoint
// origin. The synthesised raw must surface each finding-bearing field at the
// exact DistributionConfig path the grounded prompt reads — there is no
// describer to re-fetch them, so a missing field would silently kill the rule.
func TestCloudFrontDistributionToRaw_InsecurePostureFiresFindings(t *testing.T) {
	ds := cftypes.DistributionSummary{
		Id:         strp("EXMPLINSECURE1"),
		ARN:        strp("arn:aws:cloudfront::111122223333:distribution/EXMPLINSECURE1"),
		DomainName: strp("dexample.cloudfront.net"),
		Enabled:    sdkaws.Bool(true),
		Origins: &cftypes.Origins{
			Quantity: sdkaws.Int32(1),
			Items: []cftypes.Origin{{
				Id:             strp("origin-static"),
				DomainName:     strp("example-static-origin.s3.amazonaws.com"), // GLOBAL endpoint (no region segment)
				S3OriginConfig: &cftypes.S3OriginConfig{OriginAccessIdentity: strp("")},
			}},
		},
		DefaultCacheBehavior: &cftypes.DefaultCacheBehavior{
			TargetOriginId:       strp("origin-static"),
			ViewerProtocolPolicy: cftypes.ViewerProtocolPolicyAllowAll,
		},
		ViewerCertificate: &cftypes.ViewerCertificate{
			CloudFrontDefaultCertificate: sdkaws.Bool(true),
			MinimumProtocolVersion:       cftypes.MinimumProtocolVersionTLSv1,
		},
		// WebACLId empty → no WAF
	}
	logging := &cftypes.LoggingConfig{Enabled: sdkaws.Bool(false)} // Bucket empty → logging disabled

	raw, ok := cloudFrontDistributionToRaw(ds, logging, "eu-central-1")
	if !ok {
		t.Fatal("cloudFrontDistributionToRaw !ok for a valid distribution")
	}
	if raw.CFNType != "AWS::CloudFront::Distribution" || raw.Identifier != "EXMPLINSECURE1" {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}

	cfg := cfgOf(t, cfInputs(t, raw))

	// no-WAF: WebACLId omitted (putStr drops the empty string), matching
	// CloudControl's no-WAF shape, so the rule fires.
	if _, present := cfg["WebACLId"]; present {
		t.Errorf("WebACLId must be absent for a no-WAF distribution so the rule fires, got %v", cfg["WebACLId"])
	}

	// default-cert / weak-TLS.
	vc, _ := cfg["ViewerCertificate"].(map[string]any)
	if v, ok := vc["CloudFrontDefaultCertificate"].(bool); !ok || !v {
		t.Errorf("CloudFrontDefaultCertificate: got %v, want true", vc["CloudFrontDefaultCertificate"])
	}
	if vc["MinimumProtocolVersion"] != "TLSv1" {
		t.Errorf("MinimumProtocolVersion: got %v, want TLSv1", vc["MinimumProtocolVersion"])
	}

	// access logging disabled.
	lg, _ := cfg["Logging"].(map[string]any)
	if v, ok := lg["Enabled"].(bool); !ok || v {
		t.Errorf("Logging.Enabled: got %v, want false", lg["Enabled"])
	}
	if _, present := lg["Bucket"]; present {
		t.Errorf("Logging.Bucket must be absent when no log bucket is set, got %v", lg["Bucket"])
	}

	// plaintext-HTTP (already-CAUGHT finding) must survive a fallback-discovered run.
	dcb, _ := cfg["DefaultCacheBehavior"].(map[string]any)
	if dcb["ViewerProtocolPolicy"] != "allow-all" {
		t.Errorf("DefaultCacheBehavior.ViewerProtocolPolicy: got %v, want allow-all (must survive so the plaintext-HTTP finding isn't regressed)", dcb["ViewerProtocolPolicy"])
	}

	// S3 global-endpoint origin surfaced at the path the rule reads.
	origins, _ := cfg["Origins"].([]any)
	if len(origins) != 1 {
		t.Fatalf("expected 1 origin in the flat CFN list, got %d", len(origins))
	}
	o0, _ := origins[0].(map[string]any)
	dn, _ := o0["DomainName"].(string)
	if dn != "example-static-origin.s3.amazonaws.com" {
		t.Errorf("origin DomainName: got %q, want the global-endpoint form", dn)
	}
	if _, ok := o0["S3OriginConfig"]; !ok {
		t.Error("S3OriginConfig must be present so the origin is recognised as an S3 origin")
	}
}

// Focused global-vs-regional endpoint detection: the synthesised
// Origins[*].DomainName is the signal the global-endpoint rule keys on. The
// global form `<bucket>.s3.amazonaws.com` ends in `.s3.amazonaws.com`; the
// regional form `<bucket>.s3.<region>.amazonaws.com` does not (a region segment
// sits between). Asserting the suffix distinction proves the fallback surfaces
// the exact data that lets the rule discriminate the planted issue from a
// compliant regional origin.
func TestCloudFrontDistributionToRaw_GlobalEndpointDetection(t *testing.T) {
	cases := []struct {
		name       string
		domain     string
		wantGlobal bool
	}{
		{"global S3 endpoint (planted issue)", "example-origin.s3.amazonaws.com", true},
		{"regional S3 endpoint (compliant)", "example-origin.s3.eu-central-1.amazonaws.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds := cftypes.DistributionSummary{
				Id: strp("EXMPLORIGIN1"),
				Origins: &cftypes.Origins{
					Quantity: sdkaws.Int32(1),
					Items: []cftypes.Origin{{
						Id:             strp("o1"),
						DomainName:     strp(tc.domain),
						S3OriginConfig: &cftypes.S3OriginConfig{OriginAccessIdentity: strp("")},
					}},
				},
			}
			raw, ok := cloudFrontDistributionToRaw(ds, nil, "eu-central-1")
			if !ok {
				t.Fatal("cloudFrontDistributionToRaw !ok")
			}
			cfg := cfgOf(t, cfInputs(t, raw))
			origins, _ := cfg["Origins"].([]any)
			o0, _ := origins[0].(map[string]any)
			dn, _ := o0["DomainName"].(string)
			if dn != tc.domain {
				t.Fatalf("DomainName round-trip: got %q want %q", dn, tc.domain)
			}
			isGlobal := strings.HasSuffix(dn, ".s3.amazonaws.com")
			if isGlobal != tc.wantGlobal {
				t.Errorf("global-endpoint discriminator for %q = %v, want %v", dn, isGlobal, tc.wantGlobal)
			}
		})
	}
}

// The inverse posture — custom ACM cert at TLSv1.2_2021, a WAF web ACL,
// logging on, and a REGIONAL origin — must carry the compliant values so NONE
// of the four rules fire. Guards against the mapper hard-coding the "bad" shape.
func TestCloudFrontDistributionToRaw_SecurePostureInverse(t *testing.T) {
	ds := cftypes.DistributionSummary{
		Id:      strp("EXMPLSECURE1"),
		Enabled: sdkaws.Bool(true),
		Origins: &cftypes.Origins{
			Quantity: sdkaws.Int32(1),
			Items: []cftypes.Origin{{
				Id:             strp("o1"),
				DomainName:     strp("example-origin.s3.eu-central-1.amazonaws.com"), // regional → compliant
				S3OriginConfig: &cftypes.S3OriginConfig{OriginAccessIdentity: strp("origin-access-identity/cloudfront/EXMPLOAI")},
			}},
		},
		ViewerCertificate: &cftypes.ViewerCertificate{
			CloudFrontDefaultCertificate: sdkaws.Bool(false),
			MinimumProtocolVersion:       cftypes.MinimumProtocolVersionTLSv122021,
			ACMCertificateArn:            strp("arn:aws:acm:us-east-1:111122223333:certificate/abcd"),
		},
		WebACLId: strp("arn:aws:wafv2:us-east-1:111122223333:global/webacl/example/abcd"),
	}
	logging := &cftypes.LoggingConfig{Enabled: sdkaws.Bool(true), Bucket: strp("cf-logs.s3.amazonaws.com")}

	raw, ok := cloudFrontDistributionToRaw(ds, logging, "eu-central-1")
	if !ok {
		t.Fatal("cloudFrontDistributionToRaw !ok")
	}
	cfg := cfgOf(t, cfInputs(t, raw))

	if cfg["WebACLId"] != "arn:aws:wafv2:us-east-1:111122223333:global/webacl/example/abcd" {
		t.Errorf("WebACLId must be carried when set (no-WAF rule suppressed), got %v", cfg["WebACLId"])
	}
	vc, _ := cfg["ViewerCertificate"].(map[string]any)
	if v, ok := vc["CloudFrontDefaultCertificate"].(bool); !ok || v {
		t.Errorf("CloudFrontDefaultCertificate: got %v, want false (custom cert ⇒ rule suppressed)", vc["CloudFrontDefaultCertificate"])
	}
	if vc["MinimumProtocolVersion"] != "TLSv1.2_2021" {
		t.Errorf("MinimumProtocolVersion: got %v, want TLSv1.2_2021", vc["MinimumProtocolVersion"])
	}
	if vc["AcmCertificateArn"] != "arn:aws:acm:us-east-1:111122223333:certificate/abcd" {
		t.Errorf("AcmCertificateArn (CFN casing) must carry the custom cert ARN, got %v", vc["AcmCertificateArn"])
	}
	lg, _ := cfg["Logging"].(map[string]any)
	if v, ok := lg["Enabled"].(bool); !ok || !v {
		t.Errorf("Logging.Enabled: got %v, want true (logging on ⇒ rule suppressed)", lg["Enabled"])
	}
	if lg["Bucket"] != "cf-logs.s3.amazonaws.com" {
		t.Errorf("Logging.Bucket must carry the log bucket, got %v", lg["Bucket"])
	}
	origins, _ := cfg["Origins"].([]any)
	o0, _ := origins[0].(map[string]any)
	dn, _ := o0["DomainName"].(string)
	if strings.HasSuffix(dn, ".s3.amazonaws.com") {
		t.Errorf("regional origin %q must NOT match the global-endpoint suffix", dn)
	}
}

func TestCloudFrontDistributionToRaw_EmptyId(t *testing.T) {
	if _, ok := cloudFrontDistributionToRaw(cftypes.DistributionSummary{Id: nil}, nil, "eu-central-1"); ok {
		t.Error("cloudFrontDistributionToRaw returned ok for a nil Id")
	}
	if _, ok := cloudFrontDistributionToRaw(cftypes.DistributionSummary{Id: strp("")}, nil, "eu-central-1"); ok {
		t.Error("cloudFrontDistributionToRaw returned ok for an empty Id")
	}
}

// fakeCloudFrontFallback implements cloudFrontFallbackAPI so pagination and the
// per-distribution GetDistributionConfig logging probe can be exercised without a
// live call. ListDistributions returns pages[callIdx] in order (callers drive it
// via NextMarker); GetDistributionConfig reports logging[id] unless failLog[id],
// in which case it returns an AccessDenied APIError — the SCP/permission-boundary
// deny the partial-recovery path exists for. Mirrors fakeLambdaFallback.
type fakeCloudFrontFallback struct {
	pages   []*cloudfront.ListDistributionsOutput
	listErr error
	logging map[string]*cftypes.LoggingConfig
	failLog map[string]bool
	callIdx int
}

func (f *fakeCloudFrontFallback) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := f.pages[f.callIdx]
	f.callIdx++
	return out, nil
}

func (f *fakeCloudFrontFallback) GetDistributionConfig(_ context.Context, in *cloudfront.GetDistributionConfigInput, _ ...func(*cloudfront.Options)) (*cloudfront.GetDistributionConfigOutput, error) {
	id := ""
	if in.Id != nil {
		id = *in.Id
	}
	if f.failLog[id] {
		return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied by SCP"}
	}
	return &cloudfront.GetDistributionConfigOutput{
		DistributionConfig: &cftypes.DistributionConfig{Logging: f.logging[id]},
	}, nil
}

// ListDistributions paginates by Marker ← NextMarker; collectCloudFrontDistributions
// must walk every page and probe each distribution's logging. Two pages, logging
// set on one distribution, verifies both the pagination loop and that the probe
// value lands in the synthesised props (and that a distribution with no probe
// data leaves Logging absent — read as "disabled" by the rule).
func TestCollectCloudFrontDistributions_PaginatesAndProbes(t *testing.T) {
	client := &fakeCloudFrontFallback{
		pages: []*cloudfront.ListDistributionsOutput{
			{DistributionList: &cftypes.DistributionList{
				IsTruncated: sdkaws.Bool(true),
				NextMarker:  strp("page-2"),
				Items: []cftypes.DistributionSummary{
					{Id: strp("DALPHA")},
					{Id: strp("DBRAVO")},
				},
			}},
			{DistributionList: &cftypes.DistributionList{
				IsTruncated: sdkaws.Bool(false),
				Items: []cftypes.DistributionSummary{
					{Id: strp("DCHARLIE")},
				},
			}},
		},
		logging: map[string]*cftypes.LoggingConfig{
			"DBRAVO": {Enabled: sdkaws.Bool(true), Bucket: strp("logs.s3.amazonaws.com")},
		},
	}

	results, err := collectCloudFrontDistributions(context.Background(), client, "eu-central-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected all 3 distributions across both pages, got %d", len(results))
	}
	by := mappedByID(t, results)
	for _, id := range []string{"DALPHA", "DBRAVO", "DCHARLIE"} {
		if by[id] == nil {
			t.Errorf("distribution %q missing from the paginated result", id)
		}
	}
	// DBRAVO's probe → Logging present + Enabled true (rule suppressed).
	cfgB, _ := by["DBRAVO"]["DistributionConfig"].(map[string]any)
	lgB, _ := cfgB["Logging"].(map[string]any)
	if v, _ := lgB["Enabled"].(bool); !v {
		t.Errorf("DBRAVO Logging.Enabled should be true from the probe, got %v", lgB["Enabled"])
	}
	// DALPHA had no logging entry → Logging absent (rule reads as disabled, fires).
	cfgA, _ := by["DALPHA"]["DistributionConfig"].(map[string]any)
	if _, present := cfgA["Logging"]; present {
		t.Errorf("DALPHA Logging should be absent (no probe data) so the access-logging rule fires, got %v", cfgA["Logging"])
	}
}

// A per-distribution GetDistributionConfig failure must NOT drop the
// distribution — ListDistributions already carries its WAF / cert-TLS /
// origin-endpoint findings — so we keep it (Logging left absent, the
// access-logging rule still fires) and surface the first error so --diagnose
// sees the permission gap. Mirrors collectLambdaFunctions' concErr contract.
func TestCollectCloudFrontDistributions_LoggingProbeErrorKeepsDistribution(t *testing.T) {
	client := &fakeCloudFrontFallback{
		pages: []*cloudfront.ListDistributionsOutput{
			{DistributionList: &cftypes.DistributionList{
				Items: []cftypes.DistributionSummary{
					{Id: strp("DALPHA")},
					{Id: strp("DBRAVO")}, // its logging probe is denied
				},
			}},
		},
		failLog: map[string]bool{"DBRAVO": true},
	}

	results, err := collectCloudFrontDistributions(context.Background(), client, "eu-central-1")
	if len(results) != 2 {
		t.Fatalf("expected both distributions kept despite the probe denial, got %d", len(results))
	}
	if err == nil {
		t.Fatal("expected the GetDistributionConfig error surfaced alongside the recovered distributions")
	}
	if _, ok := asPermissionError(err); !ok {
		t.Errorf("expected the AccessDenied to classify as *PermissionError, got %T", err)
	}
	by := mappedByID(t, results)
	cfg, _ := by["DBRAVO"]["DistributionConfig"].(map[string]any)
	if _, present := cfg["Logging"]; present {
		t.Error("DBRAVO Logging must be absent (probe denied) so the access-logging rule still fires")
	}
}

// A ListDistributions failure is fatal — there's nothing to recover — and must
// come back classified for --diagnose.
func TestCollectCloudFrontDistributions_ListErrorFatal(t *testing.T) {
	client := &fakeCloudFrontFallback{listErr: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}}

	results, err := collectCloudFrontDistributions(context.Background(), client, "eu-central-1")
	if results != nil {
		t.Fatalf("expected nil results on a ListDistributions failure, got %d", len(results))
	}
	if _, ok := asPermissionError(err); !ok {
		t.Fatalf("expected *PermissionError from a denied ListDistributions, got %T (%v)", err, err)
	}
}

// Empty primary (CloudControl's silent-empty for AWS::CloudFront::Distribution —
// the fragility this fallback closes) must trigger the fallback. CloudFront has
// no describer, so the synthesised raw maps straight through runJob with its
// finding-bearing fields intact.
func TestRunJob_CloudFrontFallbackFires(t *testing.T) {
	fallbackRaw, ok := cloudFrontDistributionToRaw(
		cftypes.DistributionSummary{
			Id:                strp("EXMPLINSECURE1"),
			ViewerCertificate: &cftypes.ViewerCertificate{CloudFrontDefaultCertificate: sdkaws.Bool(true), MinimumProtocolVersion: cftypes.MinimumProtocolVersionTLSv1},
		}, &cftypes.LoggingConfig{Enabled: sdkaws.Bool(false)}, "eu-central-1")
	if !ok {
		t.Fatal("cloudFrontDistributionToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type:         "AWS::CloudFront::Distribution",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 distribution from the fallback, got %d", len(res.resources))
	}
	got := res.resources[0]
	if got.Type != "AWS::CloudFront::Distribution" || got.ID != "EXMPLINSECURE1" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
	cfg, _ := got.Inputs["DistributionConfig"].(map[string]any)
	vc, _ := cfg["ViewerCertificate"].(map[string]any)
	if v, _ := vc["CloudFrontDefaultCertificate"].(bool); !v {
		t.Errorf("CloudFrontDefaultCertificate must survive the fallback→runJob path, got %v", vc["CloudFrontDefaultCertificate"])
	}
}

// When CloudControl lists the distribution, the fallback must NOT fire — CC's
// payload wins and there's no double-counting.
func TestRunJob_CloudFrontFallbackNotFiredWhenPrimaryReturns(t *testing.T) {
	primaryRaw, ok := cloudFrontDistributionToRaw(cftypes.DistributionSummary{Id: strp("CCLISTED1")}, nil, "eu-central-1")
	if !ok {
		t.Fatal("cloudFrontDistributionToRaw !ok")
	}

	fallbackCalled := false
	spec := cfnTypeSpec{
		Type:         "AWS::CloudFront::Distribution",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return []rawResource{primaryRaw}, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			fallbackCalled = true
			return []rawResource{{CFNType: "AWS::CloudFront::Distribution", Identifier: "should-not-appear"}}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if fallbackCalled {
		t.Error("FallbackLister fired even though CloudControl returned a distribution")
	}
	if len(res.resources) != 1 || res.resources[0].ID != "CCLISTED1" {
		t.Fatalf("expected only the CloudControl distribution, got %+v", res.resources)
	}
}
