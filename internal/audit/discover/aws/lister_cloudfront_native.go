package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// listCloudFrontDistributionsNative is the FallbackLister for
// AWS::CloudFront::Distribution. It is the last Global type that was still
// WITHOUT a fallback: a flaky/empty CloudControl list silently drops the WHOLE
// distribution (permission_errors stays 0), and because CloudFront findings are
// LLM-emitted straight off the raw DistributionConfig with NO describer to
// re-fetch them, every CloudFront finding vanishes with it. The fixtures-01
// (static-site, S3 + CloudFront only) verdict already catches the no-WAF and
// access-logging-disabled findings — but ONLY because CloudControl happened to
// list the distribution that run; one silent-empty list and they go dark, the
// exact false-negative every other native fallback exists to prevent.
//
// LIKE the Lambda fallback (and unlike S3, whose describer re-fetches live):
// there is NO cloudFrontDescriber, so this fallback must carry EVERY
// finding-bearing field in the synthesised props. cloudfront:ListDistributions
// returns the full DistributionSummary inline — Origins (S3 global-endpoint
// rule), ViewerCertificate (default-cert / weak-TLS rule), WebACLId (no-WAF
// rule), and DefaultCacheBehavior.ViewerProtocolPolicy (so the already-CAUGHT
// plaintext-HTTP finding isn't regressed when the fallback fires). The one field
// the summary omits is Logging, so cloudfront:GetDistributionConfig is a
// best-effort per-distribution probe for it (mirrors Lambda's
// GetFunctionConcurrency): a probe failure keeps the distribution (its three
// summary-borne findings survive) and leaves Logging absent — which the
// access-logging rule reads as "logging disabled", the same value CloudControl
// emits for an unconfigured distribution, so a denied probe degrades to the
// CloudControl-empty reading rather than dropping the resource.
//
// CloudFront is GLOBAL: there is no region loop. We mirror the IAM
// ManagedPolicy fallback's convention — pin the client to the job's region (the
// CloudFront endpoint is global regardless) and stamp that region on the raw so
// the synthetic URN matches what a CloudControl-listed Global type would carry,
// and dedupeByURN collapses any cross-region duplicate.
func listCloudFrontDistributionsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	return collectCloudFrontDistributions(ctx, cloudfront.NewFromConfig(c.withRegion(region).cfg), region)
}

// cloudFrontFallbackAPI is the narrow slice of the CloudFront client
// collectCloudFrontDistributions needs — ListDistributions (the enumeration,
// paginated by Marker ← NextMarker) plus the best-effort GetDistributionConfig
// logging probe. The concrete *cloudfront.Client satisfies it; the seam lets
// pagination and the per-distribution probe's partial-failure handling be
// unit-tested without a live call (mirrors lambdaFallbackAPI / s3FallbackAPI).
type cloudFrontFallbackAPI interface {
	ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
	GetDistributionConfig(context.Context, *cloudfront.GetDistributionConfigInput, ...func(*cloudfront.Options)) (*cloudfront.GetDistributionConfigOutput, error)
}

// collectCloudFrontDistributions enumerates distributions via ListDistributions
// and synthesises a CFN-shape raw per distribution.
//
// A ListDistributions failure is fatal — we have nothing to recover. Per-
// distribution GetDistributionConfig (logging) failures are NOT: the summary
// already carries the other three findings, so we keep the distribution, leave
// Logging absent, and record the first error in logErr, returning
// (results, logErr). That tail mirrors collectLambdaFunctions' (results, concErr)
// and the runJob fallback contract (discover.go):
//   - any distributions collected → runJob keeps them and clears the primary's
//     emptiness; logErr (if any) still surfaces to --diagnose so a denied
//     GetDistributionConfig isn't silently swallowed.
//   - zero distributions, probe err → the error surfaces alone, so an all-deny
//     shows up in --diagnose instead of masquerading as a clean empty account.
//   - zero distributions, no error → a genuinely distribution-less account.
func collectCloudFrontDistributions(ctx context.Context, client cloudFrontFallbackAPI, region string) ([]rawResource, error) {
	var results []rawResource
	var logErr error
	var marker *string
	for {
		out, err := client.ListDistributions(ctx, &cloudfront.ListDistributionsInput{Marker: marker})
		if err != nil {
			return nil, classifyAWSError(err, "cloudfront", "cloudfront:ListDistributions", region)
		}
		if out == nil || out.DistributionList == nil {
			break
		}
		for _, ds := range out.DistributionList.Items {
			logging, lerr := readDistributionLogging(ctx, client, ds.Id, region)
			if lerr != nil && logErr == nil {
				logErr = lerr
			}
			if raw, ok := cloudFrontDistributionToRaw(ds, logging, region); ok {
				results = append(results, raw)
			}
		}
		if out.DistributionList.IsTruncated == nil || !*out.DistributionList.IsTruncated ||
			out.DistributionList.NextMarker == nil || *out.DistributionList.NextMarker == "" {
			break
		}
		marker = out.DistributionList.NextMarker
	}
	return results, logErr
}

// readDistributionLogging fetches a distribution's access-logging config via
// cloudfront:GetDistributionConfig (ListDistributions' summary omits Logging).
// Returns (*LoggingConfig, nil) when read, (nil, nil) when there's nothing to
// read, and (nil, err) on failure — so the caller leaves Logging absent (the
// access-logging rule reads that as "disabled", matching CloudControl's empty
// shape) and surfaces the error without dropping the distribution. Mirrors
// readReservedConcurrency.
func readDistributionLogging(ctx context.Context, client cloudFrontFallbackAPI, id *string, region string) (*cftypes.LoggingConfig, error) {
	if id == nil || *id == "" {
		return nil, nil
	}
	out, err := client.GetDistributionConfig(ctx, &cloudfront.GetDistributionConfigInput{Id: id})
	if err != nil {
		return nil, classifyAWSError(err, "cloudfront", "cloudfront:GetDistributionConfig", region)
	}
	if out == nil || out.DistributionConfig == nil {
		return nil, nil
	}
	return out.DistributionConfig.Logging, nil
}

// cloudFrontDistributionToRaw maps an SDK DistributionSummary (+ the best-effort
// Logging probe) into CloudControl's AWS::CloudFront::Distribution CFN shape so
// the synthesised resource flows through mapToDiscovered + the grounded LLM pass
// identically to a CloudControl-listed distribution. Id is the identifier
// (CloudControl's primary id for this type). The shape is the one the existing
// CloudFront prompt bullets and diagram_svg.go already read: a top-level
// `DistributionConfig` map whose `Origins` is a FLAT list (NOT the SDK
// `{Items:[...]}` wrapper). The load-bearing fields:
//
//   - ViewerCertificate.CloudFrontDefaultCertificate / .MinimumProtocolVersion →
//     default-cert / weak-minimum-TLS rule.
//   - WebACLId → no-WAF rule (empty/absent is the signal; putStr omits the
//     empty string, matching CloudControl's no-WAF shape).
//   - Logging.Bucket / .Enabled → access-logging-disabled rule (absent ⇒ off).
//   - Origins[*].DomainName + S3OriginConfig → S3-global-endpoint rule and the
//     CloudFront→S3-origin connection edge.
//   - DefaultCacheBehavior.ViewerProtocolPolicy → preserves the already-CAUGHT
//     plaintext-HTTP (allow-all) finding when the fallback fires.
//
// Pure (no SDK client) for unit testing; mirrors lambdaFunctionToRaw.
func cloudFrontDistributionToRaw(ds cftypes.DistributionSummary, logging *cftypes.LoggingConfig, region string) (rawResource, bool) {
	if ds.Id == nil || *ds.Id == "" {
		return rawResource{}, false
	}
	id := *ds.Id

	cfg := map[string]any{}
	putBool(cfg, "Enabled", ds.Enabled)

	// Origins — flat CFN list (DistributionConfig.Origins), the shape the
	// line-541 prompt bullet and diagram_svg.go read.
	if ds.Origins != nil && len(ds.Origins.Items) > 0 {
		origins := make([]any, 0, len(ds.Origins.Items))
		for _, o := range ds.Origins.Items {
			om := map[string]any{}
			putStr(om, "Id", o.Id)
			putStr(om, "DomainName", o.DomainName)
			if o.S3OriginConfig != nil {
				s3o := map[string]any{}
				putStr(s3o, "OriginAccessIdentity", o.S3OriginConfig.OriginAccessIdentity)
				om["S3OriginConfig"] = s3o
			}
			if o.CustomOriginConfig != nil {
				co := map[string]any{}
				putInt32(co, "HTTPPort", o.CustomOriginConfig.HTTPPort)
				putInt32(co, "HTTPSPort", o.CustomOriginConfig.HTTPSPort)
				if o.CustomOriginConfig.OriginProtocolPolicy != "" {
					co["OriginProtocolPolicy"] = string(o.CustomOriginConfig.OriginProtocolPolicy)
				}
				om["CustomOriginConfig"] = co
			}
			origins = append(origins, om)
		}
		cfg["Origins"] = origins
	}

	// DefaultCacheBehavior.ViewerProtocolPolicy — carried so the already-CAUGHT
	// plaintext-HTTP (allow-all) finding survives a fallback-discovered run.
	if ds.DefaultCacheBehavior != nil {
		dcb := map[string]any{}
		putStr(dcb, "TargetOriginId", ds.DefaultCacheBehavior.TargetOriginId)
		if ds.DefaultCacheBehavior.ViewerProtocolPolicy != "" {
			dcb["ViewerProtocolPolicy"] = string(ds.DefaultCacheBehavior.ViewerProtocolPolicy)
		}
		cfg["DefaultCacheBehavior"] = dcb
	}

	// ViewerCertificate — default-cert + minimum-TLS rule. AcmCertificateArn uses
	// CFN casing (the SDK field is ACMCertificateArn) to match CloudControl.
	if ds.ViewerCertificate != nil {
		vc := map[string]any{}
		putBool(vc, "CloudFrontDefaultCertificate", ds.ViewerCertificate.CloudFrontDefaultCertificate)
		if ds.ViewerCertificate.MinimumProtocolVersion != "" {
			vc["MinimumProtocolVersion"] = string(ds.ViewerCertificate.MinimumProtocolVersion)
		}
		putStr(vc, "AcmCertificateArn", ds.ViewerCertificate.ACMCertificateArn)
		cfg["ViewerCertificate"] = vc
	}

	// WebACLId — empty/absent ⇒ no-WAF rule (putStr omits the empty string).
	putStr(cfg, "WebACLId", ds.WebACLId)

	// Logging — from the best-effort GetDistributionConfig probe. Carries both the
	// CFN-native Bucket (empty/absent ⇒ disabled) and the SDK Enabled flag; absent
	// entirely when the probe failed, which the rule also reads as disabled.
	if logging != nil {
		lg := map[string]any{}
		putBool(lg, "Enabled", logging.Enabled)
		putStr(lg, "Bucket", logging.Bucket)
		cfg["Logging"] = lg
	}

	props := map[string]any{
		"Id":                 id,
		"DistributionConfig": cfg,
	}
	putStr(props, "ARN", ds.ARN)
	putStr(props, "DomainName", ds.DomainName)

	return marshalRaw("AWS::CloudFront::Distribution", id, region, props)
}
