package aws

import (
	"context"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
)

// scoutProbeTypes is the small set of CFN types we probe per region to
// answer "is anything actually deployed here?" before paying for the
// full per-type fan-out. Picked to cover the common compute/data shapes
// without false positives from AWS-managed defaults:
//
//   - EC2::Instance        — classic compute
//   - Lambda::Function     — serverless compute
//   - RDS::DBInstance      — managed databases
//   - DynamoDB::Table      — NoSQL data
//
// Notably absent: AWS::EC2::VPC (default VPC exists in every enabled
// region whether you use it or not — would always show a hit), S3 (its
// CloudControl list is global, not regional, so it's a useless region
// signal), and IAM (global by definition).
var scoutProbeTypes = []string{
	"AWS::EC2::Instance",
	"AWS::Lambda::Function",
	"AWS::RDS::DBInstance",
	"AWS::DynamoDB::Table",
}

// scoutResult captures the per-region outcome of the scout phase.
type scoutResult struct {
	Region string
	Count  int   // resources observed across the probe types
	Err    error // non-nil on permission / throttling failures
}

// scoutRegions probes every region in parallel for any sign of life,
// returning a slice of regions that have at least one resource across
// the scoutProbeTypes. Per-region failures collect into permErrs (when
// they look like IAM denials) or otherErrs and don't drop the region
// from the active set — better to over-scan than to silently skip a
// region the user might care about.
//
// All regions are probed concurrently; AWS doesn't share rate limits
// across regions and the worst case (~30 enabled regions) is well
// within reasonable goroutine territory.
func scoutRegions(ctx context.Context, c awsCfg, regions []string, onProgress func(ProgressEvent)) (active []string, permErrs []*PermissionError, otherErrs []error) {
	if len(regions) == 0 {
		return nil, nil, nil
	}

	emitProgress(onProgress, ProgressEvent{Phase: ProgressPhaseScoutStart, Total: len(regions)})

	resCh := make(chan scoutResult, len(regions))
	var wg sync.WaitGroup
	for _, region := range regions {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			count, err := probeRegion(ctx, c, r)
			resCh <- scoutResult{Region: r, Count: count, Err: err}
		}(region)
	}
	go func() {
		wg.Wait()
		close(resCh)
	}()

	done := 0
	results := map[string]int{}
	for r := range resCh {
		done++
		results[r.Region] = r.Count
		if r.Err != nil {
			if pe, ok := asPermissionError(r.Err); ok {
				permErrs = append(permErrs, pe)
			} else {
				otherErrs = append(otherErrs, r.Err)
			}
		}
		emitProgress(onProgress, ProgressEvent{
			Phase:  ProgressPhaseScoutRegionDone,
			Region: r.Region,
			Found:  r.Count,
			Done:   done,
			Total:  len(regions),
		})
	}

	// Preserve the original ordering (regions arrive in alphabetical
	// order from DescribeRegions; the scoutResult channel is unordered).
	for _, region := range regions {
		if results[region] > 0 {
			active = append(active, region)
		}
	}

	emitProgress(onProgress, ProgressEvent{Phase: ProgressPhaseScoutDone, Regions: active})
	return active, permErrs, otherErrs
}

// probeRegion runs ListResources for each scoutProbeType in this region
// and returns the total identifier count across them. Returns on the
// first error (per-region is best-effort, not exhaustive); a region
// with permission errors on the probe types is still kept in the
// active set by the caller so we don't accidentally hide infrastructure
// behind missing IAM.
func probeRegion(ctx context.Context, c awsCfg, region string) (int, error) {
	regionalCfg := c.withRegion(region)
	client := cloudcontrol.NewFromConfig(regionalCfg.cfg)

	total := 0
	for _, cfnType := range scoutProbeTypes {
		typ := cfnType
		out, err := client.ListResources(ctx, &cloudcontrol.ListResourcesInput{
			TypeName: &typ,
		})
		if err != nil {
			if isUnsupportedType(err) {
				continue
			}
			return total, classifyCloudControlError(err, cfnType, region, "cloudformation:ListResources")
		}
		total += len(out.ResourceDescriptions)
	}
	return total, nil
}

// isAllRegionsRequest reports whether the user's --regions input was
// the "all" literal (so the scout should run to narrow the deep-scan
// region set).
func isAllRegionsRequest(requested []string) bool {
	for _, r := range requested {
		if strings.EqualFold(strings.TrimSpace(r), "all") {
			return true
		}
	}
	return false
}
