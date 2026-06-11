package aws

import (
	"github.com/cloudbooster-io/cbx-cli/internal/audit"
)

// computeTrailCoverage derives per-region CloudTrail coverage from
// the discovered AWS::CloudTrail::Trail resources. A trail covers a
// region when:
//
//   - IsMultiRegionTrail=true → covers every region in the account
//     (AWS replicates trail events to the home region but the trail
//     reports for all regions).
//   - Otherwise the trail only covers its home region.
//
// Trails also need IsLogging=true to actually be capturing events;
// a paused trail is the same as no trail for audit purposes. The
// CFN Properties from CloudControl don't surface IsLogging reliably
// (it's a separate API call: cloudtrail:GetTrailStatus), so this
// pass treats "trail exists" as "trail is logging" — a stricter
// check is a v2 telemetry feature.
//
// Updates posture.TrailCoverageByRegion in place. Regions with no
// covering trail surface as value=false — the LLM flags those as
// findings.
func computeTrailCoverage(resources []DiscoveredResource, regions []string, posture *audit.AccountPosture) {
	if posture == nil || len(regions) == 0 {
		return
	}

	hasMultiRegion := false
	homeRegions := map[string]struct{}{}

	for _, r := range resources {
		if r.Type != "AWS::CloudTrail::Trail" {
			continue
		}
		// IsMultiRegionTrail is a bool field in the CFN Properties.
		if v, ok := r.Inputs["IsMultiRegionTrail"].(bool); ok && v {
			hasMultiRegion = true
		}
		// Home region: prefer the trail's CFN "HomeRegion" field;
		// fall back to the resource's discovered Region. r.Region is
		// authoritative when CloudControl strips HomeRegion (which it
		// does for global-scoped reads).
		home := ""
		if h, ok := r.Inputs["HomeRegion"].(string); ok {
			home = h
		}
		if home == "" {
			home = r.Region
		}
		if home != "" {
			homeRegions[home] = struct{}{}
		}
	}

	coverage := make(map[string]bool, len(regions))
	for _, region := range regions {
		if hasMultiRegion {
			coverage[region] = true
			continue
		}
		_, covered := homeRegions[region]
		coverage[region] = covered
	}
	posture.TrailCoverageByRegion = coverage
}
