package aws

import (
	"context"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
)

// annotateFlowLogs sets cb_describer_flow_logs_enabled on every
// discovered AWS::EC2::VPC, mirroring the cb_describer_* annotation
// convention crossReferenceNetwork uses. Unlike that pass, flow-log
// state isn't in CloudControl's VPC Properties — it needs a separate
// ec2:DescribeFlowLogs call — so this runs post-discovery with the
// already-authenticated cfg, like the account-posture probes.
//
// FP-safety is the whole point here: a missing flow log is a real
// finding, but only when we actually looked. So:
//   - We probe only regions that have a discovered VPC (no wasted calls,
//     no flagging regions we never inspected).
//   - cb_describer_flow_logs_enabled is set to false ONLY for VPCs whose
//     region was probed successfully and that have no ACTIVE VPC-level
//     flow log. A probe failure (AccessDenied, throttling) leaves the
//     key unset so the LLM treats it as unknown, not absent — and the
//     failure is surfaced in posture.Errors for --diagnose.
//
// VPC ids are matched globally (not per-region) so a VPC is never
// silently skipped on a missing/odd Region field — the determining
// factor for false vs unset is whether the VPC's region is in the
// successfully-probed set.
func annotateFlowLogs(ctx context.Context, cfg awsCfg, resources []DiscoveredResource, posture *audit.AccountPosture) {
	// Collect the regions that actually host a discovered VPC.
	vpcRegions := map[string]struct{}{}
	for _, r := range resources {
		if r.Type == "AWS::EC2::VPC" && r.Region != "" {
			vpcRegions[r.Region] = struct{}{}
		}
	}
	if len(vpcRegions) == 0 {
		return
	}

	// Sorted region order keeps any posture.Errors appended below
	// deterministic relative to each other.
	regions := make([]string, 0, len(vpcRegions))
	for region := range vpcRegions {
		regions = append(regions, region)
	}
	sort.Strings(regions)

	activeVPCIDs := map[string]bool{}
	coveredRegions := map[string]bool{}
	for _, region := range regions {
		records, err := describeFlowLogs(ctx, cfg.withRegion(region))
		if err != nil {
			if posture != nil {
				posture.Errors = append(posture.Errors, "ec2:DescribeFlowLogs "+region+": "+errSummary(err))
			}
			continue
		}
		coveredRegions[region] = true
		for id := range activeVPCFlowLogIDs(records) {
			activeVPCIDs[id] = true
		}
	}

	annotateVPCFlowLogs(resources, activeVPCIDs, coveredRegions)

	// gatherAccountPosture already sorted posture.Errors; re-sort so the
	// flow-log probe errors we appended interleave deterministically.
	if posture != nil {
		sort.Strings(posture.Errors)
	}
}

// flowLogRecord is the SDK-free projection of an ec2 FlowLog that the
// pure activeVPCFlowLogIDs reasons over, so its test needs no AWS mock.
type flowLogRecord struct {
	ResourceID string
	Status     string
}

// describeFlowLogs paginates ec2:DescribeFlowLogs for the region the cfg
// is pinned to and projects each flow log down to flowLogRecord.
func describeFlowLogs(ctx context.Context, cfg awsCfg) ([]flowLogRecord, error) {
	client := ec2.NewFromConfig(cfg.cfg)
	var out []flowLogRecord
	paginator := ec2.NewDescribeFlowLogsPaginator(client, &ec2.DescribeFlowLogsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fl := range page.FlowLogs {
			out = append(out, flowLogRecord{
				ResourceID: awssdk.ToString(fl.ResourceId),
				Status:     awssdk.ToString(fl.FlowLogStatus),
			})
		}
	}
	return out, nil
}

// activeVPCFlowLogIDs returns the set of VPC ids covered by at least one
// ACTIVE VPC-level flow log. Flow logs targeting subnets or ENIs
// (ResourceId not prefixed "vpc-") and flow logs that aren't ACTIVE
// (FlowLogStatus failed/inactive — same audit value as no flow log) are
// ignored. Pure: no SDK types, no IO.
func activeVPCFlowLogIDs(records []flowLogRecord) map[string]bool {
	out := map[string]bool{}
	for _, r := range records {
		if !strings.EqualFold(r.Status, "ACTIVE") {
			continue
		}
		if strings.HasPrefix(r.ResourceID, "vpc-") {
			out[r.ResourceID] = true
		}
	}
	return out
}

// annotateVPCFlowLogs writes cb_describer_flow_logs_enabled onto each
// discovered VPC: true when an ACTIVE flow log covers its id, false when
// its region was probed successfully but no flow log covers it, and
// unset otherwise (region not probed / probe failed → unknown, the LLM
// must not flag it). Pure: callers supply the probe results.
func annotateVPCFlowLogs(resources []DiscoveredResource, activeVPCIDs, coveredRegions map[string]bool) {
	for i := range resources {
		r := &resources[i]
		if r.Type != "AWS::EC2::VPC" {
			continue
		}
		if r.Inputs == nil {
			r.Inputs = map[string]any{}
		}
		id := r.ID
		if id == "" {
			id = stringInput(r.Inputs, "VpcId")
		}
		if id != "" && activeVPCIDs[id] {
			r.Inputs["cb_describer_flow_logs_enabled"] = true
			continue
		}
		// No covering flow log. Assert absence only when this VPC's
		// region was actually probed — otherwise leave the key unset.
		if coveredRegions[r.Region] {
			r.Inputs["cb_describer_flow_logs_enabled"] = false
		}
	}
}
