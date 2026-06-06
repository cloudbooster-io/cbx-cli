package aws

import "testing"

// TestActiveVPCFlowLogIDs verifies only ACTIVE, VPC-level flow logs land
// in the set: subnet/ENI-scoped logs and non-ACTIVE (failed) logs are
// the same as no coverage for audit purposes.
func TestActiveVPCFlowLogIDs(t *testing.T) {
	records := []flowLogRecord{
		{ResourceID: "vpc-active", Status: "ACTIVE"},
		{ResourceID: "vpc-lower", Status: "active"},  // EqualFold
		{ResourceID: "vpc-failed", Status: "FAILED"}, // not active → excluded
		{ResourceID: "subnet-x", Status: "ACTIVE"},   // subnet-level → excluded
		{ResourceID: "eni-y", Status: "ACTIVE"},      // ENI-level → excluded
	}
	got := activeVPCFlowLogIDs(records)

	if !got["vpc-active"] || !got["vpc-lower"] {
		t.Errorf("expected vpc-active and vpc-lower in set, got %v", got)
	}
	for _, bad := range []string{"vpc-failed", "subnet-x", "eni-y"} {
		if got[bad] {
			t.Errorf("did not expect %q in active set", bad)
		}
	}
	if len(got) != 2 {
		t.Errorf("expected 2 covered VPCs, got %d: %v", len(got), got)
	}
}

// TestAnnotateVPCFlowLogs is the FP-safety contract: false is asserted
// ONLY for a VPC whose region was probed; an unprobed/failed region
// leaves the key unset so the LLM treats it as unknown, not absent.
func TestAnnotateVPCFlowLogs(t *testing.T) {
	resources := []DiscoveredResource{
		{ // covered VPC, has an active flow log → true
			Type: "AWS::EC2::VPC", URN: "urn:covered", ID: "vpc-covered", Region: "us-east-1",
			Inputs: map[string]any{},
		},
		{ // probed region, no flow log → false (real finding)
			Type: "AWS::EC2::VPC", URN: "urn:nolog", ID: "vpc-nolog", Region: "us-east-1",
			Inputs: map[string]any{},
		},
		{ // region NOT probed (probe failed) → key left unset
			Type: "AWS::EC2::VPC", URN: "urn:unknown", ID: "vpc-unknown", Region: "eu-west-1",
			Inputs: map[string]any{},
		},
		{ // id only in Inputs (r.ID empty) → still matched
			Type: "AWS::EC2::VPC", URN: "urn:byinput", ID: "", Region: "us-east-1",
			Inputs: map[string]any{"VpcId": "vpc-byinput"},
		},
		{ // non-VPC resource → untouched
			Type: "AWS::EC2::Subnet", URN: "urn:subnet", ID: "subnet-1", Region: "us-east-1",
			Inputs: map[string]any{},
		},
	}
	activeVPCIDs := map[string]bool{"vpc-covered": true, "vpc-byinput": true}
	coveredRegions := map[string]bool{"us-east-1": true}

	annotateVPCFlowLogs(resources, activeVPCIDs, coveredRegions)

	if v, ok := resources[0].Inputs["cb_describer_flow_logs_enabled"].(bool); !ok || !v {
		t.Errorf("covered VPC: want flow_logs_enabled=true, got %v (ok=%t)", resources[0].Inputs["cb_describer_flow_logs_enabled"], ok)
	}
	if v, ok := resources[1].Inputs["cb_describer_flow_logs_enabled"].(bool); !ok || v {
		t.Errorf("probed-no-log VPC: want flow_logs_enabled=false, got %v (ok=%t)", resources[1].Inputs["cb_describer_flow_logs_enabled"], ok)
	}
	if _, present := resources[2].Inputs["cb_describer_flow_logs_enabled"]; present {
		t.Errorf("unprobed-region VPC: want key unset, got %v", resources[2].Inputs["cb_describer_flow_logs_enabled"])
	}
	if v, ok := resources[3].Inputs["cb_describer_flow_logs_enabled"].(bool); !ok || !v {
		t.Errorf("by-input-id VPC: want flow_logs_enabled=true, got %v (ok=%t)", resources[3].Inputs["cb_describer_flow_logs_enabled"], ok)
	}
	if _, present := resources[4].Inputs["cb_describer_flow_logs_enabled"]; present {
		t.Errorf("non-VPC resource should be untouched, got %v", resources[4].Inputs["cb_describer_flow_logs_enabled"])
	}
}
