package aws

import (
	"context"
	"testing"
)

func TestEC2InstanceDescriber_IMDSv2Required(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::EC2::Instance",
		ID:   "i-abc",
		Inputs: map[string]any{
			"MetadataOptions": map[string]any{
				"HttpTokens":              "required",
				"HttpPutResponseHopLimit": float64(2),
			},
		},
	}
	if err := (ec2InstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if r.Inputs["cb_describer_imdsv2_required"] != true {
		t.Errorf("imdsv2_required = %v, want true", r.Inputs["cb_describer_imdsv2_required"])
	}
}

func TestEC2InstanceDescriber_IMDSv2OptionalReportsFalse(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::EC2::Instance",
		ID:   "i-imds-loose",
		Inputs: map[string]any{
			"MetadataOptions": map[string]any{
				"HttpTokens": "optional",
			},
		},
	}
	if err := (ec2InstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if r.Inputs["cb_describer_imdsv2_required"] != false {
		t.Errorf("imdsv2_required = %v, want false (instance still accepts IMDSv1)", r.Inputs["cb_describer_imdsv2_required"])
	}
}

func TestEC2InstanceDescriber_NoMetadataOptionsReportsFalse(t *testing.T) {
	r := DiscoveredResource{Type: "AWS::EC2::Instance", ID: "i-default", Inputs: map[string]any{}}
	if err := (ec2InstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if r.Inputs["cb_describer_imdsv2_required"] != false {
		t.Errorf("missing MetadataOptions must report imdsv2_required=false")
	}
}

func TestEC2InstanceDescriber_InstanceProfileArn(t *testing.T) {
	cases := []struct {
		name   string
		input  any
		expect string
	}{
		{"object shape", map[string]any{"Arn": "arn:aws:iam::123:instance-profile/foo"}, "arn:aws:iam::123:instance-profile/foo"},
		{"bare string", "arn:aws:iam::123:instance-profile/bar", "arn:aws:iam::123:instance-profile/bar"},
		{"absent", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DiscoveredResource{Type: "AWS::EC2::Instance", ID: "i", Inputs: map[string]any{}}
			if tc.input != nil {
				r.Inputs["IamInstanceProfile"] = tc.input
			}
			_ = (ec2InstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &r)
			if r.Inputs["cb_describer_instance_profile_arn"] != tc.expect {
				t.Errorf("got %v, want %v", r.Inputs["cb_describer_instance_profile_arn"], tc.expect)
			}
		})
	}
}

func TestEC2InstanceDescriber_PublicIPAndState(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::EC2::Instance",
		ID:   "i-public",
		Inputs: map[string]any{
			"State":           map[string]any{"Name": "running"},
			"PublicIpAddress": "54.10.10.10",
		},
	}
	_ = (ec2InstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &r)
	if r.Inputs["cb_describer_state"] != "running" {
		t.Errorf("state = %v", r.Inputs["cb_describer_state"])
	}
	if r.Inputs["cb_describer_public_ip_present"] != true {
		t.Errorf("public_ip_present = %v, want true", r.Inputs["cb_describer_public_ip_present"])
	}
}
