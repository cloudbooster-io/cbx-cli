package aws

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// listInstancesNative discovers EC2 instances via the strongly-consistent
// ec2:DescribeInstances API. It is wired as the FallbackLister for
// AWS::EC2::Instance: CloudControl's ListResources for this type returns
// an empty set (never an error) in every fixtures run — even kitchen-sink,
// which discovered RDS/ALB/Lambda — so a freshly-created bastion/host is
// silently dropped and every per-instance rule (IMDSv1, public exposure)
// goes dark. The native Describe surfaces the instance immediately.
//
// Terminated/shutting-down instances are filtered out: they carry no live
// security posture and would only add noise to the audit.
func listInstancesNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := ec2.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var nextToken *string
	for {
		out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			NextToken: nextToken,
			Filters: []ec2types.Filter{{
				Name:   ptr("instance-state-name"),
				Values: []string{"pending", "running", "stopping", "stopped"},
			}},
		})
		if err != nil {
			return nil, classifyEC2Error(err, "ec2:DescribeInstances", region)
		}
		for _, res := range out.Reservations {
			for _, inst := range res.Instances {
				if raw, ok := instanceToRaw(inst, region); ok {
					results = append(results, raw)
				}
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return results, nil
}

// instanceToRaw maps one SDK ec2types.Instance into a rawResource whose
// Properties JSON matches the CFN shape CloudControl would have returned
// for AWS::EC2::Instance — so ec2InstanceDescriber and crossReferenceNetwork
// read it verbatim. The shape is load-bearing and asymmetric with EBS:
//   - State is NESTED ({"Name": "running"}) — the instance describer reads
//     it via readNested(State, Name). (EC2::Volume, by contrast, returns a
//     flat State string — do not unify the two.)
//   - MetadataOptions.HttpTokens drives cb_describer_imdsv2_required.
//   - IamInstanceProfile is an object with Arn.
//   - PublicIpAddress and SubnetId are flat strings; SubnetId feeds the
//     subnet→route-table reachability walk (cb_describer_subnet_is_public).
//
// Pure (no SDK client) so the field reconstruction is unit-testable.
func instanceToRaw(inst ec2types.Instance, region string) (rawResource, bool) {
	if inst.InstanceId == nil || *inst.InstanceId == "" {
		return rawResource{}, false
	}
	id := *inst.InstanceId

	props := map[string]any{
		"InstanceId": id,
	}
	if inst.ImageId != nil {
		props["ImageId"] = *inst.ImageId
	}
	if inst.InstanceType != "" {
		props["InstanceType"] = string(inst.InstanceType)
	}
	if inst.KeyName != nil {
		props["KeyName"] = *inst.KeyName
	}
	if inst.SubnetId != nil {
		props["SubnetId"] = *inst.SubnetId
	}
	if inst.VpcId != nil {
		props["VpcId"] = *inst.VpcId
	}
	if inst.PublicIpAddress != nil {
		props["PublicIpAddress"] = *inst.PublicIpAddress
	}
	if inst.PrivateIpAddress != nil {
		props["PrivateIpAddress"] = *inst.PrivateIpAddress
	}
	// State is nested under {"Name": ...} to match CloudControl's CFN shape.
	if inst.State != nil && inst.State.Name != "" {
		props["State"] = map[string]any{"Name": string(inst.State.Name)}
	}
	// MetadataOptions.HttpTokens == "required" is the only IMDSv2-enforced
	// signal; anything else (incl. absent) means IMDSv1 is still accepted.
	if inst.MetadataOptions != nil && inst.MetadataOptions.HttpTokens != "" {
		props["MetadataOptions"] = map[string]any{
			"HttpTokens": string(inst.MetadataOptions.HttpTokens),
		}
	}
	if inst.IamInstanceProfile != nil && inst.IamInstanceProfile.Arn != nil {
		props["IamInstanceProfile"] = map[string]any{"Arn": *inst.IamInstanceProfile.Arn}
	}
	if len(inst.SecurityGroups) > 0 {
		ids := make([]any, 0, len(inst.SecurityGroups))
		for _, sg := range inst.SecurityGroups {
			if sg.GroupId != nil {
				ids = append(ids, *sg.GroupId)
			}
		}
		if len(ids) > 0 {
			props["SecurityGroupIds"] = ids
		}
	}
	if tags := ec2TagsToCFN(inst.Tags); tags != nil {
		props["Tags"] = tags
	}

	raw, err := json.Marshal(props)
	if err != nil {
		return rawResource{}, false
	}
	return rawResource{
		CFNType:    "AWS::EC2::Instance",
		Identifier: id,
		Region:     region,
		Properties: string(raw),
	}, true
}

// listVolumesNative discovers EBS volumes via ec2:DescribeVolumes, the
// strongly-consistent counterpart to CloudControl's unreliable
// AWS::EC2::Volume list. Wired as the FallbackLister for that type — the
// root/orphan-volume encryption findings depend on it.
func listVolumesNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := ec2.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var nextToken *string
	for {
		out, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, classifyEC2Error(err, "ec2:DescribeVolumes", region)
		}
		for _, v := range out.Volumes {
			if raw, ok := volumeToRaw(v, region); ok {
				results = append(results, raw)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return results, nil
}

// volumeToRaw maps one SDK ec2types.Volume into a rawResource matching the
// CFN shape ebsVolumeDescriber reads. NOTE the asymmetry with instances:
// here State is a FLAT string (the volume describer reads
// r.Inputs["State"].(string)), not the nested object instances use.
// Attachments is a list whose mere length is the cb_describer_is_attached
// signal.
func volumeToRaw(v ec2types.Volume, region string) (rawResource, bool) {
	if v.VolumeId == nil || *v.VolumeId == "" {
		return rawResource{}, false
	}
	id := *v.VolumeId

	props := map[string]any{
		"VolumeId": id,
		// Flat string to match CloudControl + ebsVolumeDescriber.
		"State": string(v.State),
	}
	if v.Encrypted != nil {
		props["Encrypted"] = *v.Encrypted
	}
	if v.KmsKeyId != nil {
		props["KmsKeyId"] = *v.KmsKeyId
	}
	if v.Size != nil {
		props["Size"] = *v.Size
	}
	if v.VolumeType != "" {
		props["VolumeType"] = string(v.VolumeType)
	}
	if v.AvailabilityZone != nil {
		props["AvailabilityZone"] = *v.AvailabilityZone
	}
	if len(v.Attachments) > 0 {
		atts := make([]any, 0, len(v.Attachments))
		for _, a := range v.Attachments {
			att := map[string]any{}
			if a.InstanceId != nil {
				att["InstanceId"] = *a.InstanceId
			}
			if a.Device != nil {
				att["Device"] = *a.Device
			}
			if a.State != "" {
				att["State"] = string(a.State)
			}
			atts = append(atts, att)
		}
		props["Attachments"] = atts
	}
	if tags := ec2TagsToCFN(v.Tags); tags != nil {
		props["Tags"] = tags
	}

	raw, err := json.Marshal(props)
	if err != nil {
		return rawResource{}, false
	}
	return rawResource{
		CFNType:    "AWS::EC2::Volume",
		Identifier: id,
		Region:     region,
		Properties: string(raw),
	}, true
}

// ec2TagsToCFN renders SDK ec2types.Tag values as the list-of-{Key,Value}
// objects extractTags() expects from CloudControl. Returns nil for the
// empty case so callers can omit the field entirely.
func ec2TagsToCFN(tags []ec2types.Tag) []map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(tags))
	for _, t := range tags {
		if t.Key == nil || t.Value == nil {
			continue
		}
		out = append(out, map[string]string{"Key": *t.Key, "Value": *t.Value})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
