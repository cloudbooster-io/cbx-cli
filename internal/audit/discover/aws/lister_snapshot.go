package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/smithy-go"
)

// listOwnedSnapshots discovers EBS snapshots owned by the audited
// account via ec2:DescribeSnapshots(OwnerIds=["self"]) — bypassing
// CloudControl's AWS::EC2::Snapshot list, which is unreliable
// (returns tens of thousands of public AMI snapshots in some
// accounts, returns nothing in others).
//
// The output rawResource shape matches what CloudControl would have
// produced: Properties is a JSON object with the same field names
// (SnapshotId, VolumeId, State, StartTime, Encrypted, KmsKeyId,
// Description, OwnerId, VolumeSize), so the per-snapshot describer
// (which calls DescribeSnapshotAttribute for CreateVolumePermissions)
// runs verbatim. Tags are folded in too — CloudControl returned them
// as a list-of-{Key,Value}; we match that shape so extractTags works
// without special-casing.
func listOwnedSnapshots(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := ec2.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var nextToken *string
	for {
		out, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			OwnerIds:  []string{"self"},
			NextToken: nextToken,
		})
		if err != nil {
			return nil, classifyEC2Error(err, "ec2:DescribeSnapshots", region)
		}
		for _, s := range out.Snapshots {
			id := ""
			if s.SnapshotId != nil {
				id = *s.SnapshotId
			}
			if id == "" {
				continue
			}
			props := map[string]any{
				"SnapshotId": id,
				"State":      string(s.State),
			}
			if s.VolumeId != nil {
				props["VolumeId"] = *s.VolumeId
			}
			if s.VolumeSize != nil {
				props["VolumeSize"] = *s.VolumeSize
			}
			if s.Encrypted != nil {
				props["Encrypted"] = *s.Encrypted
			}
			if s.KmsKeyId != nil {
				props["KmsKeyId"] = *s.KmsKeyId
			}
			if s.Description != nil {
				props["Description"] = *s.Description
			}
			if s.OwnerId != nil {
				props["OwnerId"] = *s.OwnerId
			}
			if s.StartTime != nil {
				props["StartTime"] = s.StartTime.UTC().Format("2006-01-02T15:04:05Z")
			}
			if len(s.Tags) > 0 {
				tags := make([]map[string]string, 0, len(s.Tags))
				for _, t := range s.Tags {
					if t.Key == nil || t.Value == nil {
						continue
					}
					tags = append(tags, map[string]string{"Key": *t.Key, "Value": *t.Value})
				}
				props["Tags"] = tags
			}
			raw, err := json.Marshal(props)
			if err != nil {
				continue
			}
			results = append(results, rawResource{
				CFNType:    "AWS::EC2::Snapshot",
				Identifier: id,
				Region:     region,
				Properties: string(raw),
			})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return results, nil
}

// classifyEC2Error wraps AccessDenied / UnauthorizedOperation as
// *PermissionError so the --diagnose summary picks it up.
func classifyEC2Error(err error, action, region string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "UnauthorizedOperation", "AccessDenied", "AccessDeniedException":
			return &PermissionError{
				Service: "ec2",
				Action:  action,
				Region:  region,
				Cause:   err,
			}
		}
	}
	return fmt.Errorf("%s [%s]: %w", action, region, err)
}
