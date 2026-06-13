package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// ebsSnapshotDescriber enriches AWS::EC2::Snapshot with the data that
// makes the difference between "a snapshot exists" and "this snapshot
// is publicly copyable" — CreateVolumePermission. CloudControl returns
// the snapshot's metadata but not its createVolumePermission attribute,
// which is the load-bearing field for the most common snapshot finding
// (snapshot shared with `group=all` is a data-exfiltration vector).
//
// One ec2:DescribeSnapshotAttribute call per snapshot. AccessDenied
// surfaces as a PermissionError so the --diagnose summary lists the
// missing IAM permission instead of silently hiding the field.
type ebsSnapshotDescriber struct{}

func (ebsSnapshotDescriber) CFNType() string { return "AWS::EC2::Snapshot" }

func (ebsSnapshotDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	snapshotID := r.ID
	if snapshotID == "" {
		return fmt.Errorf("ebs snapshot describer: empty snapshot id")
	}

	client := ec2.NewFromConfig(c.cfg)
	out, err := client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
		Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
		SnapshotId: aws.String(snapshotID),
	})
	if err != nil {
		return classifyEC2SnapshotError(err, snapshotID)
	}

	perms := make([]map[string]any, 0, len(out.CreateVolumePermissions))
	publiclyShared := false
	for _, p := range out.CreateVolumePermissions {
		entry := map[string]any{}
		if p.Group != "" {
			entry["group"] = string(p.Group)
			// "all" is the AWS value for "everyone with an AWS account
			// can copy this snapshot". The single most critical
			// snapshot finding.
			if p.Group == ec2types.PermissionGroupAll {
				publiclyShared = true
			}
		}
		if p.UserId != nil && *p.UserId != "" {
			entry["user_id"] = *p.UserId
		}
		if len(entry) > 0 {
			perms = append(perms, entry)
		}
	}
	r.Inputs["cb_describer_create_volume_permissions"] = perms
	r.Inputs["cb_describer_publicly_shared"] = publiclyShared
	return nil
}

func classifyEC2SnapshotError(err error, snapshotID string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "UnauthorizedOperation", "AccessDenied", "AccessDeniedException":
			return &PermissionError{
				Service: "ec2",
				Action:  "ec2:DescribeSnapshotAttribute",
				Cause:   fmt.Errorf("on snapshot %s: %w", snapshotID, err),
			}
		case "InvalidSnapshot.NotFound":
			// Race: CC listed it, snapshot deleted between list+describe.
			return nil
		}
	}
	return fmt.Errorf("ec2:DescribeSnapshotAttribute on %s: %w", snapshotID, err)
}
