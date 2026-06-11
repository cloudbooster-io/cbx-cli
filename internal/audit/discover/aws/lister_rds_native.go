package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// listRDSInstancesNative is the FallbackLister for AWS::RDS::DBInstance.
// CloudControl discovered RDS in kitchen-sink but not in the RDS-targeted
// fixtures variant (07: PubliclyAccessible / unencrypted / backup-0 /
// single-AZ / no-deletion-protection all missed because the instance was
// absent from discovery) — the classic create-then-immediately-audit race.
// rds:DescribeDBInstances is strongly consistent.
func listRDSInstancesNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := rds.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var marker *string
	for {
		out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, classifyAWSError(err, "rds", "rds:DescribeDBInstances", region)
		}
		for _, inst := range out.DBInstances {
			if raw, ok := rdsInstanceToRaw(inst, region); ok {
				results = append(results, raw)
			}
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return results, nil
}

// rdsInstanceToRaw maps an SDK DBInstance into CloudControl's CFN shape so
// rdsInstanceDescriber (engine-split primitive + the cb_describer_* posture
// booleans) and crossReferenceNetwork (DBSubnetGroupName + PubliclyAccessible
// → cb_describer_effectively_public) read it verbatim. *bool / *int fields
// are set only when present, preserving the describer's "absent = unknown,
// not false" contract. Pure (no SDK client) for unit testing.
func rdsInstanceToRaw(inst rdstypes.DBInstance, region string) (rawResource, bool) {
	if inst.DBInstanceIdentifier == nil || *inst.DBInstanceIdentifier == "" {
		return rawResource{}, false
	}
	id := *inst.DBInstanceIdentifier

	props := map[string]any{"DBInstanceIdentifier": id}
	putStr(props, "DBInstanceArn", inst.DBInstanceArn)
	putStr(props, "Engine", inst.Engine)
	putStr(props, "EngineVersion", inst.EngineVersion)
	putStr(props, "KmsKeyId", inst.KmsKeyId)
	putBool(props, "MultiAZ", inst.MultiAZ)
	putBool(props, "StorageEncrypted", inst.StorageEncrypted)
	putBool(props, "PubliclyAccessible", inst.PubliclyAccessible)
	putBool(props, "DeletionProtection", inst.DeletionProtection)
	putBool(props, "AutoMinorVersionUpgrade", inst.AutoMinorVersionUpgrade)
	putInt32(props, "BackupRetentionPeriod", inst.BackupRetentionPeriod)
	if inst.DBSubnetGroup != nil {
		putStr(props, "DBSubnetGroupName", inst.DBSubnetGroup.DBSubnetGroupName)
	}
	if tags := rdsTagsToCFN(inst.TagList); tags != nil {
		props["Tags"] = tags
	}

	return marshalRaw("AWS::RDS::DBInstance", id, region, props)
}

// listRDSClustersNative is the FallbackLister for AWS::RDS::DBCluster
// (Aurora). Same race, same strongly-consistent fix.
func listRDSClustersNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := rds.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var marker *string
	for {
		out, err := client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			return nil, classifyAWSError(err, "rds", "rds:DescribeDBClusters", region)
		}
		for _, cl := range out.DBClusters {
			if raw, ok := rdsClusterToRaw(cl, region); ok {
				results = append(results, raw)
			}
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return results, nil
}

// rdsClusterToRaw mirrors rdsInstanceToRaw for DBCluster. Note DBCluster's
// DBSubnetGroup is a bare string (the group name), unlike DBInstance where
// it is a struct.
func rdsClusterToRaw(cl rdstypes.DBCluster, region string) (rawResource, bool) {
	if cl.DBClusterIdentifier == nil || *cl.DBClusterIdentifier == "" {
		return rawResource{}, false
	}
	id := *cl.DBClusterIdentifier

	props := map[string]any{"DBClusterIdentifier": id}
	putStr(props, "Engine", cl.Engine)
	putStr(props, "EngineVersion", cl.EngineVersion)
	putStr(props, "DBSubnetGroupName", cl.DBSubnetGroup)
	// KmsKeyId mirrors the instance path (rdsInstanceToRaw) — it is the CFN
	// property crossReferenceKMS walks (isKMSFieldName), so a customer CMK used
	// only as this cluster's storage-encryption key is counted as referenced
	// instead of being mis-flagged cb_describer_is_unused=true. Omitted on the
	// CC path is harmless (CC carries KmsKeyId itself); this fallback fired
	// because CC returned nothing, so it must carry the reference on its own.
	// putStr only sets it when present, so a non-encrypted cluster stays absent.
	putStr(props, "KmsKeyId", cl.KmsKeyId)
	putBool(props, "MultiAZ", cl.MultiAZ)
	putBool(props, "StorageEncrypted", cl.StorageEncrypted)
	putBool(props, "PubliclyAccessible", cl.PubliclyAccessible)
	putBool(props, "DeletionProtection", cl.DeletionProtection)
	putInt32(props, "BackupRetentionPeriod", cl.BackupRetentionPeriod)
	if tags := rdsTagsToCFN(cl.TagList); tags != nil {
		props["Tags"] = tags
	}

	return marshalRaw("AWS::RDS::DBCluster", id, region, props)
}

func rdsTagsToCFN(tags []rdstypes.Tag) []map[string]string {
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
