package aws

import (
	"context"
)

// Describer enriches a CloudControl-discovered resource with data that
// CloudControl doesn't expose. Each describer targets one CFN type via
// CFNType() and runs after mapToDiscovered (so it can mutate the
// already-populated Tags / Inputs maps in place).
//
// Describers exist for types where CB knowledge depth justifies the
// extra API surface — S3 bucket security state, IAM role last-used
// timestamps, etc. Types without a describer rely on CloudControl's
// data as-is, which is sufficient for the bulk of resources.
//
// Failures from Enrich are non-fatal: they collect into the same
// PermissionErr / OtherErrs streams the listAndGet path uses, so
// discovery continues with whatever fields CC already populated.
type Describer interface {
	CFNType() string
	Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error
}

// allDescribers is the registry of per-service describers. Order doesn't
// matter — describerFor finds the one matching a CFN type. Tests inject
// fakes by replacing this slice.
var allDescribers = []Describer{
	&s3BucketDescriber{},
	&iamRoleDescriber{},
	&iamUserDescriber{},
	&iamGroupDescriber{},
	&iamManagedPolicyDescriber{},
	&rdsInstanceDescriber{},
	&rdsClusterDescriber{},
	&lambdaFunctionDescriber{},
	&apiGatewayV2ApiDescriber{},
	&ec2InstanceDescriber{},
	&securityGroupDescriber{},
	&ebsVolumeDescriber{},
	&ebsSnapshotDescriber{},
	&eipDescriber{},
	&kmsKeyDescriber{},
	&ecrRepositoryDescriber{},
	&backupVaultDescriber{},
	&backupPlanDescriber{},
	&athenaWorkGroupDescriber{},
	&ecsClusterDescriber{},
	&ecsTaskDefinitionDescriber{},
	&albAccessLogsDescriber{},
	&eksClusterDescriber{},
}

// describerFor returns the Describer registered for cfnType, or nil if
// none. nil means "use CloudControl's data as-is."
func describerFor(cfnType string) Describer {
	for _, d := range allDescribers {
		if d.CFNType() == cfnType {
			return d
		}
	}
	return nil
}
