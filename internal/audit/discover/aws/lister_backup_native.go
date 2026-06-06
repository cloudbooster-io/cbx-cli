package aws

import (
	"context"

	backup "github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

// listBackupVaultsNative is the FallbackLister for AWS::Backup::BackupVault.
// The type is CloudControl-listable (fixtures-09 probe = 1), but a live run
// showed the audit-time list silently empty for it — the same flaky-empty
// CloudControl miss ECR and the TaskDefinition hit, so the vault-lock /
// AWS-managed-key / missing-access-policy findings went dark with
// permission_errors=[]. backup:ListBackupVaults is the authoritative
// enumeration and only fires when CloudControl returned nothing.
//
// ListBackupVaults already returns the vault-lock posture fields inline
// (Locked, Min/MaxRetentionDays) plus EncryptionKeyArn, so the synthesised
// resource is as rich as a CloudControl-listed one. backupVaultDescriber then
// resolves the AWS-managed-key and access-policy hints over it unchanged.
func listBackupVaultsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := backup.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var next *string
	for {
		out, err := client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{NextToken: next})
		if err != nil {
			return nil, classifyAWSError(err, "backup", "backup:ListBackupVaults", region)
		}
		for _, v := range out.BackupVaultList {
			if raw, ok := backupVaultToRaw(v, region); ok {
				results = append(results, raw)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	return results, nil
}

// backupVaultToRaw maps an SDK BackupVaultListMember into the CFN shape.
// BackupVaultName is the identifier (CloudControl's primary id for this type).
// Locked / Min / MaxRetentionDays carry the vault-lock posture; EncryptionKeyArn
// the encryption posture. Pure (no SDK client) for unit testing.
func backupVaultToRaw(v backuptypes.BackupVaultListMember, region string) (rawResource, bool) {
	if v.BackupVaultName == nil || *v.BackupVaultName == "" {
		return rawResource{}, false
	}
	id := *v.BackupVaultName

	props := map[string]any{"BackupVaultName": id}
	putStr(props, "BackupVaultArn", v.BackupVaultArn)
	putStr(props, "EncryptionKeyArn", v.EncryptionKeyArn)
	putBool(props, "Locked", v.Locked)
	putInt64(props, "MinRetentionDays", v.MinRetentionDays)
	putInt64(props, "MaxRetentionDays", v.MaxRetentionDays)

	return marshalRaw("AWS::Backup::BackupVault", id, region, props)
}

// listBackupPlansNative is the FallbackLister for AWS::Backup::BackupPlan.
// Same flaky-empty CloudControl miss as the vault. backup:ListBackupPlans is
// the authoritative enumeration.
//
// The lister synthesises only the plan's identity (Arn / Id / Name) — the
// rule tree and the cross-region-copy hint are owned by backupPlanDescriber,
// which calls backup:GetBackupPlan once (avoiding a redundant Get here). The
// describer is the sole source of the rule summary the LLM sees for a
// fallback-discovered plan, so it must populate it even when CloudControl
// supplied nothing.
func listBackupPlansNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := backup.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var next *string
	for {
		out, err := client.ListBackupPlans(ctx, &backup.ListBackupPlansInput{NextToken: next})
		if err != nil {
			return nil, classifyAWSError(err, "backup", "backup:ListBackupPlans", region)
		}
		for _, p := range out.BackupPlansList {
			if raw, ok := backupPlanToRaw(p, region); ok {
				results = append(results, raw)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	return results, nil
}

// backupPlanToRaw maps an SDK BackupPlansListMember into the CFN shape.
// BackupPlanId is the identifier (CloudControl's primary id for this type),
// which backupPlanDescriber feeds to GetBackupPlan. Pure for unit testing.
func backupPlanToRaw(p backuptypes.BackupPlansListMember, region string) (rawResource, bool) {
	if p.BackupPlanId == nil || *p.BackupPlanId == "" {
		return rawResource{}, false
	}
	id := *p.BackupPlanId

	props := map[string]any{"BackupPlanId": id}
	putStr(props, "BackupPlanArn", p.BackupPlanArn)
	putStr(props, "BackupPlanName", p.BackupPlanName)

	return marshalRaw("AWS::Backup::BackupPlan", id, region, props)
}
