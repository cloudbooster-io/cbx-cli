package aws

import (
	"context"
	"errors"
	"strings"

	backup "github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

// The two Backup describers surface posture that CloudControl's GetResource
// can't carry, and that the fallback listers (lister_backup_native.go)
// deliberately leave out so the Get* call happens exactly once, here.
//
// Every hint is an *absence-of-config* signal, which carries a false-positive
// risk the curated findings care about: "not configured" is sometimes a
// perfectly valid posture (a vault with no resource-based access policy; a
// single-region plan with no cross-region copy). So each hint is gated to fire
// only on an AUTHORITATIVE negative — never on a read we couldn't make:
//
//   - We assert false ONLY when AWS explicitly says the thing is absent
//     (CUSTOMER vs AWS_OWNED key type from DescribeBackupVault; a
//     ResourceNotFoundException / empty document from GetBackupVaultAccessPolicy;
//     zero cross-region copy actions from a successful GetBackupPlan).
//   - On a permission/throttle error the hint is left ABSENT, so the grounded
//     LLM is never told "no policy" / "AWS-managed key" on a failed read.
//
// That keeps the hints informative inputs to the finding (vault-aws-managed-key,
// vault-no-access-policy, plan-no-secondary-region-copy) rather than false
// alarms — the knowledge layer decides severity; we only report the fact, and
// only when we're sure of it.

// --- pure gating helpers (unit-tested in describer_backup_test.go) ---------

// backupKeyIsAwsManaged classifies a vault's EncryptionKeyType. `known` is
// false for an empty/unrecognised enum value, in which case the caller MUST
// leave the hint absent — asserting "AWS-managed" on an unknown type would be
// the false positive we're guarding against.
func backupKeyIsAwsManaged(t backuptypes.EncryptionKeyType) (isAwsManaged, known bool) {
	switch t {
	case backuptypes.EncryptionKeyTypeAwsOwnedKmsKey:
		return true, true
	case backuptypes.EncryptionKeyTypeCustomerManagedKmsKey:
		return false, true
	default:
		return false, false
	}
}

// backupPlanHasCrossRegionCopy reports whether any rule's copy action targets a
// vault in a region other than the plan's own. A same-region copy (DR within
// one region) does NOT count — the finding is specifically about a *secondary
// region* copy. An empty destVaultArns (no copy actions at all) returns false,
// which is the planted "no cross-region copy" posture. planRegion=="" can't be
// adjudicated, so it conservatively returns false (no false alarm).
func backupPlanHasCrossRegionCopy(planRegion string, destVaultArns []string) bool {
	if planRegion == "" {
		return false
	}
	for _, arn := range destVaultArns {
		rg := regionFromARN(arn)
		if rg != "" && !strings.EqualFold(rg, planRegion) {
			return true
		}
	}
	return false
}

// regionFromARN extracts the region field (the 4th colon-delimited segment)
// from an ARN: arn:partition:service:region:account-id:resource. Returns "" for
// a malformed ARN. Pure.
func regionFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}

// isBackupResourceNotFound reports whether err is the typed
// ResourceNotFoundException AWS Backup returns for a vault that has no
// resource-based access policy attached — the authoritative "no policy" signal.
func isBackupResourceNotFound(err error) bool {
	var nf *backuptypes.ResourceNotFoundException
	return errors.As(err, &nf)
}

// --- backup vault describer ------------------------------------------------

// backupVaultDescriber surfaces two absence hints CloudControl omits:
// cb_describer_vault_uses_aws_managed_key (vault-aws-managed-key) and
// cb_describer_vault_access_policy_present (vault-no-access-policy).
type backupVaultDescriber struct{}

func (backupVaultDescriber) CFNType() string { return "AWS::Backup::BackupVault" }

func (backupVaultDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	name, _ := r.Inputs["BackupVaultName"].(string)
	if name == "" {
		name = r.ID // CloudControl's primary identifier for this type is BackupVaultName.
	}
	if name == "" {
		return nil
	}
	if r.Region != "" {
		c = c.withRegion(r.Region)
	}
	client := backup.NewFromConfig(c.cfg)

	// The two probes are independent — a denied DescribeBackupVault must not
	// skip the access-policy read. Run both, join the errors.
	var errs []error

	// (1) AWS-managed-key: DescribeBackupVault returns EncryptionKeyType
	// (AWS_OWNED_KMS_KEY vs CUSTOMER_MANAGED_KMS_KEY) authoritatively — no KMS
	// resolution needed, and FP-safe via the `known` guard.
	dv, err := client.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{BackupVaultName: &name})
	if err != nil {
		errs = append(errs, classifyAWSError(err, "backup", "backup:DescribeBackupVault", r.Region))
	} else if isAws, known := backupKeyIsAwsManaged(dv.EncryptionKeyType); known {
		r.Inputs["cb_describer_vault_uses_aws_managed_key"] = isAws
	}

	// (2) Access policy: a vault with NO resource-based policy is valid and
	// common, so this is informational. GetBackupVaultAccessPolicy throws
	// ResourceNotFoundException when none is attached; some paths instead
	// return success with an empty document. Treat both as "absent".
	ap, err := client.GetBackupVaultAccessPolicy(ctx, &backup.GetBackupVaultAccessPolicyInput{BackupVaultName: &name})
	switch {
	case err == nil:
		present := ap != nil && ap.Policy != nil && *ap.Policy != ""
		r.Inputs["cb_describer_vault_access_policy_present"] = present
	case isBackupResourceNotFound(err):
		r.Inputs["cb_describer_vault_access_policy_present"] = false
	default:
		// Permission/throttle: leave the hint absent rather than claim "no
		// policy" on a read we couldn't make.
		errs = append(errs, classifyAWSError(err, "backup", "backup:GetBackupVaultAccessPolicy", r.Region))
	}

	return errors.Join(errs...)
}

// --- backup plan describer -------------------------------------------------

// backupPlanDescriber surfaces cb_describer_cross_region_copy_present
// (plan-no-secondary-region-copy) and, since the fallback lister keeps the plan
// resource identity-only, a compact rule summary (cb_describer_backup_rules) so
// a fallback-discovered plan isn't bare in the prompt.
type backupPlanDescriber struct{}

func (backupPlanDescriber) CFNType() string { return "AWS::Backup::BackupPlan" }

func (backupPlanDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	planID, _ := r.Inputs["BackupPlanId"].(string)
	if planID == "" {
		planID = r.ID // CloudControl's primary identifier for this type is BackupPlanId.
	}
	if planID == "" {
		return nil
	}
	if r.Region != "" {
		c = c.withRegion(r.Region)
	}
	client := backup.NewFromConfig(c.cfg)

	out, err := client.GetBackupPlan(ctx, &backup.GetBackupPlanInput{BackupPlanId: &planID})
	if err != nil {
		// Leave the hint absent: don't assert "no cross-region copy" on a read
		// we couldn't make.
		return classifyAWSError(err, "backup", "backup:GetBackupPlan", r.Region)
	}
	if out.BackupPlan == nil {
		return nil
	}

	var destArns []string
	rules := make([]any, 0, len(out.BackupPlan.Rules))
	for _, rule := range out.BackupPlan.Rules {
		rm := map[string]any{}
		putStr(rm, "RuleName", rule.RuleName)
		putStr(rm, "TargetBackupVault", rule.TargetBackupVaultName)
		putStr(rm, "ScheduleExpression", rule.ScheduleExpression)
		var dests []any
		for _, ca := range rule.CopyActions {
			if ca.DestinationBackupVaultArn != nil && *ca.DestinationBackupVaultArn != "" {
				destArns = append(destArns, *ca.DestinationBackupVaultArn)
				dests = append(dests, *ca.DestinationBackupVaultArn)
			}
		}
		if len(dests) > 0 {
			rm["CopyActionDestinations"] = dests
		}
		rules = append(rules, rm)
	}
	r.Inputs["cb_describer_backup_rules"] = rules
	r.Inputs["cb_describer_cross_region_copy_present"] = backupPlanHasCrossRegionCopy(r.Region, destArns)
	return nil
}
