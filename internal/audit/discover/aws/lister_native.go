package aws

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/smithy-go"
)

// The native fallback listers in this package (lister_ec2_native.go,
// lister_rds_native.go, lister_ecs_native.go, lister_ecr_native.go,
// lister_eks_native.go, lister_elb_native.go, lister_iam_native.go,
// lister_backup_native.go, lister_dynamodb_native.go) exist because
// CloudControl's ListResources silently under-returns: it answers with an empty
// set — not an error — so discovery drops the resource with permission_errors
// staying 0. Two distinct failure modes:
//
//   - Eventual consistency on freshly-created workload resources — EC2
//     instances/volumes, RDS instances/clusters, ECS services, EKS clusters,
//     and the ELBv2 Listener of a fresh ALB. An audit run right after
//     `terraform apply` is exactly when this bites. PROVEN, not theoretical:
//     2026-06-03 a live 09-backup-dr run dropped the RDS instance entirely
//     (absent from components, permission_errors=[], instance `available`)
//     once this fallback was removed — rds-backup-retention flipped
//     CAUGHT→MISSED. NOTE: the docs/audit-runs discovery-probe.json artifact
//     is a *separate* direct CloudControl call and does NOT reflect cbx's
//     audit-time list, so "the probe shows the type" never proved the audit
//     discovered it — the fallback was silently doing the work.
//   - Persistent under-return on AWS::IAM::ManagedPolicy — CloudControl
//     returns an incomplete customer-managed-policy set even though IAM is
//     strongly consistent; iam:ListPolicies(Scope=Local) is authoritative.
//   - Flaky silent-empty on strongly-consistent types that nonetheless carry
//     planted findings — a live run watched AWS::ECR::Repository,
//     AWS::ECS::TaskDefinition, AWS::Backup::BackupVault and
//     AWS::Backup::BackupPlan each come back empty from the audit-time list
//     while the probe saw count=1, and the v2 clean-baseline sweep caught
//     AWS::DynamoDB::Table dropping the same way across two variants. These
//     aren't eventual-consistency races (the resources were minutes old), but
//     the failure mode and fix are identical: a strongly-consistent native
//     Describe wired fallback-on-empty.
//
// Each fallback calls the service's native API and synthesises the same
// CFN-shape rawResource records, so the resource flows through
// mapToDiscovered + the existing describers unchanged. They are wired via
// cfnTypeSpec.FallbackLister and fire only when the primary (CloudControl)
// path returned nothing — inert and zero-cost whenever CloudControl does list
// the type, so a fallback can never regress a type CC already discovers. No
// fallback is wired for the load balancer or target group themselves:
// CloudControl lists those reliably (confirmed in a clean 08 run where the
// ALB findings fired with the LoadBalancer/TargetGroup fallbacks absent).

// classifyAWSError wraps AccessDenied / UnauthorizedOperation failures from
// the native Describe APIs as *PermissionError so the --diagnose summary
// collects them uniformly with the CloudControl path. Other errors pass
// through annotated with the service action and region.
func classifyAWSError(err error, service, action, region string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			return &PermissionError{
				Service: service,
				Action:  action,
				Region:  region,
				Cause:   err,
			}
		}
	}
	return fmt.Errorf("%s [%s]: %w", action, region, err)
}

// putStr / putBool / putInt32 set the CFN property only when the SDK pointer
// is non-nil (and, for strings, non-empty), so an unread field stays absent —
// the describers distinguish "false" / "" from "not read". Shared by every
// native lister.
func putStr(m map[string]any, key string, v *string) {
	if v != nil && *v != "" {
		m[key] = *v
	}
}

func putBool(m map[string]any, key string, v *bool) {
	if v != nil {
		m[key] = *v
	}
}

func putInt32(m map[string]any, key string, v *int32) {
	if v != nil {
		m[key] = *v
	}
}

func putInt64(m map[string]any, key string, v *int64) {
	if v != nil {
		m[key] = *v
	}
}

// marshalRaw JSON-encodes the props into the rawResource the rest of the
// discovery pipeline consumes (mapToDiscovered + describers).
func marshalRaw(cfnType, id, region string, props map[string]any) (rawResource, bool) {
	raw, err := json.Marshal(props)
	if err != nil {
		return rawResource{}, false
	}
	return rawResource{
		CFNType:    cfnType,
		Identifier: id,
		Region:     region,
		Properties: string(raw),
	}, true
}
