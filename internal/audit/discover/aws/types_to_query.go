package aws

import (
	"context"
	"strings"
)

// DiscoverableTypeCount returns the number of curated CFN types the
// discovery loop will probe. Exposed for `cbx audit aws --dry-run` so
// the CLI can show the plan without reaching into package internals.
func DiscoverableTypeCount() int { return len(discoverableCFNTypes) }

// discoverableCFNTypes is the set of CloudFormation type names the
// live-AWS discovery loop probes via CloudControl's List+Get. The goal
// is broad audit coverage, not CB-primitive coverage — the LLM can
// still reason about resources whose primitive isn't authored, because
// the prompt now ships full CFN Properties. Types absent from the CFN
// registry surface UnsupportedActionException at list time and are
// filtered out silently.
//
// Globally-scoped types (IAM, CloudFront, Route53) are marked Global so
// the per-region fan-out only lists them once.
//
// When adding a type, consider whether ListResources will return AWS-
// managed noise (IAM service-linked roles, AWS-managed policies) and
// add a KeepIdentifier filter if so.
var discoverableCFNTypes = []cfnTypeSpec{
	// --- global IAM ---
	{Type: "AWS::IAM::Role", Global: true, KeepIdentifier: keepCustomerIAMRole},
	// CloudControl's AWS::IAM::ManagedPolicy ListResources returns ALL
	// policies, including ~1,400 AWS-managed ones (arn:aws:iam::aws:policy/…).
	// Filter to customer-managed only. When CloudControl's list comes back
	// empty (observed: it under-returns customer policies even though IAM
	// is strongly consistent and permission_errors==0), fall back to the
	// authoritative iam:ListPolicies(Scope=Local).
	{Type: "AWS::IAM::ManagedPolicy", Global: true, KeepIdentifier: keepCustomerIAMPolicy, FallbackLister: listLocalManagedPoliciesNative},
	{Type: "AWS::IAM::User", Global: true},
	{Type: "AWS::IAM::Group", Global: true},

	// --- global CDN / DNS ---
	// CloudFront has NO describer — its findings are LLM-emitted straight off the
	// raw DistributionConfig — so a silent-empty CloudControl list drops the whole
	// distribution and every CloudFront finding with it (no describer re-fetches).
	// cloudfront:ListDistributions (+ GetDistributionConfig for Logging) is the
	// authoritative fallback-on-empty; the summary carries the WAF / cert-TLS /
	// origin-endpoint / viewer-protocol fields inline. See lister_cloudfront_native.go.
	{Type: "AWS::CloudFront::Distribution", Global: true, FallbackLister: listCloudFrontDistributionsNative},
	{Type: "AWS::Route53::HostedZone", Global: true},

	// --- regional storage ---
	// S3 is regional but listable globally; treat as regional and dedupe by ARN.
	// The fallback re-scopes ListBuckets to the audited region on a silent-empty
	// CloudControl list (fixtures-01 measured 2/9 from dropped buckets).
	{Type: "AWS::S3::Bucket", FallbackLister: listS3BucketsNative},
	// ec2:DescribeVolumes is the strongly-consistent fallback for
	// CloudControl's eventually-consistent (often empty) Volume list.
	{Type: "AWS::EC2::Volume", FallbackLister: listVolumesNative},
	// CloudControl's AWS::EC2::Snapshot ListResources is unreliable —
	// in some accounts it returns no results, in others it dumps tens
	// of thousands of public AMI snapshots and times out. We bypass
	// it entirely and call ec2:DescribeSnapshots(OwnerIds=["self"])
	// directly via listOwnedSnapshots, which returns only the
	// customer's snapshots and is the same API the AWS console uses.
	{Type: "AWS::EC2::Snapshot", CustomLister: listOwnedSnapshots},
	{Type: "AWS::EFS::FileSystem"},

	// --- regional compute ---
	// All four workload-instance types below get a native-Describe fallback:
	// CloudControl's audit-time list silently returns empty for them right
	// after create (the probe artifact is a separate call and doesn't reflect
	// this — see lister_native.go). The fallback fires only on empty, so it's
	// inert when CC works.
	{Type: "AWS::EC2::Instance", FallbackLister: listInstancesNative},
	{Type: "AWS::Lambda::Function", FallbackLister: listLambdaFunctionsNative},
	{Type: "AWS::ECS::Cluster"},
	{Type: "AWS::ECS::Service", FallbackLister: listECSServicesNative},
	// TaskDefinition is CloudControl-listable, but a live run dropped it from
	// the audit-time list (probe saw it, audit saw none) — so the privileged-
	// container / writable-rootfs / plaintext-env / no-log-driver findings went
	// dark. The fallback enumerates ACTIVE task defs, deduped to the latest
	// revision per family, via ecs:ListTaskDefinitions + DescribeTaskDefinition.
	{Type: "AWS::ECS::TaskDefinition", FallbackLister: listECSTaskDefinitionsNative},
	{Type: "AWS::AutoScaling::AutoScalingGroup"},
	{Type: "AWS::EKS::Cluster", FallbackLister: listEKSClustersNative},
	// ECR repositories are CloudControl-listable (fixtures-08 probe = 1) but
	// were absent from this set, so the scan-on-push / tag-mutability /
	// lifecycle findings on the discovered repo never surfaced. GetResource
	// returns ImageScanningConfiguration + ImageTagMutability inline. A live 09
	// run additionally showed the audit-time list silently empty for this type,
	// so ecr:DescribeRepositories is wired as the fallback-on-empty.
	{Type: "AWS::ECR::Repository", FallbackLister: listECRRepositoriesNative},

	// --- regional networking ---
	{Type: "AWS::EC2::VPC"},
	{Type: "AWS::EC2::Subnet"},
	{Type: "AWS::EC2::SecurityGroup"},
	{Type: "AWS::EC2::InternetGateway"},
	{Type: "AWS::EC2::NatGateway"},
	{Type: "AWS::EC2::EIP"},
	{Type: "AWS::EC2::RouteTable"},
	// SubnetRouteTableAssociation lets crossref_network resolve which
	// route table applies to a subnet. Without it the route-table walk
	// for "is this subnet internet-routable" defaults to MapPublicIpOnLaunch.
	{Type: "AWS::EC2::SubnetRouteTableAssociation"},
	{Type: "AWS::EC2::VPCEndpoint"},
	// The load balancer + target group themselves get NO fallback: CloudControl
	// lists them reliably (confirmed in a clean 08 run where the ALB findings
	// fired without one). The Listener is the exception — CloudControl returns
	// the LB but an empty listener list for a fresh ALB (07, 08), so it carries
	// the HTTP-only-listener finding only via the fallback. DescribeListeners
	// is per-LB, so the fallback enumerates load balancers first.
	{Type: "AWS::ElasticLoadBalancingV2::LoadBalancer"},
	{Type: "AWS::ElasticLoadBalancingV2::Listener", FallbackLister: listListenersNative},
	{Type: "AWS::ElasticLoadBalancingV2::TargetGroup"},

	// --- regional APIs ---
	{Type: "AWS::ApiGateway::RestApi"},
	{Type: "AWS::ApiGateway::Stage"},
	// AWS::ApiGatewayV2::Api was the last flaky-discovery type behind variant
	// 03's headline swing (3→7→8): CloudControl's audit-time list silently
	// returned empty for a freshly-created HTTP API the same way it did for
	// Lambda/DynamoDB. apigatewayv2:GetApis is the fallback-on-empty, so the
	// access-logging WARNING (apiGatewayV2ApiDescriber re-derives it via its own
	// GetStages call) survives the silent miss.
	{Type: "AWS::ApiGatewayV2::Api", FallbackLister: listAPIGatewayV2APIsNative},
	{Type: "AWS::ApiGatewayV2::Stage"},
	// Route + Integration are the two siblings the compound "unauthenticated API
	// + admin Lambda" CRITICAL rule reads — Route.AuthorizationType==NONE (no
	// authorizer) and Integration.IntegrationUri (the API→Lambda link). Both are
	// NESTED types CloudControl does not reliably enumerate from the parent-less
	// ListResources call (listAndGet sends only the TypeName, so without the
	// parent ApiId the list errors or comes back empty); Integration wasn't even
	// queried until now. Neither has a describer, so apigatewayv2:GetRoutes /
	// GetIntegrations (per-API, enumerated via GetApis) are wired as
	// fallback-on-empty, each self-carrying the finding-bearing field. See
	// lister_apigw_route_integration_native.go.
	{Type: "AWS::ApiGatewayV2::Route", FallbackLister: listAPIGatewayV2RoutesNative},
	{Type: "AWS::ApiGatewayV2::Integration", FallbackLister: listAPIGatewayV2IntegrationsNative},
	{Type: "AWS::ApiGatewayV2::Authorizer"},

	// --- regional data ---
	// RDS is the type whose silent CloudControl-empty miss was caught live
	// (09-backup-dr, 2026-06-03): probe saw the instance, the audit didn't,
	// rds-backup-retention went MISSED. rds:DescribeDB* is the fallback.
	{Type: "AWS::RDS::DBInstance", FallbackLister: listRDSInstancesNative},
	{Type: "AWS::RDS::DBCluster", FallbackLister: listRDSClustersNative},
	// DBSubnetGroup carries the SubnetIds we need to compute whether
	// an RDS instance with PubliclyAccessible=true is actually
	// reachable from the internet (any constituent subnet routable
	// via an IGW route).
	{Type: "AWS::RDS::DBSubnetGroup"},
	// DynamoDB::Table is CloudControl-listable and strongly consistent, but the
	// v2 clean-baseline sweep (2026-06-03) watched it silently vanish from the
	// audit-time list in variants 00 (−2 findings) and 03 (−3) — the same
	// non-deterministic CloudControl silent-empty defect, now on a type that
	// carries CB-curated findings (no-PITR, provisioned-capacity, AWS-owned-key
	// encryption, no-deletion-protection). dynamodb:ListTables + DescribeTable
	// (+ DescribeContinuousBackups for PITR) is the authoritative fallback-on-empty.
	{Type: "AWS::DynamoDB::Table", FallbackLister: listDynamoDBTablesNative},
	{Type: "AWS::ElastiCache::ReplicationGroup"},
	{Type: "AWS::ElastiCache::CacheCluster"},

	// --- regional backup / DR ---
	// AWS Backup vault + plan are CloudControl-listable (fixtures-09 probe =
	// 1 each) but were absent from this set, so the vault-lock / vault-CMK /
	// vault-access-policy / plan-secondary-region-copy findings never
	// surfaced. GetResource returns EncryptionKeyArn (vault) and the
	// rule/copyAction tree (plan) inline. A live run additionally showed the
	// audit-time list silently empty for both, so backup:ListBackupVaults /
	// ListBackupPlans are wired as fallback-on-empty. The absence-of-config
	// posture (AWS-managed key, no access policy, no cross-region copy) is
	// surfaced by backupVaultDescriber / backupPlanDescriber.
	{Type: "AWS::Backup::BackupVault", FallbackLister: listBackupVaultsNative},
	{Type: "AWS::Backup::BackupPlan", FallbackLister: listBackupPlansNative},

	// --- regional analytics / data-lake ---
	// Athena workgroups carry their full WorkGroupConfiguration through
	// CloudControl's read handler (EnforceWorkGroupConfiguration and
	// ResultConfiguration.EncryptionConfiguration are read-only-visible,
	// not write-only) — so the grounded analyzer can flag unenforced /
	// unencrypted workgroups straight from the discovered shape, no
	// describer needed. The Glue Data Catalog resource policy, by
	// contrast, has no CFN type and is fetched account-side via
	// glue:GetResourcePolicy (see account_posture.go).
	{Type: "AWS::Athena::WorkGroup"},

	// --- regional messaging ---
	{Type: "AWS::SQS::Queue"},
	{Type: "AWS::SNS::Topic"},
	{Type: "AWS::Events::Rule"},

	// --- regional auth ---
	{Type: "AWS::Cognito::UserPool"},

	// --- regional security ---
	{Type: "AWS::WAFv2::WebACL"},
	{Type: "AWS::CertificateManager::Certificate"},

	// --- regional ops / observability ---
	{Type: "AWS::Logs::LogGroup"},
	{Type: "AWS::CloudWatch::Alarm"},
	// CloudControl's audit-time list silently drops the secret right after
	// create (the same silent-empty miss the workload fallbacks cover, with
	// permission_errors=[]), taking the secret-no-rotation rule's only input
	// with it. secretsmanager:ListSecrets is the fallback-on-empty enumeration;
	// it carries RotationEnabled inline (CloudControl's Secret payload does not),
	// so a fallback-restored secret is self-describing for rotation and a rotated
	// one can't false-fire even with its RotationSchedule sibling absent. See
	// lister_secretsmanager_native.go.
	{Type: "AWS::SecretsManager::Secret", FallbackLister: listSecretsManagerSecretsNative},
	// RotationSchedule is a sibling CFN resource — for a CloudControl-listed
	// secret (whose payload omits RotationEnabled) the LLM cross-references the
	// two lists rather than us standing up a separate describer just for rotation
	// state. The ListSecrets fallback above makes its own restored secrets carry
	// RotationEnabled directly, so no RotationSchedule fallback is needed.
	{Type: "AWS::SecretsManager::RotationSchedule"},
	{Type: "AWS::KMS::Key"},
	// Aliases are a sibling CFN resource; cross-referenced by
	// crossReferenceKMS so a key's "is_unused" calculation can
	// resolve `alias/foo` references in other resources back to the
	// underlying key ARN.
	{Type: "AWS::KMS::Alias"},
	{Type: "AWS::CloudTrail::Trail"},
}

// cfnTypeSpec describes one type to list during discovery.
type cfnTypeSpec struct {
	Type   string // CFN type name, e.g. "AWS::S3::Bucket"
	Global bool   // true for IAM / CloudFront / Route53 / etc.

	// KeepIdentifier, if non-nil, is applied to each CloudControl
	// ListResources identifier before the GetResource call. Returning
	// false drops the identifier silently (no GetResource issued).
	// Used to filter AWS-managed noise from types where the CloudControl
	// list includes resources outside the customer's posture (IAM
	// managed policies, AWS service-linked roles).
	KeepIdentifier func(identifier string) bool

	// CustomLister, when non-nil, replaces the CloudControl
	// List+Get path entirely for this type. Used for types where
	// CloudControl is unreliable or returns the wrong set — e.g.
	// AWS::EC2::Snapshot, where CloudControl historically returned
	// too many results (or none) depending on the account's snapshot
	// share posture. The custom lister synthesises rawResource records
	// that flow through the same mapToDiscovered + describer path as
	// CloudControl-listed types, so downstream code is identical.
	CustomLister func(ctx context.Context, c awsCfg, region string) ([]rawResource, error)

	// FallbackLister, when non-nil, is invoked only when the primary
	// list path (CloudControl ListResources, or CustomLister) returns
	// an *empty* result set for this type in this region. It performs a
	// strongly-consistent native Describe and synthesises the same
	// CFN-shape rawResource records.
	//
	// This exists because CloudControl's ListResources silently under-returns
	// — it answers with an empty list, not an error, so discovery drops the
	// resource with permission_errors == 0. Wired for the workload-instance
	// types (EC2 instance/volume, RDS instance/cluster, ECS service, EKS
	// cluster) where the list is eventually consistent and comes back empty
	// right after create — proven live, not theoretical (see lister_native.go)
	// — plus the ELBv2 Listener of a fresh ALB and the persistently
	// under-returned AWS::IAM::ManagedPolicy. A live run additionally caught the
	// same silent-empty miss on strongly-consistent types that carry planted
	// findings — AWS::ECR::Repository, AWS::ECS::TaskDefinition,
	// AWS::Backup::BackupVault, AWS::Backup::BackupPlan, and AWS::DynamoDB::Table
	// — so each of those is wired too. The load balancer and target group
	// themselves need no fallback: CloudControl lists them reliably.
	//
	// Semantics are deliberately fallback-on-empty rather than full
	// replacement (the CustomLister model): when CloudControl *does*
	// list the type its richer CFN payload is used unchanged, so wiring a
	// FallbackLister can never regress a type CloudControl already
	// discovers. A partial-stale list (CloudControl returning older
	// resources but not the just-created one) won't trigger the fallback;
	// the observed failure mode is a fully empty list, which this covers.
	FallbackLister func(ctx context.Context, c awsCfg, region string) ([]rawResource, error)
}

// keepCustomerIAMPolicy returns false for AWS-managed policy ARNs
// (arn:aws:iam::aws:policy/…), true for customer-managed ones
// (arn:aws:iam::<account>:policy/…). AWS-managed policies aren't part
// of the customer's posture and listing them all (~1,400) blows the
// audit budget for no gain.
func keepCustomerIAMPolicy(identifier string) bool {
	return !strings.HasPrefix(identifier, "arn:aws:iam::aws:policy/") &&
		!strings.HasPrefix(identifier, "arn:aws-cn:iam::aws:policy/") &&
		!strings.HasPrefix(identifier, "arn:aws-us-gov:iam::aws:policy/")
}

// keepCustomerIAMRole filters out AWS service-linked roles, which the
// customer can neither modify nor delete and which clutter the role
// inventory (often dozens per account). CloudControl's primary
// identifier for AWS::IAM::Role is the RoleName, not the ARN, so we
// filter by the name prefix AWS uses for SLRs: AWSServiceRoleFor*.
// AWSReservedSSO_* roles (created by IAM Identity Center) are also
// AWS-managed and filtered for the same reason.
func keepCustomerIAMRole(identifier string) bool {
	return !strings.HasPrefix(identifier, "AWSServiceRoleFor") &&
		!strings.HasPrefix(identifier, "AWSReservedSSO_")
}

// fallbackGlobalRegion is the region used for Global types when the
// caller passed no concrete regions. AWS global services (IAM,
// CloudFront, Route53) are reachable from any region but the SDK still
// needs one set; us-east-1 is the canonical home for those services.
const fallbackGlobalRegion = "us-east-1"

// pickRegionForGlobal returns the region to use when listing a Global
// type. It prefers a region the user actually named so the UI doesn't
// show us-east-1 traffic when the user asked for eu-central-1 — global
// services route correctly through any region. Falls back to us-east-1
// when the caller has no regions (shouldn't happen in normal flows but
// kept defensively).
func pickRegionForGlobal(userRegions []string) string {
	if len(userRegions) > 0 {
		return userRegions[0]
	}
	return fallbackGlobalRegion
}
