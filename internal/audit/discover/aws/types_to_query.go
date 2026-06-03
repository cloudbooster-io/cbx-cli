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
	{Type: "AWS::CloudFront::Distribution", Global: true},
	{Type: "AWS::Route53::HostedZone", Global: true},

	// --- regional storage ---
	{Type: "AWS::S3::Bucket"}, // S3 is regional but listable globally; treat as regional and dedupe by ARN
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
	{Type: "AWS::Lambda::Function"},
	{Type: "AWS::ECS::Cluster"},
	{Type: "AWS::ECS::Service", FallbackLister: listECSServicesNative},
	{Type: "AWS::ECS::TaskDefinition"},
	{Type: "AWS::AutoScaling::AutoScalingGroup"},
	{Type: "AWS::EKS::Cluster", FallbackLister: listEKSClustersNative},
	// ECR repositories are CloudControl-listable (fixtures-08 probe = 1) but
	// were absent from this set, so the scan-on-push / tag-mutability /
	// lifecycle findings on the discovered repo never surfaced. GetResource
	// returns ImageScanningConfiguration + ImageTagMutability inline.
	{Type: "AWS::ECR::Repository"},

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
	{Type: "AWS::ApiGatewayV2::Api"},
	{Type: "AWS::ApiGatewayV2::Stage"},
	{Type: "AWS::ApiGatewayV2::Route"},
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
	{Type: "AWS::DynamoDB::Table"},
	{Type: "AWS::ElastiCache::ReplicationGroup"},
	{Type: "AWS::ElastiCache::CacheCluster"},

	// --- regional backup / DR ---
	// AWS Backup vault + plan are CloudControl-listable (fixtures-09 probe =
	// 1 each) but were absent from this set, so the vault-lock / vault-CMK /
	// vault-access-policy / plan-secondary-region-copy findings never
	// surfaced. GetResource returns EncryptionKeyArn (vault) and the
	// rule/copyAction tree (plan) inline.
	{Type: "AWS::Backup::BackupVault"},
	{Type: "AWS::Backup::BackupPlan"},

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
	{Type: "AWS::SecretsManager::Secret"},
	// RotationSchedule is a sibling CFN resource — a secret with no
	// matching RotationSchedule entry has no rotation configured. The
	// LLM cross-references the two lists rather than us standing up a
	// separate describer just for rotation state.
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
	// under-returned AWS::IAM::ManagedPolicy. The load balancer and target
	// group themselves need no fallback: CloudControl lists them reliably.
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
