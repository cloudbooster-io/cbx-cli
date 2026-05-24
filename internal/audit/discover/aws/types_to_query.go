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
	// Filter to customer-managed only.
	{Type: "AWS::IAM::ManagedPolicy", Global: true, KeepIdentifier: keepCustomerIAMPolicy},
	{Type: "AWS::IAM::User", Global: true},
	{Type: "AWS::IAM::Group", Global: true},

	// --- global CDN / DNS ---
	{Type: "AWS::CloudFront::Distribution", Global: true},
	{Type: "AWS::Route53::HostedZone", Global: true},

	// --- regional storage ---
	{Type: "AWS::S3::Bucket"}, // S3 is regional but listable globally; treat as regional and dedupe by ARN
	{Type: "AWS::EC2::Volume"},
	// CloudControl's AWS::EC2::Snapshot ListResources is unreliable —
	// in some accounts it returns no results, in others it dumps tens
	// of thousands of public AMI snapshots and times out. We bypass
	// it entirely and call ec2:DescribeSnapshots(OwnerIds=["self"])
	// directly via listOwnedSnapshots, which returns only the
	// customer's snapshots and is the same API the AWS console uses.
	{Type: "AWS::EC2::Snapshot", CustomLister: listOwnedSnapshots},
	{Type: "AWS::EFS::FileSystem"},

	// --- regional compute ---
	{Type: "AWS::EC2::Instance"},
	{Type: "AWS::Lambda::Function"},
	{Type: "AWS::ECS::Cluster"},
	{Type: "AWS::ECS::Service"},
	{Type: "AWS::ECS::TaskDefinition"},
	{Type: "AWS::AutoScaling::AutoScalingGroup"},
	{Type: "AWS::EKS::Cluster"},

	// --- regional networking ---
	{Type: "AWS::EC2::VPC"},
	{Type: "AWS::EC2::Subnet"},
	{Type: "AWS::EC2::SecurityGroup"},
	{Type: "AWS::EC2::InternetGateway"},
	{Type: "AWS::EC2::NatGateway"},
	{Type: "AWS::EC2::EIP"},
	{Type: "AWS::EC2::RouteTable"},
	{Type: "AWS::EC2::VPCEndpoint"},
	{Type: "AWS::ElasticLoadBalancingV2::LoadBalancer"},
	{Type: "AWS::ElasticLoadBalancingV2::Listener"},
	{Type: "AWS::ElasticLoadBalancingV2::TargetGroup"},

	// --- regional APIs ---
	{Type: "AWS::ApiGateway::RestApi"},
	{Type: "AWS::ApiGateway::Stage"},
	{Type: "AWS::ApiGatewayV2::Api"},
	{Type: "AWS::ApiGatewayV2::Stage"},
	{Type: "AWS::ApiGatewayV2::Route"},
	{Type: "AWS::ApiGatewayV2::Authorizer"},

	// --- regional data ---
	{Type: "AWS::RDS::DBInstance"},
	{Type: "AWS::RDS::DBCluster"},
	{Type: "AWS::DynamoDB::Table"},
	{Type: "AWS::ElastiCache::ReplicationGroup"},
	{Type: "AWS::ElastiCache::CacheCluster"},

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
