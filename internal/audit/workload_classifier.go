package audit

import (
	"sort"
)

// CB-authored workload slugs. Only these slugs hit pattern-tagged chunks
// in /v1/knowledge/aws/practices; anything else falls through to the
// undifferentiated catalog, which is signal-poor.
// Defined as constants so the classifier output and the prompt copy stay in
// lock-step.
const (
	workloadAPIWithAuth     = "api-with-auth"
	workloadEventPipeline   = "event-pipeline"
	workloadHTTPApp         = "http-app"
	workloadMultiTierWebApp = "multi-tier-web-app"
	workloadNetworkBaseline = "network-baseline"
	workloadQueueWorker     = "queue-worker"
	workloadScheduledJob    = "scheduled-job"
	workloadSecureS3Bucket  = "secure-s3-bucket"
	workloadStaticSite      = "static-site"
	workloadWorker          = "worker"
)

// AuthoredWorkloadSlugs is the immutable set of CB-authored workload slugs.
// Exported so tests can assert the classifier never emits a slug outside the
// curated set.
var AuthoredWorkloadSlugs = map[string]struct{}{
	workloadAPIWithAuth:     {},
	workloadEventPipeline:   {},
	workloadHTTPApp:         {},
	workloadMultiTierWebApp: {},
	workloadNetworkBaseline: {},
	workloadQueueWorker:     {},
	workloadScheduledJob:    {},
	workloadSecureS3Bucket:  {},
	workloadStaticSite:      {},
	workloadWorker:          {},
}

// cfnTypeToTFEquivalent canonicalises the CloudFormation type names
// `cbx audit aws` discovery emits to the Terraform names the classifier
// branches are written against. Only the subset of types the heuristics
// actually consult is enumerated — adding a new TF type to a branch
// below means adding its CFN counterpart here too. Discovery types that
// never appear in a branch (e.g. AWS::KMS::Key, AWS::SecretsManager::Secret)
// are deliberately omitted because translating them buys nothing.
//
// One subtlety: aws_rds_cluster_instance has no separate CFN type. The
// CFN cluster model treats AWS::RDS::DBInstance as the only shape, with
// DBClusterIdentifier wired to a sibling AWS::RDS::DBCluster. We don't
// double-map AWS::RDS::DBInstance to the cluster-instance TF name; the
// dbTier branch hasAny()'s both aws_db_instance and aws_rds_cluster
// already, so the simpler mapping is sufficient.
var cfnTypeToTFEquivalent = map[string]string{
	"AWS::S3::Bucket":                                 "aws_s3_bucket",
	"AWS::CloudFront::Distribution":                   "aws_cloudfront_distribution",
	"AWS::CloudFront::OriginAccessControl":            "aws_cloudfront_origin_access_control",
	"AWS::CloudFront::CloudFrontOriginAccessIdentity": "aws_cloudfront_origin_access_identity",
	"AWS::ApiGateway::RestApi":                        "aws_api_gateway_rest_api",
	"AWS::ApiGateway::Stage":                          "aws_api_gateway_stage",
	"AWS::ApiGatewayV2::Api":                          "aws_apigatewayv2_api",
	"AWS::ApiGatewayV2::Stage":                        "aws_apigatewayv2_stage",
	"AWS::ApiGateway::Authorizer":                     "aws_api_gateway_authorizer",
	"AWS::ApiGatewayV2::Authorizer":                   "aws_apigatewayv2_authorizer",
	"AWS::Lambda::Function":                           "aws_lambda_function",
	"AWS::Cognito::UserPool":                          "aws_cognito_user_pool",
	// ALB and NLB share AWS::ElasticLoadBalancingV2::LoadBalancer; the
	// classifier's `lb` predicate only needs ANY load balancer, not a
	// type split, so mapping to the canonical aws_lb is sufficient.
	"AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
	"AWS::ECS::Service":                         "aws_ecs_service",
	"AWS::ECS::Cluster":                         "aws_ecs_cluster",
	"AWS::AutoScaling::AutoScalingGroup":        "aws_autoscaling_group",
	"AWS::EC2::Instance":                        "aws_instance",
	"AWS::RDS::DBInstance":                      "aws_db_instance",
	"AWS::RDS::DBCluster":                       "aws_rds_cluster",
	"AWS::DynamoDB::Table":                      "aws_dynamodb_table",
	"AWS::ElastiCache::CacheCluster":            "aws_elasticache_cluster",
	"AWS::ElastiCache::ReplicationGroup":        "aws_elasticache_replication_group",
	"AWS::SQS::Queue":                           "aws_sqs_queue",
	"AWS::Events::Rule":                         "aws_cloudwatch_event_rule",
	"AWS::Scheduler::Schedule":                  "aws_scheduler_schedule",
	"AWS::Kinesis::Stream":                      "aws_kinesis_stream",
	"AWS::KinesisFirehose::DeliveryStream":      "aws_kinesis_firehose_delivery_stream",
	"AWS::MSK::Cluster":                         "aws_msk_cluster",
	"AWS::EC2::VPC":                             "aws_vpc",
	"AWS::EC2::Subnet":                          "aws_subnet",
	"AWS::EC2::SecurityGroup":                   "aws_security_group",
	"AWS::EC2::RouteTable":                      "aws_route_table",
	"AWS::EC2::InternetGateway":                 "aws_internet_gateway",
	"AWS::EC2::NatGateway":                      "aws_nat_gateway",
	"AWS::EC2::SubnetRouteTableAssociation":     "aws_route_table_association",
}

// ClassifyWorkloads infers which CB workload slugs the discovered resource
// set looks like. Returns a deduplicated, alphabetically-stable slice of
// only the 10 CB-authored slugs — unmapped detections (e.g. an EC2-only tree
// with no signal) yield an empty slice rather than passing through to the
// undifferentiated `aws_best_practices_for` catalog.
//
// Heuristics are intentionally generous: an audit tree may match multiple
// workloads (a webapp with a queue, a static site with an auth flow) and
// the analyzer queries all of them so the prompt primer covers the full
// posture. Cost is bounded by the slug count (≤10), not by resource count.
//
// Input resources can be Terraform- or CFN-shaped — `cbx audit aws` emits
// the latter via CloudControl. Both shapes are canonicalised to the
// Terraform form via cfnTypeToTFEquivalent before the branches run, so
// the heuristic literals stay readable in one shape rather than each
// branch hasAny()'ing both variants. CFN types absent from the
// translation map don't break anything — they just don't trip any
// branch, which is the safe degraded path.
func ClassifyWorkloads(resources []DiscoveredResource) []string {
	if len(resources) == 0 {
		return nil
	}

	tfTypes := map[string]int{}
	for _, r := range resources {
		key := r.Type
		if tf, ok := cfnTypeToTFEquivalent[key]; ok {
			key = tf
		}
		tfTypes[key]++
	}

	has := func(t string) bool { return tfTypes[t] > 0 }
	hasAny := func(types ...string) bool {
		for _, t := range types {
			if tfTypes[t] > 0 {
				return true
			}
		}
		return false
	}

	out := map[string]struct{}{}

	// static-site: S3 + CloudFront together is the canonical CB pattern.
	if has("aws_s3_bucket") && hasAny("aws_cloudfront_distribution", "aws_cloudfront_origin_access_control", "aws_cloudfront_origin_access_identity") {
		out[workloadStaticSite] = struct{}{}
	}

	// secure-s3-bucket: a bare S3 bucket with no CloudFront partner. The
	// secure-s3-bucket slug at CB is for opinionated bucket posture
	// regardless of access pattern, so emitting it whenever an S3 bucket
	// appears without CF is the safest "is there a CB best practice for
	// this bucket?" question.
	if has("aws_s3_bucket") && !has("aws_cloudfront_distribution") {
		out[workloadSecureS3Bucket] = struct{}{}
	}

	// api-with-auth: API Gateway + Lambda + auth flow (Cognito user pool
	// or API-Gateway authorizer wired up).
	apiGW := hasAny("aws_api_gateway_rest_api", "aws_api_gateway_stage", "aws_apigatewayv2_api", "aws_apigatewayv2_stage")
	if apiGW && has("aws_lambda_function") && hasAny("aws_cognito_user_pool", "aws_api_gateway_authorizer", "aws_apigatewayv2_authorizer") {
		out[workloadAPIWithAuth] = struct{}{}
	}

	// http-app: load balancer fronting compute. Both ECS and EC2 ASG count.
	lb := hasAny("aws_lb", "aws_alb")
	compute := hasAny("aws_ecs_service", "aws_ecs_cluster", "aws_autoscaling_group", "aws_instance")
	if lb && compute {
		out[workloadHTTPApp] = struct{}{}
	}

	// multi-tier-web-app: http-app posture plus a managed DB and/or cache.
	dbTier := hasAny("aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance", "aws_dynamodb_table")
	cache := hasAny("aws_elasticache_cluster", "aws_elasticache_replication_group")
	if lb && compute && (dbTier || cache) {
		out[workloadMultiTierWebApp] = struct{}{}
	}

	// queue-worker / worker: SQS + Lambda is queue-worker; ECS worker
	// services (no LB) is plain worker.
	if has("aws_sqs_queue") && has("aws_lambda_function") {
		out[workloadQueueWorker] = struct{}{}
	}
	if !lb && hasAny("aws_ecs_service") {
		out[workloadWorker] = struct{}{}
	}

	// scheduled-job: EventBridge rule/scheduler + Lambda. Heuristic also
	// fires when a Lambda has a `schedule_expression`-shaped event source
	// — but DiscoveredResource doesn't preserve that, so resource-type
	// signal only.
	if hasAny("aws_cloudwatch_event_rule", "aws_scheduler_schedule") && has("aws_lambda_function") {
		out[workloadScheduledJob] = struct{}{}
	}

	// event-pipeline: streaming consumers (Kinesis, MSK).
	if hasAny("aws_kinesis_stream", "aws_kinesis_firehose_delivery_stream", "aws_msk_cluster") {
		out[workloadEventPipeline] = struct{}{}
	}

	// network-baseline: any networking primitives, even on their own —
	// CB's network-baseline practices doc is the standard primer for VPC
	// posture and is always useful when the tree has network resources.
	if hasAny("aws_vpc", "aws_subnet", "aws_security_group", "aws_route_table", "aws_internet_gateway", "aws_nat_gateway", "aws_route_table_association") {
		out[workloadNetworkBaseline] = struct{}{}
	}

	// Drop anything not in the authored set (defence in depth — every
	// branch above sets an authored slug, but this guards future
	// refactors that might accidentally introduce a typo).
	if len(out) == 0 {
		return nil
	}
	slugs := make([]string, 0, len(out))
	for slug := range out {
		if _, ok := AuthoredWorkloadSlugs[slug]; ok {
			slugs = append(slugs, slug)
		}
	}
	sort.Strings(slugs)
	return slugs
}
