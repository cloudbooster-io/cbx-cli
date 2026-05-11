package audit

import (
	"sort"
	"strings"
)

// CB-authored workload slugs surveyed 2026-05-11 (see
// `ai_space/analyses/2026-05-11-cb-knowledge-survey.md` §2). Only these slugs
// hit pattern-tagged chunks in /v1/knowledge/aws/practices; anything else
// falls through to the undifferentiated catalog, which is signal-poor.
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
func ClassifyWorkloads(resources []DiscoveredResource) []string {
	if len(resources) == 0 {
		return nil
	}

	tfTypes := map[string]int{}
	for _, r := range resources {
		tfTypes[r.Type]++
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

// formatWorkloads is a tiny helper for prompt rendering / log lines.
func formatWorkloads(slugs []string) string {
	if len(slugs) == 0 {
		return "(none — falling back to per-primitive grounding only)"
	}
	return strings.Join(slugs, ", ")
}
