package audit

import (
	"reflect"
	"testing"
)

func res(types ...string) []DiscoveredResource {
	out := make([]DiscoveredResource, 0, len(types))
	for _, t := range types {
		out = append(out, DiscoveredResource{Type: t})
	}
	return out
}

func TestClassifyWorkloads_TableDriven(t *testing.T) {
	cases := []struct {
		name      string
		resources []DiscoveredResource
		want      []string
	}{
		{
			name:      "empty",
			resources: nil,
			want:      nil,
		},
		{
			name:      "static site",
			resources: res("aws_s3_bucket", "aws_cloudfront_distribution"),
			want:      []string{"static-site"},
		},
		{
			name:      "bare s3 bucket",
			resources: res("aws_s3_bucket"),
			want:      []string{"secure-s3-bucket"},
		},
		{
			name:      "api with auth",
			resources: res("aws_api_gateway_rest_api", "aws_lambda_function", "aws_cognito_user_pool"),
			want:      []string{"api-with-auth"},
		},
		{
			name:      "http app (ECS behind ALB)",
			resources: res("aws_lb", "aws_ecs_service", "aws_ecs_cluster"),
			want:      []string{"http-app"},
		},
		{
			name:      "multi-tier webapp",
			resources: res("aws_lb", "aws_ecs_service", "aws_db_instance"),
			want:      []string{"http-app", "multi-tier-web-app"},
		},
		{
			name:      "queue worker (sqs + lambda)",
			resources: res("aws_sqs_queue", "aws_lambda_function"),
			want:      []string{"queue-worker"},
		},
		{
			name:      "worker (ecs service, no LB)",
			resources: res("aws_ecs_service"),
			want:      []string{"worker"},
		},
		{
			name:      "scheduled job",
			resources: res("aws_cloudwatch_event_rule", "aws_lambda_function"),
			want:      []string{"scheduled-job"},
		},
		{
			name:      "event pipeline",
			resources: res("aws_kinesis_stream"),
			want:      []string{"event-pipeline"},
		},
		{
			name:      "network baseline",
			resources: res("aws_vpc", "aws_subnet", "aws_security_group"),
			want:      []string{"network-baseline"},
		},
		{
			name: "rich tree picks up multiple authored slugs",
			resources: res(
				"aws_s3_bucket", "aws_cloudfront_distribution",
				"aws_lb", "aws_ecs_service", "aws_db_instance",
				"aws_vpc", "aws_subnet",
				"aws_sqs_queue", "aws_lambda_function",
			),
			want: []string{
				"http-app",
				"multi-tier-web-app",
				"network-baseline",
				"queue-worker",
				"static-site",
			},
		},
		{
			name:      "unmapped tree (EC2 instance only) returns empty",
			resources: res("aws_instance"),
			want:      nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyWorkloads(tc.resources)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ClassifyWorkloads = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClassifyWorkloads_CFNTypeCoverage asserts that AWS-discovered
// resources (CFN-shape Type values) trip the same workload branches as
// their TF equivalents. Replays a representative subset of the
// TableDriven cases above using CFN names, so any future regression in
// the translation map is caught with a one-line diff.
func TestClassifyWorkloads_CFNTypeCoverage(t *testing.T) {
	cases := []struct {
		name      string
		resources []DiscoveredResource
		want      []string
	}{
		{
			name:      "static site",
			resources: res("AWS::S3::Bucket", "AWS::CloudFront::Distribution"),
			want:      []string{"static-site"},
		},
		{
			name:      "api-with-auth via apigatewayv2",
			resources: res("AWS::ApiGatewayV2::Api", "AWS::Lambda::Function", "AWS::Cognito::UserPool"),
			want:      []string{"api-with-auth"},
		},
		{
			name:      "http-app (ECS behind ALB)",
			resources: res("AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ECS::Service", "AWS::ECS::Cluster"),
			want:      []string{"http-app"},
		},
		{
			name: "multi-tier webapp via CFN",
			resources: res(
				"AWS::ElasticLoadBalancingV2::LoadBalancer",
				"AWS::ECS::Service",
				"AWS::RDS::DBInstance",
			),
			want: []string{"http-app", "multi-tier-web-app"},
		},
		{
			name:      "queue worker via CFN",
			resources: res("AWS::SQS::Queue", "AWS::Lambda::Function"),
			want:      []string{"queue-worker"},
		},
		{
			name:      "scheduled job via Scheduler::Schedule",
			resources: res("AWS::Scheduler::Schedule", "AWS::Lambda::Function"),
			want:      []string{"scheduled-job"},
		},
		{
			name:      "event pipeline (Kinesis Firehose CFN)",
			resources: res("AWS::KinesisFirehose::DeliveryStream"),
			want:      []string{"event-pipeline"},
		},
		{
			name:      "network baseline",
			resources: res("AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::SecurityGroup"),
			want:      []string{"network-baseline"},
		},
		{
			name:      "mixed CFN + TF in the same set still classifies correctly",
			resources: res("AWS::S3::Bucket", "aws_cloudfront_distribution"),
			want:      []string{"static-site"},
		},
		{
			name:      "AWS::Lambda::Function alone does not fire any workload",
			resources: res("AWS::Lambda::Function"),
			want:      nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyWorkloads(tc.resources)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ClassifyWorkloads = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClassifyWorkloads_NeverEmitsUnauthoredSlug(t *testing.T) {
	// Cover a wide cross-section of resource types and confirm every emitted
	// slug is in the AuthoredWorkloadSlugs set. Guards a refactor that adds
	// a new branch with a typo'd slug name.
	resources := res(
		"aws_s3_bucket", "aws_cloudfront_distribution",
		"aws_api_gateway_rest_api", "aws_lambda_function", "aws_cognito_user_pool",
		"aws_lb", "aws_ecs_service", "aws_db_instance",
		"aws_vpc", "aws_subnet", "aws_security_group",
		"aws_sqs_queue",
		"aws_cloudwatch_event_rule",
		"aws_kinesis_stream",
	)
	got := ClassifyWorkloads(resources)
	for _, slug := range got {
		if _, ok := AuthoredWorkloadSlugs[slug]; !ok {
			t.Errorf("classifier emitted unauthored slug %q", slug)
		}
	}
}
