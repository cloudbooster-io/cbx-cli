// Command genprimitives walks the CB platform-app AWS-knowledge primitive
// docs and emits internal/audit/primitives_aws.go — the Terraform / Pulumi /
// CloudFormation → CB-primitive-id mapping tables the audit pipeline uses to
// ground LLM findings against CB-curated knowledge.
//
// CB authors a primitive directory per knowledge entry, each with a
// primitive.md whose YAML frontmatter declares the canonical CB type_id:
//
//	---
//	tags: [aws, storage, s3, best-practices]
//	type_ids: ["aws:s3/bucket@v1"]
//	...
//	---
//
// The frontmatter does NOT declare Terraform / Pulumi / CFN aliases — those
// are hand-curated in this file (aliasTable) and validated against the
// walked directory set at generation time. A drift in either direction
// fails the build: missing primitive (alias references a dir CB never
// authored) or unmapped primitive (CB authored a dir we don't have aliases
// for, surfaced as a warning + listed in the generated file's commentary).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// aliasEntry maps one primitive directory to the Terraform resource types,
// Pulumi type tokens, and CloudFormation type names that should resolve to
// the dir's CB primitive id.
type aliasEntry struct {
	Dir     string   // directory name under primitives/, e.g. "s3_bucket"
	TF      []string // Terraform resource types, e.g. "aws_s3_bucket"
	Pulumi  []string // Pulumi type tokens, e.g. "aws:s3/bucket:Bucket"
	CFN     []string // CloudFormation type names, e.g. "AWS::S3::Bucket"
	Comment string   // optional note rendered in the generated file
}

// aliasTable is the source-of-truth Terraform / Pulumi / CFN → CB-primitive
// mapping. Each Dir MUST correspond to an authored primitive under
// platform-app/be/app/knowledge/resources/aws/primitives/ — the generator
// fails if not.
//
// Engine-split primitives (rds_*, aurora_*) are intentionally NOT keyed by
// the generic aws_db_instance / AWS::RDS::DBInstance type — disambiguation
// happens at audit time via rdsPrimitiveFor(engine). aws_rds_cluster /
// AWS::RDS::DBCluster lands on aurora-postgres by default since it is the
// most common Aurora engine; callers should override via rdsPrimitiveFor
// when the engine attr is parseable.
var aliasTable = []aliasEntry{
	// --- storage ---
	{Dir: "s3_bucket", TF: []string{"aws_s3_bucket"}, Pulumi: []string{"aws:s3/bucket:Bucket"}, CFN: []string{"AWS::S3::Bucket"}},
	{Dir: "ebs_volume", TF: []string{"aws_ebs_volume"}, Pulumi: []string{"aws:ebs/volume:Volume"}, CFN: []string{"AWS::EC2::Volume"}},
	{Dir: "efs", TF: []string{"aws_efs_file_system"}, Pulumi: []string{"aws:efs/fileSystem:FileSystem"}, CFN: []string{"AWS::EFS::FileSystem"}},
	// --- compute ---
	{Dir: "ec2_instance", TF: []string{"aws_instance"}, Pulumi: []string{"aws:ec2/instance:Instance"}, CFN: []string{"AWS::EC2::Instance"}},
	{Dir: "lambda_function", TF: []string{"aws_lambda_function", "aws_lambda_permission"}, Pulumi: []string{"aws:lambda/function:Function", "aws:lambda/permission:Permission"}, CFN: []string{"AWS::Lambda::Function", "AWS::Lambda::Permission"}},
	{Dir: "auto_scaling_group", TF: []string{"aws_autoscaling_group"}, Pulumi: []string{"aws:autoscaling/group:Group"}, CFN: []string{"AWS::AutoScaling::AutoScalingGroup"}},
	{Dir: "app_runner", TF: []string{"aws_apprunner_service"}, Pulumi: []string{"aws:apprunner/service:Service"}, CFN: []string{"AWS::AppRunner::Service"}},
	{Dir: "batch", TF: []string{"aws_batch_job_definition", "aws_batch_compute_environment", "aws_batch_job_queue"}, CFN: []string{"AWS::Batch::JobDefinition", "AWS::Batch::ComputeEnvironment", "AWS::Batch::JobQueue"}},
	{Dir: "ecs_fargate_service", TF: []string{"aws_ecs_service", "aws_ecs_task_definition", "aws_ecs_cluster"}, Pulumi: []string{"aws:ecs/service:Service", "aws:ecs/taskDefinition:TaskDefinition", "aws:ecs/cluster:Cluster"}, CFN: []string{"AWS::ECS::Service", "AWS::ECS::TaskDefinition", "AWS::ECS::Cluster"}},
	{Dir: "eks", TF: []string{"aws_eks_cluster", "aws_eks_node_group"}, Pulumi: []string{"aws:eks/cluster:Cluster", "aws:eks/nodeGroup:NodeGroup"}, CFN: []string{"AWS::EKS::Cluster", "AWS::EKS::Nodegroup"}},
	{Dir: "elastic_beanstalk", TF: []string{"aws_elastic_beanstalk_environment", "aws_elastic_beanstalk_application"}, CFN: []string{"AWS::ElasticBeanstalk::Environment", "AWS::ElasticBeanstalk::Application"}},
	{Dir: "step_functions", TF: []string{"aws_sfn_state_machine"}, Pulumi: []string{"aws:sfn/stateMachine:StateMachine"}, CFN: []string{"AWS::StepFunctions::StateMachine"}},
	// --- networking ---
	{Dir: "vpc", TF: []string{"aws_vpc", "aws_subnet", "aws_internet_gateway", "aws_nat_gateway", "aws_route_table", "aws_route", "aws_route_table_association"}, Pulumi: []string{"aws:ec2/vpc:Vpc", "aws:ec2/subnet:Subnet"}, CFN: []string{"AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::InternetGateway", "AWS::EC2::NatGateway", "AWS::EC2::RouteTable", "AWS::EC2::Route", "AWS::EC2::SubnetRouteTableAssociation"}},
	{Dir: "security_group", TF: []string{"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"}, Pulumi: []string{"aws:ec2/securityGroup:SecurityGroup"}, CFN: []string{"AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"}},
	{Dir: "alb", TF: []string{"aws_lb", "aws_lb_listener", "aws_lb_target_group", "aws_alb"}, Pulumi: []string{"aws:lb/loadBalancer:LoadBalancer", "aws:alb/loadBalancer:LoadBalancer"}, CFN: []string{"AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancingV2::Listener", "AWS::ElasticLoadBalancingV2::TargetGroup"}, Comment: "shares AWS::ElasticLoadBalancingV2::LoadBalancer with nlb; disambiguation via Type attribute, not handled here"},
	{Dir: "nlb"}, // shares aws_lb / AWS::ElasticLoadBalancingV2::LoadBalancer with alb; disambiguation via load_balancer_type / Type, not handled here
	{Dir: "vpc_endpoint", TF: []string{"aws_vpc_endpoint"}, Pulumi: []string{"aws:ec2/vpcEndpoint:VpcEndpoint"}, CFN: []string{"AWS::EC2::VPCEndpoint"}},
	{Dir: "transit_gateway", TF: []string{"aws_ec2_transit_gateway"}, Pulumi: []string{"aws:ec2transitgateway/transitGateway:TransitGateway"}, CFN: []string{"AWS::EC2::TransitGateway"}},
	// --- DNS / CDN ---
	{Dir: "route53_zone", TF: []string{"aws_route53_zone"}, Pulumi: []string{"aws:route53/zone:Zone"}, CFN: []string{"AWS::Route53::HostedZone"}},
	{Dir: "route53_record", TF: []string{"aws_route53_record"}, Pulumi: []string{"aws:route53/record:Record"}, CFN: []string{"AWS::Route53::RecordSet"}},
	{Dir: "cloudfront", TF: []string{"aws_cloudfront_distribution"}, Pulumi: []string{"aws:cloudfront/distribution:Distribution"}, CFN: []string{"AWS::CloudFront::Distribution"}},
	// --- IAM / auth / security ---
	{Dir: "iam_role", TF: []string{"aws_iam_role"}, Pulumi: []string{"aws:iam/role:Role"}, CFN: []string{"AWS::IAM::Role"}},
	{Dir: "iam_policy", TF: []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_policy_attachment"}, Pulumi: []string{"aws:iam/policy:Policy", "aws:iam/rolePolicy:RolePolicy", "aws:iam/rolePolicyAttachment:RolePolicyAttachment"}, CFN: []string{"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::RolePolicy"}},
	{Dir: "kms_key", TF: []string{"aws_kms_key", "aws_kms_alias"}, Pulumi: []string{"aws:kms/key:Key", "aws:kms/alias:Alias"}, CFN: []string{"AWS::KMS::Key", "AWS::KMS::Alias"}},
	{Dir: "secrets_bundle", TF: []string{"aws_secretsmanager_secret", "aws_secretsmanager_secret_version"}, Pulumi: []string{"aws:secretsmanager/secret:Secret"}, CFN: []string{"AWS::SecretsManager::Secret"}},
	{Dir: "acm_certificate", TF: []string{"aws_acm_certificate"}, Pulumi: []string{"aws:acm/certificate:Certificate"}, CFN: []string{"AWS::CertificateManager::Certificate"}},
	{Dir: "cognito_user_pool", TF: []string{"aws_cognito_user_pool"}, Pulumi: []string{"aws:cognito/userPool:UserPool"}, CFN: []string{"AWS::Cognito::UserPool"}},
	{Dir: "waf", TF: []string{"aws_wafv2_web_acl", "aws_waf_web_acl"}, Pulumi: []string{"aws:wafv2/webAcl:WebAcl"}, CFN: []string{"AWS::WAFv2::WebACL", "AWS::WAF::WebACL"}},
	// --- databases (engine-split) ---
	// rds_postgres / rds_mysql / rds_mariadb / aurora_mysql have no direct
	// TF / CFN aliases — they're resolved via rdsPrimitiveFor(engine) at
	// audit time. AWS::RDS::DBInstance + aws_db_instance follow the same
	// pattern (not aliased here).
	{Dir: "rds_postgres", Comment: "aws_db_instance / AWS::RDS::DBInstance with engine=postgres — see rdsPrimitiveFor"},
	{Dir: "rds_mysql", Comment: "aws_db_instance / AWS::RDS::DBInstance with engine=mysql — see rdsPrimitiveFor"},
	{Dir: "rds_mariadb", Comment: "aws_db_instance / AWS::RDS::DBInstance with engine=mariadb — see rdsPrimitiveFor"},
	{Dir: "aurora_postgres", TF: []string{"aws_rds_cluster", "aws_rds_cluster_instance"}, Pulumi: []string{"aws:rds/cluster:Cluster"}, CFN: []string{"AWS::RDS::DBCluster"}, Comment: "default Aurora primitive; engine=aurora-postgresql. AWS::RDS::DBInstance NOT aliased — engine-split via rdsPrimitiveFor"},
	{Dir: "aurora_mysql", Comment: "aws_rds_cluster / AWS::RDS::DBCluster with engine=aurora-mysql — see rdsPrimitiveFor"},
	{Dir: "dynamodb", TF: []string{"aws_dynamodb_table"}, Pulumi: []string{"aws:dynamodb/table:Table"}, CFN: []string{"AWS::DynamoDB::Table"}},
	{Dir: "documentdb", TF: []string{"aws_docdb_cluster", "aws_docdb_cluster_instance"}, CFN: []string{"AWS::DocDB::DBCluster", "AWS::DocDB::DBInstance"}},
	// --- caches / search ---
	{Dir: "elasticache_redis", TF: []string{"aws_elasticache_replication_group"}, CFN: []string{"AWS::ElastiCache::ReplicationGroup"}},
	{Dir: "elasticache_memcached", TF: []string{"aws_elasticache_cluster"}, CFN: []string{"AWS::ElastiCache::CacheCluster"}, Comment: "aws_elasticache_cluster / AWS::ElastiCache::CacheCluster with engine=memcached"},
	{Dir: "opensearch", TF: []string{"aws_opensearch_domain", "aws_elasticsearch_domain"}, Pulumi: []string{"aws:opensearch/domain:Domain"}, CFN: []string{"AWS::OpenSearchService::Domain", "AWS::Elasticsearch::Domain"}},
	// --- messaging ---
	{Dir: "sqs_queue", TF: []string{"aws_sqs_queue"}, Pulumi: []string{"aws:sqs/queue:Queue"}, CFN: []string{"AWS::SQS::Queue"}},
	{Dir: "sns_topic", TF: []string{"aws_sns_topic", "aws_sns_topic_subscription"}, Pulumi: []string{"aws:sns/topic:Topic"}, CFN: []string{"AWS::SNS::Topic", "AWS::SNS::Subscription"}},
	{Dir: "eventbridge", TF: []string{"aws_cloudwatch_event_rule", "aws_cloudwatch_event_target", "aws_cloudwatch_event_bus"}, Pulumi: []string{"aws:cloudwatch/eventRule:EventRule", "aws:cloudwatch/eventTarget:EventTarget"}, CFN: []string{"AWS::Events::Rule", "AWS::Events::EventBus"}},
	{Dir: "eventbridge_scheduler", TF: []string{"aws_scheduler_schedule"}, CFN: []string{"AWS::Scheduler::Schedule"}},
	{Dir: "msk", TF: []string{"aws_msk_cluster"}, CFN: []string{"AWS::MSK::Cluster"}},
	{Dir: "ses", TF: []string{"aws_ses_domain_identity", "aws_ses_email_identity", "aws_ses_configuration_set"}, CFN: []string{"AWS::SES::EmailIdentity", "AWS::SES::ConfigurationSet"}},
	// --- container registry ---
	{Dir: "ecr", TF: []string{"aws_ecr_repository", "aws_ecr_lifecycle_policy", "aws_ecr_repository_policy"}, Pulumi: []string{"aws:ecr/repository:Repository"}, CFN: []string{"AWS::ECR::Repository", "AWS::ECR::RepositoryPolicy"}},
	// --- API gateway ---
	{Dir: "api_gateway", TF: []string{"aws_apigatewayv2_api", "aws_apigatewayv2_stage", "aws_apigatewayv2_integration", "aws_apigatewayv2_route"}, Pulumi: []string{"aws:apigatewayv2/api:Api"}, CFN: []string{"AWS::ApiGatewayV2::Api", "AWS::ApiGatewayV2::Stage", "AWS::ApiGatewayV2::Integration", "AWS::ApiGatewayV2::Route"}},
	{Dir: "api_gateway_rest", TF: []string{"aws_api_gateway_rest_api", "aws_api_gateway_resource", "aws_api_gateway_method", "aws_api_gateway_integration", "aws_api_gateway_deployment", "aws_api_gateway_stage"}, Pulumi: []string{"aws:apigateway/restApi:RestApi"}, CFN: []string{"AWS::ApiGateway::RestApi", "AWS::ApiGateway::Resource", "AWS::ApiGateway::Method", "AWS::ApiGateway::Deployment", "AWS::ApiGateway::Stage"}},
	// --- observability / config ---
	{Dir: "cloudwatch_log_group", TF: []string{"aws_cloudwatch_log_group"}, Pulumi: []string{"aws:cloudwatch/logGroup:LogGroup"}, CFN: []string{"AWS::Logs::LogGroup"}},
	{Dir: "cloudwatch_alarm", TF: []string{"aws_cloudwatch_metric_alarm"}, Pulumi: []string{"aws:cloudwatch/metricAlarm:MetricAlarm"}, CFN: []string{"AWS::CloudWatch::Alarm"}},
	{Dir: "cloudtrail", TF: []string{"aws_cloudtrail"}, Pulumi: []string{"aws:cloudtrail/trail:Trail"}, CFN: []string{"AWS::CloudTrail::Trail"}},
	{Dir: "ssm_parameter", TF: []string{"aws_ssm_parameter"}, Pulumi: []string{"aws:ssm/parameter:Parameter"}, CFN: []string{"AWS::SSM::Parameter"}},
	// --- composite patterns (no direct TF / CFN type) ---
	{Dir: "ecs_fargate_worker", Comment: "pattern primitive — composed via ecs_fargate_service + sqs_queue"},
	{Dir: "ecs_scheduled_task", Comment: "pattern primitive — composed via ecs + eventbridge"},
	{Dir: "athena", TF: []string{"aws_athena_workgroup", "aws_athena_database"}, CFN: []string{"AWS::Athena::WorkGroup", "AWS::Athena::DataCatalog"}},
}

// rdsEngineMap is emitted into the generated file as the body of
// rdsPrimitiveFor — maps `engine` attribute values to authored CB ids.
var rdsEngineMap = map[string]string{
	"postgres":          "aws:db/postgres@v1",
	"postgresql":        "aws:db/postgres@v1",
	"mysql":             "aws:db/mysql@v1",
	"mariadb":           "aws:db/mariadb@v1",
	"aurora-postgresql": "aws:db/aurora-postgres@v1",
	"aurora-mysql":      "aws:db/aurora-mysql@v1",
}

// cfnTypeRe validates that a CFN type name follows the AWS::Service::Resource
// shape. The generator rejects anything that doesn't match — a typo here
// silently breaks live-AWS audit lookups, so the loud-fail is worth it.
var cfnTypeRe = regexp.MustCompile(`^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$`)

// frontmatterTypeID extracts the first quoted aws:.../...@vN token from a
// `type_ids: [...]` line in the YAML frontmatter of a primitive.md.
//
// Primitives declare a single canonical id today (e.g. `type_ids:
// ["aws:s3/bucket@v1"]`); we deliberately only honour the first entry so
// drift to multi-id primitives is loud rather than silent.
var typeIDRe = regexp.MustCompile(`type_ids:\s*\[\s*"(aws:[^"\s]+@v\d+)"`)

// readPrimitiveTypeID parses a primitive.md and returns its declared CB
// type_id, or "" if the file has no frontmatter type_ids line.
func readPrimitiveTypeID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Frontmatter is the block between the first two `---` lines.
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "---" {
		return "", nil
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			break
		}
		if m := typeIDRe.FindStringSubmatch(lines[i]); m != nil {
			return m[1], nil
		}
	}
	return "", nil
}

func main() {
	src := flag.String("src", "../platform-app/be/app/knowledge/resources/aws/primitives", "path to platform-app primitive docs root")
	out := flag.String("out", "internal/audit/primitives_aws.go", "output path for generated Go file")
	flag.Parse()

	entries, err := os.ReadDir(*src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "genprimitives: cannot read -src %q: %v\n", *src, err)
		os.Exit(1)
	}

	// Walk: dirName → CB type_id, ordered for deterministic output.
	authored := map[string]string{}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(*src, e.Name(), "primitive.md")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		tid, err := readPrimitiveTypeID(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "genprimitives: read %s: %v\n", path, err)
			os.Exit(1)
		}
		if tid == "" {
			fmt.Fprintf(os.Stderr, "genprimitives: %s has no type_ids frontmatter\n", path)
			os.Exit(1)
		}
		authored[e.Name()] = tid
		dirs = append(dirs, e.Name())
	}
	sort.Strings(dirs)

	// Validate aliasTable against the walked truth set + CFN-name shape.
	tableDirs := map[string]struct{}{}
	for _, a := range aliasTable {
		if _, ok := authored[a.Dir]; !ok {
			fmt.Fprintf(os.Stderr, "genprimitives: aliasTable entry %q has no authored primitive under %s/\n", a.Dir, *src)
			os.Exit(1)
		}
		for _, c := range a.CFN {
			if !cfnTypeRe.MatchString(c) {
				fmt.Fprintf(os.Stderr, "genprimitives: aliasTable entry %q has malformed CFN type %q (expected AWS::Service::Resource)\n", a.Dir, c)
				os.Exit(1)
			}
		}
		tableDirs[a.Dir] = struct{}{}
	}
	for _, e := range dirs {
		if engineSplitMariaAurora(e) {
			continue // intentionally aliased only via rdsPrimitiveFor
		}
		if _, ok := tableDirs[e]; !ok {
			fmt.Fprintf(os.Stderr, "genprimitives: WARN primitive %q (%s) has no Terraform/Pulumi/CFN aliases — add to aliasTable or note as composite\n", e, authored[e])
		}
	}

	// Validate rdsEngineMap targets are all authored.
	var engines []string
	for k := range rdsEngineMap {
		engines = append(engines, k)
	}
	sort.Strings(engines)
	authoredIDs := map[string]struct{}{}
	for _, id := range authored {
		authoredIDs[id] = struct{}{}
	}
	for _, e := range engines {
		if _, ok := authoredIDs[rdsEngineMap[e]]; !ok {
			fmt.Fprintf(os.Stderr, "genprimitives: rdsEngineMap[%q] = %q is not an authored CB primitive\n", e, rdsEngineMap[e])
			os.Exit(1)
		}
	}

	// Build the emitted maps. Sort keys for determinism.
	tfMap := map[string]string{}
	pulumiMap := map[string]string{}
	cfnMap := map[string]string{}
	for _, a := range aliasTable {
		id := authored[a.Dir]
		for _, t := range a.TF {
			if existing, ok := tfMap[t]; ok && existing != id {
				fmt.Fprintf(os.Stderr, "genprimitives: TF type %q maps to both %q and %q (last wins from %q)\n", t, existing, id, a.Dir)
			}
			tfMap[t] = id
		}
		for _, t := range a.Pulumi {
			if existing, ok := pulumiMap[t]; ok && existing != id {
				fmt.Fprintf(os.Stderr, "genprimitives: Pulumi token %q maps to both %q and %q (last wins from %q)\n", t, existing, id, a.Dir)
			}
			pulumiMap[t] = id
		}
		for _, t := range a.CFN {
			if existing, ok := cfnMap[t]; ok && existing != id {
				fmt.Fprintf(os.Stderr, "genprimitives: CFN type %q maps to both %q and %q (last wins from %q)\n", t, existing, id, a.Dir)
			}
			cfnMap[t] = id
		}
	}

	src1 := renderGoFile(authored, dirs, tfMap, pulumiMap, cfnMap, engines)
	formatted, err := format.Source(src1)
	if err != nil {
		// Emit the unformatted source for debugging then fail.
		_ = os.WriteFile(*out+".unformatted", src1, 0o644)
		fmt.Fprintf(os.Stderr, "genprimitives: gofmt failed: %v (raw written to %s.unformatted)\n", err, *out)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, formatted, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "genprimitives: write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "genprimitives: wrote %s (%d primitives, %d TF aliases, %d Pulumi aliases, %d CFN aliases)\n", *out, len(authored), len(tfMap), len(pulumiMap), len(cfnMap))
}

// engineSplitMariaAurora marks the engine-keyed RDS/Aurora dirs that are
// intentionally absent from aliasTable; they're addressed via
// rdsPrimitiveFor at audit time, not via a direct TF/CFN-type lookup.
func engineSplitMariaAurora(dir string) bool {
	switch dir {
	case "rds_postgres", "rds_mysql", "rds_mariadb", "aurora_mysql":
		return true
	}
	return false
}

func renderGoFile(authored map[string]string, dirs []string, tfMap, pulumiMap, cfnMap map[string]string, engines []string) []byte {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "// Code generated by tools/genprimitives. DO NOT EDIT.")
	fmt.Fprintln(&buf, "//")
	fmt.Fprintln(&buf, "// Source: platform-app/be/app/knowledge/resources/aws/primitives/*/primitive.md frontmatter.")
	fmt.Fprintln(&buf, "// Regenerate via `make codegen-primitives` and check drift with `make codegen-primitives-check`.")
	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "package audit")
	fmt.Fprintln(&buf)

	// authoredCBPrimitives — sorted CB-id set.
	fmt.Fprintln(&buf, "// authoredCBPrimitives is the set of CB primitive type_ids declared by")
	fmt.Fprintln(&buf, "// platform-app at generation time. Anything outside this set is unknown to")
	fmt.Fprintln(&buf, "// the CB knowledge base — aws_lookup_primitive will 404.")
	fmt.Fprintln(&buf, "var authoredCBPrimitives = map[string]struct{}{")
	var ids []string
	for _, id := range authored {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(&buf, "\t%q: {},\n", id)
	}
	fmt.Fprintln(&buf, "}")
	fmt.Fprintln(&buf)

	// tfTypeToCBPrimitive
	fmt.Fprintln(&buf, "// tfTypeToCBPrimitive maps a Terraform AWS resource type (e.g.")
	fmt.Fprintln(&buf, "// `aws_s3_bucket`) to the CB primitive id (e.g. `aws:s3/bucket@v1`).")
	fmt.Fprintln(&buf, "// Engine-split databases (aws_db_instance, aws_rds_cluster) are not in")
	fmt.Fprintln(&buf, "// this map — use rdsPrimitiveFor(engine) instead.")
	fmt.Fprintln(&buf, "var tfTypeToCBPrimitive = map[string]string{")
	var tfKeys []string
	for k := range tfMap {
		tfKeys = append(tfKeys, k)
	}
	sort.Strings(tfKeys)
	for _, k := range tfKeys {
		fmt.Fprintf(&buf, "\t%q: %q,\n", k, tfMap[k])
	}
	fmt.Fprintln(&buf, "}")
	fmt.Fprintln(&buf)

	// pulumiTypeToCBPrimitive
	fmt.Fprintln(&buf, "// pulumiTypeToCBPrimitive maps a Pulumi type token (e.g.")
	fmt.Fprintln(&buf, "// `aws:s3/bucket:Bucket`) to the CB primitive id. Keys use the full")
	fmt.Fprintln(&buf, "// `aws:<service>/<resource>:<Kind>` form found in Pulumi state files.")
	fmt.Fprintln(&buf, "var pulumiTypeToCBPrimitive = map[string]string{")
	var puKeys []string
	for k := range pulumiMap {
		puKeys = append(puKeys, k)
	}
	sort.Strings(puKeys)
	for _, k := range puKeys {
		fmt.Fprintf(&buf, "\t%q: %q,\n", k, pulumiMap[k])
	}
	fmt.Fprintln(&buf, "}")
	fmt.Fprintln(&buf)

	// cfnTypeToCBPrimitive
	fmt.Fprintln(&buf, "// cfnTypeToCBPrimitive maps a CloudFormation type name (e.g.")
	fmt.Fprintln(&buf, "// `AWS::S3::Bucket`) to the CB primitive id. Used by the live-AWS")
	fmt.Fprintln(&buf, "// audit path, which queries the CloudControl API and gets back")
	fmt.Fprintln(&buf, "// CFN-style type names. Engine-split databases (AWS::RDS::DBInstance)")
	fmt.Fprintln(&buf, "// are not in this map — use rdsPrimitiveFor(engine) instead.")
	fmt.Fprintln(&buf, "var cfnTypeToCBPrimitive = map[string]string{")
	var cfnKeys []string
	for k := range cfnMap {
		cfnKeys = append(cfnKeys, k)
	}
	sort.Strings(cfnKeys)
	for _, k := range cfnKeys {
		fmt.Fprintf(&buf, "\t%q: %q,\n", k, cfnMap[k])
	}
	fmt.Fprintln(&buf, "}")
	fmt.Fprintln(&buf)

	// rdsPrimitiveFor
	fmt.Fprintln(&buf, "// rdsPrimitiveFor resolves an aws_db_instance / aws_rds_cluster /")
	fmt.Fprintln(&buf, "// AWS::RDS::DBInstance / AWS::RDS::DBCluster `engine` attribute to its")
	fmt.Fprintln(&buf, "// CB primitive id. Returns \"\" when the engine is unknown or unparseable")
	fmt.Fprintln(&buf, "// (e.g. when the HCL value is a variable reference).")
	fmt.Fprintln(&buf, "func rdsPrimitiveFor(engine string) string {")
	fmt.Fprintln(&buf, "\tswitch engine {")
	for _, e := range engines {
		fmt.Fprintf(&buf, "\tcase %q:\n\t\treturn %q\n", e, rdsEngineMap[e])
	}
	fmt.Fprintln(&buf, "\t}")
	fmt.Fprintln(&buf, "\treturn \"\"")
	fmt.Fprintln(&buf, "}")

	return buf.Bytes()
}
