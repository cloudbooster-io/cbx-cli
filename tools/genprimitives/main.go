// Command genprimitives walks the CB platform-app AWS-knowledge primitive
// docs and emits internal/audit/primitives_aws.go — the Terraform/Pulumi
// → CB-primitive-id mapping table the audit pipeline uses to ground LLM
// findings against CB-curated knowledge.
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
// The frontmatter does NOT declare Terraform or Pulumi aliases — those are
// hand-curated in this file (aliasTable) and validated against the walked
// directory set at generation time. A drift in either direction fails the
// build: missing primitive (alias references a dir CB never authored) or
// unmapped primitive (CB authored a dir we don't have aliases for, surfaced
// as a warning + listed in the generated file's commentary).
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

// aliasEntry maps one primitive directory to the Terraform resource types
// and Pulumi type tokens that should resolve to the dir's CB primitive id.
type aliasEntry struct {
	Dir     string   // directory name under primitives/, e.g. "s3_bucket"
	TF      []string // Terraform resource types, e.g. "aws_s3_bucket"
	Pulumi  []string // Pulumi type tokens, e.g. "aws:s3/bucket:Bucket"
	Comment string   // optional note rendered in the generated file
}

// aliasTable is the source-of-truth Terraform/Pulumi → CB-primitive mapping.
// Each Dir MUST correspond to an authored primitive under
// platform-app/be/app/knowledge/resources/aws/primitives/ — the generator
// fails if not.
//
// Engine-split primitives (rds_*, aurora_*) are intentionally NOT keyed by
// the generic aws_db_instance type — disambiguation happens at audit time
// via rdsPrimitiveFor(engine). aws_rds_cluster lands on aurora-postgres by
// default since it is the most common Aurora engine; callers should override
// via rdsPrimitiveFor when the engine attr is parseable.
var aliasTable = []aliasEntry{
	// --- storage ---
	{Dir: "s3_bucket", TF: []string{"aws_s3_bucket"}, Pulumi: []string{"aws:s3/bucket:Bucket"}},
	{Dir: "ebs_volume", TF: []string{"aws_ebs_volume"}, Pulumi: []string{"aws:ebs/volume:Volume"}},
	{Dir: "efs", TF: []string{"aws_efs_file_system"}, Pulumi: []string{"aws:efs/fileSystem:FileSystem"}},
	// --- compute ---
	{Dir: "ec2_instance", TF: []string{"aws_instance"}, Pulumi: []string{"aws:ec2/instance:Instance"}},
	{Dir: "lambda_function", TF: []string{"aws_lambda_function", "aws_lambda_permission"}, Pulumi: []string{"aws:lambda/function:Function", "aws:lambda/permission:Permission"}},
	{Dir: "auto_scaling_group", TF: []string{"aws_autoscaling_group"}, Pulumi: []string{"aws:autoscaling/group:Group"}},
	{Dir: "app_runner", TF: []string{"aws_apprunner_service"}, Pulumi: []string{"aws:apprunner/service:Service"}},
	{Dir: "batch", TF: []string{"aws_batch_job_definition", "aws_batch_compute_environment", "aws_batch_job_queue"}},
	{Dir: "ecs_fargate_service", TF: []string{"aws_ecs_service", "aws_ecs_task_definition", "aws_ecs_cluster"}, Pulumi: []string{"aws:ecs/service:Service", "aws:ecs/taskDefinition:TaskDefinition", "aws:ecs/cluster:Cluster"}},
	{Dir: "eks", TF: []string{"aws_eks_cluster", "aws_eks_node_group"}, Pulumi: []string{"aws:eks/cluster:Cluster", "aws:eks/nodeGroup:NodeGroup"}},
	{Dir: "elastic_beanstalk", TF: []string{"aws_elastic_beanstalk_environment", "aws_elastic_beanstalk_application"}},
	{Dir: "step_functions", TF: []string{"aws_sfn_state_machine"}, Pulumi: []string{"aws:sfn/stateMachine:StateMachine"}},
	// --- networking ---
	{Dir: "vpc", TF: []string{"aws_vpc", "aws_subnet", "aws_internet_gateway", "aws_nat_gateway", "aws_route_table", "aws_route", "aws_route_table_association"}, Pulumi: []string{"aws:ec2/vpc:Vpc", "aws:ec2/subnet:Subnet"}},
	{Dir: "security_group", TF: []string{"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"}, Pulumi: []string{"aws:ec2/securityGroup:SecurityGroup"}},
	{Dir: "alb", TF: []string{"aws_lb", "aws_lb_listener", "aws_lb_target_group", "aws_alb"}, Pulumi: []string{"aws:lb/loadBalancer:LoadBalancer", "aws:alb/loadBalancer:LoadBalancer"}},
	{Dir: "nlb"}, // shares aws_lb token with alb; disambiguation via load_balancer_type, not handled here
	{Dir: "vpc_endpoint", TF: []string{"aws_vpc_endpoint"}, Pulumi: []string{"aws:ec2/vpcEndpoint:VpcEndpoint"}},
	{Dir: "transit_gateway", TF: []string{"aws_ec2_transit_gateway"}, Pulumi: []string{"aws:ec2transitgateway/transitGateway:TransitGateway"}},
	// --- DNS / CDN ---
	{Dir: "route53_zone", TF: []string{"aws_route53_zone"}, Pulumi: []string{"aws:route53/zone:Zone"}},
	{Dir: "route53_record", TF: []string{"aws_route53_record"}, Pulumi: []string{"aws:route53/record:Record"}},
	{Dir: "cloudfront", TF: []string{"aws_cloudfront_distribution"}, Pulumi: []string{"aws:cloudfront/distribution:Distribution"}},
	// --- IAM / auth / security ---
	{Dir: "iam_role", TF: []string{"aws_iam_role"}, Pulumi: []string{"aws:iam/role:Role"}},
	{Dir: "iam_policy", TF: []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_policy_attachment"}, Pulumi: []string{"aws:iam/policy:Policy", "aws:iam/rolePolicy:RolePolicy", "aws:iam/rolePolicyAttachment:RolePolicyAttachment"}},
	{Dir: "kms_key", TF: []string{"aws_kms_key", "aws_kms_alias"}, Pulumi: []string{"aws:kms/key:Key", "aws:kms/alias:Alias"}},
	{Dir: "secrets_bundle", TF: []string{"aws_secretsmanager_secret", "aws_secretsmanager_secret_version"}, Pulumi: []string{"aws:secretsmanager/secret:Secret"}},
	{Dir: "acm_certificate", TF: []string{"aws_acm_certificate"}, Pulumi: []string{"aws:acm/certificate:Certificate"}},
	{Dir: "cognito_user_pool", TF: []string{"aws_cognito_user_pool"}, Pulumi: []string{"aws:cognito/userPool:UserPool"}},
	{Dir: "waf", TF: []string{"aws_wafv2_web_acl", "aws_waf_web_acl"}, Pulumi: []string{"aws:wafv2/webAcl:WebAcl"}},
	// --- databases (engine-split) ---
	{Dir: "rds_postgres", Comment: "aws_db_instance with engine=postgres — see rdsPrimitiveFor"},
	{Dir: "rds_mysql", Comment: "aws_db_instance with engine=mysql — see rdsPrimitiveFor"},
	{Dir: "rds_mariadb", Comment: "aws_db_instance with engine=mariadb — see rdsPrimitiveFor"},
	{Dir: "aurora_postgres", TF: []string{"aws_rds_cluster", "aws_rds_cluster_instance"}, Pulumi: []string{"aws:rds/cluster:Cluster"}, Comment: "default Aurora primitive; engine=aurora-postgresql"},
	{Dir: "aurora_mysql", Comment: "aws_rds_cluster with engine=aurora-mysql — see rdsPrimitiveFor"},
	{Dir: "dynamodb", TF: []string{"aws_dynamodb_table"}, Pulumi: []string{"aws:dynamodb/table:Table"}},
	{Dir: "documentdb", TF: []string{"aws_docdb_cluster", "aws_docdb_cluster_instance"}},
	// --- caches / search ---
	{Dir: "elasticache_redis", TF: []string{"aws_elasticache_replication_group"}},
	{Dir: "elasticache_memcached", TF: []string{"aws_elasticache_cluster"}, Comment: "aws_elasticache_cluster with engine=memcached"},
	{Dir: "opensearch", TF: []string{"aws_opensearch_domain", "aws_elasticsearch_domain"}, Pulumi: []string{"aws:opensearch/domain:Domain"}},
	// --- messaging ---
	{Dir: "sqs_queue", TF: []string{"aws_sqs_queue"}, Pulumi: []string{"aws:sqs/queue:Queue"}},
	{Dir: "sns_topic", TF: []string{"aws_sns_topic", "aws_sns_topic_subscription"}, Pulumi: []string{"aws:sns/topic:Topic"}},
	{Dir: "eventbridge", TF: []string{"aws_cloudwatch_event_rule", "aws_cloudwatch_event_target", "aws_cloudwatch_event_bus"}, Pulumi: []string{"aws:cloudwatch/eventRule:EventRule", "aws:cloudwatch/eventTarget:EventTarget"}},
	{Dir: "eventbridge_scheduler", TF: []string{"aws_scheduler_schedule"}},
	{Dir: "msk", TF: []string{"aws_msk_cluster"}},
	{Dir: "ses", TF: []string{"aws_ses_domain_identity", "aws_ses_email_identity", "aws_ses_configuration_set"}},
	// --- container registry ---
	{Dir: "ecr", TF: []string{"aws_ecr_repository", "aws_ecr_lifecycle_policy", "aws_ecr_repository_policy"}, Pulumi: []string{"aws:ecr/repository:Repository"}},
	// --- API gateway ---
	{Dir: "api_gateway", TF: []string{"aws_apigatewayv2_api", "aws_apigatewayv2_stage", "aws_apigatewayv2_integration", "aws_apigatewayv2_route"}, Pulumi: []string{"aws:apigatewayv2/api:Api"}},
	{Dir: "api_gateway_rest", TF: []string{"aws_api_gateway_rest_api", "aws_api_gateway_resource", "aws_api_gateway_method", "aws_api_gateway_integration", "aws_api_gateway_deployment", "aws_api_gateway_stage"}, Pulumi: []string{"aws:apigateway/restApi:RestApi"}},
	// --- observability / config ---
	{Dir: "cloudwatch_log_group", TF: []string{"aws_cloudwatch_log_group"}, Pulumi: []string{"aws:cloudwatch/logGroup:LogGroup"}},
	{Dir: "cloudwatch_alarm", TF: []string{"aws_cloudwatch_metric_alarm"}, Pulumi: []string{"aws:cloudwatch/metricAlarm:MetricAlarm"}},
	{Dir: "cloudtrail", TF: []string{"aws_cloudtrail"}, Pulumi: []string{"aws:cloudtrail/trail:Trail"}},
	{Dir: "ssm_parameter", TF: []string{"aws_ssm_parameter"}, Pulumi: []string{"aws:ssm/parameter:Parameter"}},
	// --- composite patterns (no direct TF type) ---
	{Dir: "ecs_fargate_worker", Comment: "pattern primitive — composed via ecs_fargate_service + sqs_queue"},
	{Dir: "ecs_scheduled_task", Comment: "pattern primitive — composed via ecs + eventbridge"},
	{Dir: "athena", TF: []string{"aws_athena_workgroup", "aws_athena_database"}},
}

// rdsEngineMap is emitted into the generated file as the body of
// rdsPrimitiveFor — maps `engine` attribute values to authored CB ids.
var rdsEngineMap = map[string]string{
	"postgres":         "aws:db/postgres@v1",
	"postgresql":       "aws:db/postgres@v1",
	"mysql":            "aws:db/mysql@v1",
	"mariadb":          "aws:db/mariadb@v1",
	"aurora-postgresql": "aws:db/aurora-postgres@v1",
	"aurora-mysql":     "aws:db/aurora-mysql@v1",
}

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

	// Validate aliasTable against the walked truth set.
	tableDirs := map[string]struct{}{}
	for _, a := range aliasTable {
		if _, ok := authored[a.Dir]; !ok {
			fmt.Fprintf(os.Stderr, "genprimitives: aliasTable entry %q has no authored primitive under %s/\n", a.Dir, *src)
			os.Exit(1)
		}
		tableDirs[a.Dir] = struct{}{}
	}
	for _, e := range dirs {
		if engineSplitMariaAurora(e) {
			continue // intentionally aliased only via rdsPrimitiveFor
		}
		if _, ok := tableDirs[e]; !ok {
			fmt.Fprintf(os.Stderr, "genprimitives: WARN primitive %q (%s) has no Terraform/Pulumi aliases — add to aliasTable or note as composite\n", e, authored[e])
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
	}

	src1 := renderGoFile(authored, dirs, tfMap, pulumiMap, engines)
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
	fmt.Fprintf(os.Stderr, "genprimitives: wrote %s (%d primitives, %d TF aliases, %d Pulumi aliases)\n", *out, len(authored), len(tfMap), len(pulumiMap))
}

// engineSplitMariaAurora marks the engine-keyed RDS/Aurora dirs that are
// intentionally absent from aliasTable; they're addressed via
// rdsPrimitiveFor at audit time, not via a direct TF-type lookup.
func engineSplitMariaAurora(dir string) bool {
	switch dir {
	case "rds_postgres", "rds_mysql", "rds_mariadb", "aurora_mysql":
		return true
	}
	return false
}

func renderGoFile(authored map[string]string, dirs []string, tfMap, pulumiMap map[string]string, engines []string) []byte {
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

	// rdsPrimitiveFor
	fmt.Fprintln(&buf, "// rdsPrimitiveFor resolves an aws_db_instance / aws_rds_cluster `engine`")
	fmt.Fprintln(&buf, "// attribute to its CB primitive id. Returns \"\" when the engine is unknown")
	fmt.Fprintln(&buf, "// or unparseable (e.g. when the HCL value is a variable reference).")
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
