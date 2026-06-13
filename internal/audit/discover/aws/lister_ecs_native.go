package aws

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// listECSServicesNative is the FallbackLister for AWS::ECS::Service. The
// fixtures' ECS variant discovered the Cluster + TaskDefinition but never
// the Service (the create-then-audit race), so service-level posture
// (assignPublicIp, exec, launch type) had nothing to evaluate. ECS has no
// single "describe all services" call, so this walks
// ListClusters → ListServices → DescribeServices (batched at the API's
// 10-per-call limit), which is strongly consistent.
//
// There is no ECS::Service describer, so the synthesised CFN-shape
// Properties are read directly by the grounded LLM.
func listECSServicesNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := ecs.NewFromConfig(c.withRegion(region).cfg)

	clusters, err := listECSClusterArns(ctx, client)
	if err != nil {
		return nil, err
	}

	var results []rawResource
	for _, cluster := range clusters {
		serviceArns, err := listECSServiceArns(ctx, client, cluster)
		if err != nil {
			return nil, err
		}
		for _, batch := range chunk(serviceArns, 10) {
			out, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{
				Cluster:  &cluster,
				Services: batch,
			})
			if err != nil {
				return nil, classifyAWSError(err, "ecs", "ecs:DescribeServices", region)
			}
			for _, svc := range out.Services {
				if raw, ok := ecsServiceToRaw(svc, region); ok {
					results = append(results, raw)
				}
			}
		}
	}
	return results, nil
}

func listECSClusterArns(ctx context.Context, client *ecs.Client) ([]string, error) {
	var arns []string
	var next *string
	for {
		out, err := client.ListClusters(ctx, &ecs.ListClustersInput{NextToken: next})
		if err != nil {
			return nil, classifyAWSError(err, "ecs", "ecs:ListClusters", "")
		}
		arns = append(arns, out.ClusterArns...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	return arns, nil
}

func listECSServiceArns(ctx context.Context, client *ecs.Client, cluster string) ([]string, error) {
	var arns []string
	var next *string
	for {
		out, err := client.ListServices(ctx, &ecs.ListServicesInput{
			Cluster:   &cluster,
			NextToken: next,
		})
		if err != nil {
			return nil, classifyAWSError(err, "ecs", "ecs:ListServices", "")
		}
		arns = append(arns, out.ServiceArns...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	return arns, nil
}

// ecsServiceToRaw maps an SDK ECS Service into the CFN shape. Pure for
// unit testing.
func ecsServiceToRaw(svc ecstypes.Service, region string) (rawResource, bool) {
	if svc.ServiceArn == nil || *svc.ServiceArn == "" {
		return rawResource{}, false
	}
	id := *svc.ServiceArn

	props := map[string]any{"ServiceArn": id}
	putStr(props, "ServiceName", svc.ServiceName)
	putStr(props, "Cluster", svc.ClusterArn)
	putStr(props, "TaskDefinition", svc.TaskDefinition)
	putStr(props, "PlatformVersion", svc.PlatformVersion)
	if svc.LaunchType != "" {
		props["LaunchType"] = string(svc.LaunchType)
	}
	if svc.SchedulingStrategy != "" {
		props["SchedulingStrategy"] = string(svc.SchedulingStrategy)
	}
	props["DesiredCount"] = svc.DesiredCount
	props["EnableExecuteCommand"] = svc.EnableExecuteCommand
	if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.AwsvpcConfiguration != nil {
		v := svc.NetworkConfiguration.AwsvpcConfiguration
		netCfg := map[string]any{}
		if v.AssignPublicIp != "" {
			netCfg["AssignPublicIp"] = string(v.AssignPublicIp)
		}
		if len(v.Subnets) > 0 {
			netCfg["Subnets"] = toAnySlice(v.Subnets)
		}
		if len(v.SecurityGroups) > 0 {
			netCfg["SecurityGroups"] = toAnySlice(v.SecurityGroups)
		}
		props["NetworkConfiguration"] = map[string]any{"AwsvpcConfiguration": netCfg}
	}

	return marshalRaw("AWS::ECS::Service", id, region, props)
}

// chunk splits s into consecutive slices of at most n elements. Used for
// the ECS DescribeServices 10-per-call ceiling.
func chunk[T any](s []T, n int) [][]T {
	if n <= 0 {
		return [][]T{s}
	}
	var out [][]T
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

// toAnySlice widens a []string into []any so it serialises as a JSON array
// of strings inside the synthesised Properties.
func toAnySlice(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

// listECSTaskDefinitionsNative is the FallbackLister for
// AWS::ECS::TaskDefinition. The type is CloudControl-listable, but a live 09
// run dropped it from the audit-time list (probe saw it, audit saw none) — so
// task-level posture (privileged containers, writable root filesystem,
// plaintext-env secrets, missing log driver) had nothing to evaluate.
//
// ecs:ListTaskDefinitions(Status=ACTIVE) is strongly consistent but enumerates
// every active *revision* of every family; auditing all of them would re-flag
// the same family N times. We dedupe to the latest active revision per family
// (latestTaskDefArns) and DescribeTaskDefinition each — one task definition per
// family, the granularity the posture findings actually care about.
//
// The synthesised CFN-shape ContainerDefinitions are read directly by the
// grounded LLM; ecsTaskDefinitionDescriber re-applies the same env-value
// redaction idempotently over both this and the CloudControl origin.
func listECSTaskDefinitionsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := ecs.NewFromConfig(c.withRegion(region).cfg)

	var arns []string
	var next *string
	for {
		out, err := client.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
			Status:    ecstypes.TaskDefinitionStatusActive,
			NextToken: next,
		})
		if err != nil {
			return nil, classifyAWSError(err, "ecs", "ecs:ListTaskDefinitions", region)
		}
		arns = append(arns, out.TaskDefinitionArns...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}

	var results []rawResource
	for _, arn := range latestTaskDefArns(arns) {
		a := arn
		out, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &a})
		if err != nil {
			return nil, classifyAWSError(err, "ecs", "ecs:DescribeTaskDefinition", region)
		}
		if out.TaskDefinition == nil {
			continue
		}
		if raw, ok := taskDefinitionToRaw(*out.TaskDefinition, region); ok {
			results = append(results, raw)
		}
	}
	return results, nil
}

// latestTaskDefArns collapses a flat list of task-definition ARNs to the
// highest-revision ARN per family, so a family with 40 historical revisions is
// audited once. Unparseable ARNs are passed through untouched rather than
// dropped (fail-open: better an extra describe than a silent miss). Output is
// sorted for deterministic ordering. Pure for unit testing.
func latestTaskDefArns(arns []string) []string {
	type best struct {
		arn string
		rev int
	}
	byFamily := map[string]best{}
	for _, a := range arns {
		family, rev := parseTaskDefFamilyRevision(a)
		key := family
		if family == "" {
			// Unparseable — key by the full ARN so it survives as its own entry.
			key = a
			rev = -1
		}
		if cur, ok := byFamily[key]; !ok || rev > cur.rev {
			byFamily[key] = best{arn: a, rev: rev}
		}
	}
	out := make([]string, 0, len(byFamily))
	for _, b := range byFamily {
		out = append(out, b.arn)
	}
	sort.Strings(out)
	return out
}

// parseTaskDefFamilyRevision splits a task-definition ARN
// (…:task-definition/<family>:<revision>) into its family and integer
// revision. Returns ("", -1) when the ARN doesn't match that shape. Pure.
func parseTaskDefFamilyRevision(arn string) (family string, revision int) {
	const marker = "task-definition/"
	i := strings.LastIndex(arn, marker)
	if i < 0 {
		return "", -1
	}
	tail := arn[i+len(marker):] // <family>:<revision>
	j := strings.LastIndex(tail, ":")
	if j < 0 {
		return "", -1
	}
	rev, err := strconv.Atoi(tail[j+1:])
	if err != nil {
		return "", -1
	}
	return tail[:j], rev
}

// taskDefinitionToRaw maps an SDK TaskDefinition into CloudControl's CFN shape.
// The identifier is the TaskDefinitionArn (CloudControl's primary id for this
// type). ContainerDefinitions carries the per-container posture the findings
// key off — Privileged, ReadonlyRootFilesystem, User, plaintext Environment vs
// Secrets, and the log driver. *bool fields are emitted only when set, so the
// "absent = unknown" contract holds. Pure (no SDK client) for unit testing.
func taskDefinitionToRaw(td ecstypes.TaskDefinition, region string) (rawResource, bool) {
	if td.TaskDefinitionArn == nil || *td.TaskDefinitionArn == "" {
		return rawResource{}, false
	}
	id := *td.TaskDefinitionArn

	props := map[string]any{"TaskDefinitionArn": id}
	putStr(props, "Family", td.Family)
	putStr(props, "ExecutionRoleArn", td.ExecutionRoleArn)
	putStr(props, "TaskRoleArn", td.TaskRoleArn)
	if td.NetworkMode != "" {
		props["NetworkMode"] = string(td.NetworkMode)
	}
	if len(td.RequiresCompatibilities) > 0 {
		compat := make([]any, 0, len(td.RequiresCompatibilities))
		for _, ct := range td.RequiresCompatibilities {
			compat = append(compat, string(ct))
		}
		props["RequiresCompatibilities"] = compat
	}

	if defs := containerDefinitionsToCFN(td.ContainerDefinitions); len(defs) > 0 {
		props["ContainerDefinitions"] = defs
	}

	return marshalRaw("AWS::ECS::TaskDefinition", id, region, props)
}

// containerDefinitionsToCFN maps the per-container security posture into the
// CFN ContainerDefinitions array shape. Pure.
func containerDefinitionsToCFN(defs []ecstypes.ContainerDefinition) []any {
	if len(defs) == 0 {
		return nil
	}
	out := make([]any, 0, len(defs))
	for _, cd := range defs {
		c := map[string]any{}
		putStr(c, "Name", cd.Name)
		putStr(c, "Image", cd.Image)
		putStr(c, "User", cd.User)
		putBool(c, "Privileged", cd.Privileged)
		putBool(c, "ReadonlyRootFilesystem", cd.ReadonlyRootFilesystem)
		putBool(c, "Essential", cd.Essential)
		if len(cd.Environment) > 0 {
			env := make([]any, 0, len(cd.Environment))
			for _, kv := range cd.Environment {
				e := map[string]any{}
				putStr(e, "Name", kv.Name)
				// These Properties are read directly by the grounded LLM — a
				// secret-shaped Name's VALUE must be masked or it ships
				// verbatim into the
				// `claude -p` prompt. Same key heuristic as the Lambda
				// describer (keyLooksLikeSecret); arn:-prefixed values pass
				// through because they are the indirection shape the grounded
				// plaintext-env rule's suppress path keys off, not secrets.
				if kv.Name != nil && kv.Value != nil && keyLooksLikeSecret(*kv.Name) && !secretValueIsReference(*kv.Value) {
					e["Value"] = redactedEnvValue
				} else {
					putStr(e, "Value", kv.Value)
				}
				env = append(env, e)
			}
			c["Environment"] = env
		}
		if len(cd.Secrets) > 0 {
			secrets := make([]any, 0, len(cd.Secrets))
			for _, s := range cd.Secrets {
				sm := map[string]any{}
				putStr(sm, "Name", s.Name)
				putStr(sm, "ValueFrom", s.ValueFrom)
				secrets = append(secrets, sm)
			}
			c["Secrets"] = secrets
		}
		if cd.LogConfiguration != nil && cd.LogConfiguration.LogDriver != "" {
			c["LogConfiguration"] = map[string]any{"LogDriver": string(cd.LogConfiguration.LogDriver)}
		}
		out = append(out, c)
	}
	return out
}
