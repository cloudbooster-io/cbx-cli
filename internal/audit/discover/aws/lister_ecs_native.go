package aws

import (
	"context"

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
