package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

// listEKSClustersNative is the FallbackLister for AWS::EKS::Cluster. EKS
// clusters provision slowly, so the EKS variant (10) audited before
// CloudControl listed the cluster — every cluster-level finding (public
// endpoint, control-plane logging, secrets encryption) went dark. EKS has
// no bulk describe, so this walks ListClusters → DescribeCluster, which is
// strongly consistent.
//
// There is no EKS::Cluster describer; the synthesised CFN-shape Properties
// (ResourcesVpcConfig endpoint exposure, ClusterLogging, EncryptionConfig)
// are read directly by the grounded LLM.
func listEKSClustersNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := eks.NewFromConfig(c.withRegion(region).cfg)

	var names []string
	var next *string
	for {
		out, err := client.ListClusters(ctx, &eks.ListClustersInput{NextToken: next})
		if err != nil {
			return nil, classifyAWSError(err, "eks", "eks:ListClusters", region)
		}
		names = append(names, out.Clusters...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}

	var results []rawResource
	for _, name := range names {
		n := name
		out, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &n})
		if err != nil {
			return nil, classifyAWSError(err, "eks", "eks:DescribeCluster", region)
		}
		if out.Cluster == nil {
			continue
		}
		if raw, ok := eksClusterToRaw(*out.Cluster, region); ok {
			results = append(results, raw)
		}
	}
	return results, nil
}

// eksClusterToRaw maps an SDK EKS Cluster into the CFN shape. Pure for
// unit testing.
func eksClusterToRaw(cl ekstypes.Cluster, region string) (rawResource, bool) {
	if cl.Name == nil || *cl.Name == "" {
		return rawResource{}, false
	}
	id := *cl.Name

	props := map[string]any{"Name": id}
	putStr(props, "Arn", cl.Arn)
	putStr(props, "Version", cl.Version)
	putStr(props, "Endpoint", cl.Endpoint)
	putStr(props, "RoleArn", cl.RoleArn)

	if cl.ResourcesVpcConfig != nil {
		v := cl.ResourcesVpcConfig
		vpc := map[string]any{
			"EndpointPublicAccess":  v.EndpointPublicAccess,
			"EndpointPrivateAccess": v.EndpointPrivateAccess,
		}
		putStr(vpc, "VpcId", v.VpcId)
		if len(v.PublicAccessCidrs) > 0 {
			vpc["PublicAccessCidrs"] = toAnySlice(v.PublicAccessCidrs)
		}
		if len(v.SecurityGroupIds) > 0 {
			vpc["SecurityGroupIds"] = toAnySlice(v.SecurityGroupIds)
		}
		if len(v.SubnetIds) > 0 {
			vpc["SubnetIds"] = toAnySlice(v.SubnetIds)
		}
		props["ResourcesVpcConfig"] = vpc
	}

	if cl.Logging != nil && len(cl.Logging.ClusterLogging) > 0 {
		logs := make([]any, 0, len(cl.Logging.ClusterLogging))
		for _, ls := range cl.Logging.ClusterLogging {
			entry := map[string]any{}
			if ls.Enabled != nil {
				entry["Enabled"] = *ls.Enabled
			}
			if len(ls.Types) > 0 {
				types := make([]any, 0, len(ls.Types))
				for _, t := range ls.Types {
					types = append(types, string(t))
				}
				entry["Types"] = types
			}
			logs = append(logs, entry)
		}
		props["Logging"] = map[string]any{"ClusterLogging": logs}
	}

	// EncryptionConfig presence is the load-bearing signal (secrets
	// encryption at rest configured vs not); the key ARNs aren't needed
	// for the finding, so a count-bearing list of the resource sets is
	// enough for the LLM.
	if len(cl.EncryptionConfig) > 0 {
		props["EncryptionConfigPresent"] = true
	} else {
		props["EncryptionConfigPresent"] = false
	}

	return marshalRaw("AWS::EKS::Cluster", id, region, props)
}
