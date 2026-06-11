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

	// The cluster's OIDC issuer URL is the join key for IRSA detection: the
	// eksClusterDescriber probes IAM for an OIDC identity provider registered
	// against this exact issuer (its absence means pods fall back to the node
	// role — an IRSA gap). CloudControl, when it lists the cluster, carries the
	// same value as the flat read-only attribute OpenIdConnectIssuerUrl; the
	// describer reads either shape. Surface it nested, mirroring the SDK.
	if cl.Identity != nil && cl.Identity.Oidc != nil && cl.Identity.Oidc.Issuer != nil && *cl.Identity.Oidc.Issuer != "" {
		props["Identity"] = map[string]any{
			"Oidc": map[string]any{"Issuer": *cl.Identity.Oidc.Issuer},
		}
	}

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

	// EncryptionConfig presence is the load-bearing signal the grounded LLM
	// reads (secrets encryption at rest configured vs not). We ALSO surface the
	// CMK ARN(s) nested under the CFN EncryptionConfig[].Provider.KeyArn shape so
	// the KMS cross-reference pass (walkKMSReferences → isKMSFieldName "KeyArn")
	// marks a customer key used only for EKS secrets encryption as referenced —
	// without it that key is mis-flagged cb_describer_is_unused. Provider/KeyArn
	// may be nil/empty (older clusters), so emit the list only for entries that
	// actually carry an ARN.
	if len(cl.EncryptionConfig) > 0 {
		props["EncryptionConfigPresent"] = true
		cfgs := make([]any, 0, len(cl.EncryptionConfig))
		for _, ec := range cl.EncryptionConfig {
			if ec.Provider != nil && ec.Provider.KeyArn != nil && *ec.Provider.KeyArn != "" {
				cfgs = append(cfgs, map[string]any{
					"Provider": map[string]any{"KeyArn": *ec.Provider.KeyArn},
				})
			}
		}
		if len(cfgs) > 0 {
			props["EncryptionConfig"] = cfgs
		}
	} else {
		props["EncryptionConfigPresent"] = false
	}

	return marshalRaw("AWS::EKS::Cluster", id, region, props)
}
