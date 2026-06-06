package aws

import (
	"context"

	ecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// listECRRepositoriesNative is the FallbackLister for AWS::ECR::Repository.
// AWS::ECR::Repository is CloudControl-listable (the fixtures-08 probe saw
// count=1), yet a live 09 run showed the audit-time ListResources silently
// returning an empty set for it — the same flaky-empty failure mode RDS hit,
// just on a strongly-consistent type, so the scan-on-push / tag-mutability /
// missing-lifecycle findings on the repo went dark with permission_errors=[].
// ecr:DescribeRepositories is the authoritative, strongly-consistent
// enumeration and only fires when CloudControl returned nothing.
//
// The synthesised CFN-shape props (RepositoryName, ImageTagMutability,
// ImageScanningConfiguration.ScanOnPush) match what CloudControl's GetResource
// returns inline, so the existing ecrRepositoryDescriber (which adds the
// lifecycle-policy-present hint keyed off RepositoryName) runs over the
// fallback resource unchanged.
func listECRRepositoriesNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := ecr.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var next *string
	for {
		out, err := client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{NextToken: next})
		if err != nil {
			return nil, classifyAWSError(err, "ecr", "ecr:DescribeRepositories", region)
		}
		for _, repo := range out.Repositories {
			if raw, ok := ecrRepositoryToRaw(repo, region); ok {
				results = append(results, raw)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	return results, nil
}

// ecrRepositoryToRaw maps an SDK ECR Repository into CloudControl's CFN shape.
// RepositoryName is the identifier (CloudControl's primary id for this type),
// so ecrRepositoryDescriber resolves the lifecycle policy off it verbatim.
// ScanOnPush and ImageTagMutability are the load-bearing posture fields the
// grounded LLM reads. Pure (no SDK client) for unit testing.
func ecrRepositoryToRaw(repo ecrtypes.Repository, region string) (rawResource, bool) {
	if repo.RepositoryName == nil || *repo.RepositoryName == "" {
		return rawResource{}, false
	}
	id := *repo.RepositoryName

	props := map[string]any{"RepositoryName": id}
	putStr(props, "RepositoryArn", repo.RepositoryArn)
	putStr(props, "RepositoryUri", repo.RepositoryUri)
	if repo.ImageTagMutability != "" {
		props["ImageTagMutability"] = string(repo.ImageTagMutability)
	}
	// ImageScanningConfiguration nests ScanOnPush, mirroring CloudControl's
	// GetResource shape so the "scan-on-push disabled" finding reads the same
	// path whether the repo came from CloudControl or this fallback.
	if repo.ImageScanningConfiguration != nil {
		props["ImageScanningConfiguration"] = map[string]any{
			"ScanOnPush": repo.ImageScanningConfiguration.ScanOnPush,
		}
	}

	return marshalRaw("AWS::ECR::Repository", id, region, props)
}
