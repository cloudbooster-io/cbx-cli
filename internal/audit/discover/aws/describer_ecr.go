package aws

import (
	"context"
	"errors"

	ecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ecrRepositoryDescriber surfaces the one ECR posture signal CloudControl's
// AWS::ECR::Repository read can't carry: whether a lifecycle policy exists.
//
// CloudControl's GetResource returns ImageScanningConfiguration (ScanOnPush)
// and ImageTagMutability inline — the grounded LLM already flags scan-on-push
// and mutable-tag findings from those. The lifecycle policy, however, is a
// separate sub-resource (ecr:GetLifecyclePolicy) that GetResource omits, so
// its *absence* is invisible to the model — it can't distinguish "no
// lifecycle policy" (an untended-image-accumulation finding) from "the field
// just wasn't fetched". This describer makes the one API call and lifts the
// answer into a boolean hint, mirroring cb_describer_access_logs_enabled.
//
// The call is per-repository, but ECR repos are few and the audit visits each
// once, so the cost is negligible. A missing ecr:GetLifecyclePolicy permission
// (or any other error) degrades gracefully: the hint is left absent rather
// than failing the type, exactly like the S3 attribute describers.
type ecrRepositoryDescriber struct{}

func (ecrRepositoryDescriber) CFNType() string { return "AWS::ECR::Repository" }

func (ecrRepositoryDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	name, _ := r.Inputs["RepositoryName"].(string)
	if name == "" {
		name = r.ID // CloudControl's primary identifier for this type is RepositoryName
	}
	if name == "" {
		return nil
	}

	if r.Region != "" {
		c = c.withRegion(r.Region)
	}
	client := ecr.NewFromConfig(c.cfg)

	_, err := client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{RepositoryName: &name})
	if err != nil {
		// The repository having no lifecycle policy is the planted finding,
		// not an error — AWS signals it with this typed exception.
		var notFound *ecrtypes.LifecyclePolicyNotFoundException
		if errors.As(err, &notFound) {
			r.Inputs["cb_describer_lifecycle_policy_present"] = false
			return nil
		}
		// Any other failure (permissions, throttling): leave the hint absent
		// so the model isn't told "policy present" on a read we couldn't make.
		return classifyAWSError(err, "ecr", "ecr:GetLifecyclePolicy", r.Region)
	}

	r.Inputs["cb_describer_lifecycle_policy_present"] = true
	return nil
}
