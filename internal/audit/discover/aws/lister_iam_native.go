package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// listLocalManagedPoliciesNative is the FallbackLister for
// AWS::IAM::ManagedPolicy. Unlike the compute/db/net fallbacks this is NOT
// an eventual-consistency fix — IAM is strongly consistent. The fixtures'
// iam-landing-zone variant (02) missed its one planted issue (a customer-
// managed policy with multi-service wildcards) because AWS::IAM::ManagedPolicy
// was absent from discovery, with permission_errors == 0.
//
// Diagnosis (offline): keepCustomerIAMPolicy is NOT the culprit — it keeps
// customer ARNs (arn:aws:iam::<account>:policy/…) and only drops AWS-managed
// ones (arn:aws:iam::aws:policy/…). So the miss is CloudControl's
// ListResources returning an incomplete set for this type. iam:ListPolicies
// (Scope=Local) is the authoritative, strongly-consistent enumeration of
// customer-managed policies, and only fires when CloudControl returned none.
//
// The iamManagedPolicyDescriber reads the policy document inline from
// Inputs["PolicyDocument"] (URL-encoded, the shape CloudControl returns) —
// ListPolicies does not return the document, so this fetches it via
// GetPolicyVersion(DefaultVersionId) and stores it under the same key, so
// the describer's wildcard analysis runs verbatim.
func listLocalManagedPoliciesNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := iam.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var marker *string
	for {
		out, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{
			Scope:  iamtypes.PolicyScopeTypeLocal,
			Marker: marker,
		})
		if err != nil {
			return nil, classifyAWSError(err, "iam", "iam:ListPolicies", region)
		}
		for _, p := range out.Policies {
			doc := getPolicyDocument(ctx, client, p.Arn, p.DefaultVersionId)
			if raw, ok := iamPolicyToRaw(p, doc, region); ok {
				results = append(results, raw)
			}
		}
		if !out.IsTruncated || out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return results, nil
}

// getPolicyDocument fetches the default version's (URL-encoded) policy
// document. Returns "" on any error so a missing iam:GetPolicyVersion
// permission degrades to "policy discovered, document unread" rather than
// failing the whole type — the describer no-ops on an empty document.
func getPolicyDocument(ctx context.Context, client *iam.Client, arn, versionID *string) string {
	if arn == nil || versionID == nil {
		return ""
	}
	out, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: arn,
		VersionId: versionID,
	})
	if err != nil || out.PolicyVersion == nil || out.PolicyVersion.Document == nil {
		return ""
	}
	return *out.PolicyVersion.Document
}

// iamPolicyToRaw maps an SDK Policy (+ its URL-encoded document) into the
// CFN shape iamManagedPolicyDescriber reads. The identifier is the policy
// ARN, matching CloudControl's primary identifier for this type. Pure for
// unit testing.
func iamPolicyToRaw(p iamtypes.Policy, urlEncodedDoc, region string) (rawResource, bool) {
	if p.Arn == nil || *p.Arn == "" {
		return rawResource{}, false
	}
	id := *p.Arn

	props := map[string]any{"Arn": id}
	putStr(props, "PolicyName", p.PolicyName)
	putStr(props, "PolicyId", p.PolicyId)
	putStr(props, "Path", p.Path)
	putStr(props, "DefaultVersionId", p.DefaultVersionId)
	if urlEncodedDoc != "" {
		// Same key + URL-encoded shape CloudControl's GetResource returns,
		// so iamManagedPolicyDescriber decodes it unchanged.
		props["PolicyDocument"] = urlEncodedDoc
	}

	return marshalRaw("AWS::IAM::ManagedPolicy", id, region, props)
}
