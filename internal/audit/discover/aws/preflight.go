package aws

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// LoadAWSConfig builds an aws.Config from the standard credential chain,
// optionally overridden by an explicit profile or shared-credentials file.
//
// Resolution precedence (highest wins):
//  1. credentialsFile  — sets the shared credentials file path
//  2. profile          — sets the active profile
//  3. AWS_PROFILE env  — honoured by aws-sdk-go-v2 by default
//  4. "default" profile
//
// The returned config has no region set; callers should resolve the region
// list separately via ResolveRegions.
func LoadAWSConfig(ctx context.Context, profile, credentialsFile string) (awsCfg, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	if credentialsFile != "" {
		opts = append(opts, awsconfig.WithSharedCredentialsFiles([]string{credentialsFile}))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awsCfg{}, fmt.Errorf("loading AWS config: %w", err)
	}
	return awsCfg{cfg: cfg}, nil
}

// Preflight calls sts:GetCallerIdentity to confirm credentials are valid
// and to surface the audited account ID + caller ARN. Failure here is a
// hard stop — no partial discovery should run with broken credentials.
func Preflight(ctx context.Context, c awsCfg) (Identity, error) {
	client := sts.NewFromConfig(c.cfg)
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, &PermissionError{
			Service: "sts",
			Action:  "sts:GetCallerIdentity",
			Cause:   err,
		}
	}
	return Identity{
		AccountID:    deref(out.Account),
		AccountAlias: fetchAccountAlias(ctx, c),
		ARN:          deref(out.Arn),
		UserID:       deref(out.UserId),
	}, nil
}

// fetchAccountAlias returns the IAM account alias if one is set on the
// audited account, or "" otherwise. The call is cosmetic — used only
// in the report header — so any error (missing permission, throttling,
// no alias configured) is swallowed silently. Most accounts have no
// alias; the empty result is the common case, not a failure mode.
func fetchAccountAlias(ctx context.Context, c awsCfg) string {
	// IAM is global. If the loaded config has no region (common when
	// the user passes --regions explicitly), pin a known-good region
	// for this one call so the SDK can resolve the endpoint.
	if c.region() == "" {
		c = c.withRegion("us-east-1")
	}
	client := iam.NewFromConfig(c.cfg)
	out, err := client.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil || out == nil || len(out.AccountAliases) == 0 {
		return ""
	}
	return out.AccountAliases[0]
}

// deref returns the dereferenced value of p, or the zero value when p
// is nil. Generic so describers can use it for *bool / *int as well as
// the *string case in preflight.
func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
