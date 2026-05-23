package aws

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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
		AccountID: deref(out.Account),
		ARN:       deref(out.Arn),
		UserID:    deref(out.UserId),
	}, nil
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
