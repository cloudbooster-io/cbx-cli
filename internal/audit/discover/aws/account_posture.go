package aws

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
)

// gatherAccountPosture runs the account-level probes in parallel and
// merges results into an audit.AccountPosture (defined in the shared
// internal/audit package so the LLM prompt builder can render it
// without importing this package). Individual probe failures are
// recorded but don't stop the others — partial posture is better than
// none, and the audit user already sees permission errors via the
// existing --diagnose path.
func gatherAccountPosture(ctx context.Context, cfg awsCfg, regions []string) *audit.AccountPosture {
	out := &audit.AccountPosture{
		EBSEncryptionByDefault: map[string]bool{},
	}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Per-region EBS default-encryption check. Each region has its own
	// account-level setting and a customer can have us-east-1 encrypted
	// by default while eu-central-1 isn't — both need flagging.
	for _, region := range regions {
		region := region
		wg.Add(1)
		go func() {
			defer wg.Done()
			enabled, err := probeEBSEncryptionByDefault(ctx, cfg.withRegion(region))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out.Errors = append(out.Errors, "ec2:GetEbsEncryptionByDefault "+region+": "+errSummary(err))
				return
			}
			out.EBSEncryptionByDefault[region] = enabled
		}()
	}

	// IAM is global; run once. GetAccountSummary returns 30+ counters
	// (MFA devices, users without MFA, root access keys, etc.) — those
	// drive most of the IAM posture findings.
	wg.Add(1)
	go func() {
		defer wg.Done()
		summary, err := probeIAMAccountSummary(ctx, cfg)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			out.Errors = append(out.Errors, "iam:GetAccountSummary: "+errSummary(err))
			return
		}
		out.IAMSummary = summary
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		present, err := probePasswordPolicy(ctx, cfg)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			out.Errors = append(out.Errors, "iam:GetAccountPasswordPolicy: "+errSummary(err))
			return
		}
		out.PasswordPolicyPresent = &present
	}()

	wg.Wait()
	sort.Strings(out.Errors)
	return out
}

func probeEBSEncryptionByDefault(ctx context.Context, cfg awsCfg) (bool, error) {
	client := ec2.NewFromConfig(cfg.cfg)
	out, err := client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return false, err
	}
	if out.EbsEncryptionByDefault == nil {
		return false, nil
	}
	return *out.EbsEncryptionByDefault, nil
}

func probeIAMAccountSummary(ctx context.Context, cfg awsCfg) (map[string]int32, error) {
	client := iam.NewFromConfig(cfg.cfg)
	out, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}
	// SummaryMap is map[string]int32 in the SDK type. Copy so callers
	// can't mutate the AWS-owned map.
	if out.SummaryMap == nil {
		return map[string]int32{}, nil
	}
	cp := make(map[string]int32, len(out.SummaryMap))
	for k, v := range out.SummaryMap {
		cp[string(k)] = v
	}
	return cp, nil
}

// probePasswordPolicy returns true when a password policy is set on
// the account. GetAccountPasswordPolicy returns NoSuchEntity when no
// policy exists — that's the "no policy configured" signal, not an
// error worth surfacing in posture.Errors.
func probePasswordPolicy(ctx context.Context, cfg awsCfg) (bool, error) {
	client := iam.NewFromConfig(cfg.cfg)
	_, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err == nil {
		return true, nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity" {
		return false, nil
	}
	return false, err
}

// errSummary trims the verbose AWS SDK error wrapping to a short
// human-readable code+message. Posture errors land in the audit
// stderr; we want "AccessDenied" not the full SDK wrapper.
func errSummary(err error) string {
	if err == nil {
		return ""
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() + ": " + apiErr.ErrorMessage()
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return strings.TrimSpace(msg)
}
