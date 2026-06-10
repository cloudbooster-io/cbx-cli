package aws

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
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
		EBSEncryptionByDefault:    map[string]bool{},
		GuardDutyByRegion:         map[string]string{},
		ConfigRecorderByRegion:    map[string]audit.ConfigRecorderState{},
		GlueCatalogPolicyByRegion: map[string]*audit.GlueCatalogPolicy{},
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

		// Glue Data Catalog resource policy is also a per-region account
		// singleton — probe it in the same per-region fan-out. Absent in
		// most regions, so only present policies land in the map.
		wg.Add(1)
		go func() {
			defer wg.Done()
			pol, err := probeGlueCatalogPolicy(ctx, cfg.withRegion(region))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out.Errors = append(out.Errors, "glue:GetResourcePolicy "+region+": "+errSummary(err))
				return
			}
			if pol != nil {
				out.GlueCatalogPolicyByRegion[region] = pol
			}
		}()
	}

	// Per-region GuardDuty detector state. GuardDuty is regional; a
	// detector that exists but is suspended ("disabled") is a real
	// regression the audit must catch, distinct from never having
	// enabled it ("absent"). See probeGuardDuty.
	for _, region := range regions {
		region := region
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, err := probeGuardDuty(ctx, cfg.withRegion(region))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out.Errors = append(out.Errors, "guardduty:ListDetectors "+region+": "+errSummary(err))
				return
			}
			out.GuardDutyByRegion[region] = state
		}()
	}

	// Per-region AWS Config recorder coverage. Config is regional but
	// global resource types (IAM) only need recording in one region —
	// consumers aggregate before flagging, so we record every region's
	// state (including "no recorder").
	for _, region := range regions {
		region := region
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, err := probeConfigRecorders(ctx, cfg.withRegion(region))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out.Errors = append(out.Errors, "config:DescribeConfigurationRecorders "+region+": "+errSummary(err))
				return
			}
			out.ConfigRecorderByRegion[region] = state
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

	// IAM credential-report console-MFA probe (CIS 1.10 / FSBP IAM.5).
	// IAM is global → run once on the un-pinned cfg, like the summary and
	// password-policy probes above. A failure (AccessDenied, the report
	// never completing, a malformed CSV) lands in Errors and leaves
	// CredentialReport nil → the prompt renders nothing → UNKNOWN, never a
	// false "all console users have MFA".
	wg.Add(1)
	go func() {
		defer wg.Done()
		rep, err := probeConsoleUsersWithoutMFA(ctx, cfg)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			out.Errors = append(out.Errors, "iam:GetCredentialReport: "+errSummary(err))
			return
		}
		out.CredentialReport = rep
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

// reportPollInterval / credReportMaxAttempts bound the wait for the IAM
// credential report to finish generating. A report normally completes in
// a few seconds; we re-poll a handful of times (~12s ceiling) and then
// give up, returning the error → posture.Errors → the prompt renders
// nothing (UNKNOWN). Tune small: this runs inside the account-posture
// fan-out and must not stall the audit.
const (
	credReportPollInterval = 2 * time.Second
	credReportMaxAttempts  = 6 // ~12s ceiling, ctx-cancellable
)

// probeConsoleUsersWithoutMFA reports IAM users that have console access
// (a login password) but no MFA device — CIS 1.10 / FSBP IAM.5. Sourced
// from the IAM credential report (a CSV snapshot of every user's
// credential state). GenerateCredentialReport is idempotent and returns
// COMPLETE immediately when a recent (<~4h) report exists; otherwise it
// builds the report asynchronously, so GetCredentialReport is polled with
// a bounded, ctx-aware backoff. The account root user row is skipped (its
// MFA is the AccountMFAEnabled summary counter handled by the
// root-credential rule). Any failure — AccessDenied, the report never
// completing within the budget, a malformed CSV — returns an error so the
// caller records it in posture.Errors and the prompt renders nothing
// (UNKNOWN), never a false "all console users have MFA".
func probeConsoleUsersWithoutMFA(ctx context.Context, cfg awsCfg) (*audit.CredentialReportPosture, error) {
	client := iam.NewFromConfig(cfg.cfg)

	// Ensure a report exists. Idempotent; LimitExceeded (too many generate
	// calls in the window) is non-fatal — an older cached report is still
	// fetchable, so fall through to GetCredentialReport regardless.
	_, _ = client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})

	for attempt := 0; ; attempt++ {
		out, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil {
			return parseCredentialReportConsoleNoMFA(out.Content)
		}
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "ReportInProgress", "ReportNotPresent", "ReportExpired":
				if attempt >= credReportMaxAttempts {
					return nil, err
				}
				// Re-kick on expiry/absence, then wait and retry.
				_, _ = client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(credReportPollInterval):
				}
				continue
			}
		}
		return nil, err // AccessDenied and everything else: surface it
	}
}

// parseCredentialReportConsoleNoMFA reads the IAM credential-report CSV and
// returns the console-password users that lack an MFA device. Pure (CSV
// bytes in, result out) → unit-testable without an AWS mock, mirroring the
// recorderRecordsGlobalTypes / policyGrantsPublicPrincipal pure helpers in
// this file. The account root row (user "<root_account>", whose
// password_enabled is "not_supported") is skipped; root MFA is handled by
// the root-credential rule. A non-nil return means the probe RAN — an
// empty ConsoleUsersWithoutMFA with ConsolePasswordUsersEvaluated > 0 is
// the "ran, all compliant" signal.
func parseCredentialReportConsoleNoMFA(csvBytes []byte) (*audit.CredentialReportPosture, error) {
	rows, err := csv.NewReader(bytes.NewReader(csvBytes)).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty credential report")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	userIdx, ok1 := col["user"]
	pwIdx, ok2 := col["password_enabled"]
	mfaIdx, ok3 := col["mfa_active"]
	if !ok1 || !ok2 || !ok3 {
		return nil, fmt.Errorf("credential report missing expected columns")
	}
	rep := &audit.CredentialReportPosture{}
	for _, row := range rows[1:] {
		if len(row) <= userIdx || len(row) <= pwIdx || len(row) <= mfaIdx {
			continue
		}
		if row[userIdx] == "<root_account>" { // root handled by the root-credential rule
			continue
		}
		if row[pwIdx] != "true" { // no console password → out of scope (service/programmatic user)
			continue
		}
		rep.ConsolePasswordUsersEvaluated++
		if row[mfaIdx] == "false" {
			rep.ConsoleUsersWithoutMFA = append(rep.ConsoleUsersWithoutMFA, row[userIdx])
		}
	}
	sort.Strings(rep.ConsoleUsersWithoutMFA) // deterministic render
	return rep, nil
}

// GuardDuty detector states surfaced in AccountPosture.GuardDutyByRegion.
const (
	guardDutyEnabled  = "enabled"
	guardDutyDisabled = "disabled"
	guardDutyAbsent   = "absent"
)

// probeGuardDuty reports the GuardDuty detector state for the region the
// cfg is pinned to: "absent" when no detector exists, otherwise the
// classified status of the (single) detector. GuardDuty allows at most
// one detector per region per account, so the first id is authoritative.
func probeGuardDuty(ctx context.Context, cfg awsCfg) (string, error) {
	client := guardduty.NewFromConfig(cfg.cfg)
	list, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return "", err
	}
	if len(list.DetectorIds) == 0 {
		return guardDutyAbsent, nil
	}
	det, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{
		DetectorId: &list.DetectorIds[0],
	})
	if err != nil {
		return "", err
	}
	return classifyDetectorStatus(string(det.Status)), nil
}

// classifyDetectorStatus maps a GuardDuty detector's Status to the
// posture vocabulary. ENABLED → "enabled"; anything else (DISABLED, or
// any future suspended state) → "disabled". A detector that exists is
// never "absent" — absence is decided by the caller from ListDetectors.
func classifyDetectorStatus(status string) string {
	if strings.EqualFold(status, "ENABLED") {
		return guardDutyEnabled
	}
	return guardDutyDisabled
}

// probeConfigRecorders reports AWS Config configuration-recorder coverage
// for the region the cfg is pinned to. Present is false when the region
// has no recorder. RecordsGlobalTypes is true when any recorder in the
// region captures global (IAM) resource types — see recorderRecordsGlobalTypes.
func probeConfigRecorders(ctx context.Context, cfg awsCfg) (audit.ConfigRecorderState, error) {
	client := configservice.NewFromConfig(cfg.cfg)
	out, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return audit.ConfigRecorderState{}, err
	}
	st := audit.ConfigRecorderState{}
	for _, rec := range out.ConfigurationRecorders {
		st.Present = true
		rg := rec.RecordingGroup
		if rg == nil {
			continue
		}
		resourceTypes := make([]string, 0, len(rg.ResourceTypes))
		for _, t := range rg.ResourceTypes {
			resourceTypes = append(resourceTypes, string(t))
		}
		if recorderRecordsGlobalTypes(rg.AllSupported, rg.IncludeGlobalResourceTypes, resourceTypes) {
			st.RecordsGlobalTypes = true
		}
	}
	return st, nil
}

// recorderRecordsGlobalTypes decides whether a Config RecordingGroup
// captures global (account-wide) resource types — IAM users, roles,
// policies, groups. Two shapes cover the real world:
//
//   - Classic: AllSupported=true with IncludeGlobalResourceTypes=true.
//     AllSupported alone excludes global types unless the flag is set.
//   - Inclusion strategy: AllSupported=false but the explicit
//     resourceTypes list names a global IAM type.
//
// Kept pure (primitive args, no SDK types) so it's unit-testable without
// an AWS mock.
func recorderRecordsGlobalTypes(allSupported, includeGlobal bool, resourceTypes []string) bool {
	if allSupported && includeGlobal {
		return true
	}
	for _, t := range resourceTypes {
		if strings.HasPrefix(t, "AWS::IAM::") {
			return true
		}
	}
	return false
}

// probeGlueCatalogPolicy fetches the Glue Data Catalog resource policy
// for one region. The Data Catalog has at most one resource policy per
// account per region; glue:GetResourcePolicy with no ResourceArn
// returns the catalog-level policy. EntityNotFoundException is the
// "no policy configured" signal (the common case, identical in spirit
// to probePasswordPolicy's NoSuchEntity) — returned as (nil, nil), NOT
// an error, so Glue-less regions don't spam posture.Errors. A present
// policy is summarised with a precomputed wildcard-principal flag (the
// cross-account exposure trigger) plus the raw document for citation.
func probeGlueCatalogPolicy(ctx context.Context, cfg awsCfg) (*audit.GlueCatalogPolicy, error) {
	client := glue.NewFromConfig(cfg.cfg)
	out, err := client.GetResourcePolicy(ctx, &glue.GetResourcePolicyInput{})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "EntityNotFoundException" {
			return nil, nil
		}
		return nil, err
	}
	if out.PolicyInJson == nil || *out.PolicyInJson == "" {
		return nil, nil
	}
	doc := *out.PolicyInJson
	return &audit.GlueCatalogPolicy{
		GrantsWildcardPrincipal: policyGrantsPublicPrincipal(doc),
		Document:                doc,
	}, nil
}

// policyGrantsPublicPrincipal reports whether an IAM resource-policy
// document has an Allow statement naming an unconditional wildcard
// principal. The analysis is policy-type-agnostic (S3 bucket policies,
// Glue Data Catalog resource policies, …); bucketPolicyHasWildcardPrincipal
// (describer_s3.go) holds the implementation — this name just documents
// the reuse at the Glue call site.
func policyGrantsPublicPrincipal(doc string) bool {
	return bucketPolicyHasWildcardPrincipal(doc)
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
