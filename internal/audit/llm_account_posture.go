package audit

import (
	"fmt"
	"sort"
	"strings"
)

// SummaryKeyType keys from iam:GetAccountSummary that drive the
// root-account credential posture facts. The values match the AWS SDK
// SummaryKeyType string constants (AccountAccessKeysPresent /
// AccountMFAEnabled) — the summary map is stored keyed by the stringified
// SDK type in discover/aws/account_posture.go, so we look them up by the
// same literal. Both are documented 0/1 flags.
const (
	summaryKeyAccountAccessKeysPresent = "AccountAccessKeysPresent"
	summaryKeyAccountMFAEnabled        = "AccountMFAEnabled"
)

// writeAccountPosture serialises the account-level posture block into
// the grounded prompt. The block names every fact the LLM needs to
// flag account-wide misconfigurations that aren't tied to a single
// CloudControl resource — default EBS encryption per region, IAM
// account summary (root MFA, root access keys, MFA-device counts),
// password-policy presence — alongside any probe errors so the model
// knows when to downgrade severity for incomplete data.
//
// Rendering is deterministic: all maps are walked in sorted key order
// so two audits over the same account produce byte-identical prompt
// fragments.
func writeAccountPosture(sb *strings.Builder, p *AccountPosture) {
	if p == nil {
		sb.WriteString("==== ACCOUNT POSTURE ====\n")
		sb.WriteString("(no account-posture probes were run for this audit)\n")
		sb.WriteString("==== END ACCOUNT POSTURE ====\n\n")
		return
	}

	sb.WriteString("==== ACCOUNT POSTURE ====\n")

	if len(p.EBSEncryptionByDefault) > 0 {
		sb.WriteString("EBS default encryption (per region):\n")
		regions := make([]string, 0, len(p.EBSEncryptionByDefault))
		for r := range p.EBSEncryptionByDefault {
			regions = append(regions, r)
		}
		sort.Strings(regions)
		for _, r := range regions {
			fmt.Fprintf(sb, "  %s: %t\n", r, p.EBSEncryptionByDefault[r])
		}
		sb.WriteString("\n")
	}

	if p.PasswordPolicyPresent != nil {
		fmt.Fprintf(sb, "IAM password policy configured: %t\n\n", *p.PasswordPolicyPresent)
	}

	// Root-account credential posture, read from the exact integer counters
	// iam:GetAccountSummary returns. AccountAccessKeysPresent and
	// AccountMFAEnabled are documented 0/1 flags, so `> 0` is an exact read,
	// not a heuristic. Each line is rendered ONLY when its counter is
	// actually present in the summary map — a missing key (e.g.
	// GetAccountSummary failed, recorded in p.Errors) is left unrendered so
	// the model treats it as unknown rather than silently compliant. These
	// are bare facts mirroring the IAM password-policy line above; the
	// firing rule (root keys present → CRITICAL, root MFA off → HIGH) lives
	// in buildGroundedPrompt's account-posture cluster.
	rootCredShown := false
	if v, ok := p.IAMSummary[summaryKeyAccountAccessKeysPresent]; ok {
		fmt.Fprintf(sb, "Root account access keys present: %t\n", v > 0)
		rootCredShown = true
	}
	if v, ok := p.IAMSummary[summaryKeyAccountMFAEnabled]; ok {
		fmt.Fprintf(sb, "Root account MFA enabled: %t\n", v > 0)
		rootCredShown = true
	}
	if rootCredShown {
		sb.WriteString("\n")
	}

	// IAM console-login MFA coverage from the credential report (CIS 1.10 /
	// FSBP IAM.5). Rendered ONLY when the probe ran (CredentialReport
	// non-nil) — a nil pointer (probe failed/didn't run, recorded in Errors)
	// renders nothing so the model treats console-MFA coverage as UNKNOWN,
	// never silently compliant. The offender list names only non-compliant
	// users (password_enabled=true AND mfa_active=false); the derived
	// "(evaluated N; without MFA M)" line is positive confirmation that
	// compliant console users were checked, not silence. The firing rule
	// lives in buildGroundedPrompt's account-posture cluster.
	if p.CredentialReport != nil {
		rep := p.CredentialReport
		if len(rep.ConsoleUsersWithoutMFA) > 0 {
			sb.WriteString("IAM console users WITHOUT MFA (human users with a console login password and NO MFA device — from iam:GetCredentialReport; only NON-COMPLIANT users are listed; the account root user is excluded, its MFA is the 'Root account MFA enabled' line above; programmatic-only / service users with no console password are not in scope):\n")
			for _, u := range rep.ConsoleUsersWithoutMFA {
				fmt.Fprintf(sb, "  - %s\n", u)
			}
		}
		fmt.Fprintf(sb, "(IAM users with a console password evaluated for MFA: %d; without MFA: %d)\n\n",
			rep.ConsolePasswordUsersEvaluated, len(rep.ConsoleUsersWithoutMFA))
	}

	if len(p.GlueCatalogPolicyByRegion) > 0 {
		sb.WriteString("Glue Data Catalog resource policy (per region; only regions that HAVE a policy are listed — grants_wildcard_principal=true means the whole catalog is open to Principal \"*\" with no scoping condition):\n")
		regions := make([]string, 0, len(p.GlueCatalogPolicyByRegion))
		for r := range p.GlueCatalogPolicyByRegion {
			regions = append(regions, r)
		}
		sort.Strings(regions)
		for _, r := range regions {
			pol := p.GlueCatalogPolicyByRegion[r]
			if pol == nil {
				continue
			}
			fmt.Fprintf(sb, "  %s: grants_wildcard_principal=%t\n", r, pol.GrantsWildcardPrincipal)
			if doc := strings.TrimSpace(pol.Document); doc != "" {
				fmt.Fprintf(sb, "    document: %s\n", doc)
			}
		}
		sb.WriteString("\n")
	}

	if len(p.TrailCoverageByRegion) > 0 {
		sb.WriteString("CloudTrail coverage (per audited region; false = no trail covers this region):\n")
		regions := make([]string, 0, len(p.TrailCoverageByRegion))
		for r := range p.TrailCoverageByRegion {
			regions = append(regions, r)
		}
		sort.Strings(regions)
		for _, r := range regions {
			fmt.Fprintf(sb, "  %s: %t\n", r, p.TrailCoverageByRegion[r])
		}
		sb.WriteString("\n")
	}

	if len(p.GuardDutyByRegion) > 0 {
		sb.WriteString("GuardDuty detector (per audited region; \"disabled\" = a detector exists but is suspended — a real regression; \"absent\" = no detector; \"enabled\" = active):\n")
		regions := make([]string, 0, len(p.GuardDutyByRegion))
		for r := range p.GuardDutyByRegion {
			regions = append(regions, r)
		}
		sort.Strings(regions)
		presentAnywhere := false
		for _, r := range regions {
			st := p.GuardDutyByRegion[r]
			fmt.Fprintf(sb, "  %s: %s\n", r, st)
			// "disabled" still counts as present — a detector exists, it
			// is merely suspended. Only "absent" means no detector. This
			// mirrors the AWS Config recorder gate below (present-anywhere)
			// so a disabled detector trips the per-region HIGH WITHOUT also
			// tripping the account-wide absent-everywhere WARNING.
			if st != "absent" {
				presentAnywhere = true
			}
		}
		fmt.Fprintf(sb, "  (GuardDuty detector present in at least one audited region: %t)\n\n", presentAnywhere)
	}

	if len(p.ConfigRecorderByRegion) > 0 {
		sb.WriteString("AWS Config recorder (per audited region; records_global_types=false means IAM/global resources are NOT captured in that region):\n")
		regions := make([]string, 0, len(p.ConfigRecorderByRegion))
		for r := range p.ConfigRecorderByRegion {
			regions = append(regions, r)
		}
		sort.Strings(regions)
		presentAnywhere := false
		globalAnywhere := false
		for _, r := range regions {
			st := p.ConfigRecorderByRegion[r]
			fmt.Fprintf(sb, "  %s: present=%t records_global_types=%t\n", r, st.Present, st.RecordsGlobalTypes)
			if st.Present {
				presentAnywhere = true
			}
			if st.RecordsGlobalTypes {
				globalAnywhere = true
			}
		}
		fmt.Fprintf(sb, "  (AWS Config recorder present in at least one audited region: %t)\n", presentAnywhere)
		fmt.Fprintf(sb, "  (global resource types recorded in at least one audited region: %t)\n\n", globalAnywhere)
	}

	if len(p.IAMSummary) > 0 {
		sb.WriteString("IAM account summary (selected keys from iam:GetAccountSummary):\n")
		keys := make([]string, 0, len(p.IAMSummary))
		for k := range p.IAMSummary {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(sb, "  %s: %d\n", k, p.IAMSummary[k])
		}
		sb.WriteString("\n")
	}

	if len(p.Errors) > 0 {
		sb.WriteString("Posture probe errors (data missing — be careful flagging account-wide gaps when the probe itself failed):\n")
		for _, e := range p.Errors {
			fmt.Fprintf(sb, "  - %s\n", e)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("==== END ACCOUNT POSTURE ====\n\n")
}
