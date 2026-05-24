package audit

import (
	"fmt"
	"sort"
	"strings"
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
