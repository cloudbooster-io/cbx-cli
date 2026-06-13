package audit

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// orphanProvider flags resources that the discovery layer found running but
// nothing else references — unattached EBS volumes, unassociated Elastic
// IPs, IAM roles never assumed, empty S3 buckets, security groups with no
// consumer. It is wired into both MockScanners() and AllScanners() so the
// `cbx audit aws` subcommand picks it up (MockScanners: true is how that
// path stays free of external-CLI adapters per plan §7.10).
//
// State-mode and source-mode audits silently no-op: the provider filters
// to CFN-shaped Types ("AWS::Service::Resource") at Scan time, which only
// the live-AWS discovery layer emits. The same Scan can therefore safely
// be invoked in any mode.
//
// Findings are info-severity by design. Orphans are hygiene/cost signals,
// not security issues — the user decides whether to delete. A cost
// estimate is folded into the Description when the resource size /
// pricing is knowable from CFN properties alone; we deliberately avoid
// the Pricing API to keep the audit free of additional outbound calls.
type orphanProvider struct{}

func (orphanProvider) Name() string { return "orphan" }

func (orphanProvider) SupportsSource() bool { return false }

func (orphanProvider) ScanSource(_ context.Context, _ string) ([]Finding, error) {
	return nil, ErrSourceModeUnsupported
}

func (orphanProvider) Scan(_ context.Context, resources []Resource) ([]Finding, error) {
	aws := make([]Resource, 0, len(resources))
	for _, r := range resources {
		if strings.HasPrefix(r.Type, "AWS::") {
			aws = append(aws, r)
		}
	}
	if len(aws) == 0 {
		return nil, nil
	}

	var findings []Finding
	findings = append(findings, detectUnattachedEBS(aws)...)
	findings = append(findings, detectUnassociatedEIP(aws)...)
	findings = append(findings, detectUnusedIAMRoles(aws)...)
	findings = append(findings, detectEmptyS3Buckets(aws)...)
	findings = append(findings, detectUnreferencedSecurityGroups(aws)...)
	return findings, nil
}

// --- detectors ---

// detectUnattachedEBS flags EC2 volumes in "available" state (i.e. not
// attached to any instance). The CFN Properties expose Attachments and
// VolumeType + Size, so the monthly cost estimate is back-of-envelope
// using gp3 rates ($0.08/GB-month) — accurate within the 80/20 of typical
// orphans. Cold storage tiers (sc1/st1) will be over-estimated, but the
// signal is "you have unused capacity," not "the bill is exactly X."
func detectUnattachedEBS(resources []Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "AWS::EC2::Volume" {
			continue
		}
		if hasAttachments(r) {
			continue
		}
		size := readFloat(r.Inputs, "Size")
		cost := size * 0.08
		out = append(out, Finding{
			RuleID:      "ORPHAN-EBS-UNATTACHED",
			Title:       "Unattached EBS volume",
			Description: fmt.Sprintf("Volume %s is not attached to any instance. %s", r.ID, formatMonthlyCost(cost)),
			Severity:    SeverityInfo,
			Resource:    r.URN,
			Service:     "EC2",
			Remediation: "Snapshot the volume if needed for recovery, then delete it.",
		})
	}
	return out
}

// hasAttachments returns true when an EBS Volume's Attachments list is
// non-empty. CloudControl returns the list-of-pairs CFN shape; an empty
// list (or missing key) means orphan.
func hasAttachments(r Resource) bool {
	raw, ok := r.Inputs["Attachments"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case []any:
		return len(v) > 0
	}
	return false
}

// detectUnassociatedEIP flags Elastic IPs with no AssociationId. AWS bills
// $0.005/hour for an unassociated EIP (≈ $3.65/month assuming a 30-day
// month); associated EIPs are free. Flat estimate — there's no size knob.
func detectUnassociatedEIP(resources []Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "AWS::EC2::EIP" {
			continue
		}
		if assoc := readString(r.Inputs, "AssociationId"); assoc != "" {
			continue
		}
		out = append(out, Finding{
			RuleID:      "ORPHAN-EIP-UNASSOCIATED",
			Title:       "Unassociated Elastic IP",
			Description: fmt.Sprintf("Elastic IP %s is not associated with any resource. %s", r.ID, formatMonthlyCost(3.65)),
			Severity:    SeverityInfo,
			Resource:    r.URN,
			Service:     "EC2",
			Remediation: "Release the address unless it's being held intentionally.",
		})
	}
	return out
}

// iamRoleStaleAfter is the cutoff for the "unused IAM role" finding. AWS
// reports LastUsedDate to a 4-hour resolution; 90 days is the canonical
// "this role hasn't been touched" threshold in CIS / AWS hygiene guides.
const iamRoleStaleAfter = 90 * 24 * time.Hour

// detectUnusedIAMRoles emits a finding for any role whose
// cb_describer_last_used is nil (never used) or older than 90 days. The
// describer populates the field as ISO 8601 string or nil; we don't
// re-fetch from IAM here. Roles without the field at all (e.g. describer
// hit AccessDenied) are skipped silently — surfacing those as findings
// would conflate "unused" with "couldn't read."
func detectUnusedIAMRoles(resources []Resource) []Finding {
	var out []Finding
	now := time.Now().UTC()
	for _, r := range resources {
		if r.Type != "AWS::IAM::Role" {
			continue
		}
		raw, ok := r.Inputs["cb_describer_last_used"]
		if !ok {
			continue
		}
		var description string
		switch v := raw.(type) {
		case nil:
			description = fmt.Sprintf("Role %s has never been assumed (LastUsedDate is empty).", r.ID)
		case string:
			t, err := time.Parse("2006-01-02T15:04:05Z", v)
			if err != nil || now.Sub(t) < iamRoleStaleAfter {
				continue
			}
			description = fmt.Sprintf("Role %s was last assumed on %s (%d days ago).", r.ID, v, int(now.Sub(t).Hours()/24))
		default:
			continue
		}
		out = append(out, Finding{
			RuleID:      "ORPHAN-IAM-ROLE-UNUSED",
			Title:       "IAM role unused for 90+ days",
			Description: description,
			Severity:    SeverityInfo,
			Resource:    r.URN,
			Service:     "IAM",
			Remediation: "Verify the role isn't reserved for break-glass / disaster recovery, then delete it.",
		})
	}
	return out
}

// s3BucketStaleAfter guards against flagging freshly-created buckets a
// human just made and is about to populate. 30 days is the conventional
// hygiene window for "this looks abandoned."
const s3BucketStaleAfter = 30 * 24 * time.Hour

// detectEmptyS3Buckets flags buckets with zero objects AND a creation
// date older than 30 days. Both signals are required — an empty bucket
// younger than 30 days is most likely in active provisioning; an older
// bucket without the object probe is most likely missing IAM permissions
// for s3:ListBucket and we'd rather skip than false-positive.
//
// Both fields come from the s3 describer: cb_describer_has_objects from
// a ListObjectsV2(MaxKeys=1) probe; cb_describer_creation_date from a
// once-cached ListBuckets call (CloudControl's AWS::S3::Bucket schema
// doesn't expose CreationDate as a read-only property). When either
// field is missing, the bucket is skipped silently — typically because
// the describer hit AccessDenied and the diagnose path will already
// have logged it.
func detectEmptyS3Buckets(resources []Resource) []Finding {
	var out []Finding
	now := time.Now().UTC()
	for _, r := range resources {
		if r.Type != "AWS::S3::Bucket" {
			continue
		}
		hasObjs, ok := readBool(r.Inputs, "cb_describer_has_objects")
		if !ok || hasObjs {
			continue
		}
		created := readString(r.Inputs, "cb_describer_creation_date")
		if created == "" {
			continue
		}
		t, err := parseCFNTimestamp(created)
		if err != nil || now.Sub(t) < s3BucketStaleAfter {
			continue
		}
		out = append(out, Finding{
			RuleID:      "ORPHAN-S3-EMPTY",
			Title:       "Empty S3 bucket older than 30 days",
			Description: fmt.Sprintf("Bucket %s is empty and was created on %s (%d days ago).", r.ID, created, int(now.Sub(t).Hours()/24)),
			Severity:    SeverityInfo,
			Resource:    r.URN,
			Service:     "S3",
			Remediation: "Confirm the bucket isn't reserved as a destination for future writes, then delete it.",
		})
	}
	return out
}

// sgIDPattern matches an AWS security-group identifier anywhere in a
// resource's properties tree. The detect-by-shape approach is the v1
// trade-off documented in plan §7.9 — robust to schema drift across
// CFN types (ENIs, RDS, Lambda VpcConfig, ELB, etc.) at the cost of a
// possible false-negative when an SG is referenced only by name rather
// than ID. Real-world references in CFN-shape JSON are ID-based.
var sgIDPattern = regexp.MustCompile(`sg-[0-9a-f]{8,17}`)

// detectUnreferencedSecurityGroups walks the entire discovered resource
// set and notes which SG IDs appear in any non-SG resource's Inputs.
// Any SG whose ID isn't in that set is flagged. The default VPC SG
// (GroupName == "default") is always excluded — AWS forbids deleting it.
func detectUnreferencedSecurityGroups(resources []Resource) []Finding {
	referenced := map[string]struct{}{}
	for _, r := range resources {
		if r.Type == "AWS::EC2::SecurityGroup" {
			continue
		}
		collectSGRefs(r.Inputs, referenced)
	}

	var out []Finding
	for _, r := range resources {
		if r.Type != "AWS::EC2::SecurityGroup" {
			continue
		}
		if name := readString(r.Inputs, "GroupName"); name == "default" {
			continue
		}
		sgID := readString(r.Inputs, "GroupId")
		if sgID == "" {
			// Fall back to ID — CC's primary identifier is the SG ID for
			// this resource type.
			sgID = r.ID
		}
		if sgID == "" {
			continue
		}
		// A security group always references itself in its own egress
		// rules; the self-reference doesn't count as external use.
		// We collected references from non-SG resources only, so the
		// referenced set is clean — no extra dedupe needed here.
		if _, ok := referenced[sgID]; ok {
			continue
		}
		out = append(out, Finding{
			RuleID:      "ORPHAN-SG-UNREFERENCED",
			Title:       "Unreferenced security group",
			Description: fmt.Sprintf("Security group %s (%s) is not referenced by any discovered resource.", sgID, readString(r.Inputs, "GroupName")),
			Severity:    SeverityInfo,
			Resource:    r.URN,
			Service:     "EC2",
			Remediation: "Verify nothing outside the discovered resource set uses this group, then delete it.",
		})
	}
	return out
}

// collectSGRefs walks any JSON-like value, pulling SG IDs out of every
// string it encounters. The recursive scan accepts a small amount of
// over-collection (a string field that happens to contain "sg-..."
// substring still counts) in exchange for being schema-agnostic.
func collectSGRefs(v any, out map[string]struct{}) {
	switch x := v.(type) {
	case string:
		for _, m := range sgIDPattern.FindAllString(x, -1) {
			out[m] = struct{}{}
		}
	case map[string]any:
		for _, child := range x {
			collectSGRefs(child, out)
		}
	case []any:
		for _, child := range x {
			collectSGRefs(child, out)
		}
	}
}

// --- shared helpers ---

func readString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func readBool(m map[string]any, key string) (bool, bool) {
	if m == nil {
		return false, false
	}
	raw, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := raw.(bool)
	return b, ok
}

func readFloat(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}

func formatMonthlyCost(usd float64) string {
	if usd <= 0 {
		return ""
	}
	return fmt.Sprintf("Est. cost: $%.2f/mo.", usd)
}

// parseCFNTimestamp accepts the two formats CloudFormation emits for
// timestamp-typed properties: ISO 8601 with explicit UTC suffix
// ("2024-01-15T10:30:00Z") and the same with a fractional-second portion
// ("2024-01-15T10:30:00.000Z"). Anything else is treated as a parse
// failure and the caller skips the resource conservatively.
func parseCFNTimestamp(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02T15:04:05Z", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02T15:04:05.000Z", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
