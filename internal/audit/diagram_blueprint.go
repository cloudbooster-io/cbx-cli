package audit

import (
	"fmt"
	"sort"
	"strings"
)

// Blueprint-style box + chip helpers, plus finding-key assignment.
//
// "Keyed finding" model: every Finding gets a short stable identifier
// (C1, C2, …, H1, H2, …, W1, W2, …, I1, I2, …) based on its severity
// bucket. The same key is shown:
//   - in the chip stack inside the resource box, so a glance shows
//     which numbered notes apply to which resource,
//   - and in the NOTES table at the bottom of the report, so the
//     reader can resolve any key to the underlying finding title.
//
// Assignment is deterministic: sort findings by (severity rank,
// rule_id, title) then number within each severity bucket. Replay
// will produce identical keys.

// findingSeverityLetter returns the single-letter prefix used in keyed
// chip ids: C/H/W/I. Unknown severities fall back to "I" (info).
func findingSeverityLetter(sev string) string {
	switch sev {
	case SeverityCritical:
		return "C"
	case SeverityHigh:
		return "H"
	case SeverityWarning:
		return "W"
	case SeverityInfo:
		return "I"
	}
	return "I"
}

// FindingKey is a small struct used by the footnote renderer to draw
// the NOTES table. RuleID is the original Finding.RuleID so HTML
// chrome can deduplicate or jump-link.
type FindingKey struct {
	Key      string // "C1", "H4", …
	Severity string // "critical" | "high" | "warning" | "info"
	Title    string
	RuleID   string
}

// assignFindingKeys numbers findings within their severity bucket
// (deterministic — sorted by rule_id, then title). Returns:
//   - keyMap: finding fingerprint → key string. The fingerprint is
//     rule_id+"|"+title so two findings with the same rule_id but
//     different titles still get distinct keys.
//   - ordered: the keys themselves in display order (criticals first,
//     highs next, etc.) — used to drive the bottom NOTES table.
func assignFindingKeys(findings []Finding) (map[string]string, []FindingKey) {
	if len(findings) == 0 {
		return map[string]string{}, nil
	}
	// Severity rank — lower is more severe.
	rank := map[string]int{
		SeverityCritical: 0,
		SeverityHigh:     1,
		SeverityWarning:  2,
		SeverityInfo:     3,
	}
	sorted := make([]Finding, 0, len(findings))
	// Dedupe by fingerprint so the same finding emitted twice (e.g. by
	// two scanners) gets a single key.
	seen := map[string]bool{}
	for _, f := range findings {
		fp := findingFingerprint(f)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		sorted = append(sorted, f)
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := rank[sorted[i].Severity], rank[sorted[j].Severity]
		if ri != rj {
			return ri < rj
		}
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].Title < sorted[j].Title
	})
	keyMap := make(map[string]string, len(sorted))
	ordered := make([]FindingKey, 0, len(sorted))
	counts := map[string]int{}
	for _, f := range sorted {
		letter := findingSeverityLetter(f.Severity)
		counts[letter]++
		key := fmt.Sprintf("%s%d", letter, counts[letter])
		keyMap[findingFingerprint(f)] = key
		ordered = append(ordered, FindingKey{
			Key:      key,
			Severity: f.Severity,
			Title:    f.Title,
			RuleID:   f.RuleID,
		})
	}
	return keyMap, ordered
}

// findingFingerprint produces the dedupe key used by assignFindingKeys.
// Stable across reruns; works even when RuleID is empty (some adapters
// emit free-form findings without an id).
func findingFingerprint(f Finding) string {
	return f.RuleID + "|" + f.Title
}

// chipsByResource walks findings and returns a URN → ["C1","H3"]
// mapping ordered by severity (criticals first). Findings whose
// Resource field is set are matched against a resource URN or ID;
// findings without a Resource land on no box (they'll still appear
// in the bottom NOTES table).
//
// Only the top-severity chips are kept per resource (max 4 by
// convention — the box draws up to 4 chips, then a "+N" overflow).
// We over-collect here and let the box renderer cap on display.
func chipsByResource(
	findings []Finding,
	keyMap map[string]string,
	byURN map[string]DiscoveredResource,
	idToURN map[string]string,
) map[string][]string {
	out := map[string][]string{}
	if len(findings) == 0 {
		return out
	}
	rank := map[string]int{
		SeverityCritical: 0,
		SeverityHigh:     1,
		SeverityWarning:  2,
		SeverityInfo:     3,
	}
	// Bucket by URN first so we can sort each bucket consistently.
	type tagged struct {
		Key string
		Sev string
	}
	buckets := map[string][]tagged{}
	for _, f := range findings {
		key, ok := keyMap[findingFingerprint(f)]
		if !ok {
			continue
		}
		urn := resolveResourceURN(f.Resource, byURN, idToURN)
		if urn == "" {
			continue
		}
		buckets[urn] = append(buckets[urn], tagged{Key: key, Sev: f.Severity})
	}
	for urn, ts := range buckets {
		sort.SliceStable(ts, func(i, j int) bool {
			ri, rj := rank[ts[i].Sev], rank[ts[j].Sev]
			if ri != rj {
				return ri < rj
			}
			return ts[i].Key < ts[j].Key
		})
		// Dedup identical keys (defensive — assignFindingKeys already
		// gives one key per fingerprint, but the same fingerprint can
		// be attached to several resources, and we want at most one
		// chip per key per box).
		seen := map[string]bool{}
		for _, t := range ts {
			if seen[t.Key] {
				continue
			}
			seen[t.Key] = true
			out[urn] = append(out[urn], t.Key)
		}
	}
	return out
}

// resolveResourceURN takes a Finding.Resource field (which can be a
// URN, an ID, or an ARN) and returns the matching discovered URN, or
// "" if no match. Handles the three shapes the scanners emit:
//   - URN directly ("aws://…/AWS::S3::Bucket/cbx-audit-plain")
//   - Bare AWS resource ID ("cbx-audit-plain", "i-007e…")
//   - ARN ("arn:aws:s3:::cbx-audit-plain") — we match by trailing id
func resolveResourceURN(ref string, byURN map[string]DiscoveredResource, idToURN map[string]string) string {
	if ref == "" {
		return ""
	}
	if _, ok := byURN[ref]; ok {
		return ref
	}
	if urn, ok := idToURN[ref]; ok {
		return urn
	}
	// ARN: keep the last "/" or ":" segment.
	if strings.Contains(ref, ":") || strings.Contains(ref, "/") {
		last := ref
		if idx := strings.LastIndexAny(ref, ":/"); idx >= 0 {
			last = ref[idx+1:]
		}
		if urn, ok := idToURN[last]; ok {
			return urn
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────
// Resource box renderer — 200×56 Blueprint style.
// ─────────────────────────────────────────────────────────────────────

// renderResourceBox emits a 200×56 white box with the AWS icon on the
// left (40px), the friendly name (bold) and the AWS resource id (mono)
// stacked on the right, and a severity-keyed chip stack pinned to the
// bottom-right inside the box. Up to 4 chips are visible; the rest
// collapse into a small "+N" indicator.
func renderResourceBox(r DiscoveredResource, x, y int, chips []string) string {
	var b strings.Builder
	// Card body — .bp-node opts the white fill into theming (see
	// svgThemeStyle; #FFFFFF is deliberately not remapped globally).
	fmt.Fprintf(&b,
		`<rect class="bp-node" x="%d" y="%d" width="%d" height="%d" fill="#FFFFFF" stroke="#1C1917" stroke-width="0.9"/>`,
		x, y, boxW, boxH,
	)
	// AWS icon — 40px, left-aligned with 8px inset
	b.WriteString(iconForCFNType(r.Type, x+8, y+8, boxIconSize, monogramFor(r.Type)))
	// Name (bold) + ID (mono) — stacked, right of the icon
	name := friendlyKind(r.Type)
	fmt.Fprintf(&b,
		`<text x="%d" y="%d" font-size="11.5" font-weight="700" fill="#1C1917" font-family="Inter, ui-sans-serif, sans-serif">%s</text>`,
		x+56, y+22, svgEscape(svgTruncate(name, 22)),
	)
	if id := shortResourceID(r.ID); id != "" {
		fmt.Fprintf(&b,
			`<text x="%d" y="%d" font-size="9.5" fill="#57534E">%s</text>`,
			x+56, y+38, svgEscape(svgTruncate(id, 22)),
		)
	}
	if len(chips) > 0 {
		b.WriteString(renderChipStack(x+boxW-4, y+boxH-16, chips))
	}
	return b.String()
}

// renderChipStack emits up to 4 severity-coloured 20×12 pills laid
// out right-to-left from (rightX, y). Anything beyond the cap goes
// into a small "+N" marker to the left of the stack.
func renderChipStack(rightX, y int, chips []string) string {
	const maxChips = 4
	const chipW = 22 // 20 chip + 2 gap
	shown := chips
	overflow := 0
	if len(shown) > maxChips {
		overflow = len(shown) - maxChips
		shown = shown[:maxChips]
	}
	var b strings.Builder
	// Lay out right-to-left so the chips snap to the right edge of the box.
	x := rightX - len(shown)*chipW + 2
	for _, ck := range shown {
		colour := severityChipColour(ck)
		// .bp-chip keeps the pill out of svgThemeStyle's fill remapping —
		// it must stay identical in both themes so it keeps matching the
		// sidebar / NOTES pills, which use the same static palette.
		fmt.Fprintf(&b,
			`<rect class="bp-chip" x="%d" y="%d" width="20" height="12" fill="%s"/>`+
				`<text x="%d" y="%d" text-anchor="middle" font-size="8.5" font-weight="800" fill="#FFFFFF" font-family="'JetBrains Mono', ui-monospace, monospace">%s</text>`,
			x, y, colour,
			x+10, y+9, ck,
		)
		x += chipW
	}
	if overflow > 0 {
		fmt.Fprintf(&b,
			`<text x="%d" y="%d" text-anchor="end" font-size="8.5" font-weight="700" fill="#57534E">+%d</text>`,
			rightX-len(shown)*chipW, y+10, overflow,
		)
	}
	return b.String()
}

// severityChipColour returns the Blueprint chip-fill hex for a given
// keyed chip ("C1", "H7", "W3", "I9"). Falls back to grey if the key
// doesn't carry a recognisable severity prefix.
func severityChipColour(key string) string {
	if key == "" {
		return "#78716C"
	}
	switch key[0] {
	case 'C':
		return "#B91C1C"
	case 'H':
		return "#C2410C"
	case 'W':
		return "#A16207"
	case 'I':
		return "#1D4ED8"
	}
	return "#78716C"
}

// shortResourceID returns a display-friendly id. ARNs collapse to
// their trailing name segment ("arn:aws:elb:.../app/cbx-audit-alb/…"
// → "cbx-audit-alb"); plain ids pass through.
func shortResourceID(id string) string {
	if id == "" {
		return ""
	}
	if strings.HasPrefix(id, "arn:") {
		// ARN format: arn:aws:<svc>:<region>:<acct>:<rest>
		parts := strings.SplitN(id, ":", 6)
		if len(parts) == 6 {
			rest := parts[5]
			// loadbalancer/app/<name>/<hash>, function:<name>, etc.
			if i := strings.LastIndexAny(rest, "/:"); i >= 0 {
				// Pick the segment that looks most like a name
				// (alphanum + dashes, not a long random hash).
				segs := strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == ':' })
				if len(segs) > 0 {
					// Prefer the second-to-last segment when the
					// last looks like a hash.
					last := segs[len(segs)-1]
					if len(last) > 14 && !strings.ContainsAny(last, "-_") && len(segs) >= 2 {
						return segs[len(segs)-2]
					}
					return last
				}
				return rest[i+1:]
			}
			return rest
		}
	}
	return id
}

// severityChipColourBySeverity returns the same palette but keyed by
// the underlying Finding.Severity string — used by the footnote table.
func severityChipColourBySeverity(sev string) string {
	switch sev {
	case SeverityCritical:
		return "#B91C1C"
	case SeverityHigh:
		return "#C2410C"
	case SeverityWarning:
		return "#A16207"
	case SeverityInfo:
		return "#1D4ED8"
	}
	return "#78716C"
}

// ─────────────────────────────────────────────────────────────────────
// Subnet synthesis (graceful degradation when discovery misses Subnets)
// ─────────────────────────────────────────────────────────────────────

// synthesizeMissingSubnets walks the resource list, collects every
// subnet-id referenced by another resource (DBSubnetGroup, ALB,
// Lambda.VpcConfig, SubnetRouteTableAssociation, …), and adds a
// placeholder AWS::EC2::Subnet record for any id that wasn't already
// discovered. Returns a new slice — the original is not mutated.
//
// Why: CloudControl's ListResources for AWS::EC2::Subnet has been
// observed to silently return empty in some accounts/regions even
// when the subnets exist (permission gate, transient regional API
// degradation, etc.). Without the placeholders the renderer can't
// build the AZ/Subnet hierarchy and the diagram collapses to a flat
// lateral lane. With them we still get the right topology — just
// without CIDR / AvailabilityZone labels on the synthesized ones.
//
// Synthesized resources are marked Inputs["_synthesized"]=true so
// the renderer can render them with a faint "inferred" hint.
func synthesizeMissingSubnets(resources []DiscoveredResource) []DiscoveredResource {
	known := map[string]bool{}
	for _, r := range resources {
		if r.Type == "AWS::EC2::Subnet" && r.ID != "" {
			known[r.ID] = true
		}
	}
	// Find every subnet id referenced by another resource. The
	// region we synthesize the URN under doesn't have to match the
	// real subnet's region — the URN only needs to be unique so
	// the registry can index it. We default to "unknown" to make
	// the synthesis visible to anyone digging in the JSON.
	wanted := map[string]bool{}
	add := func(id string) {
		if id != "" && !known[id] {
			wanted[id] = true
		}
	}
	addList := func(v interface{}) {
		raw, _ := v.([]interface{})
		for _, x := range raw {
			if id, ok := x.(string); ok {
				add(id)
			}
		}
	}
	for _, r := range resources {
		switch r.Type {
		case "AWS::EC2::SubnetRouteTableAssociation":
			if sid, ok := r.Inputs["SubnetId"].(string); ok {
				add(sid)
			}
		case "AWS::RDS::DBSubnetGroup":
			addList(r.Inputs["SubnetIds"])
			if grp, ok := r.Inputs["DBSubnetGroup"].(map[string]interface{}); ok {
				if subs, ok := grp["Subnets"].([]interface{}); ok {
					for _, x := range subs {
						if m, ok := x.(map[string]interface{}); ok {
							if id, ok := m["SubnetIdentifier"].(string); ok {
								add(id)
							}
						}
					}
				}
			}
		case "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer":
			addList(r.Inputs["Subnets"])
		case "AWS::EC2::Instance":
			if sid, ok := r.Inputs["SubnetId"].(string); ok {
				add(sid)
			}
		case "AWS::Lambda::Function":
			if vc, ok := r.Inputs["VpcConfig"].(map[string]interface{}); ok {
				addList(vc["SubnetIds"])
			}
		case "AWS::RDS::DBInstance":
			if grp, ok := r.Inputs["DBSubnetGroup"].(map[string]interface{}); ok {
				if subs, ok := grp["Subnets"].([]interface{}); ok {
					for _, x := range subs {
						if m, ok := x.(map[string]interface{}); ok {
							if id, ok := m["SubnetIdentifier"].(string); ok {
								add(id)
							}
						}
					}
				}
			}
		}
	}
	if len(wanted) == 0 {
		return resources
	}
	// Pick a VPC id from the resources to attribute the synthesized
	// subnets to. If there's exactly one VPC discovered, use it;
	// otherwise leave VpcId empty (the classifier's vpcByID will
	// synthesize a placeholder VPC too).
	var vpcID string
	vpcCount := 0
	for _, r := range resources {
		if r.Type == "AWS::EC2::VPC" {
			vpcID = r.ID
			vpcCount++
		}
	}
	if vpcCount != 1 {
		vpcID = ""
	}
	out := make([]DiscoveredResource, len(resources), len(resources)+len(wanted))
	copy(out, resources)
	ids := make([]string, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic synthesis order
	for _, id := range ids {
		inputs := map[string]interface{}{"_synthesized": true}
		if vpcID != "" {
			inputs["VpcId"] = vpcID
		}
		out = append(out, DiscoveredResource{
			Type:   "AWS::EC2::Subnet",
			URN:    "aws://synth/AWS::EC2::Subnet/" + id,
			ID:     id,
			Inputs: inputs,
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Bottom IDENTITY · SECRETS · OBSERVABILITY strip
// ─────────────────────────────────────────────────────────────────────

// accountScopedResources pulls the lateral buckets that Blueprint
// shows in the bottom strip rather than in the right-side DATA·STATE
// column. Returned in a stable display order (Identity first, then
// Secrets/Security, then Observability/Management).
func accountScopedResources(buckets []lateralBucket) []DiscoveredResource {
	order := map[string]int{
		"Identity":      0,
		"Security":      1,
		"Secrets":       2,
		"Observability": 3,
		"Management":    4,
		"Logging":       5,
	}
	type tagged struct {
		bucket int
		res    DiscoveredResource
	}
	var ts []tagged
	for _, b := range buckets {
		rank, ok := order[b.Title]
		if !ok {
			continue
		}
		for _, r := range b.Resources {
			ts = append(ts, tagged{bucket: rank, res: r})
		}
	}
	sort.SliceStable(ts, func(i, j int) bool {
		if ts[i].bucket != ts[j].bucket {
			return ts[i].bucket < ts[j].bucket
		}
		return ts[i].res.ID < ts[j].res.ID
	})
	out := make([]DiscoveredResource, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.res)
	}
	return out
}

// bottomStripHeight returns the height the strip will consume at the
// given inner width. The strip lays the boxes out in a grid sized to
// fit `boxW` (200) wide cells with 16px gaps.
func bottomStripHeight(resources []DiscoveredResource, innerW int) int {
	if len(resources) == 0 {
		return 0
	}
	cellW := boxW + 16
	cols := innerW / cellW
	if cols < 1 {
		cols = 1
	}
	rows := (len(resources) + cols - 1) / cols
	return 24 + rows*(boxH+12) // 24px header
}

// renderBottomStrip emits the account-scoped row across the bottom of
// the diagram with a dashed separator above it and the boxes laid out
// in a grid.
func renderBottomStrip(sb *strings.Builder, resources []DiscoveredResource, x, y, innerW int, pr *positionRegistry) {
	// Dashed separator line — visually parts the in-VPC area from the
	// account-scoped strip below it.
	fmt.Fprintf(sb,
		`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#A8A29E" stroke-width="0.8" stroke-dasharray="2 2"/>`,
		x, y-12, x+innerW, y-12,
	)
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="9.5" font-weight="700" fill="#57534E" letter-spacing="0.12em">IDENTITY · SECRETS · OBSERVABILITY (account-scoped)</text>`,
		x, y+4,
	)
	cellW := boxW + 16
	cols := innerW / cellW
	if cols < 1 {
		cols = 1
	}
	for i, r := range resources {
		col := i % cols
		row := i / cols
		bx := x + col*cellW
		by := y + 12 + row*(boxH+12)
		pr.registerBox(r.URN, bx, by, boxW, boxH)
		sb.WriteString(renderResourceBox(r, bx, by, pr.chipsFor(r.URN)))
	}
}
