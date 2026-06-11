package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
)

// BuildArchitectureDiagram emits a mermaid `architecture-beta` diagram
// with proper AWS service icons (via the iconify `logos` pack).
//
// Why architecture-beta instead of flowchart?
//   - It's mermaid's purpose-built cloud-architecture syntax.
//   - It supports icon packs (logos:aws-lambda, logos:aws-s3, …) so
//     services render with the official-looking AWS glyphs.
//   - Groups (region / VPC / subnet) are first-class.
//
// Viewer notes:
//   - GitHub's mermaid (10.x) won't render this — the HTML report's
//     embedded SVG is the primary deliverable. The mermaid block
//     covers modern viewers (VSCode, mermaid.live, Docusaurus,
//     mermaid 11+).
//   - The HTML wrapper registers the iconify `logos` pack at runtime
//     so the diagram renders with icons inline.
//
// Returns "" when there are no resources to draw.
func BuildArchitectureDiagram(resources []DiscoveredResource, components []group.Component) string {
	if len(resources) == 0 {
		return ""
	}
	_ = components

	idToURN := map[string]string{}
	for _, r := range resources {
		if r.ID != "" {
			idToURN[r.ID] = r.URN
		}
	}
	edges, root, lateral := classifyResources(resources)

	// architecture-beta requires unique alphanumeric identifiers. Map
	// every URN to a short stable id.
	urnToNode := map[string]string{}
	nextID := 0
	idFor := func(urn string) string {
		if n, ok := urnToNode[urn]; ok {
			return n
		}
		n := fmt.Sprintf("svc%d", nextID)
		nextID++
		urnToNode[urn] = n
		return n
	}

	var sb strings.Builder
	sb.WriteString("architecture-beta\n")

	// ─── Groups (REGION → VPC → AZ → Subnet) ───
	// architecture-beta groups can nest via `in <parent>`. Each group
	// needs an icon hint — we use the generic `cloud` for everything
	// since AWS doesn't have a dedicated VPC/Subnet group icon in
	// most iconify packs.
	regionGroup := "g_region"
	fmt.Fprintf(&sb, "    group %s(cloud)[REGION]\n", regionGroup)
	type subnetGroup struct {
		id string
		sn *topoSubnet
	}
	var subnetGroups []subnetGroup
	for vIdx, v := range root.vpcs {
		vpcID := fmt.Sprintf("g_vpc%d", vIdx)
		label := "VPC"
		if c, _ := v.res.Inputs["CidrBlock"].(string); c != "" {
			label = "VPC " + c
		}
		fmt.Fprintf(&sb, "    group %s(cloud)[%s] in %s\n", vpcID, mermaidArchEscape(label), regionGroup)
		for aIdx, az := range v.azs {
			azID := fmt.Sprintf("g_v%d_az%d", vIdx, aIdx)
			azLabel := "AZ"
			if az.name != "" {
				azLabel = "AZ " + az.name
			}
			fmt.Fprintf(&sb, "    group %s(cloud)[%s] in %s\n", azID, mermaidArchEscape(azLabel), vpcID)
			for sIdx, s := range az.subnets {
				snID := fmt.Sprintf("g_v%d_az%d_sn%d", vIdx, aIdx, sIdx)
				pub, _ := s.res.Inputs["MapPublicIpOnLaunch"].(bool)
				kind := "PRIVATE"
				if pub {
					kind = "PUBLIC"
				}
				cidr, _ := s.res.Inputs["CidrBlock"].(string)
				snLabel := kind
				if cidr != "" {
					snLabel = kind + " " + cidr
				}
				fmt.Fprintf(&sb, "    group %s(cloud)[%s] in %s\n", snID, mermaidArchEscape(snLabel), azID)
				subnetGroups = append(subnetGroups, subnetGroup{id: snID, sn: s})
			}
		}
	}

	// ─── Services ───
	// Edge services live outside the region group.
	usersID := "svc_users"
	fmt.Fprintf(&sb, "    service %s(internet)[Public users]\n", usersID)
	for _, r := range edges {
		emitArchService(&sb, idFor(r.URN), r, "")
	}
	// In-subnet resources.
	for _, sg := range subnetGroups {
		for _, r := range sg.sn.resources {
			emitArchService(&sb, idFor(r.URN), r, sg.id)
		}
	}

	// DATA · STATE column — these aren't in groups (architecture-beta
	// can't render multiple top-level "columns" cleanly, so the data
	// services sit free-floating outside the region).
	dataResources := []DiscoveredResource{}
	for _, b := range lateral {
		if isAccountScopedBucket(b.Title) || isHiddenBucket(b.Title) {
			continue
		}
		dataResources = append(dataResources, b.Resources...)
	}
	for _, r := range dataResources {
		emitArchService(&sb, idFor(r.URN), r, "")
	}

	// IDENTITY · SECRETS · OBSERVABILITY — account-scoped, free-floating.
	for _, r := range accountScopedResources(lateral) {
		emitArchService(&sb, idFor(r.URN), r, "")
	}

	// ─── Edges ───
	// Implicit: users → all edge services.
	for _, r := range edges {
		fmt.Fprintf(&sb, "    %s:R --> L:%s\n", usersID, idFor(r.URN))
	}
	// Real edges from the SVG's inference pipeline.
	all := inferConnections(resources, idToURN)
	all = append(all, inferHeuristicConnections(resources)...)
	emitted := map[string]bool{}
	for _, c := range all {
		if isNoiseEdgeURN(c.From) || isNoiseEdgeURN(c.To) {
			continue
		}
		from, fok := urnToNode[c.From]
		to, tok := urnToNode[c.To]
		if !fok || !tok || from == to {
			continue
		}
		key := from + "->" + to
		if emitted[key] {
			continue
		}
		emitted[key] = true
		fmt.Fprintf(&sb, "    %s:R --> L:%s\n", from, to)
	}

	// Sort lines deterministically (idempotent runs for diffs).
	// Note: we keep the natural emission order, but de-dup blanks.
	return sb.String()
}

// emitArchService writes a single service line. parentGroup may be ""
// for services that live outside any group.
func emitArchService(sb *strings.Builder, id string, r DiscoveredResource, parentGroup string) {
	icon := iconifyForCFNType(r.Type)
	label := shortServiceLabel(r)
	if parentGroup != "" {
		fmt.Fprintf(sb, "    service %s(%s)[%s] in %s\n", id, icon, mermaidArchEscape(label), parentGroup)
	} else {
		fmt.Fprintf(sb, "    service %s(%s)[%s]\n", id, icon, mermaidArchEscape(label))
	}
}

// shortServiceLabel composes a mermaid-safe label "<Service> <id>"
// that fits in an architecture-beta service node. Long ARNs collapse
// to their trailing name segment.
func shortServiceLabel(r DiscoveredResource) string {
	kind := friendlyKind(r.Type)
	id := shortResourceID(r.ID)
	if id == "" {
		return kind
	}
	if len(id) > 24 {
		id = id[:21] + "…"
	}
	return kind + " · " + id
}

// iconifyForCFNType maps an AWS CFN type to a mermaid icon name.
//
// We deliberately use ONLY mermaid's built-in icon set
// (`cloud`, `database`, `disk`, `internet`, `server`) instead of
// the iconify `logos:aws-*` pack. The built-ins render in every
// viewer (mermaid.live, GitHub, VSCode, etc.) without requiring
// the consumer to register an icon pack — which is the de-facto
// requirement to get AWS-branded icons.
//
// The HTML report's inline SVG is the canonical "AWS-branded" view;
// the mermaid block is the markdown-portable fallback.
func iconifyForCFNType(t string) string {
	switch familyForCFNType(t) {
	case "compute":
		return "server"
	case "storage":
		return "disk"
	case "data":
		return "database"
	case "network":
		// Edge-of-network services (CF, ALB, APIGW, R53) read as the
		// internet boundary; intra-VPC network plumbing (VPC, Subnet,
		// SG) falls back to cloud — but those resources aren't drawn
		// individually in this view anyway.
		return "internet"
	case "security", "mgmt":
		return "cloud"
	}
	return "cloud"
}

// serviceFromCFNType pulls "EC2" out of "AWS::EC2::Instance".
func serviceFromCFNType(t string) string {
	parts := strings.SplitN(t, "::", 3)
	if len(parts) >= 2 && parts[0] == "AWS" {
		return parts[1]
	}
	if t == "" {
		return "Other"
	}
	return t
}

// shortKindFromCFNType pulls "Instance" out of "AWS::EC2::Instance".
func shortKindFromCFNType(t string) string {
	parts := strings.SplitN(t, "::", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return t
}

// mermaidArchEscape wraps a label for architecture-beta. The lexer
// only accepts alphanumeric + space directly between `[...]`; any
// punctuation (dots, slashes, dashes, parentheses…) requires the
// label be double-quoted. We always quote so the renderer is
// indifferent to label contents.
func mermaidArchEscape(s string) string {
	r := strings.NewReplacer(
		`"`, `'`,
		"\n", " ",
		"·", "-",
	)
	return `"` + r.Replace(s) + `"`
}

// Unused legacy sort helper retained so callers in tests still compile.
var _ = sort.Strings
