package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
)

// BuildArchitectureSVG renders the discovered AWS resources as a
// polished, self-contained SVG ready to be inlined inside the HTML
// audit report. The output is tuned to be screenshotable: an
// AWS-Architecture-Center palette on a light surface, real 2D
// topology layout, no JavaScript, no external assets. The same SVG
// renders identically in file:// HTML, in print preview, and as a
// screenshot pasted into Twitter/LinkedIn. An embedded stylesheet
// (svgThemeStyle) additionally makes it dark-mode aware in CSS-capable
// contexts — standalone via prefers-color-scheme, inlined in the HTML
// report via the page's --bp-* tokens (toggle-aware).
//
// Layout: three vertical lanes inside an account header band:
//
//	Edge lane (left)    │  AWS Cloud frame (center)        │  Lateral lane (right)
//	------------------- │ -------------------------------- │ --------------------
//	CloudFront          │ ┌── Account ───────────────────┐ │ Storage
//	Route 53            │ │ ┌── VPC ───────────────────┐ │ │   S3, EBS, EFS …
//	WAF                 │ │ │  Subnet rows (with their │ │ │ Identity
//	ALB                 │ │ │  in-subnet resources)    │ │ │   IAM, KMS, Secrets
//	                    │ │ │  VPC chrome row (SG, IGW)│ │ │ Data
//	                    │ │ └──────────────────────────┘ │ │   DynamoDB
//	                    │ └────────────────────────────────┘ │ Application
//	                    │                                    │   Lambda, SNS, SQS
//	                    │                                    │ Observability
//	                    │                                    │   Logs, CloudTrail
//
// The classifier (classifyResources) decides which lane a resource
// belongs in. Resources without a VPC association still get drawn —
// they just land in the lateral lane regardless of service family.
//
// Returns "" when there are no resources to draw — the HTML renderer
// skips the architecture section in that case.
func BuildArchitectureSVG(resources []DiscoveredResource, components []group.Component, ctx AWSAuditContext, llmConns []LLMConnection, findings []Finding) string {
	if len(resources) == 0 {
		return ""
	}

	byURN := make(map[string]DiscoveredResource, len(resources))
	idToURN := make(map[string]string, len(resources))
	for _, r := range resources {
		byURN[r.URN] = r
		if r.ID != "" {
			idToURN[r.ID] = r.URN
		}
	}
	_ = components

	// Build the global Finding → "C1"/"H3"/... key map and per-resource
	// chip list. Done once here so every resource box and the bottom
	// footnote table use the same keys.
	keyMap, _ := assignFindingKeys(findings)
	resourceChips := chipsByResource(findings, keyMap, byURN, idToURN)
	_ = resourceChips // chips are attached to the registry below

	edges, vpcRoot, lateral := classifyResources(resources)

	const (
		canvasWidth = 1480
		canvasPad   = 28
		laneGap     = 26
		edgeLaneW   = boxW + 16 // 216 — single column of 200×56 boxes
		lateralW    = boxW + 60 // 260 — single column with breathing room
	)
	headerH := 56
	cloudX := canvasPad + edgeLaneW + laneGap
	cloudW := canvasWidth - cloudX - lateralW - laneGap - canvasPad
	lateralX := canvasWidth - canvasPad - lateralW

	var body strings.Builder
	pr := newPositionRegistry()
	pr.chips = resourceChips

	// Header band — minimal Blueprint sheet header (the rich title
	// block lives in HTML chrome around the SVG).
	renderHeader(&body, ctx, canvasWidth, 0, headerH)
	_ = byURN

	// Compute the body sections. Each returns a height so we can size
	// the overall canvas to its tallest column. The position registry
	// gathers icon centers as we go so the post-pass can draw arrows
	// between connected resources.
	mainY := headerH + 28

	cloudH := renderAWSCloud(&body, ctx, vpcRoot, cloudX, mainY, cloudW, pr)
	edgeH := renderEdgeLane(&body, edges, canvasPad, mainY, edgeLaneW, pr)
	lateralH := renderLateralLane(&body, lateral, lateralX, mainY, lateralW, pr)

	bodyH := cloudH
	if edgeH > bodyH {
		bodyH = edgeH
	}
	if lateralH > bodyH {
		bodyH = lateralH
	}
	// Bottom account-scoped strip: IAM, KMS, CloudWatch Logs, etc.
	// Pulled out of the lateral buckets so the visual hierarchy
	// matches Blueprint's "AZ rows on top, identity strip below".
	accountScoped := accountScopedResources(lateral)
	stripH := 0
	stripY := mainY + bodyH + 28
	if len(accountScoped) > 0 {
		stripH = bottomStripHeight(accountScoped, canvasWidth-2*canvasPad)
	}
	canvasH := stripY + stripH + canvasPad
	if stripH == 0 {
		canvasH = mainY + bodyH + canvasPad
	}

	// Bottom IDENTITY · SECRETS · OBSERVABILITY strip — account-scoped
	// resources (IAM/KMS/Logs/CloudTrail) sit here so the VPC frame
	// reads as the in-network area and the strip reads as the
	// surrounding account chrome.
	if len(accountScoped) > 0 {
		renderBottomStrip(&body, accountScoped, canvasPad, stripY, canvasWidth-2*canvasPad, pr)
	}

	// Deterministic connections (IGW↔VPC, NAT→Subnet, EIP→Instance,
	// Instance/RDS/ALB→SG, Lambda→VPC subnets, etc.) — drawn ABOVE
	// the body block so they hover over the panels but BELOW the
	// icons stylistically. Connections are inferred from Inputs
	// fields; LLM-inferred edges (CF→S3 origin, APIGW→Lambda) are
	// stubbed in renderLLMConnections for the next pass.
	conns := inferConnections(resources, idToURN)
	// Heuristic fallback — only fires for single-instance services
	// where the deterministic pass can't find the route info but the
	// architecture is unambiguous (1 ALB + 1 Lambda → connected).
	conns = append(conns, inferHeuristicConnections(resources)...)
	renderConnections(&body, conns, pr)
	// LLM-inferred semantic edges (CloudFront→S3 origin, APIGW→Lambda,
	// Lambda→DynamoDB/S3/Secrets via IAM, etc.) — drawn in a distinct
	// accent color with the LLM-supplied label so reviewers can tell
	// structural from data-flow at a glance.
	renderLLMConnections(&body, llmConns, byURN, pr)

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" class="cbx-arch" viewBox="0 0 %d %d" preserveAspectRatio="xMidYMin meet" font-family="'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace" role="img" aria-label="CloudBooster AWS architecture diagram">`,
		canvasWidth, canvasH)
	sb.WriteString(svgThemeStyle)
	sb.WriteString(svgDefs())
	// Cream paper background + faint horizontal grid stripes — the
	// Blueprint engineering-schematic aesthetic.
	fmt.Fprintf(&sb, `<rect x="0" y="0" width="%d" height="%d" fill="#FAF7F0"/>`, canvasWidth, canvasH)
	fmt.Fprintf(&sb, `<rect x="0" y="0" width="%d" height="%d" fill="url(#bp-grid)"/>`, canvasWidth, canvasH)
	sb.WriteString(body.String())
	sb.WriteString(svgWatermark(canvasWidth, canvasH, len(llmConns) > 0))
	sb.WriteString(`</svg>`)
	return sb.String()
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

// topoVPC carries the in-VPC topology rooted at a single VPC resource.
// Subnets are bucketed by AvailabilityZone so the renderer can lay
// them out as side-by-side AZ columns (Hava-style).
type topoVPC struct {
	res    DiscoveredResource
	azs    []*topoAZ            // ordered by AZ name; "" = unknown-AZ catch-all
	chrome []DiscoveredResource // SG, IGW, NAT, RouteTable, NACL, EIP attached to this VPC
	loose  []DiscoveredResource // RDS/Lambda we can't attribute to a subnet
}

// topoAZ represents one Availability Zone column inside a VPC.
type topoAZ struct {
	name      string               // e.g. "us-east-1a"; "" when AZ data isn't available
	subnets   []*topoSubnet        // subnets in this AZ, stacked vertically
	resources []DiscoveredResource // AZ-scoped resources (e.g. RDS that match this AZ but no subnet)
}

type topoSubnet struct {
	res       DiscoveredResource
	resources []DiscoveredResource // instances, RDS, Lambda placed in this subnet
}

// -----------------------------------------------------------------------------
// Position registry — records where each resource icon was rendered
// so the connection pass can draw arrows between them.
// -----------------------------------------------------------------------------

type point struct{ X, Y int }

// boxRect holds the bounding rectangle of a rendered resource box.
// Orthogonal arrows route to the appropriate edge midpoint based on
// relative direction, instead of slicing through the icon glyph.
type boxRect struct {
	X, Y, W, H int
}

func (b boxRect) center() point   { return point{X: b.X + b.W/2, Y: b.Y + b.H/2} }
func (b boxRect) leftMid() point  { return point{X: b.X, Y: b.Y + b.H/2} }
func (b boxRect) rightMid() point { return point{X: b.X + b.W, Y: b.Y + b.H/2} }
func (b boxRect) topMid() point   { return point{X: b.X + b.W/2, Y: b.Y} }
func (b boxRect) botMid() point   { return point{X: b.X + b.W/2, Y: b.Y + b.H} }

type positionRegistry struct {
	rects map[string]boxRect
	chips map[string][]string // URN → ["C1","H3",...] severity-keyed chips
}

func newPositionRegistry() *positionRegistry {
	return &positionRegistry{rects: map[string]boxRect{}, chips: map[string][]string{}}
}

// chipsFor returns the resource's severity-keyed chip list (may be empty).
func (p *positionRegistry) chipsFor(urn string) []string {
	if p == nil {
		return nil
	}
	return p.chips[urn]
}

// registerBox records the full bounding rectangle of a 200×56-style
// resource box so the arrow router can pick the right edge to connect.
func (p *positionRegistry) registerBox(urn string, x, y, w, h int) {
	if p == nil || urn == "" {
		return
	}
	p.rects[urn] = boxRect{X: x, Y: y, W: w, H: h}
}

func (p *positionRegistry) rect(urn string) (boxRect, bool) {
	if p == nil {
		return boxRect{}, false
	}
	r, ok := p.rects[urn]
	return r, ok
}

// allRects returns every registered box rect with its URN, so the
// arrow router can check collision against everything on the canvas.
func (p *positionRegistry) allRects() map[string]boxRect {
	if p == nil {
		return nil
	}
	out := make(map[string]boxRect, len(p.rects))
	for k, v := range p.rects {
		out[k] = v
	}
	return out
}

// renderResourceIcon is the canonical "place a resource icon on the
// canvas" helper. Every call site uses it so the position registry
// captures the box rect for the connection pass and the chip
// stack can render inside the box bottom-right.
func renderResourceIcon(sb *strings.Builder, pr *positionRegistry, r DiscoveredResource, x, y int) {
	pr.registerBox(r.URN, x, y, boxW, boxH)
	sb.WriteString(renderResourceBox(r, x, y, pr.chipsFor(r.URN)))
}

// -----------------------------------------------------------------------------
// Connection inference (deterministic, no LLM)
// -----------------------------------------------------------------------------

// connection is one inferred relationship between two discovered
// resources, identified by URN. Label is shown beside the arrow.
type connection struct {
	From  string // source URN
	To    string // destination URN
	Label string // optional short caption ("attaches", "routes via", etc.)
}

// inferConnections walks Inputs and surfaces the structural edges
// we can know for certain from CloudControl data. Skipped semantic
// edges (CloudFront → S3 origin, API Gateway → Lambda integration,
// Lambda → DynamoDB/S3 via IAM) need policy / config parsing that
// is more reliably handled by the LLM pass.
func inferConnections(resources []DiscoveredResource, idToURN map[string]string) []connection {
	var out []connection
	emit := func(fromURN, toID, label string) {
		if fromURN == "" || toID == "" {
			return
		}
		toURN, ok := idToURN[toID]
		if !ok {
			return
		}
		if toURN == fromURN {
			return
		}
		out = append(out, connection{From: fromURN, To: toURN, Label: label})
	}

	for _, r := range resources {
		switch r.Type {
		case "AWS::EC2::InternetGateway":
			// Attachments: [{VpcId}]
			if atts, ok := r.Inputs["Attachments"].([]interface{}); ok {
				for _, a := range atts {
					if m, ok := a.(map[string]interface{}); ok {
						if vid, ok := m["VpcId"].(string); ok {
							emit(r.URN, vid, "")
						}
					}
				}
			}
		case "AWS::EC2::NatGateway":
			if sid, ok := r.Inputs["SubnetId"].(string); ok {
				emit(r.URN, sid, "")
			}
		case "AWS::EC2::EIP":
			if iid, ok := r.Inputs["InstanceId"].(string); ok && iid != "" {
				emit(r.URN, iid, "")
			} else if nid, ok := r.Inputs["NetworkInterfaceId"].(string); ok && nid != "" {
				emit(r.URN, nid, "")
			}
		case "AWS::EC2::Instance":
			// Instance → Security Groups
			if sgs, ok := r.Inputs["SecurityGroupIds"].([]interface{}); ok {
				for _, s := range sgs {
					if id, ok := s.(string); ok {
						emit(r.URN, id, "")
					}
				}
			}
		case "AWS::RDS::DBInstance":
			if sgs, ok := r.Inputs["VPCSecurityGroups"].([]interface{}); ok {
				for _, s := range sgs {
					if m, ok := s.(map[string]interface{}); ok {
						if id, ok := m["VPCSecurityGroupId"].(string); ok {
							emit(r.URN, id, "")
						}
					}
				}
			}
		case "AWS::ElasticLoadBalancingV2::LoadBalancer":
			if sgs, ok := r.Inputs["SecurityGroups"].([]interface{}); ok {
				for _, s := range sgs {
					if id, ok := s.(string); ok {
						emit(r.URN, id, "")
					}
				}
			}
			if subs, ok := r.Inputs["Subnets"].([]interface{}); ok {
				for _, s := range subs {
					if id, ok := s.(string); ok {
						emit(r.URN, id, "")
					}
				}
			}
		case "AWS::Lambda::Function":
			if vc, ok := r.Inputs["VpcConfig"].(map[string]interface{}); ok {
				if subs, ok := vc["SubnetIds"].([]interface{}); ok {
					for _, s := range subs {
						if id, ok := s.(string); ok {
							emit(r.URN, id, "")
						}
					}
				}
				if sgs, ok := vc["SecurityGroupIds"].([]interface{}); ok {
					for _, s := range sgs {
						if id, ok := s.(string); ok {
							emit(r.URN, id, "")
						}
					}
				}
			}
		case "AWS::CloudFront::Distribution":
			// CloudFront → S3 origin. Origins live two levels deep
			// under DistributionConfig.Origins; the DomainName field
			// is the bucket's canonical S3 endpoint
			// "<bucket>.s3.amazonaws.com" or
			// "<bucket>.s3.<region>.amazonaws.com".
			cfg, _ := r.Inputs["DistributionConfig"].(map[string]interface{})
			origins, _ := cfg["Origins"].([]interface{})
			if items, ok := cfg["Origins"].(map[string]interface{}); ok {
				if it, ok := items["Items"].([]interface{}); ok {
					origins = it
				}
			}
			for _, o := range origins {
				om, ok := o.(map[string]interface{})
				if !ok {
					continue
				}
				dn, _ := om["DomainName"].(string)
				if dn == "" {
					continue
				}
				if bucket := s3BucketFromOriginDomain(dn); bucket != "" {
					if toURN, ok := idToURN[bucket]; ok {
						out = append(out, connection{From: r.URN, To: toURN, Label: "origin"})
					}
				}
			}
		case "AWS::ApiGatewayV2::Api", "AWS::APIGatewayV2::Api",
			"AWS::ApiGateway::RestApi", "AWS::APIGateway::RestApi":
			// API Gateway → Lambda integration. CloudControl rarely
			// surfaces the route/integration tree on the Api resource
			// itself, but when it does we read it. Otherwise the
			// edge has to come from the grounded LLM pass.
			if integ, ok := r.Inputs["Target"].(string); ok && integ != "" {
				if lambdaID := parseLambdaARN(integ); lambdaID != "" {
					if toURN, ok := idToURN[lambdaID]; ok {
						out = append(out, connection{From: r.URN, To: toURN, Label: "invokes"})
					}
				}
			}
			if routes, ok := r.Inputs["Routes"].([]interface{}); ok {
				for _, raw := range routes {
					rt, ok := raw.(map[string]interface{})
					if !ok {
						continue
					}
					if uri, ok := rt["Target"].(string); ok {
						if lid := parseLambdaARN(uri); lid != "" {
							if toURN, ok := idToURN[lid]; ok {
								out = append(out, connection{From: r.URN, To: toURN, Label: "invokes"})
							}
						}
					}
				}
			}
		case "AWS::ElasticLoadBalancingV2::TargetGroup":
			// TargetGroup is the bridge ALB → Lambda/Instance. The
			// resource itself isn't drawn (filtered as "_hide"); we
			// still consume its inputs to draw the real edge.
			var lbURN string
			if lbs, ok := r.Inputs["LoadBalancerArns"].([]interface{}); ok {
				for _, raw := range lbs {
					if arn, ok := raw.(string); ok {
						if u, ok := idToURN[arn]; ok {
							lbURN = u
							break
						}
					}
				}
			}
			if lbURN == "" {
				continue
			}
			if targets, ok := r.Inputs["Targets"].([]interface{}); ok {
				for _, raw := range targets {
					tm, ok := raw.(map[string]interface{})
					if !ok {
						continue
					}
					tid, _ := tm["Id"].(string)
					if tid == "" {
						continue
					}
					// Target Id can be an instance id or a Lambda ARN.
					if lid := parseLambdaARN(tid); lid != "" {
						tid = lid
					}
					if toURN, ok := idToURN[tid]; ok {
						out = append(out, connection{From: lbURN, To: toURN, Label: "forwards"})
					}
				}
			}
		}
	}
	return out
}

// inferHeuristicConnections fills in the obvious data-flow edges
// that the deterministic pass can't find when CloudControl omits
// routes / targets / origins. Single-instance heuristics:
//
//   - 1 API Gateway + 1 Lambda → APIGW invokes the Lambda
//   - 1 ALB        + 1 Lambda → ALB forwards to the Lambda
//   - CloudFront origin matches an S3 bucket name (prefix) → CF
//     reads from that bucket
//
// These are *heuristics*, not facts — but for a 1-of-each account
// the inference is correct ~all the time and the diagram is useless
// without them. When multiple candidates exist on either side the
// heuristic stays quiet (no guessing).
func inferHeuristicConnections(resources []DiscoveredResource) []connection {
	var lambdas, albs, apigws, cfs, s3s, rds []DiscoveredResource
	for _, r := range resources {
		switch r.Type {
		case "AWS::Lambda::Function":
			lambdas = append(lambdas, r)
		case "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer":
			albs = append(albs, r)
		case "AWS::ApiGatewayV2::Api", "AWS::APIGatewayV2::Api",
			"AWS::ApiGateway::RestApi", "AWS::APIGateway::RestApi":
			apigws = append(apigws, r)
		case "AWS::CloudFront::Distribution":
			cfs = append(cfs, r)
		case "AWS::S3::Bucket":
			s3s = append(s3s, r)
		case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster":
			rds = append(rds, r)
		}
	}
	var out []connection
	if len(lambdas) == 1 {
		for _, lb := range albs {
			out = append(out, connection{From: lb.URN, To: lambdas[0].URN, Label: "forwards"})
		}
		for _, api := range apigws {
			out = append(out, connection{From: api.URN, To: lambdas[0].URN, Label: "invokes"})
		}
		// Lambda → RDS: in single-Lambda + single-DB architectures the
		// Lambda is almost certainly the DB client. If the Lambda's
		// IAM role has admin-equivalent access or its env carries the
		// DB host, we'd promote this from heuristic to deterministic;
		// without that proof we still draw it because the diagram
		// without an edge here mis-reads as "DB is unused".
		if len(rds) == 1 {
			out = append(out, connection{From: lambdas[0].URN, To: rds[0].URN, Label: "queries"})
		}
		// Lambda → S3: similar reasoning, but only fire when there is
		// exactly one S3 bucket — picking one out of three would be
		// guessing.
		if len(s3s) == 1 {
			out = append(out, connection{From: lambdas[0].URN, To: s3s[0].URN, Label: "writes"})
		}
	}
	// CloudFront → S3 by name match. CF origin's bucket prefix may
	// be substantially different from the S3 bucket name in this
	// account; we still try a prefix match before giving up.
	for _, cf := range cfs {
		cfg, _ := cf.Inputs["DistributionConfig"].(map[string]interface{})
		origins, _ := cfg["Origins"].([]interface{})
		if items, ok := cfg["Origins"].(map[string]interface{}); ok {
			if it, ok := items["Items"].([]interface{}); ok {
				origins = it
			}
		}
		for _, o := range origins {
			om, _ := o.(map[string]interface{})
			dn, _ := om["DomainName"].(string)
			bucket := s3BucketFromOriginDomain(dn)
			if bucket == "" {
				continue
			}
			// Try exact-match first, then prefix of either side.
			for _, b := range s3s {
				if b.ID == bucket {
					out = append(out, connection{From: cf.URN, To: b.URN, Label: "origin"})
					break
				}
			}
		}
	}
	return out
}

// s3BucketFromOriginDomain extracts the bucket name from a CloudFront
// origin DomainName. Supports both regional and global S3 endpoints:
//
//	"<bucket>.s3.amazonaws.com"          → <bucket>
//	"<bucket>.s3.<region>.amazonaws.com" → <bucket>
//	"<bucket>.s3-website.<region>...com" → <bucket>
//
// Returns "" when the domain isn't an S3 host (e.g. a custom origin).
func s3BucketFromOriginDomain(dn string) string {
	if !strings.Contains(dn, ".amazonaws.com") {
		return ""
	}
	// Strip everything from the first ".s3" segment onward; what
	// remains is the bucket name.
	for _, sep := range []string{".s3.", ".s3-website.", ".s3-accelerate."} {
		if i := strings.Index(dn, sep); i > 0 {
			return dn[:i]
		}
	}
	return ""
}

// parseLambdaARN extracts the function name from a Lambda invocation
// ARN. Recognises "arn:aws:lambda:<region>:<acct>:function:<name>"
// and the API Gateway "arn:aws:apigateway:...integrations/..." shape
// where the function ARN appears as a sub-component.
func parseLambdaARN(s string) string {
	if !strings.Contains(s, ":lambda:") || !strings.Contains(s, ":function:") {
		return ""
	}
	i := strings.Index(s, ":function:")
	if i < 0 {
		return ""
	}
	rest := s[i+len(":function:"):]
	// Trim trailing junk like /invocations or :ALIAS
	for _, c := range []string{"/", ":"} {
		if j := strings.Index(rest, c); j > 0 {
			rest = rest[:j]
		}
	}
	return rest
}

// renderConnections walks the inferred edge list and draws orthogonal
// Blueprint-style arrows. Each edge is routed through the gutter
// between the source's exit edge and the destination's entry edge,
// with 90° corners rounded at 10px. Numbered pill labels mark each
// edge so the reader can trace the dataflow order in the NOTES.
//
// Endpoints whose URNs aren't in the registry are silently skipped.
func renderConnections(sb *strings.Builder, conns []connection, pr *positionRegistry) {
	if len(conns) == 0 {
		return
	}
	obstacles := pr.allRects()
	sb.WriteString(`<g class="connections" stroke-linecap="round">`)
	step := 0
	for _, c := range conns {
		if isNoiseEdgeURN(c.From) || isNoiseEdgeURN(c.To) {
			continue
		}
		from, fok := pr.rect(c.From)
		to, tok := pr.rect(c.To)
		if !fok || !tok {
			continue
		}
		step++
		drawOrthogonalArrowAvoid(sb, from, to, step, false, obstacles, c.From, c.To)
	}
	sb.WriteString(`</g>`)
}

// isNoiseEdgeURN returns true for resource URNs that the diagram
// deliberately does NOT route arrows to: IAM roles (the "Lambda
// assumes role X" linkage is implicit), security groups (the
// "protected by" linkage doesn't show data-flow), and other purely
// administrative resources. Lets us keep arrows focused on real
// request/response paths.
func isNoiseEdgeURN(urn string) bool {
	switch {
	case strings.Contains(urn, "/AWS::IAM::"):
		return true
	case strings.Contains(urn, "/AWS::EC2::SecurityGroup/"):
		return true
	case strings.Contains(urn, "/AWS::EC2::RouteTable/"):
		return true
	case strings.Contains(urn, "/AWS::EC2::NetworkAcl/"):
		return true
	}
	return false
}

// drawOrthogonalArrowAvoid draws a single orthogonal arrow from `from`
// to `to`, picking a box-avoiding polyline via routeOrthogonalAvoid.
// When `isLLM` is true, an orange semi-solid style is used (data-flow);
// otherwise solid black (structural). The label is the step number,
// drawn in a paper-knockout pill at the midpoint of the longest segment.
func drawOrthogonalArrowAvoid(sb *strings.Builder, from, to boxRect, step int, isLLM bool, obstacles map[string]boxRect, fromURN, toURN string) {
	stroke, dash, markerEnd := "#1C1917", "", "url(#bp-arrow)"
	if isLLM {
		stroke, dash, markerEnd = "#C2410C", "5 4", "url(#bp-arrow-red)"
	}
	pts := routeOrthogonalAvoid(from, to, obstacles, fromURN, toURN)
	if len(pts) < 2 {
		return
	}
	d := orthoPath(pts, 10)
	fmt.Fprintf(sb,
		`<path d="%s" fill="none" stroke="%s" stroke-width="1.6" stroke-dasharray="%s" stroke-linecap="round" stroke-linejoin="round" marker-end="%s"/>`,
		d, stroke, dash, markerEnd,
	)
	if step > 0 {
		lx, ly := labelMidpointAvoidingBoxes(pts, obstacles, fromURN, toURN)
		fmt.Fprintf(sb,
			`<rect x="%d" y="%d" width="20" height="18" fill="#FAF7F0" stroke="%s" stroke-width="1"/>`+
				`<text x="%d" y="%d" text-anchor="middle" font-size="11" font-weight="800" fill="%s" font-family="'JetBrains Mono', ui-monospace, monospace">%d</text>`,
			lx-10, ly-9, stroke,
			lx, ly+4, stroke, step,
		)
	}
}

// routeOrthogonalAvoid is routeOrthogonal that *avoids* crossing any
// intermediate box. Tries the standard mid-X / mid-Y route first;
// if it would cut through any non-endpoint box, falls back to
// routing through a clear channel above or below the obstacles.
func routeOrthogonalAvoid(from, to boxRect, obstacles map[string]boxRect, fromURN, toURN string) []point {
	base := routeOrthogonal(from, to)
	if !routeHitsObstacle(base, obstacles, fromURN, toURN) {
		return base
	}
	// Find a horizontal channel above OR below the obstacles between
	// the source and target boxes. The channel is a Y where a wide
	// rectangle [from.X .. to.X] doesn't intersect any other box.
	minX, maxX := minInt(from.X, to.X), maxInt(from.X+from.W, to.X+to.W)
	const pad = 16
	// Candidate channels: above and below each obstacle that lies
	// in the X corridor. Each candidate is "just outside" the
	// obstacle, with padding.
	tried := map[int]bool{}
	var candidates []int
	for urn, b := range obstacles {
		if urn == fromURN || urn == toURN {
			continue
		}
		if b.X+b.W < minX || b.X > maxX {
			continue
		}
		for _, y := range []int{b.Y - pad, b.Y + b.H + pad} {
			if tried[y] {
				continue
			}
			tried[y] = true
			candidates = append(candidates, y)
		}
	}
	// Prefer channels closer to the natural mid-Y so the arrow
	// doesn't take wild detours when a short hop works.
	midY := (from.center().Y + to.center().Y) / 2
	sort.Slice(candidates, func(i, j int) bool {
		return absInt(candidates[i]-midY) < absInt(candidates[j]-midY)
	})
	for _, ch := range candidates {
		// Build a 4-segment route via this channel:
		//   from.{rightMid|leftMid} → (sameX, ch) → (otherX, ch) → to.{leftMid|rightMid}
		exit := from.rightMid()
		enter := to.leftMid()
		if from.X > to.X {
			exit = from.leftMid()
			enter = to.rightMid()
		}
		pts := []point{exit, {X: exit.X, Y: ch}, {X: enter.X, Y: ch}, enter}
		if !routeHitsObstacle(pts, obstacles, fromURN, toURN) {
			return pts
		}
	}
	// All channels blocked — fall back to the base route (overlap
	// is the lesser evil vs. dropping the edge entirely).
	return base
}

// routeHitsObstacle returns true if any segment of the polyline
// crosses a non-endpoint box. Endpoint boxes are skipped so the
// natural entry/exit of an arrow at a box edge doesn't false-trip.
func routeHitsObstacle(pts []point, obstacles map[string]boxRect, fromURN, toURN string) bool {
	if len(pts) < 2 {
		return false
	}
	for urn, b := range obstacles {
		if urn == fromURN || urn == toURN {
			continue
		}
		for i := 1; i < len(pts); i++ {
			if segmentIntersectsRect(pts[i-1], pts[i], b) {
				return true
			}
		}
	}
	return false
}

// segmentIntersectsRect returns true if the axis-aligned segment
// from a to b passes through the interior of rect r. The router
// always produces axis-aligned segments, so we only need to check
// the horizontal and vertical cases.
func segmentIntersectsRect(a, b point, r boxRect) bool {
	const pad = 2 // small slack so segments grazing an edge don't false-trip
	x1, x2 := minInt(a.X, b.X), maxInt(a.X, b.X)
	y1, y2 := minInt(a.Y, b.Y), maxInt(a.Y, b.Y)
	rx1, rx2 := r.X+pad, r.X+r.W-pad
	ry1, ry2 := r.Y+pad, r.Y+r.H-pad
	if x2 < rx1 || x1 > rx2 {
		return false
	}
	if y2 < ry1 || y1 > ry2 {
		return false
	}
	return true
}

// labelMidpointAvoidingBoxes returns the centre of the longest
// segment that doesn't sit on top of an obstacle box. Falls back to
// the standard midpoint when every segment crosses something.
func labelMidpointAvoidingBoxes(pts []point, obstacles map[string]boxRect, fromURN, toURN string) (int, int) {
	type seg struct {
		x, y, l int
	}
	best := seg{l: -1}
	for i := 1; i < len(pts); i++ {
		mx := (pts[i].X + pts[i-1].X) / 2
		my := (pts[i].Y + pts[i-1].Y) / 2
		l := absInt(pts[i].X-pts[i-1].X) + absInt(pts[i].Y-pts[i-1].Y)
		// Penalise mid-points that land inside an obstacle.
		blocked := false
		for urn, b := range obstacles {
			if urn == fromURN || urn == toURN {
				continue
			}
			if mx >= b.X-2 && mx <= b.X+b.W+2 && my >= b.Y-2 && my <= b.Y+b.H+2 {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		if l > best.l {
			best = seg{x: mx, y: my, l: l}
		}
	}
	if best.l < 0 {
		// All segments blocked — use the base midpoint regardless.
		return labelMidpoint(pts)
	}
	return best.x, best.y
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// routeOrthogonal returns a polyline that exits `from` from its nearest
// edge midpoint, makes one mid-point turn, and arrives at `to`'s
// matching edge midpoint. Picks horizontal-first if the boxes are
// stacked or side-by-side, else vertical-first.
func routeOrthogonal(from, to boxRect) []point {
	fc := from.center()
	tc := to.center()
	dx := tc.X - fc.X
	dy := tc.Y - fc.Y

	var p1, p4 point
	// Pick the appropriate exit / entry edge midpoint based on
	// dominant axis. Horizontal-first when the X gap exceeds the Y gap.
	if abs(dx) >= abs(dy) {
		if dx >= 0 {
			p1 = from.rightMid()
			p4 = to.leftMid()
		} else {
			p1 = from.leftMid()
			p4 = to.rightMid()
		}
		// Two-bend route: out, turn, into target. The turn happens
		// at the midpoint X.
		midX := (p1.X + p4.X) / 2
		return []point{p1, {X: midX, Y: p1.Y}, {X: midX, Y: p4.Y}, p4}
	}
	// Vertical-dominant route.
	if dy >= 0 {
		p1 = from.botMid()
		p4 = to.topMid()
	} else {
		p1 = from.topMid()
		p4 = to.botMid()
	}
	midY := (p1.Y + p4.Y) / 2
	return []point{p1, {X: p1.X, Y: midY}, {X: p4.X, Y: midY}, p4}
}

// orthoPath turns a polyline into an SVG path string with a 10px
// rounded corner at every interior bend. Adapted from the React
// Blueprint helper.
func orthoPath(pts []point, r int) string {
	if len(pts) < 2 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "M %d %d", pts[0].X, pts[0].Y)
	for i := 1; i < len(pts); i++ {
		cx, cy := pts[i].X, pts[i].Y
		if i+1 >= len(pts) {
			fmt.Fprintf(&b, " L %d %d", cx, cy)
			continue
		}
		px, py := pts[i-1].X, pts[i-1].Y
		nx, ny := pts[i+1].X, pts[i+1].Y
		eDx, eDy := sign(cx-px), sign(cy-py)
		xDx, xDy := sign(nx-cx), sign(ny-cy)
		legIn := abs(cx-px) + abs(cy-py)
		legOut := abs(nx-cx) + abs(ny-cy)
		rr := r
		if legIn/2 < rr {
			rr = legIn / 2
		}
		if legOut/2 < rr {
			rr = legOut / 2
		}
		fmt.Fprintf(&b, " L %d %d Q %d %d %d %d",
			cx-eDx*rr, cy-eDy*rr,
			cx, cy,
			cx+xDx*rr, cy+xDy*rr,
		)
	}
	return b.String()
}

// labelMidpoint returns the centre of the longest segment in the
// polyline so the step-number pill lands on whitespace rather than
// at a bend.
func labelMidpoint(pts []point) (int, int) {
	if len(pts) < 2 {
		return 0, 0
	}
	bestLen := -1
	bestX, bestY := pts[0].X, pts[0].Y
	for i := 1; i < len(pts); i++ {
		l := abs(pts[i].X-pts[i-1].X) + abs(pts[i].Y-pts[i-1].Y)
		if l > bestLen {
			bestLen = l
			bestX = (pts[i].X + pts[i-1].X) / 2
			bestY = (pts[i].Y + pts[i-1].Y) / 2
		}
	}
	return bestX, bestY
}

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	}
	return 0
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// renderLLMConnections draws the LLM-inferred semantic edges. They
// use a distinct accent color (AWS orange) and a solid (not dashed)
// line so reviewers can tell at a glance which arrows are structural
// (Inputs-based; slate dashed) vs data-flow (LLM-inferred; orange
// solid). Labels are rendered along the line midpoint.
//
// Endpoints whose URNs aren't on the diagram are silently skipped.
// Self-loops are also dropped (parseLLMConnections already filters
// these, this is defense-in-depth).
func renderLLMConnections(sb *strings.Builder, conns []LLMConnection, byURN map[string]DiscoveredResource, pr *positionRegistry) {
	if len(conns) == 0 {
		return
	}
	sb.WriteString(`<g class="connections-llm" stroke-linecap="round">`)
	obstacles := pr.allRects()
	for _, c := range conns {
		if c.From == "" || c.To == "" || c.From == c.To {
			continue
		}
		// Drop noise edges: IAM "assumes" relationships and "protected
		// by" security-group attachments don't carry data-flow value
		// in this view. The audit data still records them; the
		// diagram stays focused on actual request/response paths.
		if isNoiseEdgeURN(c.To) || isNoiseEdgeURN(c.From) {
			continue
		}
		from, fok := pr.rect(c.From)
		to, tok := pr.rect(c.To)
		if !fok || !tok {
			continue
		}
		pts := routeOrthogonalAvoid(from, to, obstacles, c.From, c.To)
		if len(pts) < 2 {
			continue
		}
		d := orthoPath(pts, 10)
		fmt.Fprintf(sb,
			`<path d="%s" fill="none" stroke="#B91C1C" stroke-width="1.3" stroke-dasharray="4 3" stroke-linecap="round" stroke-linejoin="round" marker-end="url(#bp-arrow-red)"/>`,
			d,
		)
		if c.Label != "" {
			lx, ly := labelMidpoint(pts)
			label := svgTruncate(c.Label, 22)
			labelW := len(label)*6 + 12
			fmt.Fprintf(sb,
				`<rect x="%d" y="%d" width="%d" height="16" fill="#FAF7F0" stroke="#B91C1C" stroke-width="0.9"/>`,
				lx-labelW/2, ly-8, labelW,
			)
			fmt.Fprintf(sb,
				`<text x="%d" y="%d" text-anchor="middle" font-size="9.5" font-weight="700" fill="#B91C1C" font-family="'JetBrains Mono', ui-monospace, monospace">%s</text>`,
				lx, ly+4, svgEscape(label),
			)
		}
	}
	sb.WriteString(`</g>`)
	_ = byURN
}

// topoRoot holds the VPC bucket(s) plus account-scope networked
// resources that don't belong to any specific VPC (currently rare —
// most networked resources carry VpcId in Inputs).
type topoRoot struct {
	vpcs    []*topoVPC
	orphans []DiscoveredResource
}

// lateralBucket is a labeled column in the right-hand services lane.
type lateralBucket struct {
	Title     string
	Resources []DiscoveredResource
}

// classifyResources partitions the discovery set into the three
// rendering lanes plus the in-VPC structure. It builds its own
// ID → URN index rather than taking the caller's: synthesized subnet
// entries are appended below, and the index must include them.
func classifyResources(resources []DiscoveredResource) (edges []DiscoveredResource, root topoRoot, lateral []lateralBucket) {
	// Defensive: synthesize AWS::EC2::Subnet entries for any subnet
	// id we see referenced (DBSubnetGroup.SubnetIds, ALB.Subnets,
	// Lambda.VpcConfig.SubnetIds, SubnetRouteTableAssociation.SubnetId
	// …) but which CloudControl ListResources didn't return. Without
	// this the AZ/Subnet hierarchy collapses when a permission gate
	// or transient discovery hiccup loses the EC2::Subnet list.
	resources = synthesizeMissingSubnets(resources)
	idToURN := map[string]string{}
	for _, r := range resources {
		if r.ID != "" {
			idToURN[r.ID] = r.URN
		}
	}

	// Index by AWS ID so we can resolve VpcId/SubnetId references.
	urnByID := idToURN
	resByURN := map[string]DiscoveredResource{}
	for _, r := range resources {
		resByURN[r.URN] = r
	}

	// 1) Build VPC buckets keyed by VPC URN.
	vpcMap := map[string]*topoVPC{}
	for _, r := range resources {
		if r.Type == "AWS::EC2::VPC" {
			vpcMap[r.URN] = &topoVPC{res: r}
		}
	}

	// 2) Subnets attach to a VPC by Inputs["VpcId"]. We bucket by AZ
	//    within each VPC so the renderer can lay AZs out side-by-side.
	subnetMap := map[string]*topoSubnet{}
	// (vpcURN, azName) → *topoAZ — index for O(1) AZ lookup as we
	// process subnets.
	azIndex := map[string]map[string]*topoAZ{}
	addSubnetToVPC := func(v *topoVPC, s *topoSubnet, az string) {
		azMap, ok := azIndex[v.res.URN]
		if !ok {
			azMap = map[string]*topoAZ{}
			azIndex[v.res.URN] = azMap
		}
		ax, ok := azMap[az]
		if !ok {
			ax = &topoAZ{name: az}
			azMap[az] = ax
			v.azs = append(v.azs, ax)
		}
		ax.subnets = append(ax.subnets, s)
	}

	// vpcByID looks up the VPC bucket for a given vpc-id, transparently
	// synthesizing a placeholder when the audit didn't discover the
	// AWS::EC2::VPC resource itself (CloudControl can sometimes return
	// subnets / SGs without their parent VPC if a permission gates only
	// the parent). The synthesized bucket gathers everything that
	// references the same vpc-id so chrome + subnets still cluster
	// together rather than scattering across orphan rows.
	vpcByID := func(vid string) *topoVPC {
		if vid == "" {
			return nil
		}
		if vurn := urnByID[vid]; vurn != "" {
			if v, ok := vpcMap[vurn]; ok {
				return v
			}
		}
		synthURN := "aws://synth/AWS::EC2::VPC/" + vid
		if v, ok := vpcMap[synthURN]; ok {
			return v
		}
		v := &topoVPC{res: DiscoveredResource{
			Type:   "AWS::EC2::VPC",
			URN:    synthURN,
			ID:     vid,
			Inputs: map[string]interface{}{"_synthesized": true},
		}}
		vpcMap[synthURN] = v
		return v
	}

	for _, r := range resources {
		if r.Type != "AWS::EC2::Subnet" {
			continue
		}
		vid, _ := r.Inputs["VpcId"].(string)
		az, _ := r.Inputs["AvailabilityZone"].(string)
		s := &topoSubnet{res: r}
		subnetMap[r.URN] = s
		if v := vpcByID(vid); v != nil {
			addSubnetToVPC(v, s, az)
			continue
		}
		// Subnet with no VpcId at all — last-resort catch-all.
		if _, ok := vpcMap[unknownVPCURN]; !ok {
			vpcMap[unknownVPCURN] = &topoVPC{res: DiscoveredResource{
				Type: "AWS::EC2::VPC", URN: unknownVPCURN, ID: "(no VPC reference)",
			}}
		}
		addSubnetToVPC(vpcMap[unknownVPCURN], s, az)
	}

	// 3) VPC chrome (SG, IGW, NAT, RouteTable, NACL, EIP). Snaps into
	//    the (possibly synthesized) VPC bucket the references demand.
	for _, r := range resources {
		switch r.Type {
		case "AWS::EC2::SecurityGroup", "AWS::EC2::RouteTable", "AWS::EC2::NetworkAcl",
			"AWS::EC2::InternetGateway", "AWS::EC2::NatGateway":
			vid, _ := r.Inputs["VpcId"].(string)
			if vid == "" {
				// IGW carries its VPC link inside Attachments[0].VpcId
				// — fall through to that shape.
				if atts, ok := r.Inputs["Attachments"].([]interface{}); ok && len(atts) > 0 {
					if m, ok := atts[0].(map[string]interface{}); ok {
						vid, _ = m["VpcId"].(string)
					}
				}
			}
			if v := vpcByID(vid); v != nil {
				v.chrome = append(v.chrome, r)
				continue
			}
			root.orphans = append(root.orphans, r)
		}
	}

	// 4) EIPs: float in the VPC frame, not in a subnet. Attach to a
	//    VPC if we can chain through an associated instance / NIC.
	//    When no chain resolves but only one VPC exists in the audit,
	//    park them there too — public IPs in single-VPC accounts
	//    practically always belong to that VPC, and an "unattributed"
	//    bucket below the frame looks worse than a slightly-fuzzy
	//    placement.
	var soloVPC *topoVPC
	if len(vpcMap) == 1 {
		for _, v := range vpcMap {
			soloVPC = v
		}
	}
	for _, r := range resources {
		if r.Type != "AWS::EC2::EIP" {
			continue
		}
		var vid string
		if iid, ok := r.Inputs["InstanceId"].(string); ok && iid != "" {
			if iURN := urnByID[iid]; iURN != "" {
				if inst, ok := resByURN[iURN]; ok {
					vid, _ = inst.Inputs["VpcId"].(string)
				}
			}
		}
		if v := vpcByID(vid); v != nil {
			v.chrome = append(v.chrome, r)
			continue
		}
		if soloVPC != nil {
			soloVPC.chrome = append(soloVPC.chrome, r)
			continue
		}
		root.orphans = append(root.orphans, r)
	}

	// 5) In-VPC compute/data (EC2 / Lambda VPC / RDS / ECS / EKS).
	placeInSubnet := func(r DiscoveredResource, subnetID string) bool {
		if subnetID == "" {
			return false
		}
		sURN := urnByID[subnetID]
		if sURN == "" {
			return false
		}
		if s, ok := subnetMap[sURN]; ok {
			s.resources = append(s.resources, r)
			return true
		}
		return false
	}
	placeInVPC := func(r DiscoveredResource, vpcID string) bool {
		if vpcID == "" {
			return false
		}
		vURN := urnByID[vpcID]
		if vURN == "" {
			return false
		}
		if v, ok := vpcMap[vURN]; ok {
			v.loose = append(v.loose, r)
			return true
		}
		return false
	}

	// placeInAZ drops a resource at the AZ column level (not inside any
	// subnet). Used when AZ data exists but no specific subnet does.
	placeInAZ := func(r DiscoveredResource, vpcID, az string) bool {
		if vpcID == "" || az == "" {
			return false
		}
		vURN := urnByID[vpcID]
		if vURN == "" {
			return false
		}
		v, ok := vpcMap[vURN]
		if !ok {
			return false
		}
		azMap := azIndex[vURN]
		if azMap == nil {
			return false
		}
		ax, ok := azMap[az]
		if !ok {
			// AZ wasn't seen via a subnet — create it on the fly so the
			// resource still lands inside the VPC frame.
			ax = &topoAZ{name: az}
			azMap[az] = ax
			v.azs = append(v.azs, ax)
		}
		ax.resources = append(ax.resources, r)
		return true
	}

	for _, r := range resources {
		switch r.Type {
		case "AWS::EC2::Instance":
			if subnetID, ok := r.Inputs["SubnetId"].(string); ok && placeInSubnet(r, subnetID) {
				continue
			}
			if vid, ok := r.Inputs["VpcId"].(string); ok && placeInVPC(r, vid) {
				continue
			}
			root.orphans = append(root.orphans, r)
		case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster":
			// RDS placement order: exact subnet → AZ column inside
			// the matching VPC → loose-in-VPC. CloudControl usually
			// doesn't surface a VpcId on RDS (it's hidden behind
			// DBSubnetGroup); if we know there's only one VPC in the
			// account we can safely assume that one.
			vid, _ := r.Inputs["VpcId"].(string)
			if vid == "" && len(vpcMap) == 1 {
				for vurn := range vpcMap {
					vid = vpcMap[vurn].res.ID
				}
			}
			rdsPlaced := false
			if subnetID, ok := r.Inputs["DBSubnetGroupName"].(string); ok && placeInSubnet(r, subnetID) {
				rdsPlaced = true
			}
			// Prefer to drop RDS inside a real subnet that shares its AZ
			// — visually that reads as "the database in this AZ", which
			// is how the design treats multi-AZ DBs.
			if !rdsPlaced {
				if az, ok := r.Inputs["AvailabilityZone"].(string); ok && az != "" {
					for vurn, vv := range vpcMap {
						_ = vurn
						for _, azCol := range vv.azs {
							if azCol.name != az {
								continue
							}
							for _, s := range azCol.subnets {
								if pub, _ := s.res.Inputs["MapPublicIpOnLaunch"].(bool); !pub {
									s.resources = append(s.resources, r)
									rdsPlaced = true
									break
								}
							}
							if rdsPlaced {
								break
							}
						}
						if rdsPlaced {
							break
						}
					}
				}
			}
			if !rdsPlaced {
				if az, ok := r.Inputs["AvailabilityZone"].(string); ok && placeInAZ(r, vid, az) {
					rdsPlaced = true
				}
			}
			// Fallback: place in the first private subnet of the
			// account's single VPC — most production RDS sits there.
			if !rdsPlaced && soloVPC != nil {
				for _, az := range soloVPC.azs {
					if rdsPlaced {
						break
					}
					for _, s := range az.subnets {
						if pub, _ := s.res.Inputs["MapPublicIpOnLaunch"].(bool); !pub {
							s.resources = append(s.resources, r)
							rdsPlaced = true
							break
						}
					}
				}
			}
			if rdsPlaced {
				continue
			}
			if vid != "" && placeInVPC(r, vid) {
				continue
			}
			lateral = appendToBucket(lateral, "Databases", r)
		case "AWS::Lambda::Function":
			// Real placement: VpcConfig.SubnetIds.
			placed := false
			if vc, ok := r.Inputs["VpcConfig"].(map[string]interface{}); ok {
				if sids, ok := vc["SubnetIds"].([]interface{}); ok && len(sids) > 0 {
					for _, raw := range sids {
						if sid, ok := raw.(string); ok && placeInSubnet(r, sid) {
							placed = true
							break
						}
					}
				}
			}
			// Diagrammatic fallback: when the audit shows the Lambda
			// isn't VPC-attached but the account has exactly one VPC
			// with a private subnet, place it in the first such
			// subnet. The compute lives logically with the VPC even
			// when AWS doesn't have it network-attached, and the
			// diagram reads as the design intends.
			if !placed && soloVPC != nil {
				for _, az := range soloVPC.azs {
					if placed {
						break
					}
					for _, s := range az.subnets {
						pub, _ := s.res.Inputs["MapPublicIpOnLaunch"].(bool)
						if pub {
							continue
						}
						s.resources = append(s.resources, r)
						placed = true
						break
					}
				}
			}
			if placed {
				continue
			}
			lateral = appendToBucket(lateral, "Compute", r)
		case "AWS::ECS::Cluster", "AWS::ECS::Service", "AWS::EKS::Cluster":
			if vid, ok := r.Inputs["VpcId"].(string); ok && placeInVPC(r, vid) {
				continue
			}
			lateral = appendToBucket(lateral, "Compute", r)
		case "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer":
			// ALB / NLB carry a Subnets[] array. Prefer the public
			// subnet (where the LB's public-facing listener sits);
			// fall back to any matching subnet, then to the edge
			// column if none match.
			placed := false
			if subs, ok := r.Inputs["Subnets"].([]interface{}); ok {
				// Pass 1: public subnets only.
				for _, raw := range subs {
					sid, ok := raw.(string)
					if !ok {
						continue
					}
					if sURN := urnByID[sid]; sURN != "" {
						if s, ok := subnetMap[sURN]; ok {
							if pub, _ := s.res.Inputs["MapPublicIpOnLaunch"].(bool); pub {
								s.resources = append(s.resources, r)
								placed = true
								break
							}
						}
					}
				}
				// Pass 2: any subnet.
				if !placed {
					for _, raw := range subs {
						if sid, ok := raw.(string); ok && placeInSubnet(r, sid) {
							placed = true
							break
						}
					}
				}
			}
			if placed {
				continue
			}
			edges = append(edges, r)
		}
	}

	// 6) Build VPC list (stable order by ID). Within each VPC, sort
	//    AZs by name (empty AZ goes last), and subnets within each AZ
	//    by ID.
	for _, v := range vpcMap {
		sort.SliceStable(v.azs, func(i, j int) bool {
			ai, aj := v.azs[i].name, v.azs[j].name
			if ai == "" {
				return false
			}
			if aj == "" {
				return true
			}
			return ai < aj
		})
		for _, az := range v.azs {
			sort.Slice(az.subnets, func(i, j int) bool {
				return az.subnets[i].res.ID < az.subnets[j].res.ID
			})
		}
		root.vpcs = append(root.vpcs, v)
	}
	sort.Slice(root.vpcs, func(i, j int) bool {
		return root.vpcs[i].res.ID < root.vpcs[j].res.ID
	})

	// 7) Edge services.
	for _, r := range resources {
		switch r.Type {
		case "AWS::CloudFront::Distribution", "AWS::Route53::HostedZone",
			"AWS::WAFv2::WebACL", "AWS::WAF::WebACL",
			"AWS::ApiGatewayV2::Api", "AWS::APIGatewayV2::Api",
			"AWS::ApiGateway::RestApi", "AWS::APIGateway::RestApi":
			edges = append(edges, r)
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		return edgePriority(edges[i].Type) < edgePriority(edges[j].Type)
	})

	// 8) Lateral services — everything that's not edge/in-vpc/orphan-network.
	consumed := map[string]bool{}
	for _, v := range vpcMap {
		consumed[v.res.URN] = true
		for _, az := range v.azs {
			for _, s := range az.subnets {
				consumed[s.res.URN] = true
				for _, r := range s.resources {
					consumed[r.URN] = true
				}
			}
			for _, r := range az.resources {
				consumed[r.URN] = true
			}
		}
		for _, r := range v.chrome {
			consumed[r.URN] = true
		}
		for _, r := range v.loose {
			consumed[r.URN] = true
		}
	}
	for _, r := range edges {
		consumed[r.URN] = true
	}
	for _, r := range root.orphans {
		consumed[r.URN] = true
	}
	// Anything already placed in lateral (RDS without VPC, etc.)
	for _, b := range lateral {
		for _, r := range b.Resources {
			consumed[r.URN] = true
		}
	}

	for _, r := range resources {
		if consumed[r.URN] {
			continue
		}
		lateral = appendToBucket(lateral, lateralBucketFor(r.Type), r)
	}

	// Stable bucket order.
	bucketOrder := []string{"Storage", "Databases", "Compute", "Identity", "Secrets", "Application", "Observability", "Other"}
	rank := map[string]int{}
	for i, n := range bucketOrder {
		rank[n] = i
	}
	sort.SliceStable(lateral, func(i, j int) bool {
		ri, ok := rank[lateral[i].Title]
		if !ok {
			ri = 99
		}
		rj, ok := rank[lateral[j].Title]
		if !ok {
			rj = 99
		}
		if ri != rj {
			return ri < rj
		}
		return lateral[i].Title < lateral[j].Title
	})
	for _, b := range lateral {
		sort.Slice(b.Resources, func(i, j int) bool {
			if b.Resources[i].Type != b.Resources[j].Type {
				return b.Resources[i].Type < b.Resources[j].Type
			}
			return b.Resources[i].ID < b.Resources[j].ID
		})
	}

	return edges, root, lateral
}

const unknownVPCURN = "aws://unknown/AWS::EC2::VPC/-"

func appendToBucket(b []lateralBucket, title string, r DiscoveredResource) []lateralBucket {
	for i := range b {
		if b[i].Title == title {
			b[i].Resources = append(b[i].Resources, r)
			return b
		}
	}
	return append(b, lateralBucket{Title: title, Resources: []DiscoveredResource{r}})
}

func lateralBucketFor(cfnType string) string {
	switch cfnType {
	case "AWS::S3::Bucket", "AWS::EFS::FileSystem", "AWS::Backup::BackupVault", "AWS::EC2::Volume":
		return "Storage"
	case "AWS::EC2::Snapshot":
		// Snapshots are backup state, not part of the runtime topology.
		return "_hide"
	case "AWS::DynamoDB::Table", "AWS::ElastiCache::CacheCluster", "AWS::Redshift::Cluster":
		return "Databases"
	case "AWS::Lambda::Function":
		return "Compute"
	case "AWS::ApiGatewayV2::Api", "AWS::APIGatewayV2::Api",
		"AWS::ApiGateway::RestApi", "AWS::APIGateway::RestApi":
		// API Gateway is an edge service in Blueprint — leave to edges.
		return "Edge"
	case "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy":
		return "Identity"
	case "AWS::KMS::Key", "AWS::SecretsManager::Secret", "AWS::ACM::Certificate":
		return "Secrets"
	case "AWS::KMS::Alias":
		// Aliases are pointers — they don't add diagrammatic value
		// and would flood the lateral lane. Hidden from the diagram;
		// still surfaced in the audit report data.
		return "_hide"
	case "AWS::ElasticLoadBalancingV2::TargetGroup", "AWS::ElasticLoadBalancingV2::Listener":
		// ALB chrome — folded into the ALB box rather than drawn.
		return "_hide"
	case "AWS::SNS::Topic", "AWS::SQS::Queue", "AWS::Events::Rule", "AWS::EventBridge::Rule",
		"AWS::StepFunctions::StateMachine":
		return "Application"
	case "AWS::Logs::LogGroup", "AWS::CloudWatch::Alarm", "AWS::CloudTrail::Trail":
		return "Observability"
	}
	return "Other"
}

func edgePriority(cfnType string) int {
	switch cfnType {
	case "AWS::Route53::HostedZone":
		return 1
	case "AWS::CloudFront::Distribution":
		return 2
	case "AWS::WAFv2::WebACL", "AWS::WAF::WebACL":
		return 3
	case "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer":
		return 4
	}
	return 99
}

// -----------------------------------------------------------------------------
// Header
// -----------------------------------------------------------------------------

func renderHeader(sb *strings.Builder, ctx AWSAuditContext, w, y, h int) {
	// Blueprint sheet header — single line above the schematic with a
	// SHEET tag on the left and a thin accent-orange underline. The
	// rich title block (CBX AUDIT · accountID, DATE/REV/IDENTITY meta)
	// lives in the HTML chrome around the SVG.
	pad := 28
	accent := "#C2410C"
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="10" font-weight="700" fill="#78716C" letter-spacing="0.18em" font-family="'JetBrains Mono', ui-monospace, monospace">SHEET A1 · INFRASTRUCTURE TOPOLOGY</text>`,
		pad, y+22)
	if ctx.AccountID != "" || len(ctx.Regions) > 0 {
		rightX := w - pad
		title := ""
		if ctx.AccountID != "" {
			title = ctx.AccountID
		}
		if len(ctx.Regions) > 0 {
			if title != "" {
				title += " / "
			}
			title += strings.Join(ctx.Regions, " · ")
		}
		fmt.Fprintf(sb,
			`<text x="%d" y="%d" text-anchor="end" font-size="14" font-weight="700" fill="#1C1917" letter-spacing="-0.02em">CBX AUDIT · %s</text>`,
			rightX, y+24, svgEscape(title))
	}
	// Accent underline below the header row.
	fmt.Fprintf(sb,
		`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1.5"/>`,
		pad, y+h-12, w-pad, y+h-12, accent)
}

// -----------------------------------------------------------------------------
// AWS Cloud / Account / VPC frames
// -----------------------------------------------------------------------------

const (
	frameRadius   = 0 // Blueprint is sharp-cornered
	awsHeaderH    = 32
	acctHeaderH   = 0 // Blueprint drops the Account inner frame
	vpcHeaderH    = 28
	subnetHeaderH = 22
	// Resource box geometry — 200x56 horizontal box: 40px icon left,
	// name (bold) + id (mono) on right, sev chip stack inside bottom-right.
	boxW         = 200
	boxH         = 56
	boxIconSize  = 40
	iconLabelGap = 4
	iconCellW    = 220 // box + 20px horizontal gutter
	iconCellH    = 68  // box + 12px vertical gutter
)

// renderAWSCloud draws the outer AWS Cloud → Account → VPC topology.
// Returns the total height consumed.
func renderAWSCloud(sb *strings.Builder, ctx AWSAuditContext, root topoRoot, x, y, w int, pr *positionRegistry) int {
	// Layout passes: compute each VPC's height, sum + chrome.
	pad := 18
	vpcHeights := make([]int, len(root.vpcs))
	for i, v := range root.vpcs {
		vpcHeights[i] = vpcHeight(v, w-2*pad-2*pad)
	}
	innerVPCs := 0
	for _, h := range vpcHeights {
		innerVPCs += h + 14
	}
	if innerVPCs > 0 {
		innerVPCs -= 14
	}

	orphansH := 0
	if len(root.orphans) > 0 {
		orphansH = renderOrphanRowHeight(root.orphans, w-2*pad-2*pad)
	}

	innerH := innerVPCs + orphansH
	if orphansH > 0 && innerVPCs > 0 {
		innerH += 14
	}
	if innerH < 120 {
		innerH = 120
	}

	awsOuterH := awsHeaderH + innerH + pad*2

	// Blueprint REGION frame — solid 1.5px black border, sharp corners.
	// Header band carries the REGION + account label, no separate
	// account container (Blueprint flattens that level).
	fmt.Fprintf(sb,
		`<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="#1C1917" stroke-width="1.5"/>`,
		x, y, w, awsOuterH)
	regionLbl := "REGION"
	if len(ctx.Regions) > 0 {
		regionLbl = "REGION · " + strings.Join(ctx.Regions, " · ")
	}
	sb.WriteString(iconForCFNType("__group__/aws_cloud", x+10, y+6, 20, "aws"))
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="10" font-weight="700" fill="#1C1917" letter-spacing="0.15em">%s</text>`,
		x+36, y+20, svgEscape(regionLbl))
	if ctx.AccountID != "" {
		fmt.Fprintf(sb,
			`<text x="%d" y="%d" font-size="10" fill="#78716C">(AWS account · %s)</text>`,
			x+260, y+20, svgEscape(ctx.AccountID))
	}

	// VPC frames, stacked
	vpcX := x + pad
	vpcY := y + awsHeaderH
	vpcW := w - 2*pad
	for i, v := range root.vpcs {
		renderVPC(sb, v, vpcX, vpcY, vpcW, vpcHeights[i], pr)
		vpcY += vpcHeights[i] + 14
	}
	if len(root.orphans) > 0 {
		renderOrphanRow(sb, root.orphans, vpcX, vpcY, vpcW, pr)
	}

	return awsOuterH
}

// renderOrphanRowHeight returns the height needed for a row of icons.
func renderOrphanRowHeight(orphans []DiscoveredResource, w int) int {
	cols := w / iconCellW
	if cols < 1 {
		cols = 1
	}
	rows := (len(orphans) + cols - 1) / cols
	return rows*iconCellH + 24
}

// renderOrphanRow renders orphan / VPC-less networked resources in a
// compact icon row directly inside the account frame.
func renderOrphanRow(sb *strings.Builder, orphans []DiscoveredResource, x, y, w int, pr *positionRegistry) {
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="10" font-weight="700" fill="#64748B" letter-spacing="0.16em">UNATTRIBUTED NETWORK</text>`,
		x+4, y+14)
	cols := w / iconCellW
	if cols < 1 {
		cols = 1
	}
	for i, r := range orphans {
		col := i % cols
		row := i / cols
		ix := x + col*iconCellW
		iy := y + 22 + row*iconCellH
		renderResourceIcon(sb, pr, r, ix, iy)
	}
}

// renderVPC draws one VPC container with its subnets + chrome.
// The frame uses the AWS-standard solid green border (the Networking
// & Content Delivery palette) so it reads instantly as "this is the
// VPC" to anyone familiar with the AWS Architecture Center style.
func renderVPC(sb *strings.Builder, v *topoVPC, x, y, w, h int, pr *positionRegistry) {
	const vpcBorder = "#C2410C" // Blueprint accent orange — dashed
	// Dashed orange VPC frame, sharp corners.
	fmt.Fprintf(sb,
		`<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="%s" stroke-width="1.3" stroke-dasharray="5 3"/>`,
		x, y, w, h, vpcBorder)
	name := v.res.ID
	if name == "" {
		name = "VPC"
	}
	cidr, _ := v.res.Inputs["CidrBlock"].(string)
	header := "VPC · " + name
	if cidr != "" {
		header = "VPC · " + cidr
	}
	if synth, _ := v.res.Inputs["_synthesized"].(bool); synth {
		header += "  ·  inferred"
	}
	// The full label is header + (separator + id, when there is one).
	// Compute the strip width from the full text so the knockout
	// covers everything up to the trailing id — otherwise the dashed
	// border reads through behind the id.
	headerWidth := len(header) * 7 // ~7px per mono char at 10pt
	idText := ""
	idWidth := 0
	if name != "" && name != "VPC" && name != cidr {
		idText = svgEscape(name)
		idWidth = len(name)*6 + 18 // id is 9px font, lighter spacing
	}
	stripPad := 16
	stripW := 24 /*icon*/ + headerWidth + idWidth + stripPad
	fmt.Fprintf(sb,
		`<rect x="%d" y="%d" width="%d" height="16" fill="#FAF7F0"/>`,
		x+8, y-9, stripW)
	sb.WriteString(iconForCFNType("__group__/vpc", x+12, y-9, 14, "VPC"))
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="10" font-weight="700" fill="%s" letter-spacing="0.1em">%s</text>`,
		x+32, y+1, vpcBorder, svgEscape(header))
	if idText != "" {
		fmt.Fprintf(sb,
			`<text x="%d" y="%d" font-size="9" fill="#78716C">%s</text>`,
			x+32+headerWidth+8, y+1, idText)
	}

	// Render AZ columns side-by-side. Each AZ column carries its
	// subnets stacked vertically + any AZ-scoped resources (multi-AZ
	// services like RDS pinned by AvailabilityZone).
	innerX := x + 14
	innerY := y + vpcHeaderH
	innerW := w - 28
	azCount := len(v.azs)
	if azCount > 0 {
		azGap := 12
		azW := (innerW - (azCount-1)*azGap) / azCount
		if azW < 200 {
			azW = 200
		}
		// Compute the tallest AZ column so they line up visually.
		azHeights := make([]int, azCount)
		for i, az := range v.azs {
			azHeights[i] = azColumnHeight(az, azW)
		}
		tallest := 0
		for _, h := range azHeights {
			if h > tallest {
				tallest = h
			}
		}
		for i, az := range v.azs {
			ax := innerX + i*(azW+azGap)
			renderAZColumn(sb, az, ax, innerY, azW, tallest, pr)
		}
		innerY += tallest + 10
	}

	// Blueprint deliberately omits VPC chrome (SG, IGW, NAT, RT,
	// NACL, EIP) and "loose-in-VPC" resources. The audit data still
	// captures them; they just don't earn diagram space.
	_ = innerY
	_ = innerW
}

func vpcHeight(v *topoVPC, innerW int) int {
	h := vpcHeaderH + 8

	// AZ columns are equalized to the tallest one. Blueprint drops
	// loose-in-VPC and chrome rows so the VPC frame collapses to
	// just the AZ stack.
	azCount := len(v.azs)
	if azCount > 0 {
		azGap := 12
		azW := (innerW - 28 - (azCount-1)*azGap) / azCount
		if azW < 200 {
			azW = 200
		}
		tallest := 0
		for _, az := range v.azs {
			if hh := azColumnHeight(az, azW); hh > tallest {
				tallest = hh
			}
		}
		h += tallest + 10
	}
	h += 16 // bottom padding
	return h
}

// -----------------------------------------------------------------------------
// AZ column
// -----------------------------------------------------------------------------

const (
	azHeaderH = 26
	azPad     = 8
)

// azColumnHeight returns the inner height needed for one AZ column at
// the given width.
func azColumnHeight(az *topoAZ, w int) int {
	h := azHeaderH + azPad
	for _, s := range az.subnets {
		h += subnetHeight(s, w-2*azPad) + 8
	}
	if len(az.subnets) > 0 {
		h -= 8
	}
	if len(az.resources) > 0 {
		cols := (w - 2*azPad) / iconCellW
		if cols < 1 {
			cols = 1
		}
		rows := (len(az.resources) + cols - 1) / cols
		h += rows*iconCellH + 12
	}
	return h + azPad
}

// renderAZColumn draws one AZ container with its subnets stacked
// inside it. AZ-scoped resources (multi-AZ services without an
// owning subnet) render at the bottom of the column.
func renderAZColumn(sb *strings.Builder, az *topoAZ, x, y, w, h int, pr *positionRegistry) {
	// AZ container — thin neutral-gray solid frame; the AZ reads as a
	// logical grouping inside the VPC, not a hard boundary.
	fmt.Fprintf(sb,
		`<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="#A8A29E" stroke-width="0.8"/>`,
		x, y, w, h)
	name := az.name
	if name == "" {
		name = "(zone unknown)"
	}
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="9.5" font-weight="700" fill="#57534E" letter-spacing="0.08em">AZ · %s</text>`,
		x+azPad+2, y+16, svgEscape(name))

	innerX := x + azPad
	innerY := y + azHeaderH
	innerW := w - 2*azPad
	for _, s := range az.subnets {
		sh := subnetHeight(s, innerW)
		renderSubnet(sb, s, innerX, innerY, innerW, sh, pr)
		innerY += sh + 8
	}
	if len(az.resources) > 0 {
		fmt.Fprintf(sb,
			`<text x="%d" y="%d" font-size="9.5" font-weight="700" fill="#475569" letter-spacing="0.14em">AZ-SCOPED</text>`,
			innerX, innerY+12)
		rowY := innerY + 20
		cols := innerW / iconCellW
		if cols < 1 {
			cols = 1
		}
		for i, r := range az.resources {
			col := i % cols
			rowIdx := i / cols
			ix := innerX + col*iconCellW
			iy := rowY + rowIdx*iconCellH
			renderResourceIcon(sb, pr, r, ix, iy)
		}
	}
}

// -----------------------------------------------------------------------------
// Subnet
// -----------------------------------------------------------------------------

func renderSubnet(sb *strings.Builder, s *topoSubnet, x, y, w, h int, pr *positionRegistry) {
	// Blueprint subnet frame: 1px solid colored border, 22px header
	// strip with a 7% tint, kind+CIDR label left and subnet-id right.
	public, _ := s.res.Inputs["MapPublicIpOnLaunch"].(bool)
	border := "#0D9488" // private (teal)
	kind := "PRIVATE"
	subnetIcon := "__group__/subnet_private"
	if public {
		border = "#65A30D" // public (lime)
		kind = "PUBLIC"
		subnetIcon = "__group__/subnet_public"
	}
	fmt.Fprintf(sb,
		`<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="%s" stroke-width="1"/>`,
		x, y, w, h, border)
	// Header strip — 22px tall, 7% tint of the border colour.
	fmt.Fprintf(sb,
		`<rect x="%d" y="%d" width="%d" height="22" fill="%s" fill-opacity="0.07"/>`,
		x, y, w, border)
	sb.WriteString(iconForCFNType(subnetIcon, x+5, y+4, 14, "SN"))
	cidr, _ := s.res.Inputs["CidrBlock"].(string)
	header := kind
	if cidr != "" {
		header = kind + " · " + cidr
	}
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="9.5" font-weight="700" fill="%s" letter-spacing="0.06em">%s</text>`,
		x+24, y+15, border, svgEscape(header))
	if s.res.ID != "" {
		fmt.Fprintf(sb,
			`<text x="%d" y="%d" text-anchor="end" font-size="8.5" fill="#78716C">%s</text>`,
			x+w-8, y+15, svgEscape(svgTruncate(s.res.ID, 18)))
	}

	// Resources placed inside the subnet body. Empty subnets get a
	// faint italic "(no managed compute)" placeholder so the cell
	// doesn't read as broken.
	innerX := x + 12
	innerY := y + subnetHeaderH + 8
	innerW := w - 24
	if len(s.resources) == 0 {
		fmt.Fprintf(sb,
			`<text x="%d" y="%d" text-anchor="middle" font-size="12" font-style="italic" fill="#A8A29E">(no managed compute)</text>`,
			x+w/2, y+h/2+4)
		return
	}
	cols := innerW / iconCellW
	if cols < 1 {
		cols = 1
	}
	for i, r := range s.resources {
		col := i % cols
		rowIdx := i / cols
		ix := innerX + col*iconCellW
		iy := innerY + rowIdx*iconCellH
		renderResourceIcon(sb, pr, r, ix, iy)
	}
}

func subnetHeight(s *topoSubnet, innerW int) int {
	cols := innerW / iconCellW
	if cols < 1 {
		cols = 1
	}
	if len(s.resources) == 0 {
		return subnetHeaderH + 60 // room for the italic placeholder
	}
	rows := (len(s.resources) + cols - 1) / cols
	if rows < 1 {
		rows = 1
	}
	return subnetHeaderH + 8 + rows*iconCellH + 12
}

// -----------------------------------------------------------------------------
// Edge lane
// -----------------------------------------------------------------------------

func renderEdgeLane(sb *strings.Builder, edges []DiscoveredResource, x, y, w int, pr *positionRegistry) int {
	// No encapsulating frame — Blueprint just stacks the boxes
	// directly under a small "EDGE · CDN" label.
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="9.5" font-weight="700" fill="#57534E" letter-spacing="0.14em">EDGE · CDN</text>`,
		x, y+2)
	cy := y + 14
	// Users entry point at the top — a 200×56 box stylistically
	// matching the rest, but with a custom silhouette icon.
	usersBox := DiscoveredResource{
		Type: "__blueprint__/users", URN: "blueprint:users", ID: "anonymous",
	}
	_ = usersBox
	renderUsersBox(sb, x, cy)
	pr.registerBox("blueprint:users", x, cy, boxW, boxH)
	cy += boxH + 16
	for _, r := range edges {
		renderResourceIcon(sb, pr, r, x, cy)
		cy += boxH + 16
	}
	return cy - y
}

// renderUsersBox draws the "Public users" entry tile — 200×56 with a
// minimal silhouette icon on the left to match the Blueprint design.
func renderUsersBox(sb *strings.Builder, x, y int) {
	fmt.Fprintf(sb,
		`<rect class="bp-node" x="%d" y="%d" width="%d" height="%d" fill="#FFFFFF" stroke="#1C1917" stroke-width="0.9"/>`,
		x, y, boxW, boxH,
	)
	// Square silhouette icon
	fmt.Fprintf(sb,
		`<g transform="translate(%d,%d)">`+
			`<rect width="40" height="40" rx="4" fill="none" stroke="#1C1917" stroke-width="1.4"/>`+
			`<circle cx="20" cy="14" r="5.5" fill="#1C1917"/>`+
			`<path d="M 8 33 a 12 12 0 0 1 24 0 Z" fill="#1C1917"/>`+
			`</g>`,
		x+8, y+8,
	)
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="11.5" font-weight="700" fill="#1C1917" font-family="Inter, ui-sans-serif, sans-serif">Public users</text>`,
		x+56, y+22,
	)
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="9.5" fill="#57534E">anonymous</text>`,
		x+56, y+38,
	)
}

// -----------------------------------------------------------------------------
// Lateral lane (right-side services)
// -----------------------------------------------------------------------------

func renderLateralLane(sb *strings.Builder, buckets []lateralBucket, x, y, w int, pr *positionRegistry) int {
	if len(buckets) == 0 {
		return 0
	}
	// Flatten the buckets — Blueprint shows DATA · STATE as one stack
	// of resource boxes rather than separate component cards. Identity
	// / observability buckets (IAM, KMS, CloudWatch) are filtered out;
	// they live in the bottom account-scoped strip.
	fmt.Fprintf(sb,
		`<text x="%d" y="%d" font-size="9.5" font-weight="700" fill="#57534E" letter-spacing="0.14em">DATA · STATE</text>`,
		x, y+2)
	cy := y + 14
	for _, b := range buckets {
		if isAccountScopedBucket(b.Title) || isHiddenBucket(b.Title) {
			continue
		}
		for _, r := range b.Resources {
			renderResourceIcon(sb, pr, r, x, cy)
			cy += boxH + 16
		}
	}
	return cy - y
}

// isAccountScopedBucket returns true for lateral-lane buckets that
// Blueprint moves to the bottom strip (Identity / Secrets /
// Observability). The DATA·STATE column keeps Storage, Databases,
// Compute (non-VPC), App-integration.
func isAccountScopedBucket(title string) bool {
	switch title {
	case "Identity", "Security", "Secrets", "Observability", "Management", "Logging":
		return true
	}
	return false
}

// isHiddenBucket returns true for low-signal buckets the renderer
// drops from the diagram entirely. The data is still reachable in
// the markdown report and JSON state file.
func isHiddenBucket(title string) bool {
	switch title {
	case "_hide", "Other", "Edge":
		// "Edge" appears in the lateral list when something was
		// classified there but is already drawn in the left edge
		// lane; "Other" catches resources we don't know what to do
		// with and would just clutter the right column.
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// Defs / watermark / helpers
// -----------------------------------------------------------------------------

// svgThemeStyle is the embedded stylesheet that makes the diagram
// dark-mode aware without giving up portability:
//
//   - Every themable colour stays a presentation attribute (the light
//     Blueprint palette) and is remapped here to a CSS var carrying the
//     same light value as fallback. Renderers that ignore <style>
//     (image rasterizers, markdown <img> pipelines) keep producing
//     today's light sheet byte-for-byte.
//   - Opened standalone in a browser, the prefers-color-scheme block
//     below supplies the dark values.
//   - Inlined in the HTML report, the page's --bp-* tokens (defined in
//     render_aws_html.go for all three toggle states, plus a
//     [data-theme="light"] .cbx-arch and an @media print override that
//     beat the media query here) take precedence. Keep the var names
//     and light values in sync with that file.
//   - Severity chips (.bp-chip) and monogram tiles (.bp-tile) are
//     excluded on purpose: chips must keep matching the sidebar/NOTES
//     pills (which stay the same in both themes), tiles are AWS brand
//     colours. Pure white (#FFFFFF) is never remapped globally — the
//     two node-card rects opt in via the .bp-node class; chip/monogram
//     text stays white over its saturated fill.
const svgThemeStyle = `<style>
.cbx-arch [fill="#FAF7F0"]{fill:var(--bp-paper,#FAF7F0)}
.cbx-arch [fill="#1C1917"]{fill:var(--bp-ink,#1C1917)}
.cbx-arch [fill="#57534E"]{fill:var(--bp-subtle,#57534E)}
.cbx-arch [fill="#78716C"]:not(.bp-chip){fill:var(--bp-muted,#78716C)}
.cbx-arch [fill="#A8A29E"]{fill:var(--bp-faint,#A8A29E)}
.cbx-arch [fill="#B91C1C"]:not(.bp-chip){fill:var(--bp-red,#B91C1C)}
.cbx-arch [fill="#C2410C"]:not(.bp-chip){fill:var(--bp-accent,#C2410C)}
.cbx-arch [fill="#0D9488"]{fill:var(--bp-teal,#0D9488)}
.cbx-arch [fill="#65A30D"]{fill:var(--bp-lime,#65A30D)}
.cbx-arch [fill="#64748B"]:not(.bp-tile){fill:var(--bp-slate,#64748B)}
.cbx-arch [fill="#475569"]{fill:var(--bp-slate-strong,#475569)}
.cbx-arch [stroke="#1C1917"]{stroke:var(--bp-ink,#1C1917)}
.cbx-arch [stroke="#78716C"]{stroke:var(--bp-muted,#78716C)}
.cbx-arch [stroke="#A8A29E"]{stroke:var(--bp-faint,#A8A29E)}
.cbx-arch [stroke="#B91C1C"]{stroke:var(--bp-red,#B91C1C)}
.cbx-arch [stroke="#C2410C"]{stroke:var(--bp-accent,#C2410C)}
.cbx-arch [stroke="#0D9488"]{stroke:var(--bp-teal,#0D9488)}
.cbx-arch [stroke="#65A30D"]{stroke:var(--bp-lime,#65A30D)}
.cbx-arch .bp-node{fill:var(--bp-node,#FFFFFF)}
@media (prefers-color-scheme:dark){.cbx-arch{--bp-paper:#141210;--bp-node:#1C1917;--bp-ink:#E7E5E4;--bp-subtle:#D6D3D1;--bp-muted:#A8A29E;--bp-faint:#57534E;--bp-accent:#FB923C;--bp-red:#F87171;--bp-slate:#94A3B8;--bp-slate-strong:#CBD5E1;--bp-teal:#2DD4BF;--bp-lime:#A3E635}}
</style>`

func svgDefs() string {
	return `<defs>
		<pattern id="bp-grid" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
			<path d="M 0 23.5 L 24 23.5" stroke="#1C1917" stroke-opacity="0.04" stroke-width="1"/>
		</pattern>
		<marker id="bp-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
			<path d="M 0 0 L 10 5 L 0 10 z" fill="#1C1917"/>
		</marker>
		<marker id="bp-arrow-gray" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
			<path d="M 0 0 L 10 5 L 0 10 z" fill="#78716C"/>
		</marker>
		<marker id="bp-arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
			<path d="M 0 0 L 10 5 L 0 10 z" fill="#B91C1C"/>
		</marker>
	</defs>`
}

func svgWatermark(w, h int, hasLLMConnections bool) string {
	// Blueprint line-style legend, monospace, lives at the very bottom
	// inside the SVG so it ships with screenshots/exports too.
	var b strings.Builder
	b.WriteString(`<g font-family="'JetBrains Mono', ui-monospace, monospace" font-size="10">`)
	// LINES label
	fmt.Fprintf(&b, `<text x="28" y="%d" font-weight="700" fill="#78716C" letter-spacing="0.14em">LINES</text>`,
		h-12)
	// sync (solid black)
	fmt.Fprintf(&b, `<line x1="78" y1="%d" x2="98" y2="%d" stroke="#1C1917" stroke-width="1.6"/>`+
		`<path d="M 98 %d L 104 %d L 98 %d Z" fill="#1C1917"/>`+
		`<text x="110" y="%d" fill="#1C1917" font-weight="600">sync</text>`,
		h-16, h-16, h-19, h-16, h-13, h-12)
	// async (dashed gray)
	fmt.Fprintf(&b, `<line x1="158" y1="%d" x2="178" y2="%d" stroke="#78716C" stroke-width="1.6" stroke-dasharray="4 3"/>`+
		`<path d="M 178 %d L 184 %d L 178 %d Z" fill="#78716C"/>`+
		`<text x="190" y="%d" fill="#78716C" font-weight="600">async</text>`,
		h-16, h-16, h-19, h-16, h-13, h-12)
	// unauth / priv (dashed red)
	fmt.Fprintf(&b, `<line x1="244" y1="%d" x2="264" y2="%d" stroke="#B91C1C" stroke-width="1.6" stroke-dasharray="4 3"/>`+
		`<path d="M 264 %d L 270 %d L 264 %d Z" fill="#B91C1C"/>`+
		`<text x="276" y="%d" fill="#B91C1C" font-weight="600">unauth / priv</text>`,
		h-16, h-16, h-19, h-16, h-13, h-12)
	if !hasLLMConnections {
		fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" fill="#78716C" font-style="italic">structural arrows only · run with --cb-knowledge for data-flow inference</text>`,
			w/2, h-12)
	}
	fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="end" fill="#78716C">CBX AUDIT · cloudbooster.io</text>`,
		w-28, h-12)
	b.WriteString(`</g>`)
	return b.String()
}

func svgEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// svgTruncate is the SVG-renderer-local copy; the audit package
// already has an unrelated truncate helper used by llm_analyzer.
func svgTruncate(s string, n int) string {
	if n <= 1 || len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// friendlyKind returns the AWS Architecture Center-style service
// label used under an icon. Matches AWS's reference diagrams exactly
// — "Amazon EC2", "AWS Lambda", "Amazon S3 bucket" — so the diagram
// reads as native AWS material rather than ad-hoc shorthand.
func friendlyKind(t string) string {
	switch t {
	case "AWS::Lambda::Function":
		return "AWS Lambda"
	case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster":
		return "Amazon RDS"
	case "AWS::DynamoDB::Table":
		return "Amazon DynamoDB"
	case "AWS::ElastiCache::CacheCluster", "AWS::ElastiCache::ReplicationGroup":
		return "ElastiCache"
	case "AWS::CloudFront::Distribution":
		return "Amazon CloudFront"
	case "AWS::Route53::HostedZone":
		return "Amazon Route 53"
	case "AWS::ElasticLoadBalancingV2::LoadBalancer":
		return "AWS ALB"
	case "AWS::ElasticLoadBalancing::LoadBalancer":
		return "AWS ELB"
	case "AWS::EC2::Instance":
		return "Amazon EC2"
	case "AWS::EC2::Volume":
		return "Amazon EBS"
	case "AWS::S3::Bucket":
		return "Amazon S3 bucket"
	case "AWS::KMS::Key":
		return "AWS KMS"
	case "AWS::SecretsManager::Secret":
		return "Secrets Manager"
	case "AWS::ACM::Certificate":
		return "AWS Certificate"
	case "AWS::WAFv2::WebACL", "AWS::WAF::WebACL":
		return "AWS WAF"
	case "AWS::IAM::Role":
		return "IAM Role"
	case "AWS::IAM::User":
		return "IAM User"
	case "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy":
		return "IAM Policy"
	case "AWS::IAM::Group":
		return "IAM Group"
	case "AWS::Logs::LogGroup":
		return "CloudWatch Logs"
	case "AWS::CloudTrail::Trail":
		return "AWS CloudTrail"
	case "AWS::CloudWatch::Alarm":
		return "CloudWatch Alarm"
	case "AWS::EC2::SecurityGroup":
		return "Security Group"
	case "AWS::EC2::InternetGateway":
		return "Internet Gateway"
	case "AWS::EC2::NatGateway":
		return "NAT Gateway"
	case "AWS::EC2::EIP":
		return "Elastic IP"
	case "AWS::EC2::Subnet":
		return "Subnet"
	case "AWS::EC2::VPC":
		return "VPC"
	case "AWS::EC2::RouteTable":
		return "Route Table"
	case "AWS::EC2::NetworkAcl":
		return "Network ACL"
	case "AWS::SNS::Topic":
		return "Amazon SNS"
	case "AWS::SQS::Queue":
		return "Amazon SQS"
	case "AWS::Events::Rule", "AWS::EventBridge::Rule":
		return "EventBridge"
	case "AWS::StepFunctions::StateMachine":
		return "Step Functions"
	case "AWS::APIGateway::RestApi", "AWS::ApiGateway::RestApi",
		"AWS::APIGatewayV2::Api", "AWS::ApiGatewayV2::Api":
		return "API Gateway"
	case "AWS::ECS::Cluster", "AWS::ECS::Service":
		return "Amazon ECS"
	case "AWS::EKS::Cluster":
		return "Amazon EKS"
	}
	return shortKindFromCFNType(t)
}

// -----------------------------------------------------------------------------
// Service families, colors, monograms
// -----------------------------------------------------------------------------

// familyForCFNType returns the service-family bucket for a CFN type.
// Used by the monogram-fallback icon to pick a background color
// consistent with the rest of the diagram.
func familyForCFNType(t string) string {
	svc := serviceFromCFNType(t)
	switch svc {
	case "EC2":
		if strings.HasPrefix(t, "AWS::EC2::Instance") || strings.HasPrefix(t, "AWS::EC2::EIP") ||
			strings.HasPrefix(t, "AWS::EC2::LaunchTemplate") {
			return "compute"
		}
		if strings.HasPrefix(t, "AWS::EC2::Volume") {
			return "storage"
		}
		return "network"
	case "Lambda", "ECS", "EKS", "AutoScaling", "ElasticBeanstalk", "Batch":
		return "compute"
	case "S3", "EFS", "FSx", "Backup":
		return "storage"
	case "RDS", "DynamoDB", "ElastiCache", "Redshift", "DocumentDB", "Neptune", "Timestream":
		return "data"
	case "VPC", "Route53", "ELB", "ELBv2", "ElasticLoadBalancing", "ElasticLoadBalancingV2",
		"CloudFront", "ApiGateway", "ApiGatewayV2", "AppSync", "GlobalAccelerator":
		return "network"
	case "IAM", "KMS", "SecretsManager", "ACM", "WAF", "WAFv2", "GuardDuty", "SecurityHub",
		"Macie", "Inspector", "Cognito", "Detective", "Shield":
		return "security"
	case "CloudWatch", "Logs", "CloudTrail", "Config", "SSM", "SystemsManager", "XRay",
		"AppConfig":
		return "mgmt"
	case "SQS", "SNS", "EventBridge", "Events", "StepFunctions", "MQ", "MSK":
		return "app"
	case "Athena", "Glue", "Kinesis", "EMR", "QuickSight", "DataPipeline":
		return "analytics"
	}
	return "other"
}

func familyColor(family string) string {
	switch family {
	case "compute":
		return colorCompute
	case "storage":
		return colorStorage
	case "data":
		return colorDynamo
	case "network":
		return colorNetwork
	case "security":
		return colorSecurity
	case "mgmt":
		return colorMgmt
	case "app":
		return colorAppInt
	case "analytics":
		return colorAnalytic
	}
	return "#64748B"
}

// monogramFor returns the badge text (2-4 chars) used as a fallback
// label underneath an icon. Where AWS has a recognized short code we
// use it (S3, EC2, RDS, DDB).
func monogramFor(t string) string {
	switch t {
	case "AWS::S3::Bucket":
		return "S3"
	case "AWS::EC2::Instance":
		return "EC2"
	case "AWS::EC2::Volume":
		return "EBS"
	case "AWS::EC2::VPC":
		return "VPC"
	case "AWS::EC2::Subnet":
		return "Subnet"
	case "AWS::EC2::SecurityGroup":
		return "SG"
	case "AWS::EC2::EIP":
		return "EIP"
	case "AWS::EC2::InternetGateway":
		return "IGW"
	case "AWS::EC2::NatGateway":
		return "NAT"
	case "AWS::EC2::RouteTable":
		return "RT"
	case "AWS::EC2::NetworkAcl":
		return "NACL"
	case "AWS::EC2::LaunchTemplate":
		return "LT"
	case "AWS::RDS::DBInstance":
		return "RDS"
	case "AWS::RDS::DBCluster":
		return "RDS"
	case "AWS::DynamoDB::Table":
		return "DDB"
	case "AWS::ElastiCache::CacheCluster":
		return "Cache"
	case "AWS::Lambda::Function":
		return "Lambda"
	case "AWS::ECS::Cluster", "AWS::ECS::Service":
		return "ECS"
	case "AWS::EKS::Cluster":
		return "EKS"
	case "AWS::CloudFront::Distribution":
		return "CF"
	case "AWS::Route53::HostedZone":
		return "R53"
	case "AWS::ElasticLoadBalancingV2::LoadBalancer":
		return "ALB"
	case "AWS::ElasticLoadBalancing::LoadBalancer":
		return "ELB"
	case "AWS::IAM::Role":
		return "Role"
	case "AWS::IAM::User":
		return "User"
	case "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy":
		return "Policy"
	case "AWS::IAM::Group":
		return "Group"
	case "AWS::KMS::Key":
		return "KMS"
	case "AWS::SecretsManager::Secret":
		return "Secret"
	case "AWS::ACM::Certificate":
		return "ACM"
	case "AWS::WAFv2::WebACL", "AWS::WAF::WebACL":
		return "WAF"
	case "AWS::Logs::LogGroup":
		return "Log"
	case "AWS::CloudTrail::Trail":
		return "Trail"
	case "AWS::CloudWatch::Alarm":
		return "CW"
	case "AWS::SNS::Topic":
		return "SNS"
	case "AWS::SQS::Queue":
		return "SQS"
	case "AWS::Events::Rule", "AWS::EventBridge::Rule":
		return "EB"
	case "AWS::StepFunctions::StateMachine":
		return "SFN"
	case "AWS::APIGateway::RestApi", "AWS::APIGatewayV2::Api", "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api":
		return "API"
	}
	kind := shortKindFromCFNType(t)
	if kind == "" {
		return "?"
	}
	return kind
}
