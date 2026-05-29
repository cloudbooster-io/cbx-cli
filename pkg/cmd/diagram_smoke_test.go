package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
)

// TestArchitectureDiagram_RoundTrip exercises the full RenderAWSHTML +
// RenderAWSMarkdown path against a fixture that mirrors the kind of
// account `cbx audit aws` actually surfaces (EIPs, EBS, KMS, S3, SGs,
// IAM, RDS, DynamoDB, Lambda, CloudFront, subnets, EC2). Dumps the
// HTML when DIAGRAM_DUMP_DIR is set so a developer can spot-check the
// rendered SVG in a browser.
func TestArchitectureDiagram_RoundTrip(t *testing.T) {
	res := func(typ, urn, id string) audit.DiscoveredResource {
		return audit.DiscoveredResource{Type: typ, URN: urn, ID: id}
	}
	resIn := func(typ, urn, id string, inputs map[string]interface{}) audit.DiscoveredResource {
		return audit.DiscoveredResource{Type: typ, URN: urn, ID: id, Inputs: inputs}
	}

	resources := []audit.DiscoveredResource{
		// Compute — placed inside subnet-001 / subnet-003 via Inputs.
		// SecurityGroupIds chain to the SGs below so the connection
		// inference pass draws Instance → SG arrows.
		resIn("AWS::EC2::Instance", "aws://us-east-1/AWS::EC2::Instance/i-007e1a32c5193099", "i-007e1a32c",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d", "SubnetId": "subnet-01732f0", "SecurityGroupIds": []interface{}{"sg-067ca7f"}}),
		resIn("AWS::EC2::Instance", "aws://us-east-1/AWS::EC2::Instance/i-09f21ec97b1afa29", "i-09f21ec97b",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d", "SubnetId": "subnet-09abcf1", "SecurityGroupIds": []interface{}{"sg-0bda14d"}}),
		// Lambda is VPC-attached so it connects to two subnets + a SG
		resIn("AWS::Lambda::Function", "aws://us-east-1/AWS::Lambda::Function/cbx-audit-lambda", "cbx-audit-lambda",
			map[string]interface{}{"VpcConfig": map[string]interface{}{
				"SubnetIds":        []interface{}{"subnet-04e91bd"},
				"SecurityGroupIds": []interface{}{"sg-0bda14d"},
			}}),
		// EIP-001 is attached to the first instance so the arrow draws.
		resIn("AWS::EC2::EIP", "aws://us-east-1/AWS::EC2::EIP/eipalloc-001", "eipalloc-001",
			map[string]interface{}{"InstanceId": "i-007e1a32c"}),
		res("AWS::EC2::EIP", "aws://us-east-1/AWS::EC2::EIP/eipalloc-002", "eipalloc-002"),
		res("AWS::EC2::EIP", "aws://us-east-1/AWS::EC2::EIP/eipalloc-003", "eipalloc-003"),
		// Storage
		res("AWS::S3::Bucket", "aws://us-east-1/AWS::S3::Bucket/cbx-audit-plain", "cbx-audit-plain-x9N4z7"),
		res("AWS::S3::Bucket", "aws://us-east-1/AWS::S3::Bucket/cbx-audit-private", "cbx-audit-private-k9N4z7"),
		res("AWS::S3::Bucket", "aws://us-east-1/AWS::S3::Bucket/cbx-audit-public", "cbx-audit-public-pN4z7"),
		res("AWS::EC2::Volume", "aws://us-east-1/AWS::EC2::Volume/vol-01a", "vol-01abc0fa3a76c39c1"),
		res("AWS::EC2::Volume", "aws://us-east-1/AWS::EC2::Volume/vol-02b", "vol-02bccebe793cd0a3"),
		res("AWS::EC2::Volume", "aws://us-east-1/AWS::EC2::Volume/vol-03c", "vol-03c0964a755a8a92"),
		// Data — RDS has an AvailabilityZone so the classifier can
		// pin it inside the right AZ column. DynamoDB is global so it
		// stays in the lateral lane.
		resIn("AWS::RDS::DBInstance", "aws://us-east-1/AWS::RDS::DBInstance/cbx-audit-pg", "cbx-audit-pg",
			map[string]interface{}{
				"VpcId":            "vpc-0a1b2c3d",
				"AvailabilityZone": "us-east-1b",
				"VPCSecurityGroups": []interface{}{
					map[string]interface{}{"VPCSecurityGroupId": "sg-067ca7f"},
				},
			}),
		res("AWS::DynamoDB::Table", "aws://us-east-1/AWS::DynamoDB::Table/cbx-audit-ddb", "cbx-audit-ddb"),
		// Network — give them real refs so the topology classifier
		// can chain VPC → Subnet → Instance / RDS.
		resIn("AWS::EC2::VPC", "aws://us-east-1/AWS::EC2::VPC/vpc-cbx", "vpc-0a1b2c3d",
			map[string]interface{}{"CidrBlock": "10.0.0.0/16"}),
		resIn("AWS::EC2::Subnet", "aws://us-east-1/AWS::EC2::Subnet/subnet-001", "subnet-01732f0",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d", "AvailabilityZone": "us-east-1a", "CidrBlock": "10.0.1.0/24"}),
		resIn("AWS::EC2::Subnet", "aws://us-east-1/AWS::EC2::Subnet/subnet-002", "subnet-04e91bd",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d", "AvailabilityZone": "us-east-1a", "CidrBlock": "10.0.2.0/24"}),
		resIn("AWS::EC2::Subnet", "aws://us-east-1/AWS::EC2::Subnet/subnet-003", "subnet-09abcf1",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d", "AvailabilityZone": "us-east-1b", "CidrBlock": "10.0.3.0/24"}),
		resIn("AWS::EC2::Subnet", "aws://us-east-1/AWS::EC2::Subnet/subnet-004", "subnet-0f73a98",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d", "AvailabilityZone": "us-east-1b", "CidrBlock": "10.0.4.0/24"}),
		resIn("AWS::EC2::SecurityGroup", "aws://us-east-1/AWS::EC2::SecurityGroup/sg-001", "sg-067ca7f",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d"}),
		resIn("AWS::EC2::SecurityGroup", "aws://us-east-1/AWS::EC2::SecurityGroup/sg-002", "sg-0bda14d",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d"}),
		// IGW attaches to the VPC via Attachments[].VpcId — the
		// CloudControl-style shape we expect from a real audit.
		resIn("AWS::EC2::InternetGateway", "aws://us-east-1/AWS::EC2::InternetGateway/igw-001", "igw-0a1b2",
			map[string]interface{}{
				"VpcId":       "vpc-0a1b2c3d",
				"Attachments": []interface{}{map[string]interface{}{"VpcId": "vpc-0a1b2c3d"}},
			}),
		// NAT GW lives in a specific subnet — the arrow points to it.
		resIn("AWS::EC2::NatGateway", "aws://us-east-1/AWS::EC2::NatGateway/nat-001", "nat-0a1b2",
			map[string]interface{}{"VpcId": "vpc-0a1b2c3d", "SubnetId": "subnet-01732f0"}),
		// Edge
		res("AWS::CloudFront::Distribution", "aws://global/AWS::CloudFront::Distribution/E2", "E2VRNAOMA4B2P"),
		res("AWS::CloudFront::Distribution", "aws://global/AWS::CloudFront::Distribution/E3", "E2VIQLAH9KDT9HQ"),
		// Security / Identity
		res("AWS::IAM::Role", "aws://global/AWS::IAM::Role/OrganizationAccountAccessRole", "OrganizationAccountAccessRole"),
		res("AWS::IAM::Role", "aws://global/AWS::IAM::Role/cbx-audit-lambda-admin", "cbx-audit-lambda-admin"),
		res("AWS::IAM::Role", "aws://global/AWS::IAM::Role/cbx-audit-overprivileged", "cbx-audit-overprivileged"),
		res("AWS::KMS::Key", "aws://us-east-1/AWS::KMS::Key/key-01", "529c2814-4022-4775-93cb-fa1e29a93a"),
		res("AWS::KMS::Key", "aws://us-east-1/AWS::KMS::Key/key-02", "ca9551b-9f1d-4727-84a0-cbeb2e93e1"),
		res("AWS::KMS::Key", "aws://us-east-1/AWS::KMS::Key/key-03", "a3003954-b131-4a4e-ac11-bd2f3e9ac0"),
		res("AWS::SecretsManager::Secret", "aws://us-east-1/AWS::SecretsManager::Secret/cbx-audit", "arn:aws:secretsmanager:1"),
		// Observability
		res("AWS::Logs::LogGroup", "aws://us-east-1/AWS::Logs::LogGroup/cbx-audit-test", "/cbx-audit-test/no-retention"),
	}

	prim := func(name string, urns []string) group.Component {
		return group.Component{Name: name + ":urn", Kind: "cb-primitive", Resources: urns,
			Source: map[string]string{"primitive": name}}
	}
	tagComp := func(name string, urns []string) group.Component {
		return group.Component{Name: name, Kind: "tag", Resources: urns}
	}

	components := []group.Component{
		tagComp("eip", []string{
			"aws://us-east-1/AWS::EC2::EIP/eipalloc-001",
			"aws://us-east-1/AWS::EC2::EIP/eipalloc-002",
			"aws://us-east-1/AWS::EC2::EIP/eipalloc-003",
		}),
		prim("aws:storage/ebs@v1", []string{
			"aws://us-east-1/AWS::EC2::Volume/vol-01a",
			"aws://us-east-1/AWS::EC2::Volume/vol-02b",
			"aws://us-east-1/AWS::EC2::Volume/vol-03c",
		}),
		prim("aws:security/kms-keys@v1", []string{
			"aws://us-east-1/AWS::KMS::Key/key-01",
			"aws://us-east-1/AWS::KMS::Key/key-02",
			"aws://us-east-1/AWS::KMS::Key/key-03",
		}),
		prim("aws:secrets/bundle@v1", []string{
			"aws://us-east-1/AWS::SecretsManager::Secret/cbx-audit",
		}),
		prim("aws:s3/bucket@v1", []string{
			"aws://us-east-1/AWS::S3::Bucket/cbx-audit-plain",
			"aws://us-east-1/AWS::S3::Bucket/cbx-audit-private",
			"aws://us-east-1/AWS::S3::Bucket/cbx-audit-public",
		}),
		prim("aws:observability/log-group@v1", []string{
			"aws://us-east-1/AWS::Logs::LogGroup/cbx-audit-test",
		}),
		prim("aws:network/security-group@v1", []string{
			"aws://us-east-1/AWS::EC2::SecurityGroup/sg-001",
			"aws://us-east-1/AWS::EC2::SecurityGroup/sg-002",
		}),
		prim("aws:iam/role@v1", []string{
			"aws://global/AWS::IAM::Role/OrganizationAccountAccessRole",
			"aws://global/AWS::IAM::Role/cbx-audit-lambda-admin",
			"aws://global/AWS::IAM::Role/cbx-audit-overprivileged",
		}),
		prim("aws:db/postgres@v1", []string{
			"aws://us-east-1/AWS::RDS::DBInstance/cbx-audit-pg",
		}),
		prim("aws:db/dynamodb@v1", []string{
			"aws://us-east-1/AWS::DynamoDB::Table/cbx-audit-ddb",
		}),
		prim("aws:compute/lambda@v1", []string{
			"aws://us-east-1/AWS::Lambda::Function/cbx-audit-lambda",
		}),
		prim("aws:compute/ec2@v1", []string{
			"aws://us-east-1/AWS::EC2::Instance/i-007e1a32c5193099",
			"aws://us-east-1/AWS::EC2::Instance/i-09f21ec97b1afa29",
		}),
		prim("aws:network/subnet@v1", []string{
			"aws://us-east-1/AWS::EC2::Subnet/subnet-001",
			"aws://us-east-1/AWS::EC2::Subnet/subnet-002",
			"aws://us-east-1/AWS::EC2::Subnet/subnet-003",
			"aws://us-east-1/AWS::EC2::Subnet/subnet-004",
		}),
		prim("aws:cdn/distribution@v1", []string{
			"aws://global/AWS::CloudFront::Distribution/E2",
			"aws://global/AWS::CloudFront::Distribution/E3",
		}),
	}

	ctx := audit.AWSAuditContext{
		AccountID:  "123456789012",
		Identity:   "arn:aws:iam::123456789012:user/cbx-audit",
		Regions:    []string{"us-east-1"},
		EventCount: 117,
	}

	// Hand-built LLM connections so the smoke test exercises the
	// new arrow path. In a real audit these come from the grounded
	// analyzer's JSON response.
	llmConns := []audit.LLMConnection{
		{
			From:  "aws://us-east-1/AWS::Lambda::Function/cbx-audit-lambda",
			To:    "aws://us-east-1/AWS::DynamoDB::Table/cbx-audit-ddb",
			Label: "reads",
		},
		{
			From:  "aws://us-east-1/AWS::Lambda::Function/cbx-audit-lambda",
			To:    "aws://us-east-1/AWS::SecretsManager::Secret/cbx-audit",
			Label: "fetches",
		},
		{
			From:  "aws://global/AWS::CloudFront::Distribution/E2",
			To:    "aws://us-east-1/AWS::S3::Bucket/cbx-audit-public",
			Label: "origin",
		},
	}
	svg := audit.BuildArchitectureSVG(resources, components, ctx, llmConns, nil)
	if !strings.HasPrefix(svg, "<svg") {
		t.Fatalf("expected SVG output, got %.80q", svg)
	}

	mermaidSrc := audit.BuildArchitectureDiagram(resources, components)
	result := &audit.Result{
		Components: components,
		Diagram:    mermaidSrc,
		DiagramSVG: svg,
	}
	md := audit.RenderAWSMarkdown(result, ctx)
	html := audit.RenderAWSHTML(result, ctx, md)

	// Markdown architecture section embeds the SVG (inline, since
	// this test passes svg without a sibling filename). Mermaid was
	// removed — the SVG is the only architecture diagram now.
	if !strings.Contains(md, "## Architecture") || !strings.Contains(md, "<svg") {
		t.Error("markdown report missing the Architecture section with embedded <svg>")
	}
	if strings.Contains(md, "```mermaid") {
		t.Error("markdown still contains a mermaid block — should be removed")
	}
	if !strings.Contains(html, `<svg`) {
		t.Error("HTML report missing <svg> root")
	}
	if !strings.Contains(html, "SHEET A1 · INFRASTRUCTURE TOPOLOGY") {
		t.Error("HTML missing the Blueprint sheet header")
	}
	if strings.Contains(html, "mermaid.initialize") {
		t.Error("HTML still bundles mermaid.js — should be stripped")
	}

	// State sidecar round-trip — verifies the audit-state JSON
	// captures everything the replay tool needs.
	stateRoundtripDir := t.TempDir()
	statePath := stateRoundtripDir + "/state.json"
	if err := audit.SaveAuditState(statePath, audit.AuditState{
		Context:        ctx,
		Resources:      resources,
		Components:     components,
		LLMConnections: llmConns,
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}
	loaded, err := audit.LoadAuditState(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(loaded.Resources) != len(resources) {
		t.Errorf("state resources: got %d, want %d", len(loaded.Resources), len(resources))
	}
	if len(loaded.Components) != len(components) {
		t.Errorf("state components: got %d, want %d", len(loaded.Components), len(components))
	}
	if len(loaded.LLMConnections) != len(llmConns) {
		t.Errorf("state llm-connections: got %d, want %d", len(loaded.LLMConnections), len(llmConns))
	}
	// Re-render from the loaded state — the SVG should be identical
	// modulo any non-determinism (there shouldn't be any).
	svg2 := audit.BuildArchitectureSVG(loaded.Resources, loaded.Components, loaded.Context, loaded.LLMConnections, loaded.Findings)
	if svg2 != svg {
		t.Errorf("replay SVG differs from original (lens=%d vs %d)", len(svg2), len(svg))
	}

	if dir := os.Getenv("DIAGRAM_DUMP_DIR"); dir != "" {
		_ = audit.SaveAuditState(dir+"/sample.state.json", audit.AuditState{
			Context:        ctx,
			Resources:      resources,
			Components:     components,
			LLMConnections: llmConns,
		})
		_ = os.WriteFile(dir+"/out.html", []byte(html), 0o644)
		_ = os.WriteFile(dir+"/out.md", []byte(md), 0o644)
		_ = os.WriteFile(dir+"/out.svg", []byte(svg), 0o644)
		t.Logf("wrote sample report to %s", dir)
	}
}
