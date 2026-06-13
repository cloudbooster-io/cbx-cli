package audit

import (
	"fmt"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/assets"
)

// AWS service icons rendered as inline SVG.
//
// We use official AWS Architecture Icons (curated subset shipped under
// internal/assets/aws-icons/). The dispatcher iconForCFNType maps a
// discovered CloudControl resource type to its icon, preferring the
// "resource"-level icon (e.g. EC2 Instance with the gridlined box) over
// the "service"-level icon (e.g. plain EC2 logo) where both exist.
//
// Falls back to a colored monogram badge when no AWS icon is mapped —
// this keeps unfamiliar resource types from leaving holes in the
// diagram.

// iconForCFNType returns an SVG <g> snippet rendering the right AWS
// icon for `cfnType` at (x,y), sized so it fits in `size` × `size`.
// `monogram` is a short fallback label used when the type is unknown.
//
// Two special cfnType shapes are recognized:
//   - "__group__/<name>" loads the named group icon directly
//     (used by the topology renderer for the AWS Cloud / VPC / Subnet
//     frames so it can pull the official corner badges).
//   - regular CFN types route through awsIconNameForCFNType.
func iconForCFNType(cfnType string, x, y, size int, monogram string) string {
	if strings.HasPrefix(cfnType, "__group__/") {
		name := strings.TrimPrefix(cfnType, "__group__/")
		if ic, err := assets.LoadAWSIcon("group/" + name); err == nil {
			scale := float64(size) / float64(ic.ViewSize)
			return fmt.Sprintf(
				`<g transform="translate(%d,%d) scale(%.4f)">%s</g>`,
				x, y, scale, ic.Inner,
			)
		}
	}
	name := awsIconNameForCFNType(cfnType)
	if name != "" {
		if ic, err := assets.LoadAWSIcon(name); err == nil {
			scale := float64(size) / float64(ic.ViewSize)
			return fmt.Sprintf(
				`<g transform="translate(%d,%d) scale(%.4f)">%s</g>`,
				x, y, scale, ic.Inner,
			)
		}
	}
	return monogramFallback(x, y, size, monogram, familyForCFNType(cfnType))
}

// awsIconNameForCFNType returns the bundled-icon name (matches the
// path under internal/assets/aws-icons/) for a given CloudControl
// type, or "" when no icon is mapped.
func awsIconNameForCFNType(cfnType string) string {
	switch cfnType {
	// --- Compute ---
	case "AWS::EC2::Instance":
		return "resource/ec2_instance"
	case "AWS::EC2::EIP":
		return "resource/eip"
	case "AWS::Lambda::Function":
		return "service/lambda"
	case "AWS::ECS::Cluster", "AWS::ECS::Service", "AWS::ECS::TaskDefinition":
		return "service/ecs"
	case "AWS::EKS::Cluster":
		return "service/eks"
	case "AWS::AutoScaling::AutoScalingGroup":
		return "service/autoscaling"

	// --- Storage ---
	case "AWS::S3::Bucket":
		return "resource/s3_bucket"
	case "AWS::EC2::Volume":
		return "resource/ebs_volume"
	case "AWS::EFS::FileSystem":
		return "service/efs"

	// --- Database ---
	case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster":
		return "service/rds"
	case "AWS::DynamoDB::Table":
		return "service/dynamodb"
	case "AWS::ElastiCache::CacheCluster", "AWS::ElastiCache::ReplicationGroup":
		return "service/elasticache"

	// --- Network ---
	case "AWS::EC2::InternetGateway":
		return "resource/igw"
	case "AWS::EC2::NatGateway":
		return "resource/nat_gw"
	case "AWS::EC2::RouteTable":
		return "resource/route_table"
	case "AWS::EC2::NetworkAcl":
		return "resource/nacl"
	case "AWS::EC2::SecurityGroup":
		// AWS doesn't ship a dedicated SG icon; closest neighbor is the
		// security-identity bucket. Fall through to the monogram which
		// will render in the security-red palette.
		return ""
	case "AWS::EC2::VPC":
		return "group/vpc"
	case "AWS::EC2::Subnet":
		return "group/subnet_private"
	case "AWS::ElasticLoadBalancingV2::LoadBalancer":
		return "resource/alb"
	case "AWS::ElasticLoadBalancing::LoadBalancer":
		return "service/elb"
	case "AWS::CloudFront::Distribution":
		return "service/cloudfront"
	case "AWS::Route53::HostedZone":
		return "resource/route53_zone"
	case "AWS::APIGateway::RestApi", "AWS::ApiGateway::RestApi",
		"AWS::APIGatewayV2::Api", "AWS::ApiGatewayV2::Api":
		return "service/apigw"

	// --- Security ---
	case "AWS::IAM::Role":
		return "resource/iam_role"
	case "AWS::IAM::User", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Group":
		return "service/iam"
	case "AWS::KMS::Key":
		return "service/kms"
	case "AWS::SecretsManager::Secret":
		return "service/secrets"
	case "AWS::ACM::Certificate":
		return "service/acm"
	case "AWS::WAFv2::WebACL", "AWS::WAF::WebACL":
		return "service/waf"

	// --- Management ---
	case "AWS::CloudTrail::Trail":
		return "service/cloudtrail"
	case "AWS::CloudWatch::Alarm":
		return "service/cloudwatch"
	case "AWS::Logs::LogGroup":
		return "service/cloudwatch" // closest neighbour in the bundled set

	// --- Application integration ---
	case "AWS::SNS::Topic":
		return "service/sns"
	case "AWS::SQS::Queue":
		return "service/sqs"
	case "AWS::Events::Rule", "AWS::EventBridge::Rule":
		return "service/eventbridge"
	case "AWS::StepFunctions::StateMachine":
		return "service/stepfn"
	}
	return ""
}

// monogramFallback renders the legacy colored-square + initials icon
// for resource types we don't have a bundled icon for. Keeps the
// rendering pipeline honest: a missing icon never leaves a hole.
func monogramFallback(x, y, size int, monogram, family string) string {
	bg := familyColor(family)
	if len(monogram) > 4 {
		monogram = monogram[:4]
	}
	fontSize := 13
	switch len(monogram) {
	case 1:
		fontSize = 19
	case 2:
		fontSize = 16
	case 3:
		fontSize = 12
	case 4:
		fontSize = 10
	}
	scale := float64(size) / 40.0
	// .bp-tile keeps the badge out of svgThemeStyle's fill remapping —
	// family colours are AWS brand tiles and render fine on both themes
	// (the slate fallback shares its hex with a themed text colour).
	return fmt.Sprintf(
		`<g transform="translate(%d,%d) scale(%.4f)">`+
			`<rect class="bp-tile" x="2" y="2" width="36" height="36" rx="6" fill="%s"/>`+
			`<text x="20" y="%d" text-anchor="middle" font-family="Inter, sans-serif" font-size="%d" font-weight="700" fill="#FFFFFF" letter-spacing="0.02em">%s</text>`+
			`</g>`,
		x, y, scale, bg, 20+fontSize/3, fontSize, svgEscape(monogram),
	)
}

// -----------------------------------------------------------------------------
// Service-family palettes (AWS Architecture Icons-inspired)
// -----------------------------------------------------------------------------

// AWS official square-icon backgrounds use these category colors.
// Used by monogramFallback so missing-icon resources still feel
// like part of the same diagram. Real AWS-icon shapes carry their
// own colors, so these consts don't influence them.
const (
	colorCompute  = "#ED7100"
	colorStorage  = "#7AA116"
	colorRDS      = "#527FFF"
	colorDynamo   = "#C925D1"
	colorCache    = "#C925D1"
	colorNetwork  = "#8C4FFF"
	colorSecurity = "#DD344C"
	colorMgmt     = "#E7157B"
	colorAppInt   = "#E7157B"
	colorAnalytic = "#8C4FFF"
)
