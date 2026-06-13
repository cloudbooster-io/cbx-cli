package aws

import (
	"context"
	"strconv"
	"strings"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

// albAccessLogsDescriber enriches AWS::ElasticLoadBalancingV2::LoadBalancer
// resources with their access-logging posture, which CloudControl does NOT
// expose. CloudControl returns the LoadBalancer's writeable properties (Name,
// Scheme, Type, Subnets, SecurityGroups, …) but access logging lives in the
// load balancer ATTRIBUTES sub-resource (access_logs.s3.enabled), which has no
// CFN property and is invisible in the CC payload. Without this describer the
// audit has zero signal about whether an ALB logs requests to S3 — empirically
// confirmed absent from raw-audit.json in the pre-check.
//
// So the describer makes one best-effort
// elasticloadbalancing:DescribeLoadBalancerAttributes call (authorized by the
// elasticloadbalancing:Describe* grant already in docs/cbx-audit-aws-iam.json)
// and folds the access_logs.s3.enabled attribute into a single POSITIVE
// boolean the grounded prompt's (forthcoming) baseline rule keys off:
//
//	cb_describer_alb_access_logs_enabled — true iff access logs are enabled,
//	                                       false iff explicitly disabled.
//
// Scope: only Application Load Balancers. NLB (Type=network) also supports
// access_logs.s3.enabled, but it is out of scope for the ALB rule and would be
// a false-positive source there; GWLB (Type=gateway) doesn't support the
// attribute at all. Type is a create-only property defaulting to "application",
// so an ABSENT/empty Type is an ALB — NLB and GWLB always carry an explicit
// non-application Type — which we treat as in-scope. Restricting the field-set
// to ALBs keeps the cb_describer_alb_* name literally accurate and means the
// downstream rule cannot fire on an NLB even if it forgets to gate on Type.
//
// FP-safety / polarity (mirrors the RDS replica-role probe): the boolean is a
// POSITIVE field, NEVER inferred from absence. It is set ONLY when the
// DescribeLoadBalancerAttributes call succeeds AND returns a parseable
// access_logs.s3.enabled attribute. A probe error (returned classified so
// --diagnose surfaces a missing grant), an empty ARN, or a missing/unparseable
// attribute all leave the field ABSENT — absence reads as UNKNOWN downstream
// and the rule does NOT fire, so a permission/throttle error can never
// masquerade as "access logging disabled."
type albAccessLogsDescriber struct{}

func (albAccessLogsDescriber) CFNType() string {
	return "AWS::ElasticLoadBalancingV2::LoadBalancer"
}

func (albAccessLogsDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	// Only Application Load Balancers are in scope (see type comment). An
	// explicit non-"application" Type (network / gateway) is skipped; an
	// absent/empty Type is the AWS default "application" → in scope.
	if t := readStr(r.Inputs, "Type"); t != "" && !strings.EqualFold(t, "application") {
		return nil
	}

	// The awsCfg handed to Enrich is the BASE config; the lister gets the
	// region separately, so we MUST re-pin to the resource's region here.
	// DescribeLoadBalancerAttributes is region-bound, and calling it against
	// the wrong region would 400 and silently suppress the signal. r.Region is
	// populated by mapToDiscovered.
	if r.Region != "" {
		c = c.withRegion(r.Region)
	}
	return enrichALBAccessLogs(ctx, newELBAttributesClient(c), c.region(), r)
}

// newELBAttributesClient builds the ELBv2 client the describer probes with. It
// is a package-level var (not an inline elbv2.NewFromConfig) purely so unit
// tests can inject a fake — Enrich takes awsCfg, not an interface, so the seam
// has to live here. Mirrors newRDSReplicaClient.
var newELBAttributesClient = func(c awsCfg) elbAttributesAPI {
	return elbv2.NewFromConfig(c.cfg)
}

// elbAttributesAPI is the narrow slice of the ELBv2 client the probe needs —
// just DescribeLoadBalancerAttributes. The concrete *elbv2.Client satisfies it;
// the seam lets the partial-failure / unknown-state handling be unit-tested
// without a live call (mirrors rdsReplicaAPI).
type elbAttributesAPI interface {
	DescribeLoadBalancerAttributes(context.Context, *elbv2.DescribeLoadBalancerAttributesInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancerAttributesOutput, error)
}

// enrichALBAccessLogs runs the best-effort attributes probe and publishes the
// POSITIVE access-logging boolean. It must NEVER abort: a probe error returns
// the classified error (so the discovery loop collects it for --diagnose) while
// the resource itself is kept with every CC field intact (discover.go appends
// the resource regardless of Enrich's error). An undeterminable result leaves
// the field ABSENT, never false.
func enrichALBAccessLogs(ctx context.Context, client elbAttributesAPI, region string, r *DiscoveredResource) error {
	enabled, ok, err := lookupALBAccessLogsEnabled(ctx, client, r.ID, region)
	if err != nil {
		return err
	}
	if !ok {
		return nil // could not determine — leave the field absent (UNKNOWN)
	}
	r.Inputs["cb_describer_alb_access_logs_enabled"] = enabled
	return nil
}

// lookupALBAccessLogsEnabled resolves the access_logs.s3.enabled attribute via
// a single ARN-filtered DescribeLoadBalancerAttributes.
//
// ok=false means "could not determine" — an empty ARN, a nil response, or the
// attribute simply not being present (GWLB never returns it). The caller leaves
// the field absent rather than asserting a value it never read. A real API
// error is classified and returned so it surfaces to --diagnose without
// dropping the resource.
func lookupALBAccessLogsEnabled(ctx context.Context, client elbAttributesAPI, arn, region string) (enabled, ok bool, err error) {
	if arn == "" {
		return false, false, nil
	}
	out, derr := client.DescribeLoadBalancerAttributes(ctx, &elbv2.DescribeLoadBalancerAttributesInput{
		LoadBalancerArn: &arn,
	})
	if derr != nil {
		return false, false, classifyAWSError(derr, "elasticloadbalancing", "elasticloadbalancing:DescribeLoadBalancerAttributes", region)
	}
	if out == nil {
		return false, false, nil
	}
	for _, a := range out.Attributes {
		if a.Key == nil || *a.Key != "access_logs.s3.enabled" {
			continue
		}
		if a.Value == nil {
			return false, false, nil
		}
		// The attribute value is the string "true" / "false". A value that
		// doesn't parse is treated as UNKNOWN rather than guessed.
		v, perr := strconv.ParseBool(*a.Value)
		if perr != nil {
			return false, false, nil
		}
		return v, true, nil
	}
	return false, false, nil // attribute not present — leave UNKNOWN
}
