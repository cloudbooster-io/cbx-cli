package aws

import (
	"context"
	"errors"
	"testing"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// fakeELBAttributesClient is the test double for the access-logs probe's narrow
// API seam. out/err drive DescribeLoadBalancerAttributes; gotARN records the
// ARN filter the describer passed so a test can assert the probe is scoped to
// the resource.
type fakeELBAttributesClient struct {
	out    *elbv2.DescribeLoadBalancerAttributesOutput
	err    error
	gotARN string
	calls  int
}

func (f *fakeELBAttributesClient) DescribeLoadBalancerAttributes(_ context.Context, in *elbv2.DescribeLoadBalancerAttributesInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancerAttributesOutput, error) {
	f.calls++
	if in.LoadBalancerArn != nil {
		f.gotARN = *in.LoadBalancerArn
	}
	return f.out, f.err
}

// installFakeELBClient swaps the package-level client seam for a fake so the
// describer's Enrich never makes a live AWS call, restoring the real
// constructor when the test ends.
func installFakeELBClient(t *testing.T, fake elbAttributesAPI) {
	t.Helper()
	prev := newELBAttributesClient
	newELBAttributesClient = func(awsCfg) elbAttributesAPI { return fake }
	t.Cleanup(func() { newELBAttributesClient = prev })
}

// attrsOut wraps a single access_logs.s3.enabled attribute in the SDK output
// shape the probe reads.
func attrsOut(enabledValue string) *elbv2.DescribeLoadBalancerAttributesOutput {
	return &elbv2.DescribeLoadBalancerAttributesOutput{
		Attributes: []elbv2types.LoadBalancerAttribute{
			{Key: strPtr("idle_timeout.timeout_seconds"), Value: strPtr("60")},
			{Key: strPtr("access_logs.s3.enabled"), Value: strPtr(enabledValue)},
		},
	}
}

const albARN = "arn:aws:elasticloadbalancing:eu-central-1:111122223333:loadbalancer/app/web/abc"

func TestALBDescriber_AccessLogsDisabled_SetsFieldFalse(t *testing.T) {
	installFakeELBClient(t, &fakeELBAttributesClient{out: attrsOut("false")})

	r := DiscoveredResource{
		Type:   "AWS::ElasticLoadBalancingV2::LoadBalancer",
		ID:     albARN,
		Region: "eu-central-1",
		Inputs: map[string]any{"Type": "application"},
	}
	if err := (albAccessLogsDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got, ok := r.Inputs["cb_describer_alb_access_logs_enabled"]; !ok || got != false {
		t.Errorf("cb_describer_alb_access_logs_enabled = (%v, %v), want (false, true)", got, ok)
	}
}

func TestALBDescriber_AccessLogsEnabled_SetsFieldTrue(t *testing.T) {
	installFakeELBClient(t, &fakeELBAttributesClient{out: attrsOut("true")})

	r := DiscoveredResource{
		Type:   "AWS::ElasticLoadBalancingV2::LoadBalancer",
		ID:     albARN,
		Region: "eu-central-1",
		Inputs: map[string]any{"Type": "application"},
	}
	if err := (albAccessLogsDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got, ok := r.Inputs["cb_describer_alb_access_logs_enabled"]; !ok || got != true {
		t.Errorf("cb_describer_alb_access_logs_enabled = (%v, %v), want (true, true)", got, ok)
	}
}

func TestALBDescriber_ProbeError_LeavesFieldAbsent(t *testing.T) {
	// A denied probe must NEVER abort: it returns the classified error (so
	// --diagnose surfaces the missing grant) but leaves the boolean ABSENT
	// (UNKNOWN, never false) so the rule cannot false-fire off a fetch failure.
	installFakeELBClient(t, &fakeELBAttributesClient{err: &fakeAPIError{code: "AccessDenied"}})

	r := DiscoveredResource{
		Type:   "AWS::ElasticLoadBalancingV2::LoadBalancer",
		ID:     albARN,
		Region: "eu-central-1",
		Inputs: map[string]any{"Type": "application"},
	}
	err := (albAccessLogsDescriber{}).Enrich(context.Background(), awsCfg{}, &r)
	if err == nil {
		t.Fatal("expected the probe error to surface, got nil")
	}
	var pe *PermissionError
	if !errors.As(err, &pe) {
		t.Errorf("error = %T, want *PermissionError (so --diagnose collects it)", err)
	}
	if _, ok := r.Inputs["cb_describer_alb_access_logs_enabled"]; ok {
		t.Error("cb_describer_alb_access_logs_enabled must be ABSENT on probe error, not false")
	}
}

func TestALBDescriber_AttributeAbsent_LeavesFieldAbsent(t *testing.T) {
	// GWLB (and any LB whose response omits the attribute) → leave UNKNOWN.
	installFakeELBClient(t, &fakeELBAttributesClient{out: &elbv2.DescribeLoadBalancerAttributesOutput{
		Attributes: []elbv2types.LoadBalancerAttribute{
			{Key: strPtr("idle_timeout.timeout_seconds"), Value: strPtr("60")},
		},
	}})

	r := DiscoveredResource{
		Type:   "AWS::ElasticLoadBalancingV2::LoadBalancer",
		ID:     albARN,
		Region: "eu-central-1",
		Inputs: map[string]any{"Type": "application"},
	}
	if err := (albAccessLogsDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if _, ok := r.Inputs["cb_describer_alb_access_logs_enabled"]; ok {
		t.Error("field must be ABSENT when the attribute isn't returned, not false")
	}
}

func TestALBDescriber_AbsentType_TreatedAsALB(t *testing.T) {
	// Type is a create-only property defaulting to "application"; CloudControl
	// may omit it. An absent Type is an ALB → the probe must still run and set
	// the field (this is the common quick-created-ALB case).
	installFakeELBClient(t, &fakeELBAttributesClient{out: attrsOut("false")})

	r := DiscoveredResource{
		Type:   "AWS::ElasticLoadBalancingV2::LoadBalancer",
		ID:     albARN,
		Region: "eu-central-1",
		Inputs: map[string]any{}, // no Type key
	}
	if err := (albAccessLogsDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got, ok := r.Inputs["cb_describer_alb_access_logs_enabled"]; !ok || got != false {
		t.Errorf("absent Type should be treated as ALB; field = (%v, %v), want (false, true)", got, ok)
	}
}

func TestALBDescriber_NLB_SkippedNoProbe(t *testing.T) {
	// An NLB (Type=network) is out of scope: the probe must NOT run and the
	// field must stay absent, so the ALB rule can never false-fire on it.
	fake := &fakeELBAttributesClient{out: attrsOut("false")}
	installFakeELBClient(t, fake)

	r := DiscoveredResource{
		Type:   "AWS::ElasticLoadBalancingV2::LoadBalancer",
		ID:     "arn:aws:elasticloadbalancing:eu-central-1:111122223333:loadbalancer/net/nlb/xyz",
		Region: "eu-central-1",
		Inputs: map[string]any{"Type": "network"},
	}
	if err := (albAccessLogsDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if fake.calls != 0 {
		t.Errorf("expected no probe for an NLB, got %d call(s)", fake.calls)
	}
	if _, ok := r.Inputs["cb_describer_alb_access_logs_enabled"]; ok {
		t.Error("field must be ABSENT for an out-of-scope NLB")
	}
}

func TestLookupALBAccessLogs_EmptyARN(t *testing.T) {
	// No ARN to probe → ok=false, no error, no API call.
	fake := &fakeELBAttributesClient{out: attrsOut("false")}
	_, ok, err := lookupALBAccessLogsEnabled(context.Background(), fake, "", "eu-central-1")
	if err != nil {
		t.Fatalf("lookupALBAccessLogsEnabled: %v", err)
	}
	if ok {
		t.Error("ok must be false for an empty ARN")
	}
	if fake.calls != 0 {
		t.Errorf("expected no API call for empty ARN, got %d", fake.calls)
	}
}

func TestLookupALBAccessLogs_ScopesProbeToARN(t *testing.T) {
	fake := &fakeELBAttributesClient{out: attrsOut("true")}
	if _, _, err := lookupALBAccessLogsEnabled(context.Background(), fake, albARN, "eu-central-1"); err != nil {
		t.Fatalf("lookupALBAccessLogsEnabled: %v", err)
	}
	if fake.gotARN != albARN {
		t.Errorf("probe ARN filter = %q, want %q", fake.gotARN, albARN)
	}
}
