package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fakeEKSOIDCClient is the test double for the IRSA probe's IAM seam. out/err
// drive ListOpenIDConnectProviders; calls records whether the probe ran so a
// test can assert it is skipped when the cluster issuer is unknown.
type fakeEKSOIDCClient struct {
	out   *iam.ListOpenIDConnectProvidersOutput
	err   error
	calls int
}

func (f *fakeEKSOIDCClient) ListOpenIDConnectProviders(_ context.Context, _ *iam.ListOpenIDConnectProvidersInput, _ ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error) {
	f.calls++
	return f.out, f.err
}

// installFakeEKSOIDCClient swaps the package-level seam for a fake so the EKS
// describer's Enrich never makes a live AWS call, restoring the real
// constructor when the test ends (mirrors installFakeRDSClient).
func installFakeEKSOIDCClient(t *testing.T, fake eksOIDCProviderAPI) {
	t.Helper()
	prev := newEKSOIDCProviderClient
	newEKSOIDCProviderClient = func(awsCfg) eksOIDCProviderAPI { return fake }
	t.Cleanup(func() { newEKSOIDCProviderClient = prev })
}

func oidcProvidersOut(arns ...string) *iam.ListOpenIDConnectProvidersOutput {
	entries := make([]iamtypes.OpenIDConnectProviderListEntry, 0, len(arns))
	for _, a := range arns {
		a := a
		entries = append(entries, iamtypes.OpenIDConnectProviderListEntry{Arn: &a})
	}
	return &iam.ListOpenIDConnectProvidersOutput{OpenIDConnectProviderList: entries}
}

const (
	// Cluster issuer (https-scheme) and the IAM provider ARN that matches it —
	// the ARN suffix after :oidc-provider/ is the same host+path, scheme-less.
	eksIssuerAAAA      = "https://oidc.eks.us-east-1.amazonaws.com/id/AAAA1111BBBB2222CCCC3333DDDD4444"
	eksProviderARNAAAA = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/AAAA1111BBBB2222CCCC3333DDDD4444"
	// SAME oidc.eks host, DIFFERENT cluster /id path — a sibling cluster's
	// provider, which must NOT match eksIssuerAAAA.
	eksProviderARNBBBB = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/BBBB5555CCCC6666DDDD7777EEEE8888"

	eksIRSAField = "cb_describer_eks_irsa_oidc_provider_present"
)

// eksClusterResource builds a discovered cluster carrying the nested issuer
// shape listEKSClustersNative emits.
func eksClusterResource(issuer string) *DiscoveredResource {
	return &DiscoveredResource{
		Type: "AWS::EKS::Cluster",
		ID:   "prod-cluster",
		Inputs: map[string]any{
			"Identity": map[string]any{
				"Oidc": map[string]any{"Issuer": issuer},
			},
		},
	}
}

func TestEKSDescriber_MatchingProvider_PresentTrue(t *testing.T) {
	// A registered provider whose URL matches the cluster issuer = IRSA wired.
	// The matching ARN is not first in the list, so iteration must scan past a
	// non-match.
	installFakeEKSOIDCClient(t, &fakeEKSOIDCClient{out: oidcProvidersOut(eksProviderARNBBBB, eksProviderARNAAAA)})
	r := eksClusterResource(eksIssuerAAAA)
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := r.Inputs[eksIRSAField]; got != true {
		t.Errorf("%s = %v, want true (matching provider URL = IRSA wired)", eksIRSAField, got)
	}
}

func TestEKSDescriber_SameHostDifferentPath_PresentFalse(t *testing.T) {
	// FP-safety linchpin: a provider exists for the SAME oidc.eks.<region> host
	// but a DIFFERENT cluster's /id path. Every cluster in a region shares that
	// host, so a host-only match would wrongly report IRSA wired and SUPPRESS a
	// genuine finding. Full host+path matching must yield present=false.
	installFakeEKSOIDCClient(t, &fakeEKSOIDCClient{out: oidcProvidersOut(eksProviderARNBBBB)})
	r := eksClusterResource(eksIssuerAAAA)
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got, ok := r.Inputs[eksIRSAField]; !ok || got != false {
		t.Errorf("%s = (%v, %v), want (false, true) — sibling cluster's provider is NOT a match", eksIRSAField, got, ok)
	}
}

func TestEKSDescriber_NoProviders_PresentFalse(t *testing.T) {
	// The planted variant-10 state: cluster exists, account has zero OIDC
	// providers. ListOpenIDConnectProviders is non-paginated, so a successful
	// empty response is a COMPLETE enumeration → present=false, a definite
	// "no IRSA" (never absence-inferred).
	installFakeEKSOIDCClient(t, &fakeEKSOIDCClient{out: &iam.ListOpenIDConnectProvidersOutput{}})
	r := eksClusterResource(eksIssuerAAAA)
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got, ok := r.Inputs[eksIRSAField]; !ok || got != false {
		t.Errorf("%s = (%v, %v), want (false, true)", eksIRSAField, got, ok)
	}
}

func TestEKSDescriber_ProbeError_LeavesFieldAbsent(t *testing.T) {
	// A denied probe must NEVER abort: it returns the classified error (so
	// --diagnose surfaces the missing iam:ListOpenIDConnectProviders grant) but
	// leaves the field ABSENT (UNKNOWN, never false) so a rule keyed on
	// `== false` cannot false-fire on a cluster we could not verify.
	installFakeEKSOIDCClient(t, &fakeEKSOIDCClient{err: &fakeAPIError{code: "AccessDenied"}})
	r := eksClusterResource(eksIssuerAAAA)
	err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r)
	if err == nil {
		t.Fatal("expected the probe error to surface, got nil")
	}
	var pe *PermissionError
	if !errors.As(err, &pe) {
		t.Errorf("error = %T, want *PermissionError (so --diagnose collects it)", err)
	}
	if _, ok := r.Inputs[eksIRSAField]; ok {
		t.Error("field must be ABSENT on probe error (UNKNOWN), not false")
	}
}

func TestEKSDescriber_MissingIssuer_NoProbe(t *testing.T) {
	// No issuer to match against → leave the field ABSENT and never spend the
	// IAM call. Matching on an empty issuer would be meaningless.
	fake := &fakeEKSOIDCClient{out: oidcProvidersOut(eksProviderARNAAAA)}
	installFakeEKSOIDCClient(t, fake)
	r := &DiscoveredResource{Type: "AWS::EKS::Cluster", ID: "no-issuer", Inputs: map[string]any{}}
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if _, ok := r.Inputs[eksIRSAField]; ok {
		t.Error("field must be ABSENT when the cluster issuer is unknown")
	}
	if fake.calls != 0 {
		t.Errorf("expected no IAM probe when issuer is missing, got %d calls", fake.calls)
	}
}

func TestEKSDescriber_FlatIssuerAttribute_Probes(t *testing.T) {
	// When CloudControl (not the native fallback) lists the cluster, the issuer
	// arrives as the flat read-only attribute OpenIdConnectIssuerUrl rather than
	// the nested Identity shape. IRSA detection must work on both, or it is
	// silently fallback-only.
	installFakeEKSOIDCClient(t, &fakeEKSOIDCClient{out: oidcProvidersOut(eksProviderARNAAAA)})
	r := &DiscoveredResource{Type: "AWS::EKS::Cluster", ID: "cc-cluster", Inputs: map[string]any{
		"OpenIdConnectIssuerUrl": eksIssuerAAAA,
	}}
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := r.Inputs[eksIRSAField]; got != true {
		t.Errorf("%s = %v, want true (flat issuer attribute must be matched)", eksIRSAField, got)
	}
}

// TestEKSClusterToRaw_SurfacesOIDCIssuer pins the lister↔describer shape
// contract: the lister must emit the issuer in exactly the shape the describer
// reads. Rather than hand-build Inputs, this round-trips through the same
// marshalRaw → mapToDiscovered the discovery pipeline uses, then reads it back
// via the describer's own extractor — so a divergence between writer and
// reader fails here, not silently in production.
func TestEKSClusterToRaw_SurfacesOIDCIssuer(t *testing.T) {
	issuer := eksIssuerAAAA
	cl := ekstypes.Cluster{
		Name:     strPtr("prod-cluster"),
		Identity: &ekstypes.Identity{Oidc: &ekstypes.OIDC{Issuer: &issuer}},
	}
	raw, ok := eksClusterToRaw(cl, "us-east-1")
	if !ok {
		t.Fatal("eksClusterToRaw returned ok=false")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if got := eksOIDCIssuer(dr.Inputs); got != issuer {
		t.Errorf("eksOIDCIssuer(lister output) = %q, want %q", got, issuer)
	}
}

func TestEKSClusterToRaw_OmitsIssuerWhenAbsent(t *testing.T) {
	// No Identity on the cluster → no Identity block emitted, so the describer
	// reads "" and skips the probe (UNKNOWN), never a spurious present=false.
	cl := ekstypes.Cluster{Name: strPtr("bare-cluster")}
	raw, ok := eksClusterToRaw(cl, "us-east-1")
	if !ok {
		t.Fatal("eksClusterToRaw returned ok=false")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if got := eksOIDCIssuer(dr.Inputs); got != "" {
		t.Errorf("eksOIDCIssuer = %q, want \"\" when the cluster carries no OIDC identity", got)
	}
}

// --- Pod Identity probe ----------------------------------------------------

const eksPodIdentityField = "cb_describer_eks_pod_identity_present"

// fakeEKSPodIdentityClient is the test double for the Pod-Identity probe's EKS
// seam. It returns pages[call-1] on each successive call so a test can drive
// the pagination walk; err (when set) is returned on the first call. calls
// records invocations so a test can assert the probe is skipped when the
// cluster name is unknown, or that the walk paged the expected number of times.
type fakeEKSPodIdentityClient struct {
	pages []*eks.ListPodIdentityAssociationsOutput
	err   error
	calls int
}

func (f *fakeEKSPodIdentityClient) ListPodIdentityAssociations(_ context.Context, _ *eks.ListPodIdentityAssociationsInput, _ ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if i := f.calls - 1; i < len(f.pages) {
		return f.pages[i], nil
	}
	return &eks.ListPodIdentityAssociationsOutput{}, nil
}

// installFakeEKSPodIdentityClient swaps the package-level seam for a fake so the
// EKS describer's Pod-Identity probe never makes a live AWS call, restoring the
// real constructor when the test ends (mirrors installFakeEKSOIDCClient).
func installFakeEKSPodIdentityClient(t *testing.T, fake eksPodIdentityAPI) {
	t.Helper()
	prev := newEKSPodIdentityClient
	newEKSPodIdentityClient = func(awsCfg) eksPodIdentityAPI { return fake }
	t.Cleanup(func() { newEKSPodIdentityClient = prev })
}

// podIDPage builds one ListPodIdentityAssociations page carrying n associations
// (their contents don't matter to the probe — only the count) and an optional
// NextToken so a test can chain pages.
func podIDPage(n int, nextToken string) *eks.ListPodIdentityAssociationsOutput {
	out := &eks.ListPodIdentityAssociationsOutput{}
	for i := 0; i < n; i++ {
		out.Associations = append(out.Associations, ekstypes.PodIdentityAssociationSummary{})
	}
	if nextToken != "" {
		out.NextToken = &nextToken
	}
	return out
}

// eksClusterResourceNamed builds a discovered cluster carrying only the CFN
// Name primary identifier and NO OIDC issuer, so the OIDC probe is skipped and
// the test exercises the Pod-Identity probe in isolation.
func eksClusterResourceNamed(name string) *DiscoveredResource {
	return &DiscoveredResource{
		Type:   "AWS::EKS::Cluster",
		ID:     name,
		Inputs: map[string]any{"Name": name},
	}
}

func TestEKSDescriber_PodIdentityAssociationPresent_True(t *testing.T) {
	// One association on the first page = Pod Identity in use. The walk
	// short-circuits, so exactly one page is read.
	fake := &fakeEKSPodIdentityClient{pages: []*eks.ListPodIdentityAssociationsOutput{podIDPage(1, "")}}
	installFakeEKSPodIdentityClient(t, fake)
	r := eksClusterResourceNamed("prod-cluster")
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := r.Inputs[eksPodIdentityField]; got != true {
		t.Errorf("%s = %v, want true (an association exists = Pod Identity in use)", eksPodIdentityField, got)
	}
	if fake.calls != 1 {
		t.Errorf("expected the walk to short-circuit after 1 page, got %d calls", fake.calls)
	}
}

func TestEKSDescriber_PodIdentityAssociationOnSecondPage_True(t *testing.T) {
	// FP-safety partner of the false-case: the first page is empty but carries a
	// NextToken, the association is only on page 2. The probe must page past the
	// empty first page rather than declaring false on a partial read.
	fake := &fakeEKSPodIdentityClient{pages: []*eks.ListPodIdentityAssociationsOutput{
		podIDPage(0, "more"),
		podIDPage(1, ""),
	}}
	installFakeEKSPodIdentityClient(t, fake)
	r := eksClusterResourceNamed("prod-cluster")
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := r.Inputs[eksPodIdentityField]; got != true {
		t.Errorf("%s = %v, want true (association on page 2 must be found)", eksPodIdentityField, got)
	}
	if fake.calls != 2 {
		t.Errorf("expected the walk to read 2 pages, got %d calls", fake.calls)
	}
}

func TestEKSDescriber_NoPodIdentityAcrossAllPages_False(t *testing.T) {
	// The planted variant state: cluster exists, zero Pod-Identity associations.
	// ListPodIdentityAssociations IS paginated, so present=false is asserted only
	// after EVERY page is walked — a COMPLETE enumeration, never absence-inferred
	// from the first empty page.
	fake := &fakeEKSPodIdentityClient{pages: []*eks.ListPodIdentityAssociationsOutput{
		podIDPage(0, "more"),
		podIDPage(0, ""),
	}}
	installFakeEKSPodIdentityClient(t, fake)
	r := eksClusterResourceNamed("prod-cluster")
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got, ok := r.Inputs[eksPodIdentityField]; !ok || got != false {
		t.Errorf("%s = (%v, %v), want (false, true) after a complete empty enumeration", eksPodIdentityField, got, ok)
	}
	if fake.calls != 2 {
		t.Errorf("expected the walk to enumerate both pages before false, got %d calls", fake.calls)
	}
}

func TestEKSDescriber_PodIdentityProbeError_LeavesFieldAbsent(t *testing.T) {
	// A denied probe must NEVER abort: it returns the classified error (so
	// --diagnose surfaces the missing eks:ListPodIdentityAssociations grant) but
	// leaves the field ABSENT (UNKNOWN, never false) so a rule keyed on
	// `== false` cannot false-fire on a cluster we could not verify.
	installFakeEKSPodIdentityClient(t, &fakeEKSPodIdentityClient{err: &fakeAPIError{code: "AccessDenied"}})
	r := eksClusterResourceNamed("prod-cluster")
	err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r)
	if err == nil {
		t.Fatal("expected the probe error to surface, got nil")
	}
	var pe *PermissionError
	if !errors.As(err, &pe) {
		t.Errorf("error = %T, want *PermissionError (so --diagnose collects it)", err)
	}
	if _, ok := r.Inputs[eksPodIdentityField]; ok {
		t.Error("field must be ABSENT on probe error (UNKNOWN), not false")
	}
}

func TestEKSDescriber_MissingClusterName_NoPodIdentityProbe(t *testing.T) {
	// No cluster Name → nothing to probe → leave the field ABSENT and never spend
	// the EKS call.
	fake := &fakeEKSPodIdentityClient{pages: []*eks.ListPodIdentityAssociationsOutput{podIDPage(1, "")}}
	installFakeEKSPodIdentityClient(t, fake)
	r := &DiscoveredResource{Type: "AWS::EKS::Cluster", ID: "no-name", Inputs: map[string]any{}}
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if _, ok := r.Inputs[eksPodIdentityField]; ok {
		t.Error("field must be ABSENT when the cluster Name is unknown")
	}
	if fake.calls != 0 {
		t.Errorf("expected no EKS probe when the cluster Name is missing, got %d calls", fake.calls)
	}
}

func TestEKSDescriber_BothProbesRun_IRSAAndPodIdentity(t *testing.T) {
	// The real production shape: a cluster carries BOTH an OIDC issuer and a Name,
	// so both probes run in one Enrich. The restructure must keep the IRSA path
	// working alongside the new Pod-Identity path, each publishing its own field.
	installFakeEKSOIDCClient(t, &fakeEKSOIDCClient{out: oidcProvidersOut(eksProviderARNAAAA)})
	installFakeEKSPodIdentityClient(t, &fakeEKSPodIdentityClient{pages: []*eks.ListPodIdentityAssociationsOutput{podIDPage(1, "")}})
	r := &DiscoveredResource{Type: "AWS::EKS::Cluster", ID: "prod-cluster", Inputs: map[string]any{
		"Name":     "prod-cluster",
		"Identity": map[string]any{"Oidc": map[string]any{"Issuer": eksIssuerAAAA}},
	}}
	if err := (eksClusterDescriber{}).Enrich(context.Background(), awsCfg{}, r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := r.Inputs[eksIRSAField]; got != true {
		t.Errorf("%s = %v, want true (matching OIDC provider)", eksIRSAField, got)
	}
	if got := r.Inputs[eksPodIdentityField]; got != true {
		t.Errorf("%s = %v, want true (Pod-Identity association exists)", eksPodIdentityField, got)
	}
}
