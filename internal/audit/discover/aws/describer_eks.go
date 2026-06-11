package aws

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// eksClusterDescriber enriches AWS::EKS::Cluster with the one signal the
// cluster's own describe payload cannot answer on its own: whether IRSA (IAM
// Roles for Service Accounts) is actually wired. The cluster carries its OIDC
// *issuer* URL (surfaced by listEKSClustersNative under Identity.Oidc.Issuer),
// but IRSA is enabled only when a matching IAM OIDC *identity provider* has
// been registered for that issuer. Without it, pods fall back to the node
// instance role — a privilege-scoping gap. That provider lives in IAM, not
// EKS, so confirming it takes a best-effort iam:ListOpenIDConnectProviders
// probe.
//
// The published field cb_describer_eks_irsa_oidc_provider_present is a
// POSITIVE signal with FP-safe polarity that mirrors the RDS replica probe
// (enrichRDSInstanceRole):
//
//   - true   — a registered provider's URL exactly matches the cluster issuer
//     (IRSA wired).
//   - false  — the probe SUCCEEDED and enumerated every provider, none
//     matched. ListOpenIDConnectProviders is NOT paginated — it returns the
//     whole account's providers in one response — so "no match" is a COMPLETE
//     enumeration and a definite determination, never inferred from a partial
//     read.
//   - ABSENT — the issuer is unknown, or the probe errored (UNKNOWN). A rule
//     keyed on `== false` must NOT fire here: we refuse to assert an IRSA gap
//     we could not verify.
//
// The describer also publishes a SECOND, complementary signal —
// cb_describer_eks_pod_identity_present — because IRSA is no longer the only
// way to give a pod a scoped IAM role. EKS Pod Identity (GA Nov 2023) binds a
// service account to a role with NO IAM OIDC provider involved, so a
// Pod-Identity cluster has cb_describer_eks_irsa_oidc_provider_present == false
// even though its pods DO receive scoped credentials. A rule that read the IRSA
// field alone would false-fire HIGH on every such cluster; the Pod-Identity
// field is the positive signal that lets the rule avoid that. It is published
// by enrichEKSPodIdentity with the same FP-safe polarity (true / false only on
// a complete enumeration / ABSENT on error).
type eksClusterDescriber struct{}

func (eksClusterDescriber) CFNType() string { return "AWS::EKS::Cluster" }

func (eksClusterDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	// The awsCfg handed to Enrich is the BASE config; the lister gets the
	// region separately (see runJob), so re-pin to the resource's region here.
	// eks:ListPodIdentityAssociations is region-bound and would 400 against the
	// wrong region. IAM is global so this is harmless for the OIDC probe — it
	// merely makes that probe's --diagnose region label accurate. r.Region is
	// populated by mapToDiscovered.
	if r.Region != "" {
		c = c.withRegion(r.Region)
	}

	// The two probes are independent — a denied IRSA probe must not skip the
	// Pod-Identity probe, and vice versa. Run both, join the errors so each
	// surfaces to --diagnose (errors.As traverses the join, so a joined
	// *PermissionError is still collected by the discovery loop).
	var errs []error

	// (1) IRSA OIDC provider (global IAM probe). Skipped when the cluster
	// carries no issuer — matching against an empty issuer is meaningless and
	// leaves the field ABSENT (UNKNOWN).
	if issuer := eksOIDCIssuer(r.Inputs); issuer != "" {
		if err := enrichEKSIRSAProvider(ctx, newEKSOIDCProviderClient(c), c.region(), issuer, r); err != nil {
			errs = append(errs, err)
		}
	}

	// (2) Pod Identity associations (regional EKS probe). Independent of IRSA:
	// a cluster can scope pod roles via Pod Identity with no OIDC provider, so
	// this must run even when the IRSA probe is skipped. Name is the cluster's
	// CFN primary identifier, set by both listEKSClustersNative (props["Name"])
	// and a CloudControl-listed cluster; without it there is nothing to probe.
	if name := readStr(r.Inputs, "Name"); name != "" {
		if err := enrichEKSPodIdentity(ctx, newEKSPodIdentityClient(c), c.region(), name, r); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// newEKSOIDCProviderClient is the package-level seam the describer probes
// through, so unit tests can inject a fake (mirrors newRDSReplicaClient). IAM
// is a global service, so the client is built straight from c.cfg with no
// per-region configuration.
var newEKSOIDCProviderClient = func(c awsCfg) eksOIDCProviderAPI { return iam.NewFromConfig(c.cfg) }

// eksOIDCProviderAPI is the narrow IAM slice the IRSA probe needs — just
// ListOpenIDConnectProviders. The concrete *iam.Client satisfies it; the seam
// lets the FP-safe polarity be unit-tested without a live call (mirrors
// rdsReplicaAPI).
type eksOIDCProviderAPI interface {
	ListOpenIDConnectProviders(context.Context, *iam.ListOpenIDConnectProvidersInput, ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error)
}

// enrichEKSIRSAProvider runs the best-effort probe and publishes the POSITIVE
// presence boolean. The contract mirrors enrichRDSInstanceRole: it must NEVER
// abort — a probe error returns the classified error (so --diagnose surfaces a
// missing iam:ListOpenIDConnectProviders grant) while the field is left ABSENT
// and the resource is kept by the discovery loop with every other field
// intact. A successful probe always publishes true/false because the list is
// complete.
func enrichEKSIRSAProvider(ctx context.Context, client eksOIDCProviderAPI, region, issuer string, r *DiscoveredResource) error {
	out, err := client.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return classifyAWSError(err, "iam", "iam:ListOpenIDConnectProviders", region)
	}
	want := normalizeOIDCIssuer(issuer)
	present := false
	if out != nil {
		for _, p := range out.OpenIDConnectProviderList {
			if p.Arn == nil {
				continue
			}
			url := oidcProviderURLFromARN(*p.Arn)
			if url == "" {
				continue // ARN carried no parseable provider URL — never matches
			}
			if normalizeOIDCIssuer(url) == want {
				present = true
				break
			}
		}
	}
	r.Inputs["cb_describer_eks_irsa_oidc_provider_present"] = present
	return nil
}

// newEKSPodIdentityClient is the package-level seam the Pod-Identity probe
// builds its client through, so unit tests can inject a fake (mirrors
// newEKSOIDCProviderClient). EKS is regional, so Enrich re-pins awsCfg to the
// cluster's region before calling this.
var newEKSPodIdentityClient = func(c awsCfg) eksPodIdentityAPI { return eks.NewFromConfig(c.cfg) }

// eksPodIdentityAPI is the narrow EKS slice the Pod-Identity probe needs — just
// ListPodIdentityAssociations. The concrete *eks.Client satisfies it; the seam
// lets the FP-safe polarity and the pagination walk be unit-tested without a
// live call (mirrors eksOIDCProviderAPI).
type eksPodIdentityAPI interface {
	ListPodIdentityAssociations(context.Context, *eks.ListPodIdentityAssociationsInput, ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
}

// enrichEKSPodIdentity runs the best-effort EKS Pod-Identity probe and
// publishes the POSITIVE cb_describer_eks_pod_identity_present boolean. The
// contract mirrors enrichEKSIRSAProvider: it must NEVER abort — a probe error
// returns the classified error (so --diagnose surfaces a missing
// eks:ListPodIdentityAssociations grant, which the existing eks:List* grant
// already covers) while the field is left ABSENT and the resource is kept by
// the discovery loop with every other field intact.
//
// FP-safe polarity:
//   - true   — at least one Pod-Identity association exists. One is enough, so
//     the walk short-circuits without paging further.
//   - false  — the probe SUCCEEDED and the FULL paginated list enumerated zero
//     associations. UNLIKE ListOpenIDConnectProviders, this API IS paginated,
//     so "none" is asserted only after every page is walked — a COMPLETE
//     enumeration, never inferred from a partial read.
//   - ABSENT — the probe errored (UNKNOWN). A rule keyed on `== false` must NOT
//     fire here: we refuse to assert a no-Pod-Identity state we could not
//     verify.
func enrichEKSPodIdentity(ctx context.Context, client eksPodIdentityAPI, region, clusterName string, r *DiscoveredResource) error {
	var next *string
	for {
		out, err := client.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
			ClusterName: &clusterName,
			NextToken:   next,
		})
		if err != nil {
			return classifyAWSError(err, "eks", "eks:ListPodIdentityAssociations", region)
		}
		if out != nil && len(out.Associations) > 0 {
			r.Inputs["cb_describer_eks_pod_identity_present"] = true
			return nil
		}
		if out == nil || out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	// Every page walked, zero associations → a COMPLETE enumeration and a
	// definite "no Pod Identity" (mirrors the OIDC probe's false-case).
	r.Inputs["cb_describer_eks_pod_identity_present"] = false
	return nil
}

// eksOIDCIssuer reads the cluster's OIDC issuer URL. listEKSClustersNative
// surfaces it nested as Identity.Oidc.Issuer (the SDK shape); if CloudControl
// lists the cluster instead, the same value arrives as the flat read-only
// attribute OpenIdConnectIssuerUrl. Reading both keeps IRSA detection from
// being silently fallback-only. Returns "" when neither is present.
func eksOIDCIssuer(m map[string]any) string {
	if identity, ok := m["Identity"].(map[string]any); ok {
		if oidc, ok := identity["Oidc"].(map[string]any); ok {
			if s, ok := oidc["Issuer"].(string); ok && s != "" {
				return s
			}
		}
	}
	return readStr(m, "OpenIdConnectIssuerUrl")
}

// oidcProviderURLFromARN extracts the provider URL embedded in an IAM OIDC
// provider ARN. The ARN format is
// arn:aws:iam::<acct>:oidc-provider/<url-without-scheme>, so the substring
// after ":oidc-provider/" IS the provider URL (host+path) —
// ListOpenIDConnectProviders returns only ARNs, so this avoids a per-provider
// GetOpenIDConnectProvider call (and its extra grant). Returns "" when the ARN
// lacks that segment, so a malformed ARN can never spuriously match.
func oidcProviderURLFromARN(arn string) string {
	const marker = ":oidc-provider/"
	i := strings.Index(arn, marker)
	if i < 0 {
		return ""
	}
	return arn[i+len(marker):]
}

// normalizeOIDCIssuer canonicalises an issuer/provider URL for comparison: the
// cluster issuer carries an https:// scheme while the IAM provider URL (parsed
// from the ARN) does not, and a trailing slash is insignificant. Matching is
// on the FULL host+path — every cluster in a region shares the
// oidc.eks.<region>.amazonaws.com host, so only the /id/<unique> path tells one
// cluster's provider from another's. Host-only matching would report IRSA
// wired for a different cluster's provider and suppress a genuine finding.
func normalizeOIDCIssuer(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimRight(s, "/")
}
