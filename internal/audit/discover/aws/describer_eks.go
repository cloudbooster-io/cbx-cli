package aws

import (
	"context"
	"strings"

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
type eksClusterDescriber struct{}

func (eksClusterDescriber) CFNType() string { return "AWS::EKS::Cluster" }

func (eksClusterDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	issuer := eksOIDCIssuer(r.Inputs)
	if issuer == "" {
		return nil // no issuer to match — leave the field ABSENT (UNKNOWN)
	}
	return enrichEKSIRSAProvider(ctx, newEKSOIDCProviderClient(c), c.region(), issuer, r)
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
