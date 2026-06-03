package aws

import (
	"context"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// describeAllLoadBalancers paginates DescribeLoadBalancers. Listeners are
// listed per-LB, so the Listener fallback needs the LB ARNs first.
func describeAllLoadBalancers(ctx context.Context, client *elbv2.Client, region string) ([]elbv2types.LoadBalancer, error) {
	var lbs []elbv2types.LoadBalancer
	var marker *string
	for {
		out, err := client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, classifyAWSError(err, "elasticloadbalancing", "elasticloadbalancing:DescribeLoadBalancers", region)
		}
		lbs = append(lbs, out.LoadBalancers...)
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return lbs, nil
}

// listListenersNative is the FallbackLister for
// AWS::ElasticLoadBalancingV2::Listener — the one validated native fallback.
// The "HTTP-only listener, no HTTPS" planted finding lives on the Listener,
// whose CloudControl list is empty for a fresh ALB even though CloudControl
// lists the load balancer itself (observed in fixtures 07 and 08).
// elbv2:DescribeListeners is strongly consistent but requires a
// LoadBalancerArn, so this enumerates LBs first, then walks each.
//
// There is no Listener describer; the synthesised CFN-shape Properties
// (Protocol=HTTP vs HTTPS, Port, Certificates presence) are read directly
// by the grounded LLM.
func listListenersNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := elbv2.NewFromConfig(c.withRegion(region).cfg)

	lbs, err := describeAllLoadBalancers(ctx, client, region)
	if err != nil {
		return nil, err
	}

	var results []rawResource
	for _, lb := range lbs {
		if lb.LoadBalancerArn == nil {
			continue
		}
		var marker *string
		for {
			out, err := client.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
				LoadBalancerArn: lb.LoadBalancerArn,
				Marker:          marker,
			})
			if err != nil {
				return nil, classifyAWSError(err, "elasticloadbalancing", "elasticloadbalancing:DescribeListeners", region)
			}
			for _, l := range out.Listeners {
				if raw, ok := listenerToRaw(l, region); ok {
					results = append(results, raw)
				}
			}
			if out.NextMarker == nil || *out.NextMarker == "" {
				break
			}
			marker = out.NextMarker
		}
	}
	return results, nil
}

// listenerToRaw maps an SDK Listener into the CFN shape. Pure for unit
// testing. Protocol is the load-bearing field: "HTTP" (with no paired
// HTTPS listener) is the planted plaintext-traffic finding.
func listenerToRaw(l elbv2types.Listener, region string) (rawResource, bool) {
	if l.ListenerArn == nil || *l.ListenerArn == "" {
		return rawResource{}, false
	}
	id := *l.ListenerArn

	props := map[string]any{"ListenerArn": id}
	putStr(props, "LoadBalancerArn", l.LoadBalancerArn)
	putStr(props, "SslPolicy", l.SslPolicy)
	if l.Protocol != "" {
		props["Protocol"] = string(l.Protocol)
	}
	if l.Port != nil {
		props["Port"] = *l.Port
	}
	// Certificate presence is the "is TLS actually configured?" signal —
	// an HTTP listener has none; an HTTPS listener has at least one.
	props["cb_describer_has_tls_certificate"] = len(l.Certificates) > 0

	return marshalRaw("AWS::ElasticLoadBalancingV2::Listener", id, region, props)
}
