package aws

import (
	"context"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// listLoadBalancersNative is the FallbackLister for
// AWS::ElasticLoadBalancingV2::LoadBalancer. CloudControl discovered ALBs
// in kitchen-sink but not in the ALB-targeted variant (07: HTTP-only,
// no-WAF, access-logging all missed because the LB was absent from
// discovery). elbv2:DescribeLoadBalancers is strongly consistent.
//
// There is no LoadBalancer describer, so the synthesised CFN-shape
// Properties are what the grounded LLM reads directly — Scheme (is it
// internet-facing?), Type, VpcId, SecurityGroups and the access-logs
// attribute are the load-bearing fields. Access logging lives in the
// LB *attributes*, fetched per-LB (the fallback fires rarely, so the
// extra call is cheap) and folded in as cb_describer_access_logs_enabled.
func listLoadBalancersNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := elbv2.NewFromConfig(c.withRegion(region).cfg)

	lbs, err := describeAllLoadBalancers(ctx, client, region)
	if err != nil {
		return nil, err
	}
	var results []rawResource
	for _, lb := range lbs {
		accessLogs := loadBalancerAccessLogsEnabled(ctx, client, lb.LoadBalancerArn)
		if raw, ok := loadBalancerToRaw(lb, accessLogs, region); ok {
			results = append(results, raw)
		}
	}
	return results, nil
}

// describeAllLoadBalancers paginates DescribeLoadBalancers. Shared by the
// LoadBalancer fallback and the Listener fallback (listeners are listed
// per-LB, so the Listener path needs the LB ARNs first).
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
// AWS::ElasticLoadBalancingV2::Listener. The variant-07 "HTTP-only
// listener, no HTTPS" planted finding lives on the Listener, whose
// CloudControl list is empty for a fresh ALB exactly like the LB itself.
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

// listTargetGroupsNative is the FallbackLister for
// AWS::ElasticLoadBalancingV2::TargetGroup. DescribeTargetGroups lists
// every target group in the region in one paginated call (no per-LB
// fan-out), so it is the cheapest of the ELBv2 fallbacks.
func listTargetGroupsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := elbv2.NewFromConfig(c.withRegion(region).cfg)

	var results []rawResource
	var marker *string
	for {
		out, err := client.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{Marker: marker})
		if err != nil {
			return nil, classifyAWSError(err, "elasticloadbalancing", "elasticloadbalancing:DescribeTargetGroups", region)
		}
		for _, tg := range out.TargetGroups {
			if raw, ok := targetGroupToRaw(tg, region); ok {
				results = append(results, raw)
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return results, nil
}

// targetGroupToRaw maps an SDK TargetGroup into the CFN shape. Pure for
// unit testing.
func targetGroupToRaw(tg elbv2types.TargetGroup, region string) (rawResource, bool) {
	if tg.TargetGroupArn == nil || *tg.TargetGroupArn == "" {
		return rawResource{}, false
	}
	id := *tg.TargetGroupArn

	props := map[string]any{"TargetGroupArn": id}
	putStr(props, "TargetGroupName", tg.TargetGroupName)
	putStr(props, "VpcId", tg.VpcId)
	if tg.Protocol != "" {
		props["Protocol"] = string(tg.Protocol)
	}
	if tg.Port != nil {
		props["Port"] = *tg.Port
	}
	if tg.TargetType != "" {
		props["TargetType"] = string(tg.TargetType)
	}

	return marshalRaw("AWS::ElasticLoadBalancingV2::TargetGroup", id, region, props)
}

// loadBalancerAccessLogsEnabled reads the access_logs.s3.enabled attribute.
// Returns nil (unknown) on any error so a missing elasticloadbalancing:
// DescribeLoadBalancerAttributes permission degrades gracefully rather than
// failing the whole type.
func loadBalancerAccessLogsEnabled(ctx context.Context, client *elbv2.Client, arn *string) *bool {
	if arn == nil {
		return nil
	}
	out, err := client.DescribeLoadBalancerAttributes(ctx, &elbv2.DescribeLoadBalancerAttributesInput{
		LoadBalancerArn: arn,
	})
	if err != nil {
		return nil
	}
	for _, a := range out.Attributes {
		if a.Key != nil && *a.Key == "access_logs.s3.enabled" && a.Value != nil {
			enabled := *a.Value == "true"
			return &enabled
		}
	}
	return nil
}

// loadBalancerToRaw maps an SDK LoadBalancer (+ resolved access-logs flag)
// into a rawResource. Pure for unit testing — the attribute lookup is the
// caller's job.
func loadBalancerToRaw(lb elbv2types.LoadBalancer, accessLogsEnabled *bool, region string) (rawResource, bool) {
	if lb.LoadBalancerArn == nil || *lb.LoadBalancerArn == "" {
		return rawResource{}, false
	}
	id := *lb.LoadBalancerArn

	props := map[string]any{"LoadBalancerArn": id}
	putStr(props, "LoadBalancerName", lb.LoadBalancerName)
	putStr(props, "DNSName", lb.DNSName)
	putStr(props, "VpcId", lb.VpcId)
	if lb.Scheme != "" {
		props["Scheme"] = string(lb.Scheme)
	}
	if lb.Type != "" {
		props["Type"] = string(lb.Type)
	}
	if len(lb.SecurityGroups) > 0 {
		sgs := make([]any, 0, len(lb.SecurityGroups))
		for _, sg := range lb.SecurityGroups {
			sgs = append(sgs, sg)
		}
		props["SecurityGroups"] = sgs
	}
	if len(lb.AvailabilityZones) > 0 {
		subnets := make([]any, 0, len(lb.AvailabilityZones))
		for _, az := range lb.AvailabilityZones {
			if az.SubnetId != nil {
				subnets = append(subnets, *az.SubnetId)
			}
		}
		if len(subnets) > 0 {
			props["SubnetIds"] = subnets
		}
	}
	putBool(props, "cb_describer_access_logs_enabled", accessLogsEnabled)

	return marshalRaw("AWS::ElasticLoadBalancingV2::LoadBalancer", id, region, props)
}
