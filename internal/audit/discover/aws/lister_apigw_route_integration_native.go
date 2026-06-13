package aws

import (
	"context"

	apigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

// listAPIGatewayV2RoutesNative / listAPIGatewayV2IntegrationsNative are the
// FallbackListers for AWS::ApiGatewayV2::Route and AWS::ApiGatewayV2::Integration.
// They close the gap lister_apigw_native.go's SCOPE note flagged as a follow-up:
// restoring the Api alone cannot make the compound "unauthenticated API + admin
// Lambda" CRITICAL rule (llm_analyzer.go) fire, because that rule reads three
// SIBLING resources, two of which the discovery loop does not reliably enumerate
// and neither of which has a describer:
//
//   - AWS::ApiGatewayV2::Route — Route.AuthorizationType == NONE is the
//     "no authorizer / open access" signal. Route is a NESTED type, and
//     listAndGet issues CloudControl ListResources with only the TypeName (no
//     ResourceModel), so without the parent ApiId it does not reliably return
//     routes (it errors or comes back empty) — and until now there was no
//     fallback, so the route was simply dropped.
//   - AWS::ApiGatewayV2::Integration — Integration.IntegrationUri is the
//     API→Lambda link (the wrapped Lambda invoke-ARN). This type was not in the
//     discoverable set at all until this change, so the link was never present.
//   - AWS::Lambda::Function — cb_describer_role_is_admin_equivalent /
//     cb_describer_role_has_wildcard_inline_policy, already restored by
//     listLambdaFunctionsNative + lambdaFunctionDescriber.
//
// Neither Route nor Integration has a describer (their fields are read straight
// off the synthesised CloudControl Properties by the grounded LLM, exactly like
// the ELBv2 Listener), so — following the Lambda / DynamoDB self-carry pattern
// rather than the S3 re-fetch one — these fallbacks must carry every
// finding-bearing field inline: AuthorizationType + ApiId on the route,
// IntegrationUri + ApiId on the integration. The ApiId on each is what lets the
// LLM tie a NONE-auth route and an admin-Lambda integration back to the same API.
//
// GetRoutes / GetIntegrations both require an ApiId, so — like listListenersNative
// (which enumerates load balancers before DescribeListeners) — these enumerate
// APIs first (reusing the Api fallback's GetApis walk) and then walk each API's
// children. Both fire only when CloudControl returned NOTHING for their type in
// this region, so they're inert (and can't regress) whenever CloudControl lists
// the routes / integrations itself.
func listAPIGatewayV2RoutesNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	return collectAPIGatewayV2Routes(ctx, apigatewayv2.NewFromConfig(c.withRegion(region).cfg), region)
}

func listAPIGatewayV2IntegrationsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	return collectAPIGatewayV2Integrations(ctx, apigatewayv2.NewFromConfig(c.withRegion(region).cfg), region)
}

// apigwV2RoutesAPI / apigwV2IntegrationsAPI embed apigwV2FallbackAPI (GetApis) so
// the per-API enumeration is shared with the Api fallback, then add the child
// list call. The concrete *apigatewayv2.Client satisfies both; the seams let the
// pagination and per-API skip-and-continue be unit-tested without a live call.
type apigwV2RoutesAPI interface {
	apigwV2FallbackAPI
	GetRoutes(context.Context, *apigatewayv2.GetRoutesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error)
}

type apigwV2IntegrationsAPI interface {
	apigwV2FallbackAPI
	GetIntegrations(context.Context, *apigatewayv2.GetIntegrationsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error)
}

// apiIDsForRegion reuses collectAPIGatewayV2APIs' GetApis walk — each raw it
// returns is keyed by ApiId (apiV2ToRaw skips empty ids) — so the Route /
// Integration fallbacks enumerate APIs through one tested path instead of
// duplicating the pagination. A GetApis failure is fatal: there's no API to walk
// children of, so there's nothing to recover.
func apiIDsForRegion(ctx context.Context, client apigwV2FallbackAPI, region string) ([]string, error) {
	raws, err := collectAPIGatewayV2APIs(ctx, client, region)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(raws))
	for _, r := range raws {
		ids = append(ids, r.Identifier)
	}
	return ids, nil
}

// collectAPIGatewayV2Routes enumerates every API, then paginates GetRoutes per
// API and synthesises a CFN-shape raw per route.
//
// The GetApis enumeration is fatal (apiIDsForRegion returns the classified
// error). A per-API GetRoutes failure is NOT — unlike listListenersNative's
// fatal DescribeListeners — because one API's AccessDenied / throttle must not
// nuke route discovery for every OTHER API in the region. So a failed API is
// skipped, its first error captured in firstErr, and the walk continues,
// returning (results, firstErr). discover.go's fallback contract then keeps the
// recovered routes AND surfaces firstErr to --diagnose when results > 0, or
// surfaces the error alone when nothing was recovered — the same (results, err)
// tail as collectLambdaFunctions' best-effort concurrency probe.
func collectAPIGatewayV2Routes(ctx context.Context, client apigwV2RoutesAPI, region string) ([]rawResource, error) {
	apiIDs, err := apiIDsForRegion(ctx, client, region)
	if err != nil {
		return nil, err
	}
	var results []rawResource
	var firstErr error
	for _, apiID := range apiIDs {
		var nextToken *string
		for {
			out, err := client.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{ApiId: &apiID, NextToken: nextToken})
			if err != nil {
				if firstErr == nil {
					firstErr = classifyAWSError(err, "apigateway", "apigatewayv2:GetRoutes", region)
				}
				break // skip this API; keep the routes other APIs yield
			}
			for _, rt := range out.Items {
				if raw, ok := routeToRaw(rt, apiID, region); ok {
					results = append(results, raw)
				}
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			nextToken = out.NextToken
		}
	}
	return results, firstErr
}

// collectAPIGatewayV2Integrations mirrors collectAPIGatewayV2Routes for
// AWS::ApiGatewayV2::Integration: enumerate APIs (fatal on GetApis failure),
// then paginate GetIntegrations per API with the same per-API skip-and-continue.
func collectAPIGatewayV2Integrations(ctx context.Context, client apigwV2IntegrationsAPI, region string) ([]rawResource, error) {
	apiIDs, err := apiIDsForRegion(ctx, client, region)
	if err != nil {
		return nil, err
	}
	var results []rawResource
	var firstErr error
	for _, apiID := range apiIDs {
		var nextToken *string
		for {
			out, err := client.GetIntegrations(ctx, &apigatewayv2.GetIntegrationsInput{ApiId: &apiID, NextToken: nextToken})
			if err != nil {
				if firstErr == nil {
					firstErr = classifyAWSError(err, "apigateway", "apigatewayv2:GetIntegrations", region)
				}
				break // skip this API; keep the integrations other APIs yield
			}
			for _, intg := range out.Items {
				if raw, ok := integrationToRaw(intg, apiID, region); ok {
					results = append(results, raw)
				}
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			nextToken = out.NextToken
		}
	}
	return results, firstErr
}

// routeToRaw maps an SDK Route into CloudControl's AWS::ApiGatewayV2::Route CFN
// shape. CloudControl keys this type by the COMPOSITE ApiId|RouteId (its
// primaryIdentifier is both properties), so the synthesised identifier matches
// CC and two routes in different APIs can't collide on the region-qualified URN.
// Pure (no SDK client) for unit testing; mirrors listenerToRaw.
//
// AuthorizationType is the load-bearing field the compound rule reads — NONE is
// the "unauthenticated route" signal. For a route with no authorizer the API
// returns NONE explicitly, but an empty value is normalised to NONE too: the
// route object DEFINITIVELY exists and its auth is open-access, so this is NOT
// the "infer-the-gap-from-an-absent-key" anti-pattern the describers guard
// against (that applies to cb_describer_* probe fields that may not have run).
// The enum is closed (NONE / AWS_IAM / CUSTOM / JWT) and an authorized route
// always carries its non-NONE type plus an AuthorizerId, so empty can only mean
// NONE — and emitting it explicitly keeps the open-access signal visible to the
// LLM exactly as CloudControl would.
func routeToRaw(rt apigatewayv2types.Route, apiID, region string) (rawResource, bool) {
	if rt.RouteId == nil || *rt.RouteId == "" {
		return rawResource{}, false
	}
	routeID := *rt.RouteId
	id := apiID + "|" + routeID

	props := map[string]any{
		"ApiId":   apiID,
		"RouteId": routeID,
	}
	authType := string(rt.AuthorizationType)
	if authType == "" {
		authType = string(apigatewayv2types.AuthorizationTypeNone)
	}
	props["AuthorizationType"] = authType

	putStr(props, "RouteKey", rt.RouteKey) // e.g. "POST /admin" — read-only-visible context
	putStr(props, "Target", rt.Target)     // "integrations/<id>" — ties the route to its integration
	// AuthorizerId is present ONLY on an authorized route; its presence is the
	// counter-signal that keeps the LLM from flagging a CUSTOM/JWT/AWS_IAM route.
	putStr(props, "AuthorizerId", rt.AuthorizerId)
	putBool(props, "ApiKeyRequired", rt.ApiKeyRequired)

	return marshalRaw("AWS::ApiGatewayV2::Route", id, region, props)
}

// integrationToRaw maps an SDK Integration into CloudControl's
// AWS::ApiGatewayV2::Integration CFN shape (composite ApiId|IntegrationId
// identifier, matching CC's primaryIdentifier). Pure for unit testing.
//
// IntegrationUri is the load-bearing API→Lambda link the compound rule and the
// API-Gateway→Lambda connection edge (llm_analyzer.go) read. For an AWS_PROXY
// Lambda integration it's the wrapped invoke-ARN
// (arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/<lambda-arn>/invocations);
// the function ARN is embedded verbatim, so it is carried UNMODIFIED — the
// connection rule substring-matches the discovered Lambda ARN against it, and
// any "cleanup" to the bare function ARN would break that match.
func integrationToRaw(intg apigatewayv2types.Integration, apiID, region string) (rawResource, bool) {
	if intg.IntegrationId == nil || *intg.IntegrationId == "" {
		return rawResource{}, false
	}
	integrationID := *intg.IntegrationId
	id := apiID + "|" + integrationID

	props := map[string]any{
		"ApiId":         apiID,
		"IntegrationId": integrationID,
	}
	putStr(props, "IntegrationUri", intg.IntegrationUri)
	if intg.IntegrationType != "" {
		props["IntegrationType"] = string(intg.IntegrationType) // AWS_PROXY for a Lambda integration
	}
	putStr(props, "IntegrationMethod", intg.IntegrationMethod)
	putStr(props, "PayloadFormatVersion", intg.PayloadFormatVersion)
	if intg.ConnectionType != "" {
		props["ConnectionType"] = string(intg.ConnectionType)
	}
	putStr(props, "CredentialsArn", intg.CredentialsArn)

	return marshalRaw("AWS::ApiGatewayV2::Integration", id, region, props)
}
