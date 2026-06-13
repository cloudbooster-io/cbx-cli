package aws

import (
	"context"

	apigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

// listAPIGatewayV2APIsNative is the FallbackLister for AWS::ApiGatewayV2::Api.
// It exists for the same reason as the Lambda / DynamoDB / ECS fallbacks: the
// final recall sweep watched variant 03 (serverless) swing 3→7→8 as
// CloudControl's audit-time ListResources non-deterministically enumerated the
// HTTP API on retry — a fresh API created right before the audit is exactly the
// eventually-consistent window where CloudControl answers with an empty set (not
// an error, permission_errors stays []), silently dropping the API. apigatewayv2
// GetApis is the strongly-consistent enumeration and fires only when CloudControl
// returned nothing for this type in this region — inert (and can't regress)
// whenever CloudControl does list the API.
//
// SCOPE — read before extending this. Unlike the Lambda / DynamoDB fallbacks,
// whose describers are pure Inputs-readers, apiGatewayV2ApiDescriber makes its
// OWN live apigatewayv2:GetStages call in Enrich and folds the result into
// cb_describer_access_logging_enabled (the S3-fallback pattern, where the
// describer re-fetches posture off the identifier). So this fallback does NOT
// need to carry the finding-bearing field itself — it only needs to restore the
// API resource (keyed by ApiId) so runJob's describer pass can re-derive the
// access-logging signal. That single rule — the access-logging WARNING
// (buildGroundedPrompt, "API Gateway with access logging disabled") — is what
// this fallback closes for the silent-empty case.
//
// It deliberately does NOT feed the compound "unauthenticated API + admin
// Lambda" CRITICAL rule. That rule reads three SIBLING CloudControl types this
// fallback does not synthesise — AWS::ApiGatewayV2::Route (AuthorizationType, the
// "no authorizer" signal), AWS::ApiGatewayV2::Integration (IntegrationUri, the
// API→Lambda link), and the Lambda itself (cb_describer_role_is_admin_equivalent,
// already covered by listLambdaFunctionsNative). Those routes/integrations are
// dropped by the same CloudControl silent-empty miss and have no describer, so
// restoring only the Api cannot make the compound rule fire. That gap is closed
// by the per-type Route + Integration fallbacks (each enumerating APIs then
// GetRoutes / GetIntegrations, mirroring listListenersNative) in
// lister_apigw_route_integration_native.go.
func listAPIGatewayV2APIsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	return collectAPIGatewayV2APIs(ctx, apigatewayv2.NewFromConfig(c.withRegion(region).cfg), region)
}

// apigwV2FallbackAPI is the narrow slice of the apigatewayv2 client
// collectAPIGatewayV2APIs needs — just GetApis (the enumeration). The concrete
// *apigatewayv2.Client satisfies it; the seam lets the NextToken pagination loop
// be unit-tested without a live call (mirrors lambdaFallbackAPI / s3FallbackAPI).
type apigwV2FallbackAPI interface {
	GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error)
}

// collectAPIGatewayV2APIs enumerates HTTP/WebSocket APIs via GetApis (paginated
// by NextToken) and synthesises a CFN-shape raw per API. A GetApis failure is
// fatal — there's nothing to recover — and is classified so an AccessDenied
// surfaces in --diagnose as a *PermissionError, the same shape the CloudControl
// path collects. APIs with no ApiId are skipped (apiV2ToRaw returns !ok) rather
// than synthesised with an empty identifier the describer's GetStages can't key
// off.
func collectAPIGatewayV2APIs(ctx context.Context, client apigwV2FallbackAPI, region string) ([]rawResource, error) {
	var results []rawResource
	var nextToken *string
	for {
		out, err := client.GetApis(ctx, &apigatewayv2.GetApisInput{NextToken: nextToken})
		if err != nil {
			return nil, classifyAWSError(err, "apigateway", "apigatewayv2:GetApis", region)
		}
		for _, api := range out.Items {
			if raw, ok := apiV2ToRaw(api, region); ok {
				results = append(results, raw)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return results, nil
}

// apiV2ToRaw maps an SDK apigatewayv2 Api into CloudControl's
// AWS::ApiGatewayV2::Api CFN shape so the synthesised resource flows through
// mapToDiscovered + apiGatewayV2ApiDescriber identically to a CC-listed API.
// ApiId is the identifier (CloudControl's primary id for this type) and is the
// ONLY field the describer needs — it re-pins the region and calls GetStages
// keyed by DiscoveredResource.ID (= this identifier) to derive the access-logging
// signal. The remaining props (Name, ProtocolType, ApiEndpoint,
// DisableExecuteApiEndpoint) are carried because they're the read-only-visible
// CloudControl fields the grounded prompt can reason over, and to keep the
// synthesised shape indistinguishable from CloudControl's. Pure (no SDK client)
// for unit testing; mirrors dynamoTableToRaw / lambdaFunctionToRaw.
func apiV2ToRaw(api apigatewayv2types.Api, region string) (rawResource, bool) {
	if api.ApiId == nil || *api.ApiId == "" {
		return rawResource{}, false
	}
	id := *api.ApiId

	props := map[string]any{"ApiId": id}
	putStr(props, "Name", api.Name)
	if api.ProtocolType != "" {
		props["ProtocolType"] = string(api.ProtocolType)
	}
	putStr(props, "ApiEndpoint", api.ApiEndpoint)
	putBool(props, "DisableExecuteApiEndpoint", api.DisableExecuteApiEndpoint)

	return marshalRaw("AWS::ApiGatewayV2::Api", id, region, props)
}
