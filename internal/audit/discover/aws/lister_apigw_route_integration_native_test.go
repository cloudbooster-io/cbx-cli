package aws

import (
	"context"
	"testing"

	apigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/smithy-go"
)

const (
	testAPIID    = "ghv0blt39d"
	adminLambda  = "arn:aws:lambda:eu-central-1:111122223333:function:admin-fn"
	invokeURIFmt = "arn:aws:apigateway:eu-central-1:lambda:path/2015-03-31/functions/" + adminLambda + "/invocations"
)

// routeToRaw must synthesise the CloudControl AWS::ApiGatewayV2::Route shape: the
// composite ApiId|RouteId identifier (CloudControl's primaryIdentifier is both
// properties) so two routes can't collide on the URN, ApiId carried so the LLM
// can tie the route to its API, and AuthorizationType==NONE — the load-bearing
// "unauthenticated route" signal the compound rule reads — round-tripping intact.
func TestRouteToRaw_NoneAuthRoundTrip(t *testing.T) {
	raw, ok := routeToRaw(apigatewayv2types.Route{
		RouteId:           strp("r-abc123"),
		RouteKey:          strp("POST /admin"),
		AuthorizationType: apigatewayv2types.AuthorizationTypeNone,
		Target:            strp("integrations/i-def456"),
	}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("routeToRaw !ok for a valid route")
	}
	if raw.CFNType != "AWS::ApiGatewayV2::Route" || raw.Identifier != testAPIID+"|r-abc123" {
		t.Fatalf("unexpected raw: type=%q id=%q (want composite ApiId|RouteId)", raw.CFNType, raw.Identifier)
	}

	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if dr.Inputs["ApiId"] != testAPIID {
		t.Errorf("ApiId: got %v, want %s (the API linkage the compound rule keys off)", dr.Inputs["ApiId"], testAPIID)
	}
	if dr.Inputs["AuthorizationType"] != "NONE" {
		t.Errorf("AuthorizationType: got %v, want NONE (the unauthenticated-route signal)", dr.Inputs["AuthorizationType"])
	}
	if dr.Inputs["RouteKey"] != "POST /admin" {
		t.Errorf("RouteKey: got %v, want POST /admin", dr.Inputs["RouteKey"])
	}
	if dr.Inputs["Target"] != "integrations/i-def456" {
		t.Errorf("Target: got %v, want integrations/i-def456", dr.Inputs["Target"])
	}
	if dr.URN != "aws://eu-central-1/AWS::ApiGatewayV2::Route/"+testAPIID+"|r-abc123" {
		t.Errorf("URN: got %q", dr.URN)
	}
}

// An empty AuthorizationType is normalised to NONE: the route object exists and
// its auth is open-access (the enum is closed and an authorized route always
// carries its non-NONE type), so the unauthenticated signal must stay visible.
func TestRouteToRaw_EmptyAuthDefaultsToNone(t *testing.T) {
	raw, ok := routeToRaw(apigatewayv2types.Route{RouteId: strp("r-1")}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("routeToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if dr.Inputs["AuthorizationType"] != "NONE" {
		t.Errorf("empty AuthorizationType: got %v, want normalised to NONE", dr.Inputs["AuthorizationType"])
	}
}

// An AUTHORIZED route (JWT/CUSTOM/AWS_IAM) carries its non-NONE type AND an
// AuthorizerId — the counter-signal that keeps the LLM from flagging it as
// unauthenticated. The fallback must NOT flatten these to NONE.
func TestRouteToRaw_AuthorizedCarriesTypeAndAuthorizerId(t *testing.T) {
	raw, ok := routeToRaw(apigatewayv2types.Route{
		RouteId:           strp("r-2"),
		AuthorizationType: apigatewayv2types.AuthorizationTypeJwt,
		AuthorizerId:      strp("auth-xyz"),
	}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("routeToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if dr.Inputs["AuthorizationType"] != "JWT" {
		t.Errorf("AuthorizationType: got %v, want JWT (an authorized route must not flatten to NONE)", dr.Inputs["AuthorizationType"])
	}
	if dr.Inputs["AuthorizerId"] != "auth-xyz" {
		t.Errorf("AuthorizerId: got %v, want auth-xyz (the counter-signal)", dr.Inputs["AuthorizerId"])
	}
}

// A route with no RouteId can't be keyed, so it's skipped (!ok) rather than
// synthesised with a dangling "ApiId|" identifier.
func TestRouteToRaw_EmptyRouteIdSkipped(t *testing.T) {
	if _, ok := routeToRaw(apigatewayv2types.Route{RouteId: nil}, testAPIID, "eu-central-1"); ok {
		t.Error("routeToRaw returned ok for a nil RouteId")
	}
	if _, ok := routeToRaw(apigatewayv2types.Route{RouteId: strp("")}, testAPIID, "eu-central-1"); ok {
		t.Error("routeToRaw returned ok for an empty RouteId")
	}
}

// integrationToRaw must carry IntegrationUri VERBATIM — for an AWS_PROXY Lambda
// integration it's the wrapped invoke-ARN with the function ARN embedded, and
// the API-Gateway→Lambda connection rule substring-matches the discovered Lambda
// ARN against it, so any rewrite to the bare ARN would break the link.
func TestIntegrationToRaw_LambdaProxyRoundTrip(t *testing.T) {
	raw, ok := integrationToRaw(apigatewayv2types.Integration{
		IntegrationId:        strp("i-def456"),
		IntegrationType:      apigatewayv2types.IntegrationTypeAwsProxy,
		IntegrationUri:       strp(invokeURIFmt),
		IntegrationMethod:    strp("POST"),
		PayloadFormatVersion: strp("2.0"),
	}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("integrationToRaw !ok for a valid integration")
	}
	if raw.Identifier != testAPIID+"|i-def456" {
		t.Fatalf("Identifier: got %q, want composite ApiId|IntegrationId", raw.Identifier)
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if dr.Inputs["ApiId"] != testAPIID {
		t.Errorf("ApiId: got %v, want %s", dr.Inputs["ApiId"], testAPIID)
	}
	if dr.Inputs["IntegrationUri"] != invokeURIFmt {
		t.Errorf("IntegrationUri: got %v, want the verbatim invoke-ARN (the API→Lambda link)", dr.Inputs["IntegrationUri"])
	}
	if dr.Inputs["IntegrationType"] != "AWS_PROXY" {
		t.Errorf("IntegrationType: got %v, want AWS_PROXY", dr.Inputs["IntegrationType"])
	}
}

func TestIntegrationToRaw_EmptyIntegrationIdSkipped(t *testing.T) {
	if _, ok := integrationToRaw(apigatewayv2types.Integration{IntegrationId: nil}, testAPIID, "eu-central-1"); ok {
		t.Error("integrationToRaw returned ok for a nil IntegrationId")
	}
	if _, ok := integrationToRaw(apigatewayv2types.Integration{IntegrationId: strp("")}, testAPIID, "eu-central-1"); ok {
		t.Error("integrationToRaw returned ok for an empty IntegrationId")
	}
}

// fakeRouteIntgClient implements apigwV2RoutesAPI and apigwV2IntegrationsAPI so
// the per-API enumeration + pagination + skip-and-continue can be exercised
// without a live call. GetApis returns apisPages[idx] in order; GetRoutes /
// GetIntegrations return routePages[ApiId][idx] / intgPages[ApiId][idx] in order
// (exhausted → empty page), or routeErr[ApiId] / intgErr[ApiId] when set.
type fakeRouteIntgClient struct {
	apisPages []*apigatewayv2.GetApisOutput
	apisIdx   int
	apisErr   error

	routePages map[string][]*apigatewayv2.GetRoutesOutput
	routeIdx   map[string]int
	routeErr   map[string]error

	intgPages map[string][]*apigatewayv2.GetIntegrationsOutput
	intgIdx   map[string]int
	intgErr   map[string]error
}

func (f *fakeRouteIntgClient) GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	if f.apisErr != nil {
		return nil, f.apisErr
	}
	out := f.apisPages[f.apisIdx]
	f.apisIdx++
	return out, nil
}

func (f *fakeRouteIntgClient) GetRoutes(_ context.Context, in *apigatewayv2.GetRoutesInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error) {
	apiID := *in.ApiId
	if err := f.routeErr[apiID]; err != nil {
		return nil, err
	}
	if f.routeIdx == nil {
		f.routeIdx = map[string]int{}
	}
	idx := f.routeIdx[apiID]
	pages := f.routePages[apiID]
	if idx >= len(pages) {
		return &apigatewayv2.GetRoutesOutput{}, nil
	}
	f.routeIdx[apiID] = idx + 1
	return pages[idx], nil
}

func (f *fakeRouteIntgClient) GetIntegrations(_ context.Context, in *apigatewayv2.GetIntegrationsInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error) {
	apiID := *in.ApiId
	if err := f.intgErr[apiID]; err != nil {
		return nil, err
	}
	if f.intgIdx == nil {
		f.intgIdx = map[string]int{}
	}
	idx := f.intgIdx[apiID]
	pages := f.intgPages[apiID]
	if idx >= len(pages) {
		return &apigatewayv2.GetIntegrationsOutput{}, nil
	}
	f.intgIdx[apiID] = idx + 1
	return pages[idx], nil
}

func apisPage(ids ...string) *apigatewayv2.GetApisOutput {
	out := &apigatewayv2.GetApisOutput{}
	for _, id := range ids {
		out.Items = append(out.Items, apigatewayv2types.Api{ApiId: strp(id), ProtocolType: apigatewayv2types.ProtocolTypeHttp})
	}
	return out
}

// collectAPIGatewayV2Routes must enumerate every API and paginate GetRoutes
// per-API. Two APIs, the first paginating across two pages, verifies both the
// per-API walk and the NextToken loop.
func TestCollectAPIGatewayV2Routes_PaginatesPerAPI(t *testing.T) {
	client := &fakeRouteIntgClient{
		apisPages: []*apigatewayv2.GetApisOutput{apisPage("api-1", "api-2")},
		routePages: map[string][]*apigatewayv2.GetRoutesOutput{
			"api-1": {
				{Items: []apigatewayv2types.Route{{RouteId: strp("r-1a")}}, NextToken: strp("p2")},
				{Items: []apigatewayv2types.Route{{RouteId: strp("r-1b")}}},
			},
			"api-2": {
				{Items: []apigatewayv2types.Route{{RouteId: strp("r-2a")}}},
			},
		},
	}
	results, err := collectAPIGatewayV2Routes(context.Background(), client, "eu-central-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := map[string]bool{}
	for _, r := range results {
		got[r.Identifier] = true
	}
	for _, want := range []string{"api-1|r-1a", "api-1|r-1b", "api-2|r-2a"} {
		if !got[want] {
			t.Errorf("route %q missing from the per-API paginated result", want)
		}
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(results))
	}
}

// A per-API GetRoutes failure must NOT abort the region: the failed API is
// skipped, its error captured as a *PermissionError for --diagnose, and the
// other APIs' routes still collected. (results, firstErr) — discover.go keeps
// the results and surfaces the error.
func TestCollectAPIGatewayV2Routes_SkipAndContinueOnPerAPIError(t *testing.T) {
	client := &fakeRouteIntgClient{
		apisPages: []*apigatewayv2.GetApisOutput{apisPage("denied-api", "ok-api")},
		routePages: map[string][]*apigatewayv2.GetRoutesOutput{
			"ok-api": {{Items: []apigatewayv2types.Route{{RouteId: strp("r-ok")}}}},
		},
		routeErr: map[string]error{
			"denied-api": &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"},
		},
	}
	results, err := collectAPIGatewayV2Routes(context.Background(), client, "eu-central-1")
	if len(results) != 1 || results[0].Identifier != "ok-api|r-ok" {
		t.Fatalf("expected the ok-api route to survive the denied-api skip, got %+v", results)
	}
	if _, ok := asPermissionError(err); !ok {
		t.Fatalf("expected a *PermissionError captured from the denied API, got %T (%v)", err, err)
	}
}

// A GetApis enumeration failure is fatal — there are no APIs to walk children of,
// so nothing to recover — and surfaces classified for --diagnose.
func TestCollectAPIGatewayV2Routes_GetApisFatal(t *testing.T) {
	client := &fakeRouteIntgClient{apisErr: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}}
	results, err := collectAPIGatewayV2Routes(context.Background(), client, "eu-central-1")
	if results != nil {
		t.Fatalf("expected nil results on a GetApis failure, got %d", len(results))
	}
	if _, ok := asPermissionError(err); !ok {
		t.Fatalf("expected *PermissionError from a denied GetApis, got %T (%v)", err, err)
	}
}

// collectAPIGatewayV2Integrations mirrors the route collector: per-API
// enumeration + pagination + skip-and-continue.
func TestCollectAPIGatewayV2Integrations_PaginatesAndSkipsOnError(t *testing.T) {
	client := &fakeRouteIntgClient{
		apisPages: []*apigatewayv2.GetApisOutput{apisPage("denied-api", "ok-api")},
		intgPages: map[string][]*apigatewayv2.GetIntegrationsOutput{
			"ok-api": {
				{Items: []apigatewayv2types.Integration{{IntegrationId: strp("i-1a"), IntegrationUri: strp(invokeURIFmt)}}, NextToken: strp("p2")},
				{Items: []apigatewayv2types.Integration{{IntegrationId: strp("i-1b")}}},
			},
		},
		intgErr: map[string]error{
			"denied-api": &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"},
		},
	}
	results, err := collectAPIGatewayV2Integrations(context.Background(), client, "eu-central-1")
	got := map[string]bool{}
	for _, r := range results {
		got[r.Identifier] = true
	}
	for _, want := range []string{"ok-api|i-1a", "ok-api|i-1b"} {
		if !got[want] {
			t.Errorf("integration %q missing (paginated, post-skip)", want)
		}
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 integrations from ok-api, got %d", len(results))
	}
	if _, ok := asPermissionError(err); !ok {
		t.Fatalf("expected *PermissionError from the denied API, got %T (%v)", err, err)
	}
}

// THE compound-input round-trip: a NONE-auth route and an admin-Lambda AWS_PROXY
// integration on the SAME API must both flow through mapToDiscovered carrying the
// exact fields the compound "unauthenticated API + admin Lambda" rule reads — the
// route's AuthorizationType==NONE, the integration's IntegrationUri (→ the admin
// Lambda ARN), and a shared ApiId tying them together. (The prompt-assembly side
// — that these reach the LLM's resource table — is proved in the audit package's
// TestBuildGroundedPrompt_APIGatewayV2CompoundInputs.)
func TestCompoundInputs_NoneAuthRoutePlusAdminLambdaIntegration_RoundTrip(t *testing.T) {
	routeRaw, ok := routeToRaw(apigatewayv2types.Route{
		RouteId:           strp("r-admin"),
		RouteKey:          strp("POST /admin"),
		AuthorizationType: apigatewayv2types.AuthorizationTypeNone,
	}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("routeToRaw !ok")
	}
	intgRaw, ok := integrationToRaw(apigatewayv2types.Integration{
		IntegrationId:   strp("i-admin"),
		IntegrationType: apigatewayv2types.IntegrationTypeAwsProxy,
		IntegrationUri:  strp(invokeURIFmt),
	}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("integrationToRaw !ok")
	}

	routeDR, err := routeRaw.mapToDiscovered()
	if err != nil {
		t.Fatalf("route mapToDiscovered: %v", err)
	}
	intgDR, err := intgRaw.mapToDiscovered()
	if err != nil {
		t.Fatalf("integration mapToDiscovered: %v", err)
	}

	if routeDR.Inputs["AuthorizationType"] != "NONE" {
		t.Errorf("route AuthorizationType: got %v, want NONE", routeDR.Inputs["AuthorizationType"])
	}
	if intgDR.Inputs["IntegrationUri"] != invokeURIFmt {
		t.Errorf("integration IntegrationUri: got %v, want the admin-Lambda invoke-ARN", intgDR.Inputs["IntegrationUri"])
	}
	if routeDR.Inputs["ApiId"] != intgDR.Inputs["ApiId"] || routeDR.Inputs["ApiId"] != testAPIID {
		t.Errorf("ApiId linkage broken: route=%v integration=%v want both %s",
			routeDR.Inputs["ApiId"], intgDR.Inputs["ApiId"], testAPIID)
	}
}

// An empty primary (CloudControl's silent-empty for AWS::ApiGatewayV2::Route)
// must trigger the fallback and flow the synthesised route through runJob. Route
// has no describer, so no registry swap is needed — but mirror the Api test's
// CustomLister-empty + FallbackLister wiring.
func TestRunJob_APIGatewayV2RouteFallbackFires(t *testing.T) {
	fallbackRaw, ok := routeToRaw(apigatewayv2types.Route{
		RouteId:           strp("r-admin"),
		AuthorizationType: apigatewayv2types.AuthorizationTypeNone,
	}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("routeToRaw !ok")
	}
	spec := cfnTypeSpec{
		Type:         "AWS::ApiGatewayV2::Route",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}
	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 route from the fallback, got %d", len(res.resources))
	}
	if got := res.resources[0]; got.Type != "AWS::ApiGatewayV2::Route" || got.ID != testAPIID+"|r-admin" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
}

// When CloudControl lists the route, the fallback must NOT fire.
func TestRunJob_APIGatewayV2RouteFallbackNotFiredWhenPrimaryReturns(t *testing.T) {
	primaryRaw, ok := routeToRaw(apigatewayv2types.Route{RouteId: strp("cc-route")}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("routeToRaw !ok")
	}
	fallbackCalled := false
	spec := cfnTypeSpec{
		Type:         "AWS::ApiGatewayV2::Route",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return []rawResource{primaryRaw}, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			fallbackCalled = true
			return []rawResource{{CFNType: "AWS::ApiGatewayV2::Route", Identifier: "should-not-appear"}}, nil
		},
	}
	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if fallbackCalled {
		t.Error("FallbackLister fired even though CloudControl returned a route")
	}
	if len(res.resources) != 1 || res.resources[0].ID != testAPIID+"|cc-route" {
		t.Fatalf("expected only the CloudControl route, got %+v", res.resources)
	}
}

// Integration's fallback-on-empty wiring, mirroring the Route case.
func TestRunJob_APIGatewayV2IntegrationFallbackFires(t *testing.T) {
	fallbackRaw, ok := integrationToRaw(apigatewayv2types.Integration{
		IntegrationId:   strp("i-admin"),
		IntegrationType: apigatewayv2types.IntegrationTypeAwsProxy,
		IntegrationUri:  strp(invokeURIFmt),
	}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("integrationToRaw !ok")
	}
	spec := cfnTypeSpec{
		Type:         "AWS::ApiGatewayV2::Integration",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}
	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 integration from the fallback, got %d", len(res.resources))
	}
	if got := res.resources[0]; got.Type != "AWS::ApiGatewayV2::Integration" || got.ID != testAPIID+"|i-admin" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
}

func TestRunJob_APIGatewayV2IntegrationFallbackNotFiredWhenPrimaryReturns(t *testing.T) {
	primaryRaw, ok := integrationToRaw(apigatewayv2types.Integration{IntegrationId: strp("cc-intg")}, testAPIID, "eu-central-1")
	if !ok {
		t.Fatal("integrationToRaw !ok")
	}
	fallbackCalled := false
	spec := cfnTypeSpec{
		Type:         "AWS::ApiGatewayV2::Integration",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return []rawResource{primaryRaw}, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			fallbackCalled = true
			return []rawResource{{CFNType: "AWS::ApiGatewayV2::Integration", Identifier: "should-not-appear"}}, nil
		},
	}
	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if fallbackCalled {
		t.Error("FallbackLister fired even though CloudControl returned an integration")
	}
	if len(res.resources) != 1 || res.resources[0].ID != testAPIID+"|cc-intg" {
		t.Fatalf("expected only the CloudControl integration, got %+v", res.resources)
	}
}
