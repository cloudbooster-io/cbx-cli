package aws

import (
	"context"
	"testing"

	apigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/smithy-go"
)

// apiV2ToRaw must synthesise the CloudControl AWS::ApiGatewayV2::Api shape: the
// ApiId is both the primary identifier (→ DiscoveredResource.ID, the only field
// apiGatewayV2ApiDescriber keys off for its GetStages call) and the ApiId prop,
// with the audited region carried through so the region-qualified URN — which the
// describer re-pins GetStages to — is correct. The read-only-visible props
// (Name, ProtocolType, ApiEndpoint, DisableExecuteApiEndpoint) round-trip so the
// synthesised shape is indistinguishable from a CloudControl-listed API.
func TestApiV2ToRaw_RoundTrip(t *testing.T) {
	raw, ok := apiV2ToRaw(apigatewayv2types.Api{
		ApiId:                     strp("ghv0blt39d"),
		Name:                      strp("checkout-http-api"),
		ProtocolType:              apigatewayv2types.ProtocolTypeHttp,
		ApiEndpoint:               strp("https://ghv0blt39d.execute-api.eu-central-1.amazonaws.com"),
		DisableExecuteApiEndpoint: boolp(false),
	}, "eu-central-1")
	if !ok {
		t.Fatal("apiV2ToRaw !ok for a valid API")
	}
	if raw.CFNType != "AWS::ApiGatewayV2::Api" || raw.Identifier != "ghv0blt39d" {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}
	if raw.Region != "eu-central-1" {
		t.Fatalf("Region: got %q, want eu-central-1", raw.Region)
	}

	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if dr.ID != "ghv0blt39d" {
		t.Errorf("ID: got %q, want ghv0blt39d (the ApiId apiGatewayV2ApiDescriber keys GetStages off)", dr.ID)
	}
	if dr.Inputs["ApiId"] != "ghv0blt39d" {
		t.Errorf("ApiId: got %v, want ghv0blt39d", dr.Inputs["ApiId"])
	}
	if dr.Inputs["Name"] != "checkout-http-api" {
		t.Errorf("Name: got %v, want checkout-http-api", dr.Inputs["Name"])
	}
	if dr.Inputs["ProtocolType"] != "HTTP" {
		t.Errorf("ProtocolType: got %v, want HTTP", dr.Inputs["ProtocolType"])
	}
	if v, ok := dr.Inputs["DisableExecuteApiEndpoint"].(bool); !ok || v {
		t.Errorf("DisableExecuteApiEndpoint: got %v, want false (carried through)", dr.Inputs["DisableExecuteApiEndpoint"])
	}
	if dr.URN != "aws://eu-central-1/AWS::ApiGatewayV2::Api/ghv0blt39d" {
		t.Errorf("URN: got %q (region-qualified URN is why region scoping matters)", dr.URN)
	}
}

// An API with no ApiId can't be keyed by the describer's GetStages, so it must be
// skipped (apiV2ToRaw !ok) rather than synthesised with an empty identifier.
func TestApiV2ToRaw_EmptyApiId(t *testing.T) {
	if _, ok := apiV2ToRaw(apigatewayv2types.Api{ApiId: nil}, "eu-central-1"); ok {
		t.Error("apiV2ToRaw returned ok for a nil ApiId")
	}
	if _, ok := apiV2ToRaw(apigatewayv2types.Api{ApiId: strp("")}, "eu-central-1"); ok {
		t.Error("apiV2ToRaw returned ok for an empty ApiId")
	}
}

// fakeAPIGWV2Fallback implements apigwV2FallbackAPI so the NextToken pagination
// loop can be exercised without a live call. GetApis returns pages[callIdx] in
// order (the loop drives it via NextToken); listErr, when set, simulates an
// AccessDenied / throttle the fatal-error path classifies.
type fakeAPIGWV2Fallback struct {
	pages   []*apigatewayv2.GetApisOutput
	listErr error
	callIdx int
}

func (f *fakeAPIGWV2Fallback) GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := f.pages[f.callIdx]
	f.callIdx++
	return out, nil
}

// GetApis paginates by NextToken; collectAPIGatewayV2APIs must walk every page
// and synthesise a raw per API. Two pages with an empty-ApiId entry mixed in
// verifies both the pagination loop and the skip-and-continue on a bad API.
func TestCollectAPIGatewayV2APIs_PaginatesViaNextToken(t *testing.T) {
	client := &fakeAPIGWV2Fallback{
		pages: []*apigatewayv2.GetApisOutput{
			{
				Items: []apigatewayv2types.Api{
					{ApiId: strp("alpha"), ProtocolType: apigatewayv2types.ProtocolTypeHttp},
					{ApiId: nil}, // skipped: no ApiId, must not abort the page
					{ApiId: strp("bravo"), ProtocolType: apigatewayv2types.ProtocolTypeWebsocket},
				},
				NextToken: strp("page-2"),
			},
			{
				Items: []apigatewayv2types.Api{
					{ApiId: strp("charlie"), ProtocolType: apigatewayv2types.ProtocolTypeHttp},
				},
			},
		},
	}

	results, err := collectAPIGatewayV2APIs(context.Background(), client, "eu-central-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 APIs across both pages (the nil-ApiId skipped), got %d", len(results))
	}
	ids := map[string]bool{}
	for _, r := range results {
		ids[r.Identifier] = true
		if r.CFNType != "AWS::ApiGatewayV2::Api" {
			t.Errorf("unexpected CFNType %q on %q", r.CFNType, r.Identifier)
		}
	}
	for _, want := range []string{"alpha", "bravo", "charlie"} {
		if !ids[want] {
			t.Errorf("API %q missing from the paginated result", want)
		}
	}
}

// A GetApis failure is fatal — there's nothing to recover — and must come back
// classified as *PermissionError so an all-deny surfaces in --diagnose instead of
// masquerading as a clean empty account.
func TestCollectAPIGatewayV2APIs_GetApisErrorFatal(t *testing.T) {
	client := &fakeAPIGWV2Fallback{listErr: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}}

	results, err := collectAPIGatewayV2APIs(context.Background(), client, "eu-central-1")
	if results != nil {
		t.Fatalf("expected nil results on a GetApis failure, got %d", len(results))
	}
	if _, ok := asPermissionError(err); !ok {
		t.Fatalf("expected *PermissionError from a denied GetApis, got %T (%v)", err, err)
	}
}

// Empty primary (CloudControl's silent-empty for AWS::ApiGatewayV2::Api — the
// variant-03 gap) must trigger the fallback and flow the synthesised API through
// runJob into the resource set. apiGatewayV2ApiDescriber makes a live GetStages
// call, so we swap the describer registry out — the wiring under test is the
// fallback-on-empty path, not the describer's network call (mirrors
// TestRunJob_S3BucketFallbackFires).
func TestRunJob_APIGatewayV2APIFallbackFires(t *testing.T) {
	saved := allDescribers
	allDescribers = []Describer{}
	defer func() { allDescribers = saved }()

	fallbackRaw, ok := apiV2ToRaw(apigatewayv2types.Api{
		ApiId:        strp("ghv0blt39d"),
		Name:         strp("checkout-http-api"),
		ProtocolType: apigatewayv2types.ProtocolTypeHttp,
	}, "eu-central-1")
	if !ok {
		t.Fatal("apiV2ToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type:         "AWS::ApiGatewayV2::Api",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 API from the fallback, got %d", len(res.resources))
	}
	if got := res.resources[0]; got.Type != "AWS::ApiGatewayV2::Api" || got.ID != "ghv0blt39d" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
}

// When CloudControl lists the API, the fallback must NOT fire — CC's richer
// payload wins and there's no double-counting.
func TestRunJob_APIGatewayV2APIFallbackNotFiredWhenPrimaryReturns(t *testing.T) {
	saved := allDescribers
	allDescribers = []Describer{}
	defer func() { allDescribers = saved }()

	primaryRaw, ok := apiV2ToRaw(apigatewayv2types.Api{ApiId: strp("cc-listed-api")}, "eu-central-1")
	if !ok {
		t.Fatal("apiV2ToRaw !ok")
	}

	fallbackCalled := false
	spec := cfnTypeSpec{
		Type:         "AWS::ApiGatewayV2::Api",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return []rawResource{primaryRaw}, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			fallbackCalled = true
			return []rawResource{{CFNType: "AWS::ApiGatewayV2::Api", Identifier: "should-not-appear"}}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if fallbackCalled {
		t.Error("FallbackLister fired even though CloudControl returned an API")
	}
	if len(res.resources) != 1 || res.resources[0].ID != "cc-listed-api" {
		t.Fatalf("expected only the CloudControl API, got %+v", res.resources)
	}
}
