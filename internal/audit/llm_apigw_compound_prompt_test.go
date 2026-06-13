package audit

import (
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// TestBuildGroundedPrompt_APIGatewayV2CompoundInputs is the end-to-end wiring
// check the Route + Integration native fallbacks exist to satisfy: it proves the
// finding-bearing fields those fallbacks self-carry survive serialiseInputs and
// land in the LLM's resource table verbatim, so the compound "unauthenticated API
// + admin Lambda" CRITICAL rule actually has its inputs.
//
// The Inputs maps here mirror exactly what routeToRaw / integrationToRaw /
// lambdaFunctionToRaw synthesise (those round-trips are unit-tested in the aws
// package). The compound rule reads three signals — Route.AuthorizationType==NONE
// (unauthenticated), Integration.IntegrationUri (→ the admin Lambda ARN), and the
// Lambda's cb_describer_role_is_admin_equivalent — all tied by a shared ApiId.
// A regression in writeResourceTable / serialiseInputs (a per-type allowlist, a
// truncation) would drop one of these and silently neuter the rule while the aws
// package's round-trip tests stayed green; this guards that gap.
func TestBuildGroundedPrompt_APIGatewayV2CompoundInputs(t *testing.T) {
	const (
		apiID     = "ghv0blt39d"
		lambdaArn = "arn:aws:lambda:eu-central-1:111122223333:function:admin-fn"
		invokeURI = "arn:aws:apigateway:eu-central-1:lambda:path/2015-03-31/functions/" + lambdaArn + "/invocations"
	)
	resources := []DiscoveredResource{
		{
			Type: "AWS::ApiGatewayV2::Route",
			URN:  "aws://eu-central-1/AWS::ApiGatewayV2::Route/" + apiID + "|r-admin",
			ID:   apiID + "|r-admin",
			Inputs: map[string]any{
				"ApiId":             apiID,
				"RouteId":           "r-admin",
				"RouteKey":          "POST /admin",
				"AuthorizationType": "NONE",
			},
		},
		{
			Type: "AWS::ApiGatewayV2::Integration",
			URN:  "aws://eu-central-1/AWS::ApiGatewayV2::Integration/" + apiID + "|i-admin",
			ID:   apiID + "|i-admin",
			Inputs: map[string]any{
				"ApiId":           apiID,
				"IntegrationId":   "i-admin",
				"IntegrationType": "AWS_PROXY",
				"IntegrationUri":  invokeURI,
			},
		},
		{
			Type: "AWS::Lambda::Function",
			URN:  "aws://eu-central-1/AWS::Lambda::Function/admin-fn",
			ID:   "admin-fn",
			Inputs: map[string]any{
				"FunctionName":                          "admin-fn",
				"Arn":                                   lambdaArn,
				"cb_describer_role_is_admin_equivalent": true,
			},
		},
	}

	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, resources, &GroundingBundle{}, nil, rulesbundletest.Pack(t))

	for _, want := range []string{
		`"AuthorizationType": "NONE"`,                   // the unauthenticated-route signal
		`"IntegrationUri": "` + invokeURI,               // the API→Lambda link, carried verbatim
		`"cb_describer_role_is_admin_equivalent": true`, // the admin-Lambda signal
		`"ApiId": "` + apiID,                            // the linkage tying route + integration to one API
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt dropped a compound-rule input — missing %q\n(the Route/Integration fallback feeds this; a writeResourceTable regression would silently neuter the CRITICAL)", want)
		}
	}
}
