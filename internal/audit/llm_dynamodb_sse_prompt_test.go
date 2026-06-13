package audit

import (
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// TestBuildGroundedPrompt_DynamoDBSSEAWSOwnedInput is the end-to-end wiring check
// the DynamoDB SSE positive field exists to satisfy: it proves the AWS-owned-key
// signal dynamoTableToRaw self-carries survives serialiseInputs and lands in the
// LLM's resource table verbatim, so the intent-scoped non-CMK rule actually has
// its input. The aws package round-trips the field into dr.Inputs; this guards
// the next hop — a writeResourceTable / serialiseInputs regression (a per-type
// allowlist, a truncation) would drop it and silently neuter the rule while the
// aws round-trip stayed green.
//
// The Inputs map here mirrors exactly what dynamoTableToRaw synthesises for an
// AWS-owned-key table. This asserts the field reaches the prompt; it does NOT
// assert the LLM fires (the rule is intent-scoped — see the MR description).
func TestBuildGroundedPrompt_DynamoDBSSEAWSOwnedInput(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type: "AWS::DynamoDB::Table",
			URN:  "aws://eu-central-1/AWS::DynamoDB::Table/cbx-serverless-items",
			ID:   "cbx-serverless-items",
			Inputs: map[string]any{
				"TableName":                           "cbx-serverless-items",
				"BillingMode":                         "PROVISIONED",
				"cb_describer_dynamodb_sse_aws_owned": true,
			},
		},
	}

	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, resources, &GroundingBundle{}, nil, rulesbundletest.Pack(t))

	if !strings.Contains(prompt, `"cb_describer_dynamodb_sse_aws_owned": true`) {
		t.Errorf("grounded prompt dropped the DynamoDB AWS-owned-key signal — the intent-scoped non-CMK rule reads cb_describer_dynamodb_sse_aws_owned; a writeResourceTable/serialiseInputs regression would silently neuter it")
	}
}
