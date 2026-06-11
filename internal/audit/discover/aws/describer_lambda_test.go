package aws

import (
	"context"
	"testing"
)

func TestLambdaDescriber_NormalizesCoreFields(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::Lambda::Function",
		ID:   "fn-prod",
		Inputs: map[string]any{
			"Runtime":    "python3.12",
			"Role":       "arn:aws:iam::123:role/fn-role",
			"MemorySize": float64(512),
			"Timeout":    float64(30),
			"VpcConfig": map[string]any{
				"SubnetIds":        []any{"subnet-aaa", "subnet-bbb"},
				"SecurityGroupIds": []any{"sg-0abc12345"},
			},
		},
	}
	if err := (lambdaFunctionDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if r.Inputs["cb_describer_runtime"] != "python3.12" {
		t.Errorf("runtime = %v", r.Inputs["cb_describer_runtime"])
	}
	if r.Inputs["cb_describer_vpc_attached"] != true {
		t.Errorf("vpc_attached = %v, want true", r.Inputs["cb_describer_vpc_attached"])
	}
	if r.Inputs["cb_describer_env_var_count"] != float64(0) {
		t.Errorf("env_var_count = %v, want 0", r.Inputs["cb_describer_env_var_count"])
	}
}

func TestLambdaDescriber_DetectsPlaintextSecretEnvKey(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]any
		expect bool
	}{
		{
			name:   "DB_PASSWORD trips heuristic",
			env:    map[string]any{"DB_PASSWORD": "hunter2", "LOG_LEVEL": "info"},
			expect: true,
		},
		{
			name:   "DB_PASSWORD_ARN is the indirection shape and is allowed",
			env:    map[string]any{"DB_PASSWORD_ARN": "arn:aws:secretsmanager:..."},
			expect: false,
		},
		{
			name:   "API_KEY trips heuristic",
			env:    map[string]any{"GITHUB_API_KEY": "ghp_xxx"},
			expect: true,
		},
		{
			name:   "API_KEY_ID is reference-shape",
			env:    map[string]any{"GITHUB_API_KEY_ID": "ghp_pointer"},
			expect: false,
		},
		{
			name:   "plain config keys do not trip",
			env:    map[string]any{"BUCKET_NAME": "x", "QUEUE_URL": "y"},
			expect: false,
		},
		{
			name:   "TOKEN_URL is allowed (URL reference, not the token itself)",
			env:    map[string]any{"OAUTH_TOKEN_URL": "https://example"},
			expect: false,
		},
		{
			name:   "no env at all → false",
			env:    nil,
			expect: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DiscoveredResource{
				Type: "AWS::Lambda::Function",
				ID:   "fn-test",
				Inputs: map[string]any{
					"Environment": map[string]any{"Variables": tc.env},
				},
			}
			if err := (lambdaFunctionDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
				t.Fatalf("Enrich: %v", err)
			}
			got := r.Inputs["cb_describer_env_has_plaintext_secrets"]
			if got != tc.expect {
				t.Errorf("got %v, want %v", got, tc.expect)
			}
		})
	}
}

// The Inputs map is inlined verbatim into the grounded prompt, so Enrich must
// mask secret-shaped env-var VALUES in place — AFTER computing the
// cb_describer_env_has_plaintext_secrets flag, which must still fire off the
// un-redacted key names. Reference-shaped keys (_ARN-suffixed) and arn:-prefixed
// values are the canonical indirection shapes and must survive un-masked, as
// must plain config values.
func TestLambdaDescriber_RedactsSecretEnvValues(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::Lambda::Function",
		ID:   "fn-leaky",
		Inputs: map[string]any{
			"Environment": map[string]any{"Variables": map[string]any{
				"DB_PASSWORD":     "hunter2",                                          // secret-shaped key, literal value → masked
				"DB_PASSWORD_ARN": "arn:aws:secretsmanager:eu-central-1:123:secret:x", // reference-shaped key → untouched
				"API_TOKEN":       "arn:aws:ssm:eu-central-1:123:parameter/token",     // secret-shaped key, ARN value → indirection, untouched
				"LOG_LEVEL":       "info",                                             // plain config → untouched
			}},
		},
	}
	if err := (lambdaFunctionDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	// The flag is computed BEFORE the mask — its key-shape signal must be intact.
	if r.Inputs["cb_describer_env_has_plaintext_secrets"] != true {
		t.Errorf("env_has_plaintext_secrets = %v, want true (flag must be computed before redaction)", r.Inputs["cb_describer_env_has_plaintext_secrets"])
	}

	vars := r.Inputs["Environment"].(map[string]any)["Variables"].(map[string]any)
	if got := vars["DB_PASSWORD"]; got != "[REDACTED by cbx]" {
		t.Errorf("DB_PASSWORD = %v, want the redaction marker (value must not reach the prompt)", got)
	}
	if got := vars["DB_PASSWORD_ARN"]; got != "arn:aws:secretsmanager:eu-central-1:123:secret:x" {
		t.Errorf("DB_PASSWORD_ARN = %v, want the reference untouched", got)
	}
	if got := vars["API_TOKEN"]; got != "arn:aws:ssm:eu-central-1:123:parameter/token" {
		t.Errorf("API_TOKEN = %v, want the ARN value untouched (indirection shape)", got)
	}
	if got := vars["LOG_LEVEL"]; got != "info" {
		t.Errorf("LOG_LEVEL = %v, want the non-secret value untouched", got)
	}
}

func TestLambdaDescriber_DLQAndReservedConcurrency(t *testing.T) {
	cases := []struct {
		name              string
		inputs            map[string]any
		wantDLQ           bool
		wantReservedSet   bool
		wantReservedValue float64 // checked only when wantReservedSet
	}{
		{
			name:            "no DLQ, no reserved concurrency (the 03-serverless-api shape)",
			inputs:          map[string]any{"Runtime": "python3.12"},
			wantDLQ:         false,
			wantReservedSet: false,
		},
		{
			name: "DLQ with TargetArn is configured",
			inputs: map[string]any{
				"DeadLetterConfig": map[string]any{"TargetArn": "arn:aws:sqs:eu-central-1:123:dlq"},
			},
			wantDLQ:         true,
			wantReservedSet: false,
		},
		{
			name: "empty DeadLetterConfig block is not a DLQ",
			inputs: map[string]any{
				"DeadLetterConfig": map[string]any{"TargetArn": "  "},
			},
			wantDLQ:         false,
			wantReservedSet: false,
		},
		{
			name: "reserved concurrency 0 (throttle-to-zero) still counts as set",
			inputs: map[string]any{
				"ReservedConcurrentExecutions": float64(0),
			},
			wantDLQ:           false,
			wantReservedSet:   true,
			wantReservedValue: 0,
		},
		{
			name: "reserved concurrency set to a positive value",
			inputs: map[string]any{
				"ReservedConcurrentExecutions": float64(10),
			},
			wantDLQ:           false,
			wantReservedSet:   true,
			wantReservedValue: 10,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DiscoveredResource{Type: "AWS::Lambda::Function", ID: "fn", Inputs: tc.inputs}
			if err := (lambdaFunctionDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
				t.Fatalf("Enrich: %v", err)
			}
			if got := r.Inputs["cb_describer_dlq_configured"]; got != tc.wantDLQ {
				t.Errorf("dlq_configured = %v, want %v", got, tc.wantDLQ)
			}
			if got := r.Inputs["cb_describer_reserved_concurrency_set"]; got != tc.wantReservedSet {
				t.Errorf("reserved_concurrency_set = %v, want %v", got, tc.wantReservedSet)
			}
			if tc.wantReservedSet {
				if got := r.Inputs["cb_describer_reserved_concurrency"]; got != tc.wantReservedValue {
					t.Errorf("reserved_concurrency = %v, want %v", got, tc.wantReservedValue)
				}
			} else if _, present := r.Inputs["cb_describer_reserved_concurrency"]; present {
				t.Errorf("reserved_concurrency must be absent when not set")
			}
		})
	}
}

func TestLambdaDescriber_NotVPCAttachedWhenSubnetsEmpty(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::Lambda::Function",
		ID:   "fn-public",
		Inputs: map[string]any{
			"VpcConfig": map[string]any{"SubnetIds": []any{}},
		},
	}
	if err := (lambdaFunctionDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if r.Inputs["cb_describer_vpc_attached"] != false {
		t.Errorf("got %v, want false", r.Inputs["cb_describer_vpc_attached"])
	}
}
