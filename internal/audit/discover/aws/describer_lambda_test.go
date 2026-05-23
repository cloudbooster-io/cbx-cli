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
