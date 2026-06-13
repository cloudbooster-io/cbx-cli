package aws

import (
	"context"
	"fmt"
	"testing"
)

func TestApplyContainerInsights(t *testing.T) {
	cases := []struct {
		name        string
		settings    []clusterSetting
		wantKey     bool // whether cb_describer_container_insights_enabled is set
		wantEnabled bool
	}{
		{
			name:     "no settings -> key absent (account default may apply, FP-safety)",
			settings: nil,
			wantKey:  false,
		},
		{
			name:     "settings present but no containerInsights entry -> key absent",
			settings: []clusterSetting{{name: "somethingElse", value: "x"}},
			wantKey:  false,
		},
		{
			name:        "explicit disabled -> false",
			settings:    []clusterSetting{{name: "containerInsights", value: "disabled"}},
			wantKey:     true,
			wantEnabled: false,
		},
		{
			name:        "explicit enabled -> true",
			settings:    []clusterSetting{{name: "containerInsights", value: "enabled"}},
			wantKey:     true,
			wantEnabled: true,
		},
		{
			name:        "enhanced counts as enabled",
			settings:    []clusterSetting{{name: "containerInsights", value: "enhanced"}},
			wantKey:     true,
			wantEnabled: true,
		},
		{
			name:     "unrecognised value -> key absent (don't guess)",
			settings: []clusterSetting{{name: "containerInsights", value: ""}},
			wantKey:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := map[string]any{}
			applyContainerInsights(inputs, tc.settings)
			got, present := inputs["cb_describer_container_insights_enabled"]
			if present != tc.wantKey {
				t.Fatalf("container_insights_enabled present = %v, want %v", present, tc.wantKey)
			}
			if tc.wantKey && got != tc.wantEnabled {
				t.Errorf("container_insights_enabled = %v, want %v", got, tc.wantEnabled)
			}
		})
	}
}

func TestReadClusterSettings_TolerantOfCCShape(t *testing.T) {
	// Mirrors the JSON-unmarshalled CloudControl Properties shape: a
	// []any of map[string]any, with a malformed entry that must be skipped.
	inputs := map[string]any{
		"ClusterSettings": []any{
			map[string]any{"Name": "containerInsights", "Value": "disabled"},
			"garbage-not-a-map",
			map[string]any{"Name": "other", "Value": "y"},
		},
	}
	got := readClusterSettings(inputs)
	if len(got) != 2 {
		t.Fatalf("readClusterSettings returned %d entries, want 2 (malformed entry skipped)", len(got))
	}
	if got[0] != (clusterSetting{name: "containerInsights", value: "disabled"}) {
		t.Errorf("entry[0] = %+v", got[0])
	}
}

func TestReadClusterSettings_MissingKey(t *testing.T) {
	if got := readClusterSettings(map[string]any{}); got != nil {
		t.Errorf("readClusterSettings(empty) = %v, want nil", got)
	}
}

func TestECSClusterDescriber_EnrichEndToEnd(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::ECS::Cluster",
		ID:   "prod-cluster",
		Inputs: map[string]any{
			"ClusterSettings": []any{
				map[string]any{"Name": "containerInsights", "Value": "disabled"},
			},
		},
	}
	if err := (ecsClusterDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got, ok := r.Inputs["cb_describer_container_insights_enabled"]; !ok || got != false {
		t.Errorf("cb_describer_container_insights_enabled = (%v, %v), want (false, true)", got, ok)
	}
}

func TestECSClusterDescriber_CFNTypeAndRegistration(t *testing.T) {
	if got := (ecsClusterDescriber{}).CFNType(); got != "AWS::ECS::Cluster" {
		t.Errorf("CFNType = %q", got)
	}
	// Must be wired into the registry, else discovery never runs it and the
	// Container Insights signal never reaches the grounded prompt.
	if describerFor("AWS::ECS::Cluster") == nil {
		t.Error("ecsClusterDescriber not registered in allDescribers")
	}
}

// taskDefEnvInputs builds the CC Properties shape CloudControl hands the
// describer: ContainerDefinitions → []any of container maps → Environment
// → []any of {"Name","Value"} maps.
func taskDefEnvInputs(env ...map[string]any) map[string]any {
	envAny := make([]any, 0, len(env))
	for _, e := range env {
		envAny = append(envAny, e)
	}
	return map[string]any{
		"ContainerDefinitions": []any{
			map[string]any{
				"Name":        "app",
				"Image":       "example/app:latest",
				"Environment": envAny,
			},
		},
	}
}

func TestRedactTaskDefEnvValues_CCOrigin(t *testing.T) {
	const secretsManagerRef = "arn:aws:secretsmanager:eu-central-1:123456789012:secret:db-creds"

	cases := []struct {
		name  string
		entry map[string]any
		want  any // expected Value after redaction
	}{
		{
			name:  "secret-shaped name with plaintext value -> masked",
			entry: map[string]any{"Name": "DB_PASSWORD", "Value": "hunter2"},
			want:  redactedEnvValue,
		},
		{
			name:  "secret-shaped name with arn: reference -> untouched (indirection shape)",
			entry: map[string]any{"Name": "DB_PASSWORD_REF", "Value": secretsManagerRef},
			want:  secretsManagerRef,
		},
		{
			name:  "benign name -> untouched",
			entry: map[string]any{"Name": "LOG_LEVEL", "Value": "debug"},
			want:  "debug",
		},
		{
			name:  "non-string value under secret-shaped name -> masked (fail closed)",
			entry: map[string]any{"Name": "API_KEY", "Value": float64(42)},
			want:  redactedEnvValue,
		},
		{
			name:  "already-redacted value -> stable (fallback raws are re-enriched)",
			entry: map[string]any{"Name": "API_KEY", "Value": redactedEnvValue},
			want:  redactedEnvValue,
		},
		{
			name:  "safe-suffix name (reference shape) -> untouched",
			entry: map[string]any{"Name": "DB_PASSWORD_ARN", "Value": "not-actually-an-arn"},
			want:  "not-actually-an-arn",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := taskDefEnvInputs(tc.entry)
			redactTaskDefEnvValues(inputs)
			got := tc.entry["Value"]
			if got != tc.want {
				t.Errorf("Value = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRedactTaskDefEnvValues_FailsOpenOnStructure(t *testing.T) {
	// Structurally-weird Inputs must neither panic nor be modified —
	// fail open on structure, the describer only ever masks values it
	// positively recognises as secret-shaped.
	cases := []struct {
		name   string
		inputs map[string]any
	}{
		{name: "no ContainerDefinitions key", inputs: map[string]any{"Family": "web"}},
		{name: "ContainerDefinitions not a list", inputs: map[string]any{"ContainerDefinitions": "garbage"}},
		{name: "container entry not a map", inputs: map[string]any{"ContainerDefinitions": []any{"garbage"}}},
		{
			name: "Environment not a list",
			inputs: map[string]any{"ContainerDefinitions": []any{
				map[string]any{"Environment": map[string]any{"DB_PASSWORD": "hunter2"}},
			}},
		},
		{
			name: "env entry not a map",
			inputs: map[string]any{"ContainerDefinitions": []any{
				map[string]any{"Environment": []any{"garbage"}},
			}},
		},
		{
			name: "Name not a string",
			inputs: map[string]any{"ContainerDefinitions": []any{
				map[string]any{"Environment": []any{map[string]any{"Name": float64(1), "Value": "x"}}},
			}},
		},
		{
			name: "secret-shaped Name with no Value key",
			inputs: map[string]any{"ContainerDefinitions": []any{
				map[string]any{"Environment": []any{map[string]any{"Name": "DB_PASSWORD"}}},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := fmt.Sprintf("%#v", tc.inputs)
			redactTaskDefEnvValues(tc.inputs)
			if got := fmt.Sprintf("%#v", tc.inputs); got != want {
				t.Errorf("inputs changed:\n got %s\nwant %s", got, want)
			}
		})
	}
}

func TestECSTaskDefinitionDescriber_EnrichEndToEnd(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::ECS::TaskDefinition",
		ID:   "arn:aws:ecs:eu-central-1:123456789012:task-definition/web:3",
		Inputs: taskDefEnvInputs(
			map[string]any{"Name": "DB_PASSWORD", "Value": "hunter2"},
			map[string]any{"Name": "LOG_LEVEL", "Value": "debug"},
		),
	}
	if err := (ecsTaskDefinitionDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	env := r.Inputs["ContainerDefinitions"].([]any)[0].(map[string]any)["Environment"].([]any)
	if got := env[0].(map[string]any)["Value"]; got != redactedEnvValue {
		t.Errorf("secret value = %v, want %q", got, redactedEnvValue)
	}
	if got := env[1].(map[string]any)["Value"]; got != "debug" {
		t.Errorf("benign value = %v, want %q", got, "debug")
	}
}

func TestECSTaskDefinitionDescriber_NilInputsNoPanic(t *testing.T) {
	r := DiscoveredResource{Type: "AWS::ECS::TaskDefinition", ID: "thing"}
	if err := (ecsTaskDefinitionDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich on nil Inputs: %v", err)
	}
	if r.Inputs != nil {
		t.Errorf("Enrich allocated Inputs = %v, want nil (describer adds no keys)", r.Inputs)
	}
}

func TestECSTaskDefinitionDescriber_CFNTypeAndRegistration(t *testing.T) {
	if got := (ecsTaskDefinitionDescriber{}).CFNType(); got != "AWS::ECS::TaskDefinition" {
		t.Errorf("CFNType = %q", got)
	}
	// Must be wired into the registry, else CloudControl-origin task
	// definitions ship env-var values to the grounded prompt unredacted.
	if describerFor("AWS::ECS::TaskDefinition") == nil {
		t.Error("ecsTaskDefinitionDescriber not registered in allDescribers")
	}
}
