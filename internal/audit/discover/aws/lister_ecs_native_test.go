package aws

import (
	"testing"

	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// TestTaskDefinitionToRaw_RoundTrip pins the per-container posture the ECS
// native lister synthesises into CloudControl's CFN shape — specifically the
// two signals the grounded writable-root rule reads: an EXPLICIT
// ReadonlyRootFilesystem=false (the firing condition) and the Essential flag
// (used to scope the finding to the primary application container). There is no
// ECS::TaskDefinition describer, so this round-trip is the only guard that the
// fields land in Inputs exactly as the grounded LLM will read them.
//
// The sidecar container deliberately leaves ReadonlyRootFilesystem unset:
// putBool emits a *bool only when non-nil, so the field must stay ABSENT. The
// rule is explicit-false-only precisely so that an absent value reads as
// UNKNOWN (not a finding) — this test is its emission-side guard.
func TestTaskDefinitionToRaw_RoundTrip(t *testing.T) {
	td := ecstypes.TaskDefinition{
		TaskDefinitionArn: strp("arn:aws:ecs:eu-central-1:111122223333:task-definition/cbx-ecs-task:1"),
		Family:            strp("cbx-ecs-task"),
		ContainerDefinitions: []ecstypes.ContainerDefinition{
			{
				Name:                   strp("app"),
				Image:                  strp("public.ecr.aws/nginx/nginx:stable-perl"),
				Essential:              boolp(true),
				ReadonlyRootFilesystem: boolp(false), // explicit → the writable-root finding
			},
			{
				// Field UNSET → must stay absent so the explicit-false-only rule
				// treats it as UNKNOWN, not a finding.
				Name:      strp("log-sidecar"),
				Image:     strp("public.ecr.aws/aws-observability/aws-for-fluent-bit:stable"),
				Essential: boolp(false),
			},
		},
	}

	raw, ok := taskDefinitionToRaw(td, "eu-central-1")
	if !ok {
		t.Fatal("taskDefinitionToRaw !ok")
	}
	if raw.CFNType != "AWS::ECS::TaskDefinition" {
		t.Fatalf("unexpected CFN type %q", raw.CFNType)
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}

	defs, ok := dr.Inputs["ContainerDefinitions"].([]any)
	if !ok || len(defs) != 2 {
		t.Fatalf("ContainerDefinitions: got %T len=%d, want []any len 2", dr.Inputs["ContainerDefinitions"], len(defs))
	}

	app, _ := defs[0].(map[string]any)
	// Writable-root signal: the explicit false must survive (the rule fires on it).
	if v, ok := app["ReadonlyRootFilesystem"].(bool); !ok || v {
		t.Errorf("app ReadonlyRootFilesystem: got %v, want explicit false (writable-root finding)", app["ReadonlyRootFilesystem"])
	}
	// Scoping signal: Essential must survive so the rule can target the primary
	// application container and skip sidecars/init jobs.
	if v, ok := app["Essential"].(bool); !ok || !v {
		t.Errorf("app Essential: got %v, want true (scoping signal)", app["Essential"])
	}

	sidecar, _ := defs[1].(map[string]any)
	// Unset readonly-root must stay ABSENT — the explicit-false-only contract
	// (a bare container with the field unset is NOT a finding) depends on it.
	if _, present := sidecar["ReadonlyRootFilesystem"]; present {
		t.Errorf("sidecar ReadonlyRootFilesystem: present, want absent (unset *bool must not serialise)")
	}
}

// TestTaskDefinitionToRaw_RedactsSecretEnvValues pins the env-value redaction
// at the lister itself (ecsTaskDefinitionDescriber re-applies the same policy
// idempotently at enrich time) — a secret-shaped Name's literal
// Value must come out masked, while the Name itself survives (the grounded
// plaintext-env rule is a key-NAME heuristic and still needs it). Non-secret
// values, reference-shaped keys (_ARN-suffixed) and arn:-prefixed values (the
// indirection shape the rule's suppress path keys off) pass through untouched.
func TestTaskDefinitionToRaw_RedactsSecretEnvValues(t *testing.T) {
	td := ecstypes.TaskDefinition{
		TaskDefinitionArn: strp("arn:aws:ecs:eu-central-1:111122223333:task-definition/cbx-leaky-task:3"),
		Family:            strp("cbx-leaky-task"),
		ContainerDefinitions: []ecstypes.ContainerDefinition{
			{
				Name:  strp("app"),
				Image: strp("public.ecr.aws/nginx/nginx:stable-perl"),
				Environment: []ecstypes.KeyValuePair{
					{Name: strp("DB_PASSWORD"), Value: strp("hunter2")},                                             // secret-shaped name, literal value → masked
					{Name: strp("DB_SECRET_ARN"), Value: strp("arn:aws:secretsmanager:eu-central-1:123:secret:db")}, // reference-shaped name → untouched
					{Name: strp("API_TOKEN"), Value: strp("arn:aws:ssm:eu-central-1:123:parameter/token")},          // secret name, ARN value → indirection, untouched
					{Name: strp("LOG_LEVEL"), Value: strp("debug")},                                                 // plain config → untouched
				},
			},
		},
	}

	raw, ok := taskDefinitionToRaw(td, "eu-central-1")
	if !ok {
		t.Fatal("taskDefinitionToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}

	defs, ok := dr.Inputs["ContainerDefinitions"].([]any)
	if !ok || len(defs) != 1 {
		t.Fatalf("ContainerDefinitions: got %T len=%d, want []any len 1", dr.Inputs["ContainerDefinitions"], len(defs))
	}
	app, _ := defs[0].(map[string]any)
	env, ok := app["Environment"].([]any)
	if !ok || len(env) != 4 {
		t.Fatalf("Environment: got %T len=%d, want []any len 4", app["Environment"], len(env))
	}

	want := map[string]string{
		"DB_PASSWORD":   "[REDACTED by cbx]",
		"DB_SECRET_ARN": "arn:aws:secretsmanager:eu-central-1:123:secret:db",
		"API_TOKEN":     "arn:aws:ssm:eu-central-1:123:parameter/token",
		"LOG_LEVEL":     "debug",
	}
	for _, entry := range env {
		e, _ := entry.(map[string]any)
		name, _ := e["Name"].(string)
		expected, known := want[name]
		if !known {
			t.Errorf("unexpected env entry %q", name)
			continue
		}
		if got := e["Value"]; got != expected {
			t.Errorf("%s Value = %v, want %q", name, got, expected)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("env entry %q missing from synthesised ContainerDefinitions", name)
	}
}
