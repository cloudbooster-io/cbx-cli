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
