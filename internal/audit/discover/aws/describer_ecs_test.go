package aws

import (
	"context"
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
