package aws

import (
	"reflect"
	"testing"
)

func TestApplyStageAccessLogging(t *testing.T) {
	cases := []struct {
		name           string
		stages         []stageAccessLog
		wantCount      float64
		wantEnabledKey bool // whether cb_describer_access_logging_enabled is set
		wantEnabled    bool
		wantMissing    []any // nil = key should be absent
	}{
		{
			name:           "no stages -> count only, no enabled key (FP-safety)",
			stages:         nil,
			wantCount:      0,
			wantEnabledKey: false,
		},
		{
			name:           "single $default stage without a log destination -> disabled",
			stages:         []stageAccessLog{{name: "$default", hasLogDest: false}},
			wantCount:      1,
			wantEnabledKey: true,
			wantEnabled:    false,
			wantMissing:    []any{"$default"},
		},
		{
			name:           "stage with a log destination -> enabled, no missing list",
			stages:         []stageAccessLog{{name: "prod", hasLogDest: true}},
			wantCount:      1,
			wantEnabledKey: true,
			wantEnabled:    true,
			wantMissing:    nil,
		},
		{
			name: "mixed stages -> disabled, missing names sorted for prompt determinism",
			stages: []stageAccessLog{
				{name: "prod", hasLogDest: true},
				{name: "staging", hasLogDest: false},
				{name: "dev", hasLogDest: false},
			},
			wantCount:      3,
			wantEnabledKey: true,
			wantEnabled:    false,
			wantMissing:    []any{"dev", "staging"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := map[string]any{}
			applyStageAccessLogging(inputs, tc.stages)

			if got := inputs["cb_describer_stage_count"]; got != tc.wantCount {
				t.Errorf("stage_count = %v, want %v", got, tc.wantCount)
			}

			got, present := inputs["cb_describer_access_logging_enabled"]
			if present != tc.wantEnabledKey {
				t.Errorf("access_logging_enabled present = %v, want %v", present, tc.wantEnabledKey)
			}
			if tc.wantEnabledKey && got != tc.wantEnabled {
				t.Errorf("access_logging_enabled = %v, want %v", got, tc.wantEnabled)
			}

			gotMissing, missingPresent := inputs["cb_describer_stages_without_access_log"]
			if tc.wantMissing == nil {
				if missingPresent {
					t.Errorf("stages_without_access_log should be absent, got %v", gotMissing)
				}
			} else if !reflect.DeepEqual(gotMissing, tc.wantMissing) {
				t.Errorf("stages_without_access_log = %v, want %v", gotMissing, tc.wantMissing)
			}
		})
	}
}

func TestApiGatewayV2Describer_CFNType(t *testing.T) {
	if got := (apiGatewayV2ApiDescriber{}).CFNType(); got != "AWS::ApiGatewayV2::Api" {
		t.Errorf("CFNType = %q", got)
	}
	// The describer must be wired into the registry, else discovery never
	// runs it and the access-logging signal never reaches the prompt.
	if describerFor("AWS::ApiGatewayV2::Api") == nil {
		t.Error("apiGatewayV2ApiDescriber not registered in allDescribers")
	}
}
