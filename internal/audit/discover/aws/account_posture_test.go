package aws

import "testing"

// TestClassifyDetectorStatus pins the GuardDuty status → posture
// vocabulary mapping. The load-bearing case is that any non-ENABLED
// status (including a suspended detector) classifies as "disabled" — the
// regression the audit must catch — never silently as "enabled".
func TestClassifyDetectorStatus(t *testing.T) {
	cases := map[string]string{
		"ENABLED":   guardDutyEnabled,
		"enabled":   guardDutyEnabled, // EqualFold — SDK enum is upper, be defensive
		"DISABLED":  guardDutyDisabled,
		"":          guardDutyDisabled,
		"SUSPENDED": guardDutyDisabled,
	}
	for in, want := range cases {
		if got := classifyDetectorStatus(in); got != want {
			t.Errorf("classifyDetectorStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRecorderRecordsGlobalTypes covers the two real-world shapes that
// count as "records global (IAM) resource types" plus the FP-relevant
// negatives — notably AllSupported with IncludeGlobalResourceTypes=false,
// which is exactly the 06-observability gap (global resources excluded).
func TestRecorderRecordsGlobalTypes(t *testing.T) {
	cases := []struct {
		name          string
		allSupported  bool
		includeGlobal bool
		resourceTypes []string
		want          bool
	}{
		{"classic all+global", true, true, nil, true},
		{"classic all, global excluded", true, false, nil, false}, // the gap
		{"inclusion lists IAM role", false, false, []string{"AWS::IAM::Role"}, true},
		{"inclusion lists IAM user among others", false, false, []string{"AWS::EC2::Instance", "AWS::IAM::User"}, true},
		{"inclusion, no global type", false, false, []string{"AWS::EC2::Instance"}, false},
		{"global flag without all-supported is meaningless", false, true, nil, false},
		{"empty recorder", false, false, nil, false},
	}
	for _, c := range cases {
		if got := recorderRecordsGlobalTypes(c.allSupported, c.includeGlobal, c.resourceTypes); got != c.want {
			t.Errorf("%s: recorderRecordsGlobalTypes(%t,%t,%v) = %t, want %t",
				c.name, c.allSupported, c.includeGlobal, c.resourceTypes, got, c.want)
		}
	}
}
