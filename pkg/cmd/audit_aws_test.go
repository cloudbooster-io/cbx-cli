package cmd

import "testing"

// TestParseConsoleURL covers the URL-as-positional shape detection
// `cbx audit aws <url>` introduced in B4. The non-URL fallback (plain
// profile name) is exercised by the wider audit aws integration; the
// unit tests here pin the URL recognition + region extraction.
func TestParseConsoleURL(t *testing.T) {
	cases := []struct {
		name       string
		arg        string
		wantRegion string
		wantOK     bool
	}{
		{
			name:       "regional console",
			arg:        "https://us-east-1.console.aws.amazon.com/console/home",
			wantRegion: "us-east-1",
			wantOK:     true,
		},
		{
			name:       "regional console with query",
			arg:        "https://eu-west-3.console.aws.amazon.com/ec2/v2/home?region=eu-west-3#Instances:",
			wantRegion: "eu-west-3",
			wantOK:     true,
		},
		{
			name:       "global console (no region in host)",
			arg:        "https://console.aws.amazon.com/billing/home",
			wantRegion: "",
			wantOK:     true,
		},
		{
			name:       "not a URL — plain profile name",
			arg:        "prod",
			wantRegion: "",
			wantOK:     false,
		},
		{
			name:       "not the AWS console",
			arg:        "https://example.com/foo",
			wantRegion: "",
			wantOK:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			region, _, ok := parseConsoleURL(tc.arg)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if region != tc.wantRegion {
				t.Fatalf("region = %q, want %q", region, tc.wantRegion)
			}
		})
	}
}

// TestMergeRegions pins the merge precedence and dedup behavior between
// the new repeatable --region and the back-compat --regions CSV alias.
func TestMergeRegions(t *testing.T) {
	cases := []struct {
		name string
		rep  []string
		csv  string
		want []string
	}{
		{name: "empty", rep: nil, csv: "", want: nil},
		{name: "repeatable only", rep: []string{"us-east-1", "us-west-2"}, csv: "", want: []string{"us-east-1", "us-west-2"}},
		{name: "csv only", rep: nil, csv: "us-east-1,us-west-2", want: []string{"us-east-1", "us-west-2"}},
		{name: "dedup across both", rep: []string{"us-east-1"}, csv: "us-east-1,us-west-2", want: []string{"us-east-1", "us-west-2"}},
		{name: "csv inside --region", rep: []string{"us-east-1,eu-west-1"}, csv: "", want: []string{"us-east-1", "eu-west-1"}},
		{name: "trims whitespace", rep: []string{" us-east-1 "}, csv: " us-west-2 ", want: []string{"us-east-1", "us-west-2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeRegions(tc.rep, tc.csv)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d (%v), want %d (%v)", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
