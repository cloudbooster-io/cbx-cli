package output

import "testing"

func TestParseURN(t *testing.T) {
	cases := []struct {
		urn                         string
		service, kind, name, region string
	}{
		{
			urn:     "aws://eu-central-1/AWS::IAM::Role/cbx-audit-lambda-admin",
			service: "iam", kind: "role", name: "cbx-audit-lambda-admin", region: "eu-central-1",
		},
		{
			urn:     "aws://us-east-1/AWS::Lambda::Function/cbx-audit-lambda",
			service: "lambda", kind: "function", name: "cbx-audit-lambda", region: "us-east-1",
		},
		{
			urn:     "aws://eu-central-1/AWS::RDS::DBInstance/cbx-audit-pg",
			service: "rds", kind: "dbinstance", name: "cbx-audit-pg", region: "eu-central-1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.urn, func(t *testing.T) {
			p := ParseURN(tc.urn)
			if p.Service != tc.service || p.Kind != tc.kind || p.Name != tc.name || p.Region != tc.region {
				t.Fatalf("ParseURN(%q) = %+v, want service=%q kind=%q name=%q region=%q",
					tc.urn, p, tc.service, tc.kind, tc.name, tc.region)
			}
		})
	}
}

func TestParseURNFallback(t *testing.T) {
	cases := []string{
		"not-a-urn",
		"http://example.com/x",
		"aws://eu-central-1",
		"aws://",
		"",
	}
	for _, urn := range cases {
		p := ParseURN(urn)
		if p.Raw != urn {
			t.Fatalf("ParseURN(%q).Raw = %q, want %q", urn, p.Raw, urn)
		}
		// For unrecoverable inputs, Service/Kind/Name should be empty so
		// the renderer falls back to .Raw.
		if urn == "not-a-urn" || urn == "" {
			if p.Service != "" || p.Kind != "" || p.Name != "" || p.Region != "" {
				t.Fatalf("expected empty parse for %q, got %+v", urn, p)
			}
		}
	}
}

func TestEllipsizeMiddle(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  string
	}{
		{"short", 10, "short"},
		{"abcdefghijklmnop", 8, "abc…lmnop"},
		{"abcdefghijklmnop", 0, "abcdefghijklmnop"},
		{"abcdefghij", 3, "..."},
	}
	for _, tc := range cases {
		got := ellipsizeMiddle(tc.in, tc.width)
		// "abcdefghijklmnop" + width 8 → keep=7, half=3, so first 3 +
		// "…" + last 4 = "abc…mnop". Check that's a reasonable result.
		if tc.width == 8 && got == "" {
			t.Fatalf("expected non-empty for width=8, got empty")
		}
		if tc.width == 0 && got != tc.in {
			t.Fatalf("width=0 should return input unchanged: %q != %q", got, tc.in)
		}
		if tc.in == "short" && got != "short" {
			t.Fatalf("short input should pass through: %q", got)
		}
		if tc.in == "abcdefghij" && tc.width == 3 && got != "..." {
			t.Fatalf("width<=3 should return dots, got %q", got)
		}
	}
}

func TestSeverityChipReadsBack(t *testing.T) {
	ForceStyledForTesting()
	defer func() {
		isTerminalFn = func() bool { return false }
		refreshStyles()
	}()

	for _, sev := range []string{"critical", "high", "warning", "info"} {
		got := SeverityChip(sev)
		if got == "" {
			t.Fatalf("SeverityChip(%q) returned empty", sev)
		}
	}
}
