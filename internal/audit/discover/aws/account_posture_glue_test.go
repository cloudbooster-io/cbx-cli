package aws

import "testing"

// TestPolicyGrantsPublicPrincipal covers the Glue Data Catalog
// resource-policy reuse of the S3 wildcard-principal analysis. The
// catalog policy is a plain IAM resource policy, so the same
// Allow + Principal:"*" + no-scoping-condition rule applies. We assert
// the Glue-shaped documents (Resource: arn:aws:glue:…:catalog) resolve
// the same way bucket policies do.
func TestPolicyGrantsPublicPrincipal(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want bool
	}{
		{
			name: "wildcard principal on the catalog, no condition → public",
			doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                "Principal":{"AWS":"*"},"Action":"glue:GetTable",
                "Resource":"arn:aws:glue:us-east-1:111122223333:catalog"}]}`,
			want: true,
		},
		{
			name: "wildcard principal scoped by aws:PrincipalOrgID → not public",
			doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                "Principal":{"AWS":"*"},"Action":"glue:GetTable",
                "Resource":"arn:aws:glue:us-east-1:111122223333:*",
                "Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}`,
			want: false,
		},
		{
			name: "specific cross-account principal → not public",
			doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                "Principal":{"AWS":"arn:aws:iam::444455556666:root"},
                "Action":"glue:GetTable","Resource":"arn:aws:glue:us-east-1:111122223333:catalog"}]}`,
			want: false,
		},
		{
			name: "no policy document → false (defensive)",
			doc:  ``,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyGrantsPublicPrincipal(tc.doc); got != tc.want {
				t.Errorf("policyGrantsPublicPrincipal = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAthenaWorkGroupIsDiscoverable guards the wiring that lets the
// grounded analyzer see Athena workgroup configuration: the type must
// be in discoverableCFNTypes so CloudControl lists + reads it (the
// WorkGroupConfiguration block rides in through the read handler). A
// rebase that drops the line would silently kill the Athena rule.
func TestAthenaWorkGroupIsDiscoverable(t *testing.T) {
	var found bool
	for _, spec := range discoverableCFNTypes {
		if spec.Type == "AWS::Athena::WorkGroup" {
			found = true
			if spec.Global {
				t.Errorf("AWS::Athena::WorkGroup must be regional, got Global=true")
			}
		}
	}
	if !found {
		t.Errorf("AWS::Athena::WorkGroup missing from discoverableCFNTypes")
	}
}
