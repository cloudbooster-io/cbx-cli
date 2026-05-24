package aws

import "testing"

func TestBucketPolicyHasWildcardPrincipal(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want bool
	}{
		{
			name: "wildcard principal string, no condition → public",
			doc:  `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`,
			want: true,
		},
		{
			name: "AWS:* object, no condition → public",
			doc:  `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}`,
			want: true,
		},
		{
			name: "AWS:[*] list, no condition → public",
			doc:  `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]}}]}`,
			want: true,
		},
		{
			name: "wildcard principal with aws:PrincipalOrgID → scoped (not public)",
			doc: `{"Statement":[{"Effect":"Allow","Principal":"*",
                "Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc"}}}]}`,
			want: false,
		},
		{
			name: "wildcard principal with aws:SourceIp → scoped",
			doc: `{"Statement":[{"Effect":"Allow","Principal":"*",
                "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
			want: false,
		},
		{
			name: "no wildcard principal → not public",
			doc:  `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"}}]}`,
			want: false,
		},
		{
			name: "Deny statement with * → not public (deny is fine)",
			doc:  `{"Statement":[{"Effect":"Deny","Principal":"*"}]}`,
			want: false,
		},
		{
			name: "malformed JSON → false (defensive)",
			doc:  `not json`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bucketPolicyHasWildcardPrincipal(tc.doc); got != tc.want {
				t.Errorf("bucketPolicyHasWildcardPrincipal = %v, want %v", got, tc.want)
			}
		})
	}
}
