package aws

import "testing"

// TestEstimateEventCount_DominantTerms locks in the cost formula so
// the "this run generated ~N CloudTrail Read events" header doesn't
// drift silently when a new describer lands. Numbers are derived from
// the structural model in estimateEventCount — change them in the same
// commit as the formula.
func TestEstimateEventCount_DominantTerms(t *testing.T) {
	cases := []struct {
		name      string
		types     []cfnTypeSpec
		regions   []string
		resources []DiscoveredResource
		want      int
	}{
		{
			name:      "empty scan: just the STS preflight call",
			types:     nil,
			regions:   nil,
			resources: nil,
			want:      1,
		},
		{
			name:      "one regional type, one region, no resources, no describers",
			types:     []cfnTypeSpec{{Type: "AWS::EC2::Instance"}},
			regions:   []string{"us-east-1"},
			resources: nil,
			want:      1 /* sts */ + 1, /* 1 list × 1 region */
		},
		{
			name:    "two regions × two types + two resources, no describers",
			types:   []cfnTypeSpec{{Type: "AWS::EC2::Instance"}, {Type: "AWS::DynamoDB::Table"}},
			regions: []string{"us-east-1", "eu-west-1"},
			resources: []DiscoveredResource{
				{Type: "AWS::EC2::Instance"},
				{Type: "AWS::DynamoDB::Table"},
			},
			want: 1 + 2*2 + 2,
		},
		{
			name:    "global type counted once across two regions",
			types:   []cfnTypeSpec{{Type: "AWS::IAM::Role", Global: true}},
			regions: []string{"us-east-1", "eu-west-1"},
			resources: []DiscoveredResource{
				{Type: "AWS::IAM::Role"}, // IAM describer adds 3 calls (GetRole + ListAttached + ListInline)
			},
			want: 1 /* sts */ + 1 /* one list (global) */ + 1 /* one get */ + 3, /* iam describer */
		},
		{
			name:    "one S3 bucket triggers describer (5) + shared list-buckets (1)",
			types:   []cfnTypeSpec{{Type: "AWS::S3::Bucket"}},
			regions: []string{"us-east-1"},
			resources: []DiscoveredResource{
				{Type: "AWS::S3::Bucket"},
			},
			want: 1 + 1 + 1 + 5 + 1,
		},
		{
			name:    "two S3 buckets: shared list-buckets still counted once",
			types:   []cfnTypeSpec{{Type: "AWS::S3::Bucket"}},
			regions: []string{"us-east-1"},
			resources: []DiscoveredResource{
				{Type: "AWS::S3::Bucket"},
				{Type: "AWS::S3::Bucket"},
			},
			want: 1 + 1 + 2 + 5*2 + 1,
		},
		{
			name:    "describer-free resource types contribute nothing extra",
			types:   []cfnTypeSpec{{Type: "AWS::Lambda::Function"}},
			regions: []string{"us-east-1"},
			resources: []DiscoveredResource{
				{Type: "AWS::Lambda::Function"},
			},
			want: 1 + 1 + 1, // sts + list + get; Lambda describer is normalization-only
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := estimateEventCount(tc.types, tc.regions, tc.resources)
			if got != tc.want {
				t.Errorf("estimateEventCount = %d, want %d", got, tc.want)
			}
		})
	}
}
