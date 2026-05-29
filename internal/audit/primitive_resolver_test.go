package audit

import (
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

// TestPrimitiveIDFor pins the load-bearing resolution order:
//  1. Per-resource describer override (used by RDS engine-split)
//  2. Terraform engine-split (aws_db_instance / aws_rds_cluster)
//  3. Static CFN → primitive map (live-AWS discovery)
//  4. Static Terraform → primitive map (source / state mode)
func TestPrimitiveIDFor(t *testing.T) {
	cases := []struct {
		name string
		r    DiscoveredResource
		want string
	}{
		{
			name: "describer override wins even when other lookups would match",
			r: DiscoveredResource{
				Type: "AWS::S3::Bucket",
				Inputs: map[string]any{
					parsers.CBDescriberPrimitiveResolved: "aws:db/postgres@v1",
				},
			},
			want: "aws:db/postgres@v1",
		},
		{
			name: "AWS::RDS::DBInstance with describer override resolves to engine-specific primitive",
			r: DiscoveredResource{
				Type: "AWS::RDS::DBInstance",
				Inputs: map[string]any{
					parsers.CBDescriberPrimitiveResolved: "aws:db/postgres@v1",
				},
			},
			want: "aws:db/postgres@v1",
		},
		{
			name: "AWS::RDS::DBInstance WITHOUT override falls through and returns empty (CFN map omits engine-split types)",
			r:    DiscoveredResource{Type: "AWS::RDS::DBInstance"},
			want: "",
		},
		{
			name: "Terraform aws_db_instance with engine input still works through step-2 path",
			r: DiscoveredResource{
				Type:   "aws_db_instance",
				Inputs: map[string]any{"engine": "mysql"},
			},
			want: "aws:db/mysql@v1",
		},
		{
			name: "AWS::S3::Bucket resolves via the CFN map",
			r:    DiscoveredResource{Type: "AWS::S3::Bucket"},
			want: "aws:s3/bucket@v1",
		},
		{
			name: "aws_s3_bucket resolves via the TF map",
			r:    DiscoveredResource{Type: "aws_s3_bucket"},
			want: "aws:s3/bucket@v1",
		},
		{
			name: "unknown type returns empty",
			r:    DiscoveredResource{Type: "AWS::Quantum::Reactor"},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := primitiveIDFor(tc.r); got != tc.want {
				t.Errorf("primitiveIDFor = %q, want %q", got, tc.want)
			}
		})
	}
}
