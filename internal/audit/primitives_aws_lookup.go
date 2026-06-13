package audit

// Exported lookups over the generated primitive maps. Kept in a
// non-generated file so `make codegen-primitives` regen doesn't clobber
// them. Callers outside this package (notably the group package via the
// PrimitiveLookup closure pattern) use these to avoid pulling the
// underlying maps into their import surface.

// CFNTypeToCBPrimitive returns the CB primitive id for a CloudFormation
// type name (e.g. "AWS::S3::Bucket" → "aws:s3/bucket@v1"), or "" when
// the type is not authored in CB's knowledge base.
func CFNTypeToCBPrimitive(cfnType string) string {
	return cfnTypeToCBPrimitive[cfnType]
}

// TFTypeToCBPrimitive returns the CB primitive id for a Terraform AWS
// resource type, or "". Engine-split DBs (aws_db_instance,
// aws_rds_cluster) return "" — use RDSPrimitiveFor with the engine.
func TFTypeToCBPrimitive(tfType string) string {
	return tfTypeToCBPrimitive[tfType]
}

// PulumiTypeToCBPrimitive returns the CB primitive id for a Pulumi
// type token (e.g. "aws:s3/bucket:Bucket"), or "".
func PulumiTypeToCBPrimitive(token string) string {
	return pulumiTypeToCBPrimitive[token]
}

// RDSPrimitiveFor exposes the engine-split lookup from the generated
// rdsPrimitiveFor for callers outside this package.
func RDSPrimitiveFor(engine string) string {
	return rdsPrimitiveFor(engine)
}
