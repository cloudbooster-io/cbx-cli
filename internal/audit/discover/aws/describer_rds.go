package aws

import (
	"context"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

// CloudControl exposes nearly everything we need for AWS::RDS::DBInstance
// and AWS::RDS::DBCluster — Engine, EngineVersion, MultiAZ,
// StorageEncrypted, PubliclyAccessible, BackupRetentionPeriod,
// DeletionProtection are all in CFN's writeable+read properties. We
// therefore don't make an SDK call here; the describer reads CC's
// Properties (already on r.Inputs) and re-publishes the load-bearing
// fields under stable cb_describer_* keys plus, critically, the engine-
// split CB primitive id via audit.RDSPrimitiveFor.
//
// Engine-split matters because aws_lookup_primitive in cbx-mcp keys off
// the CB primitive id (rds_postgres / rds_mysql / aurora_postgres /
// aurora_mysql / rds_mariadb) — not the CFN type. Without that id the
// grouped report names the wrong primitive for AWS DB resources.
//
// The grouping pass (group/primitive.go) reads the resolved id today and
// prefers it over the static CFN→primitive map. The grounded prompt
// builder (llm_analyzer.buildGroundedPrompt) gets it through the same
// path once PR 8 wires --cb-knowledge into the AWS subcommand; until
// then the AWS path runs MockScanners only (audit_aws.go) and never
// reaches the grounded analyzer at all.

type rdsInstanceDescriber struct{}

func (rdsInstanceDescriber) CFNType() string { return "AWS::RDS::DBInstance" }

func (rdsInstanceDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	engine := readStr(r.Inputs, "Engine")
	if pid := audit.RDSPrimitiveFor(engine); pid != "" {
		r.Inputs[parsers.CBDescriberPrimitiveResolved] = pid
	}
	normalizeRDSCommonFields(r)
	return nil
}

type rdsClusterDescriber struct{}

func (rdsClusterDescriber) CFNType() string { return "AWS::RDS::DBCluster" }

func (rdsClusterDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	engine := readStr(r.Inputs, "Engine")
	if pid := audit.RDSPrimitiveFor(engine); pid != "" {
		r.Inputs[parsers.CBDescriberPrimitiveResolved] = pid
	}
	normalizeRDSCommonFields(r)
	return nil
}

// normalizeRDSCommonFields lifts the security-posture booleans the
// audit cares about out of CC's Properties into top-level keys. The CFN
// shape uses TitleCase ("MultiAZ", "StorageEncrypted", …); we keep the
// describer keys snake_case-ish under the cb_describer_ namespace for
// consistency with the S3 / IAM describers shipped earlier.
//
// Fields not present in CC's Properties are left absent — there's a
// real difference between "value is false" and "we didn't read this
// field", and rule code that reacts to e.g. unencrypted storage should
// not false-positive on a CC response that simply omitted the key.
func normalizeRDSCommonFields(r *DiscoveredResource) {
	copyBool(r.Inputs, "MultiAZ", "cb_describer_multi_az")
	copyBool(r.Inputs, "StorageEncrypted", "cb_describer_storage_encrypted")
	copyBool(r.Inputs, "PubliclyAccessible", "cb_describer_publicly_accessible")
	copyBool(r.Inputs, "DeletionProtection", "cb_describer_deletion_protection")
	copyNumeric(r.Inputs, "BackupRetentionPeriod", "cb_describer_backup_retention_days")
	copyStr(r.Inputs, "Engine", "cb_describer_engine")
	copyStr(r.Inputs, "EngineVersion", "cb_describer_engine_version")
}
