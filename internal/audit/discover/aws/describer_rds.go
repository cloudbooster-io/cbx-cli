package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/rds"

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

func (rdsInstanceDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	engine := readStr(r.Inputs, "Engine")
	if pid := audit.RDSPrimitiveFor(engine); pid != "" {
		r.Inputs[parsers.CBDescriberPrimitiveResolved] = pid
	}
	normalizeRDSCommonFields(r)

	// Replica / cluster-membership are the carve-out signals for the
	// insufficient-backup-retention rule (llm_analyzer buildGroundedPrompt):
	// a HIGH retention finding must fire ONLY on a standalone primary, never
	// on a read replica (BackupRetentionPeriod=0 BY DESIGN — backups are taken
	// on the source) and never on an Aurora / Multi-AZ DB cluster member
	// (retention is governed at the cluster, so the instance-level value is
	// not authoritative). CloudControl exposes neither signal:
	// SourceDBInstanceIdentifier is writeOnly, and ReadReplicaSourceDBInstanceIdentifier
	// is an SDK-only field with no CFN property at all. So we learn both from a
	// best-effort rds:DescribeDBInstances probe.
	if r.Region != "" {
		c = c.withRegion(r.Region)
	}
	return enrichRDSInstanceRole(ctx, newRDSReplicaClient(c), c.region(), r)
}

// newRDSReplicaClient builds the RDS client the instance describer probes
// with. It is a package-level var (not an inline rds.NewFromConfig) purely so
// unit tests can inject a fake — Enrich takes awsCfg, not an interface, so the
// seam has to live here rather than in the signature. Mirrors how the native
// listers are tested via their *FallbackAPI interfaces.
var newRDSReplicaClient = func(c awsCfg) rdsReplicaAPI { return rds.NewFromConfig(c.cfg) }

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

// rdsReplicaAPI is the narrow slice of the RDS client the role probe needs —
// just DescribeDBInstances. The concrete *rds.Client satisfies it; the seam
// lets the partial-failure / unknown-state handling be unit-tested without a
// live call (mirrors s3FallbackAPI / lambdaFallbackAPI).
type rdsReplicaAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// enrichRDSInstanceRole runs the best-effort role probe and publishes the two
// carve-out booleans. The contract mirrors the Lambda GetFunctionConcurrency /
// S3 GetBucketLocation probes — it must NEVER abort: a probe error returns the
// classified error (so --diagnose surfaces a missing rds:DescribeDBInstances
// grant) while the resource itself is kept by the discovery loop with every CC
// field intact (discover.go appends the resource regardless of Enrich's error).
//
// Polarity is deliberately the OPPOSITE of the Lambda reserved-concurrency
// probe: an unresolved role (probe error OR the instance not found) leaves
// BOTH booleans ABSENT, never false. The retention rule keys off `== false`,
// so absence reads as UNKNOWN and the rule does NOT fire — we refuse to risk a
// HIGH false-positive on a replica/cluster member we could not verify.
func enrichRDSInstanceRole(ctx context.Context, client rdsReplicaAPI, region string, r *DiscoveredResource) error {
	isReplica, isClusterMember, ok, err := lookupRDSInstanceRole(ctx, client, r.ID, region)
	if err != nil {
		return err
	}
	if !ok {
		return nil // could not determine — leave both fields absent (UNKNOWN)
	}
	r.Inputs["cb_describer_is_read_replica"] = isReplica
	r.Inputs["cb_describer_is_cluster_member"] = isClusterMember
	return nil
}

// lookupRDSInstanceRole resolves whether a DB instance is a read replica and
// whether it is a cluster member, via a single id-filtered DescribeDBInstances.
//
//   - is_read_replica  ← ReadReplicaSourceDBInstanceIdentifier is non-empty
//     (a classic read replica points at its source). CloudControl never carries
//     this — it is the field the whole probe exists to recover.
//   - is_cluster_member ← DBClusterIdentifier is non-empty. This is the faithful
//     encoding of "standalone": an Aurora instance can ONLY exist inside a
//     cluster, and non-Aurora Multi-AZ DB cluster members also carry it, so a
//     blank DBClusterIdentifier is the one reliable "true standalone primary"
//     signal. Gating on this instead of the engine string closes the Multi-AZ
//     DB cluster hole (engine `mysql`/`postgres` would otherwise slip past an
//     `aurora-`-prefix gate while inheriting cluster-level retention).
//
// ok=false means "could not determine" (empty id, or the instance vanished
// between discovery and enrich): the caller leaves both fields absent rather
// than asserting a value it never read. A real API error is classified and
// returned so it surfaces to --diagnose without dropping the resource.
func lookupRDSInstanceRole(ctx context.Context, client rdsReplicaAPI, id, region string) (isReplica, isClusterMember, ok bool, err error) {
	if id == "" {
		return false, false, false, nil
	}
	out, derr := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{DBInstanceIdentifier: &id})
	if derr != nil {
		return false, false, false, classifyAWSError(derr, "rds", "rds:DescribeDBInstances", region)
	}
	if out == nil || len(out.DBInstances) == 0 {
		return false, false, false, nil
	}
	inst := out.DBInstances[0]
	isReplica = inst.ReadReplicaSourceDBInstanceIdentifier != nil && *inst.ReadReplicaSourceDBInstanceIdentifier != ""
	isClusterMember = inst.DBClusterIdentifier != nil && *inst.DBClusterIdentifier != ""
	return isReplica, isClusterMember, true, nil
}
