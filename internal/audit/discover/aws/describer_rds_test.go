package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/smithy-go"
)

// fakeRDSReplicaClient is the test double for the role probe's narrow API
// seam. out/err drive DescribeDBInstances; gotID records the id filter the
// describer passed so a test can assert the probe is scoped to the resource.
type fakeRDSReplicaClient struct {
	out   *rds.DescribeDBInstancesOutput
	err   error
	gotID string
	calls int
}

func (f *fakeRDSReplicaClient) DescribeDBInstances(_ context.Context, in *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	f.calls++
	if in.DBInstanceIdentifier != nil {
		f.gotID = *in.DBInstanceIdentifier
	}
	return f.out, f.err
}

// installFakeRDSClient swaps the package-level client seam for a fake so the
// instance describer's Enrich never makes a live AWS call, restoring the real
// constructor when the test ends.
func installFakeRDSClient(t *testing.T, fake rdsReplicaAPI) {
	t.Helper()
	prev := newRDSReplicaClient
	newRDSReplicaClient = func(awsCfg) rdsReplicaAPI { return fake }
	t.Cleanup(func() { newRDSReplicaClient = prev })
}

// strPtr is a tiny helper for the SDK's *string fields.
func strPtr(s string) *string { return &s }

func TestRDSInstanceDescriber_ResolvesPostgresPrimitive(t *testing.T) {
	// Empty DescribeDBInstances output → role probe is a no-op (ok=false), so
	// this test stays focused on primitive resolution + normalization without
	// a live call.
	installFakeRDSClient(t, &fakeRDSReplicaClient{out: &rds.DescribeDBInstancesOutput{}})

	r := DiscoveredResource{
		Type: "AWS::RDS::DBInstance",
		ID:   "db-prod",
		Inputs: map[string]any{
			"Engine":                "postgres",
			"EngineVersion":         "15.4",
			"MultiAZ":               true,
			"StorageEncrypted":      true,
			"PubliclyAccessible":    false,
			"DeletionProtection":    true,
			"BackupRetentionPeriod": float64(14),
		},
	}
	if err := (rdsInstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if got := r.Inputs["cb_describer_primitive_resolved"]; got != "aws:db/postgres@v1" {
		t.Errorf("cb_describer_primitive_resolved = %v, want aws:db/postgres@v1", got)
	}
	for _, k := range []string{
		"cb_describer_multi_az",
		"cb_describer_storage_encrypted",
		"cb_describer_publicly_accessible",
		"cb_describer_deletion_protection",
		"cb_describer_backup_retention_days",
		"cb_describer_engine",
		"cb_describer_engine_version",
	} {
		if _, ok := r.Inputs[k]; !ok {
			t.Errorf("missing normalized field %q", k)
		}
	}
}

func TestRDSInstanceDescriber_SkipsResolveOnUnknownEngine(t *testing.T) {
	installFakeRDSClient(t, &fakeRDSReplicaClient{out: &rds.DescribeDBInstancesOutput{}})

	r := DiscoveredResource{
		Type: "AWS::RDS::DBInstance",
		ID:   "db-mystery",
		Inputs: map[string]any{
			"Engine": "oracle-ee", // not in rdsEngineMap
		},
	}
	if err := (rdsInstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if _, ok := r.Inputs["cb_describer_primitive_resolved"]; ok {
		t.Error("unknown engines must NOT publish a resolved primitive id — would mislead the grounded analyzer")
	}
}

func TestRDSClusterDescriber_ResolvesAuroraMySQL(t *testing.T) {
	r := DiscoveredResource{
		Type: "AWS::RDS::DBCluster",
		ID:   "cluster-prod",
		Inputs: map[string]any{
			"Engine":             "aurora-mysql",
			"StorageEncrypted":   true,
			"DeletionProtection": true,
		},
	}
	if err := (rdsClusterDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := r.Inputs["cb_describer_primitive_resolved"]; got != "aws:db/aurora-mysql@v1" {
		t.Errorf("cb_describer_primitive_resolved = %v, want aws:db/aurora-mysql@v1", got)
	}
}

func TestRDSDescriber_PreservesAbsenceVsExplicitFalse(t *testing.T) {
	installFakeRDSClient(t, &fakeRDSReplicaClient{out: &rds.DescribeDBInstancesOutput{}})

	// MultiAZ is absent — normalized field must also be absent so rule
	// code can distinguish "value is false" from "we didn't read this."
	r := DiscoveredResource{
		Type: "AWS::RDS::DBInstance",
		ID:   "db-sparse",
		Inputs: map[string]any{
			"Engine":           "mysql",
			"StorageEncrypted": false, // explicit false should be copied
		},
	}
	if err := (rdsInstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if _, ok := r.Inputs["cb_describer_multi_az"]; ok {
		t.Error("cb_describer_multi_az was copied despite the source being absent")
	}
	if got, ok := r.Inputs["cb_describer_storage_encrypted"]; !ok || got != false {
		t.Errorf("cb_describer_storage_encrypted = (%v, %v), want (false, true)", got, ok)
	}
}

// --- backup-retention carve-out enrichment (replica / cluster-member) ---

// dbInstanceOut wraps a single DBInstance in the SDK output shape the probe
// reads (DescribeDBInstances is id-filtered, so it returns at most one).
func dbInstanceOut(inst rdstypes.DBInstance) *rds.DescribeDBInstancesOutput {
	return &rds.DescribeDBInstancesOutput{DBInstances: []rdstypes.DBInstance{inst}}
}

func TestEnrichRDSInstanceRole_ReadReplica_NotFlaggable(t *testing.T) {
	// A read replica carries ReadReplicaSourceDBInstanceIdentifier. retention=0
	// is BY DESIGN here — the rule must see is_read_replica=true and suppress.
	fake := &fakeRDSReplicaClient{out: dbInstanceOut(rdstypes.DBInstance{
		DBInstanceIdentifier:                  strPtr("db-replica"),
		ReadReplicaSourceDBInstanceIdentifier: strPtr("db-primary"),
	})}
	r := &DiscoveredResource{ID: "db-replica", Inputs: map[string]any{
		"cb_describer_backup_retention_days": float64(0),
	}}
	if err := enrichRDSInstanceRole(context.Background(), fake, "us-east-1", r); err != nil {
		t.Fatalf("enrichRDSInstanceRole: %v", err)
	}
	if got := r.Inputs["cb_describer_is_read_replica"]; got != true {
		t.Errorf("cb_describer_is_read_replica = %v, want true", got)
	}
	if got := r.Inputs["cb_describer_is_cluster_member"]; got != false {
		t.Errorf("cb_describer_is_cluster_member = %v, want false", got)
	}
	if fake.gotID != "db-replica" {
		t.Errorf("probe id filter = %q, want db-replica", fake.gotID)
	}
}

func TestEnrichRDSInstanceRole_ClusterMember_NotFlaggable(t *testing.T) {
	// A cluster member (Aurora OR non-Aurora Multi-AZ DB cluster) carries
	// DBClusterIdentifier and is NOT a classic read replica. Its instance-level
	// retention is not authoritative, so the rule must suppress via
	// is_cluster_member=true — this is the hole the engine-string gate missed.
	fake := &fakeRDSReplicaClient{out: dbInstanceOut(rdstypes.DBInstance{
		DBInstanceIdentifier: strPtr("db-member-1"),
		Engine:               strPtr("mysql"), // non-Aurora cluster deployment
		DBClusterIdentifier:  strPtr("my-mysql-cluster"),
	})}
	r := &DiscoveredResource{ID: "db-member-1", Inputs: map[string]any{
		"cb_describer_backup_retention_days": float64(1),
	}}
	if err := enrichRDSInstanceRole(context.Background(), fake, "us-east-1", r); err != nil {
		t.Fatalf("enrichRDSInstanceRole: %v", err)
	}
	if got := r.Inputs["cb_describer_is_cluster_member"]; got != true {
		t.Errorf("cb_describer_is_cluster_member = %v, want true", got)
	}
	if got := r.Inputs["cb_describer_is_read_replica"]; got != false {
		t.Errorf("cb_describer_is_read_replica = %v, want false", got)
	}
}

func TestEnrichRDSInstanceRole_StandalonePrimary_Flaggable(t *testing.T) {
	// Standalone non-Aurora primary: not a replica, not a cluster member. With
	// retention<=1 this is the one case the rule SHOULD flag — assert both
	// carve-out booleans resolve to false (the prompt gate `== false`).
	fake := &fakeRDSReplicaClient{out: dbInstanceOut(rdstypes.DBInstance{
		DBInstanceIdentifier: strPtr("db-standalone"),
		Engine:               strPtr("postgres"),
	})}
	r := &DiscoveredResource{ID: "db-standalone", Inputs: map[string]any{
		"cb_describer_backup_retention_days": float64(1),
	}}
	if err := enrichRDSInstanceRole(context.Background(), fake, "us-east-1", r); err != nil {
		t.Fatalf("enrichRDSInstanceRole: %v", err)
	}
	if got := r.Inputs["cb_describer_is_read_replica"]; got != false {
		t.Errorf("cb_describer_is_read_replica = %v, want false", got)
	}
	if got := r.Inputs["cb_describer_is_cluster_member"]; got != false {
		t.Errorf("cb_describer_is_cluster_member = %v, want false", got)
	}
	// retention field is untouched by the probe — the rule reads it directly.
	if got := r.Inputs["cb_describer_backup_retention_days"]; got != float64(1) {
		t.Errorf("cb_describer_backup_retention_days = %v, want 1", got)
	}
}

// fakeAPIError is a smithy.APIError so classifyAWSError maps AccessDenied to a
// *PermissionError, exactly as the live SDK would.
type fakeAPIError struct{ code string }

func (e *fakeAPIError) Error() string                 { return e.code }
func (e *fakeAPIError) ErrorCode() string             { return e.code }
func (e *fakeAPIError) ErrorMessage() string          { return e.code }
func (e *fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestEnrichRDSInstanceRole_ProbeError_LeavesFieldsAbsent(t *testing.T) {
	// A denied probe must NEVER abort: it returns the classified error (so
	// --diagnose surfaces the missing grant) but leaves BOTH booleans ABSENT
	// (UNKNOWN, never false) so the rule cannot false-fire on a replica/cluster
	// member we could not verify. The CC-derived fields stay intact.
	fake := &fakeRDSReplicaClient{err: &fakeAPIError{code: "AccessDenied"}}
	r := &DiscoveredResource{ID: "db-x", Inputs: map[string]any{
		"cb_describer_backup_retention_days": float64(0),
	}}
	err := enrichRDSInstanceRole(context.Background(), fake, "us-east-1", r)
	if err == nil {
		t.Fatal("expected the probe error to surface, got nil")
	}
	var pe *PermissionError
	if !errors.As(err, &pe) {
		t.Errorf("error = %T, want *PermissionError (so --diagnose collects it)", err)
	}
	if _, ok := r.Inputs["cb_describer_is_read_replica"]; ok {
		t.Error("is_read_replica must be ABSENT on probe error, not false")
	}
	if _, ok := r.Inputs["cb_describer_is_cluster_member"]; ok {
		t.Error("is_cluster_member must be ABSENT on probe error, not false")
	}
	if got := r.Inputs["cb_describer_backup_retention_days"]; got != float64(0) {
		t.Errorf("CC field clobbered: backup_retention_days = %v, want 0", got)
	}
}

func TestEnrichRDSInstanceRole_NotFound_LeavesFieldsAbsent(t *testing.T) {
	// Instance vanished between discovery and enrich → empty result, no error.
	// Treat as UNKNOWN: leave both fields absent rather than asserting false.
	fake := &fakeRDSReplicaClient{out: &rds.DescribeDBInstancesOutput{}}
	r := &DiscoveredResource{ID: "db-gone", Inputs: map[string]any{}}
	if err := enrichRDSInstanceRole(context.Background(), fake, "us-east-1", r); err != nil {
		t.Fatalf("enrichRDSInstanceRole: %v", err)
	}
	if _, ok := r.Inputs["cb_describer_is_read_replica"]; ok {
		t.Error("is_read_replica must be ABSENT when the instance isn't found")
	}
	if _, ok := r.Inputs["cb_describer_is_cluster_member"]; ok {
		t.Error("is_cluster_member must be ABSENT when the instance isn't found")
	}
}

func TestLookupRDSInstanceRole_EmptyID(t *testing.T) {
	// No id to probe → ok=false, no error, no API call.
	fake := &fakeRDSReplicaClient{out: dbInstanceOut(rdstypes.DBInstance{})}
	_, _, ok, err := lookupRDSInstanceRole(context.Background(), fake, "", "us-east-1")
	if err != nil {
		t.Fatalf("lookupRDSInstanceRole: %v", err)
	}
	if ok {
		t.Error("ok must be false for an empty id")
	}
	if fake.calls != 0 {
		t.Errorf("expected no API call for empty id, got %d", fake.calls)
	}
}
