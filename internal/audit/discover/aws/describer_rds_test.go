package aws

import (
	"context"
	"testing"
)

func TestRDSInstanceDescriber_ResolvesPostgresPrimitive(t *testing.T) {
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
