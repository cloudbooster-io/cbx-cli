package aws

import (
	"context"
	"reflect"
	"testing"

	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// --- ECR repository round-trip -------------------------------------------

// ScanOnPush must land under the nested ImageScanningConfiguration shape
// CloudControl's GetResource uses, and RepositoryName must be the identifier
// (so ecrRepositoryDescriber resolves the lifecycle policy off it).
func TestECRRepositoryToRaw_RoundTrip(t *testing.T) {
	repo := ecrtypes.Repository{
		RepositoryName:             strp("cbx-app"),
		RepositoryArn:              strp("arn:aws:ecr:eu-central-1:111122223333:repository/cbx-app"),
		ImageTagMutability:         ecrtypes.ImageTagMutabilityMutable,
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: false},
	}
	raw, ok := ecrRepositoryToRaw(repo, "eu-central-1")
	if !ok {
		t.Fatal("ecrRepositoryToRaw !ok")
	}
	if raw.CFNType != "AWS::ECR::Repository" || raw.Identifier != "cbx-app" {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if got := dr.Inputs["ImageTagMutability"]; got != "MUTABLE" {
		t.Errorf("ImageTagMutability: got %v, want MUTABLE", got)
	}
	isc, _ := dr.Inputs["ImageScanningConfiguration"].(map[string]any)
	if v, _ := isc["ScanOnPush"].(bool); v {
		t.Errorf("ImageScanningConfiguration.ScanOnPush: got true, want false (scan-on-push disabled is the finding)")
	}
}

// --- ECS TaskDefinition: pure parse helpers + round-trip + fallback fires --

func TestParseTaskDefFamilyRevision(t *testing.T) {
	cases := []struct {
		arn    string
		family string
		rev    int
	}{
		{"arn:aws:ecs:eu-central-1:111122223333:task-definition/web:7", "web", 7},
		{"arn:aws:ecs:eu-central-1:111122223333:task-definition/api-svc:142", "api-svc", 142},
		{"arn:aws:ecs:eu-central-1:111122223333:task-definition/web", "", -1}, // no revision
		{"not-an-arn", "", -1},
	}
	for _, tc := range cases {
		fam, rev := parseTaskDefFamilyRevision(tc.arn)
		if fam != tc.family || rev != tc.rev {
			t.Errorf("parseTaskDefFamilyRevision(%q) = (%q, %d), want (%q, %d)", tc.arn, fam, rev, tc.family, tc.rev)
		}
	}
}

// latestTaskDefArns must collapse a family to its highest revision (so a family
// with many historical revisions is audited once) while keeping distinct
// families, and pass unparseable ARNs through rather than dropping them.
func TestLatestTaskDefArns(t *testing.T) {
	in := []string{
		"arn:aws:ecs:eu-central-1:1:task-definition/web:1",
		"arn:aws:ecs:eu-central-1:1:task-definition/web:3",
		"arn:aws:ecs:eu-central-1:1:task-definition/web:2",
		"arn:aws:ecs:eu-central-1:1:task-definition/api:5",
	}
	got := latestTaskDefArns(in)
	want := []string{
		"arn:aws:ecs:eu-central-1:1:task-definition/api:5",
		"arn:aws:ecs:eu-central-1:1:task-definition/web:3", // latest web revision only
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("latestTaskDefArns = %v, want %v", got, want)
	}
}

// The privileged-container + plaintext-env posture must survive the synthesised
// CFN shape (the LLM reads these raw fields; the TaskDefinition describer only
// re-applies env redaction), and an empty primary must trigger the fallback
// through the real runJob path.
func TestRunJob_TaskDefinitionFallbackFires(t *testing.T) {
	td := ecstypes.TaskDefinition{
		TaskDefinitionArn: strp("arn:aws:ecs:eu-central-1:111122223333:task-definition/web:7"),
		Family:            strp("web"),
		NetworkMode:       ecstypes.NetworkMode("awsvpc"),
		ContainerDefinitions: []ecstypes.ContainerDefinition{{
			Name:                   strp("app"),
			Image:                  strp("example/app:latest"),
			Privileged:             boolp(true),
			ReadonlyRootFilesystem: boolp(false),
			Environment:            []ecstypes.KeyValuePair{{Name: strp("DB_PASSWORD"), Value: strp("hunter2")}},
		}},
	}
	fallbackRaw, ok := taskDefinitionToRaw(td, "eu-central-1")
	if !ok {
		t.Fatal("taskDefinitionToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type:         "AWS::ECS::TaskDefinition",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 task definition from the fallback, got %d", len(res.resources))
	}
	got := res.resources[0]
	if got.Type != "AWS::ECS::TaskDefinition" {
		t.Fatalf("type: got %q", got.Type)
	}
	defs, _ := got.Inputs["ContainerDefinitions"].([]any)
	if len(defs) != 1 {
		t.Fatalf("expected 1 container definition, got %d", len(defs))
	}
	cd, _ := defs[0].(map[string]any)
	if v, _ := cd["Privileged"].(bool); !v {
		t.Errorf("Privileged: got false, want true (privileged-container finding)")
	}
	if v, ok := cd["ReadonlyRootFilesystem"].(bool); !ok || v {
		t.Errorf("ReadonlyRootFilesystem: got %v, want false", cd["ReadonlyRootFilesystem"])
	}
	env, _ := cd["Environment"].([]any)
	if len(env) != 1 {
		t.Fatalf("expected 1 env var, got %d", len(env))
	}
	if e, _ := env[0].(map[string]any); e["Name"] != "DB_PASSWORD" {
		t.Errorf("Environment[0].Name: got %v, want DB_PASSWORD (plaintext-secret-in-env finding)", e["Name"])
	}
}

// --- Backup vault + plan round-trips + fallback fires ---------------------

func TestBackupVaultToRaw_RoundTrip(t *testing.T) {
	v := backuptypes.BackupVaultListMember{
		BackupVaultName:  strp("cbx-vault"),
		BackupVaultArn:   strp("arn:aws:backup:eu-central-1:111122223333:backup-vault:cbx-vault"),
		EncryptionKeyArn: strp("arn:aws:kms:eu-central-1:111122223333:key/abcd"),
		Locked:           boolp(false),
		MinRetentionDays: int64p(7),
	}
	raw, ok := backupVaultToRaw(v, "eu-central-1")
	if !ok {
		t.Fatal("backupVaultToRaw !ok")
	}
	if raw.CFNType != "AWS::Backup::BackupVault" || raw.Identifier != "cbx-vault" {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if dr.Inputs["BackupVaultName"] != "cbx-vault" {
		t.Errorf("BackupVaultName: got %v", dr.Inputs["BackupVaultName"])
	}
	if v, ok := dr.Inputs["Locked"].(bool); !ok || v {
		t.Errorf("Locked: got %v, want false (vault-lock-not-enabled posture)", dr.Inputs["Locked"])
	}
	if got, _ := dr.Inputs["MinRetentionDays"].(float64); got != 7 {
		t.Errorf("MinRetentionDays: got %v, want 7", dr.Inputs["MinRetentionDays"])
	}
}

func TestBackupPlanToRaw_RoundTrip(t *testing.T) {
	p := backuptypes.BackupPlansListMember{
		BackupPlanId:   strp("plan-uuid"),
		BackupPlanArn:  strp("arn:aws:backup:eu-central-1:111122223333:backup-plan:plan-uuid"),
		BackupPlanName: strp("daily"),
	}
	raw, ok := backupPlanToRaw(p, "eu-central-1")
	if !ok {
		t.Fatal("backupPlanToRaw !ok")
	}
	if raw.CFNType != "AWS::Backup::BackupPlan" || raw.Identifier != "plan-uuid" {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if dr.Inputs["BackupPlanName"] != "daily" {
		t.Errorf("BackupPlanName: got %v, want daily", dr.Inputs["BackupPlanName"])
	}
}

// Production-wiring guard: the runJob fallback-fires tests use synthetic
// cfnTypeSpec literals, so they prove the mechanism but NOT that the real
// discoverableCFNTypes entries point at the listers. This asserts the four
// types a live run caught CloudControl silently dropping have a FallbackLister
// wired on their PRODUCTION spec (a typo / missing wiring would otherwise pass
// every other test), keeps the pre-existing fallbacks from regressing, and
// enforces the scope discipline that the LB / target group get none.
func TestDiscoverableTypes_FallbackWiring(t *testing.T) {
	byType := map[string]cfnTypeSpec{}
	for _, s := range discoverableCFNTypes {
		byType[s.Type] = s
	}

	mustHaveFallback := []string{
		// added this change
		"AWS::S3::Bucket",
		// added by the prior fallback batches — regression guard
		"AWS::DynamoDB::Table",
		"AWS::ECR::Repository",
		"AWS::ECS::TaskDefinition",
		"AWS::Backup::BackupVault",
		"AWS::Backup::BackupPlan",
		// pre-existing — regression guard
		"AWS::EC2::Instance",
		"AWS::EC2::Volume",
		"AWS::RDS::DBInstance",
		"AWS::RDS::DBCluster",
		"AWS::ECS::Service",
		"AWS::EKS::Cluster",
		"AWS::ElasticLoadBalancingV2::Listener",
		"AWS::IAM::ManagedPolicy",
	}
	for _, ty := range mustHaveFallback {
		s, ok := byType[ty]
		if !ok {
			t.Errorf("%s missing from discoverableCFNTypes", ty)
			continue
		}
		if s.FallbackLister == nil {
			t.Errorf("%s: FallbackLister not wired on its production spec", ty)
		}
	}

	// Scope discipline: CloudControl lists these reliably — a fallback here
	// would be the over-reach the change deliberately avoids.
	mustNotHaveFallback := []string{
		"AWS::ElasticLoadBalancingV2::LoadBalancer",
		"AWS::ElasticLoadBalancingV2::TargetGroup",
	}
	for _, ty := range mustNotHaveFallback {
		if s, ok := byType[ty]; ok && s.FallbackLister != nil {
			t.Errorf("%s: must NOT have a fallback (CloudControl lists it reliably)", ty)
		}
	}
}

// The vault fallback must fire on an empty primary and flow through runJob. The
// backupVaultDescriber makes live API calls, so we swap it out (the wiring under
// test is the fallback-on-empty path, not the describer's network calls).
func TestRunJob_BackupVaultFallbackFires(t *testing.T) {
	saved := allDescribers
	allDescribers = []Describer{}
	defer func() { allDescribers = saved }()

	v := backuptypes.BackupVaultListMember{
		BackupVaultName: strp("cbx-vault"),
		Locked:          boolp(false),
	}
	fallbackRaw, ok := backupVaultToRaw(v, "eu-central-1")
	if !ok {
		t.Fatal("backupVaultToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type:         "AWS::Backup::BackupVault",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 vault from the fallback, got %d", len(res.resources))
	}
	if got := res.resources[0]; got.Type != "AWS::Backup::BackupVault" || got.ID != "cbx-vault" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
}
