package aws

import (
	"context"
	"testing"

	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The DynamoDB posture that carries the four planted findings must survive the
// synthesised CFN shape: PROVISIONED billing (provisioned-capacity), no
// SSEDescription ⇒ no SSESpecification (AWS-owned-key / no-CMK),
// DeletionProtectionEnabled=false (no-deletion-protection), and
// PointInTimeRecoveryEnabled=false (no-PITR). There is no DynamoDB describer, so
// the round-trip asserts the raw fields land in Inputs exactly as the grounded
// LLM will read them.
func TestDynamoTableToRaw_RoundTrip(t *testing.T) {
	td := dynamodbtypes.TableDescription{
		TableName: strp("cbx-sessions"),
		TableArn:  strp("arn:aws:dynamodb:eu-central-1:111122223333:table/cbx-sessions"),
		ProvisionedThroughput: &dynamodbtypes.ProvisionedThroughputDescription{
			ReadCapacityUnits:  int64p(5),
			WriteCapacityUnits: int64p(5),
		},
		// No SSEDescription → default AWS-owned key (the no-CMK finding).
		DeletionProtectionEnabled: boolp(false),
	}
	pitrDisabled := false

	raw, ok := dynamoTableToRaw(td, &pitrDisabled, "eu-central-1")
	if !ok {
		t.Fatal("dynamoTableToRaw !ok")
	}
	if raw.CFNType != "AWS::DynamoDB::Table" || raw.Identifier != "cbx-sessions" {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}

	// provisioned-capacity: BillingMode defaults to PROVISIONED (nil summary)
	// and the throughput numbers survive.
	if got := dr.Inputs["BillingMode"]; got != "PROVISIONED" {
		t.Errorf("BillingMode: got %v, want PROVISIONED (provisioned-capacity finding)", got)
	}
	pt, _ := dr.Inputs["ProvisionedThroughput"].(map[string]any)
	if got, _ := pt["ReadCapacityUnits"].(float64); got != 5 {
		t.Errorf("ProvisionedThroughput.ReadCapacityUnits: got %v, want 5", pt["ReadCapacityUnits"])
	}

	// SSE-AWS-owned-key: a table with no CMK must carry NO SSESpecification AND
	// the POSITIVE cb_describer_dynamodb_sse_aws_owned signal — the rule reads the
	// present field, never infers the gap from the absent SSESpecification.
	if _, present := dr.Inputs["SSESpecification"]; present {
		t.Errorf("SSESpecification: present, want absent (AWS-owned key carries no SSEDescription)")
	}
	if v, ok := dr.Inputs["cb_describer_dynamodb_sse_aws_owned"].(bool); !ok || !v {
		t.Errorf("cb_describer_dynamodb_sse_aws_owned: got %v, want true (AWS-owned key ⇒ non-CMK signal)", dr.Inputs["cb_describer_dynamodb_sse_aws_owned"])
	}

	// no-deletion-protection: explicit false.
	if v, ok := dr.Inputs["DeletionProtectionEnabled"].(bool); !ok || v {
		t.Errorf("DeletionProtectionEnabled: got %v, want false (no-deletion-protection finding)", dr.Inputs["DeletionProtectionEnabled"])
	}

	// no-PITR: explicit false, threaded in from the best-effort
	// DescribeContinuousBackups read.
	pitr, _ := dr.Inputs["PointInTimeRecoverySpecification"].(map[string]any)
	if v, ok := pitr["PointInTimeRecoveryEnabled"].(bool); !ok || v {
		t.Errorf("PointInTimeRecoveryEnabled: got %v, want false (no-PITR finding)", pitr["PointInTimeRecoveryEnabled"])
	}
}

// A CMK-encrypted, on-demand, PITR-on table is the inverse posture: it must
// emit SSESpecification (with the CMK ARN that feeds the DynamoDB → KMS edge),
// report PAY_PER_REQUEST, omit ProvisionedThroughput, and carry PITR enabled —
// so none of the four findings fire. Guards against the mapper hard-coding the
// "bad" shape.
func TestDynamoTableToRaw_SecurePostureInverse(t *testing.T) {
	td := dynamodbtypes.TableDescription{
		TableName:          strp("cbx-secure"),
		BillingModeSummary: &dynamodbtypes.BillingModeSummary{BillingMode: dynamodbtypes.BillingModePayPerRequest},
		// On-demand reports 0/0 throughput — must be omitted, not emitted as zeros.
		ProvisionedThroughput: &dynamodbtypes.ProvisionedThroughputDescription{
			ReadCapacityUnits:  int64p(0),
			WriteCapacityUnits: int64p(0),
		},
		SSEDescription: &dynamodbtypes.SSEDescription{
			Status:          dynamodbtypes.SSEStatusEnabled,
			SSEType:         dynamodbtypes.SSETypeKms,
			KMSMasterKeyArn: strp("arn:aws:kms:eu-central-1:111122223333:key/abcd-1234"),
		},
		DeletionProtectionEnabled: boolp(true),
	}
	pitrEnabled := true

	raw, ok := dynamoTableToRaw(td, &pitrEnabled, "eu-central-1")
	if !ok {
		t.Fatal("dynamoTableToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}

	if got := dr.Inputs["BillingMode"]; got != "PAY_PER_REQUEST" {
		t.Errorf("BillingMode: got %v, want PAY_PER_REQUEST", got)
	}
	if _, present := dr.Inputs["ProvisionedThroughput"]; present {
		t.Errorf("ProvisionedThroughput: present, want absent for on-demand (0/0 must not emit)")
	}
	sse, _ := dr.Inputs["SSESpecification"].(map[string]any)
	if sse["KMSMasterKeyId"] != "arn:aws:kms:eu-central-1:111122223333:key/abcd-1234" {
		t.Errorf("SSESpecification.KMSMasterKeyId: got %v (CMK must surface for the KMS edge)", sse["KMSMasterKeyId"])
	}
	// A KMS-encrypted table (SSEType=KMS) logs key usage to CloudTrail, so it must
	// NOT carry the AWS-owned signal — guards the rule against firing on tier-2/3.
	if _, present := dr.Inputs["cb_describer_dynamodb_sse_aws_owned"]; present {
		t.Errorf("cb_describer_dynamodb_sse_aws_owned: present, want absent for a KMS-encrypted table")
	}
	if v, ok := dr.Inputs["DeletionProtectionEnabled"].(bool); !ok || !v {
		t.Errorf("DeletionProtectionEnabled: got %v, want true", dr.Inputs["DeletionProtectionEnabled"])
	}
	pitr, _ := dr.Inputs["PointInTimeRecoverySpecification"].(map[string]any)
	if v, ok := pitr["PointInTimeRecoveryEnabled"].(bool); !ok || !v {
		t.Errorf("PointInTimeRecoveryEnabled: got %v, want true", pitr["PointInTimeRecoveryEnabled"])
	}
}

// A legacy AES256 table populates SSEDescription but with a non-KMS SSEType —
// still the AWS-owned tier (no CloudTrail audit trail of decrypts), so the
// positive signal must fire off "SSEType != KMS", not merely "SSEDescription
// absent". Guards the field condition against a present-but-non-CMK posture.
func TestDynamoTableToRaw_LegacyAES256IsAWSOwned(t *testing.T) {
	td := dynamodbtypes.TableDescription{
		TableName:      strp("cbx-legacy"),
		SSEDescription: &dynamodbtypes.SSEDescription{SSEType: dynamodbtypes.SSETypeAes256},
	}

	raw, ok := dynamoTableToRaw(td, nil, "eu-central-1")
	if !ok {
		t.Fatal("dynamoTableToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if v, ok := dr.Inputs["cb_describer_dynamodb_sse_aws_owned"].(bool); !ok || !v {
		t.Errorf("cb_describer_dynamodb_sse_aws_owned: got %v, want true (AES256 is AWS-owned, not a CMK)", dr.Inputs["cb_describer_dynamodb_sse_aws_owned"])
	}
}

// A table we couldn't probe for PITR (DescribeContinuousBackups denied/failed)
// must leave PointInTimeRecoverySpecification ABSENT — never assert a false
// "PITR disabled" for a state that was never read.
func TestDynamoTableToRaw_PITRUnreadOmitsSpec(t *testing.T) {
	td := dynamodbtypes.TableDescription{TableName: strp("cbx-unknown-pitr")}

	raw, ok := dynamoTableToRaw(td, nil, "eu-central-1")
	if !ok {
		t.Fatal("dynamoTableToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if _, present := dr.Inputs["PointInTimeRecoverySpecification"]; present {
		t.Errorf("PointInTimeRecoverySpecification: present, want absent when PITR was not read")
	}
}

// When the primary (CloudControl) list returns empty — the silent-empty miss
// the v2 sweep caught — the FallbackLister must fire and its table must flow
// through the real runJob path into the resource set the LLM sees.
func TestRunJob_DynamoDBTableFallbackFires(t *testing.T) {
	td := dynamodbtypes.TableDescription{
		TableName:                 strp("cbx-sessions"),
		DeletionProtectionEnabled: boolp(false),
	}
	pitrDisabled := false
	fallbackRaw, ok := dynamoTableToRaw(td, &pitrDisabled, "eu-central-1")
	if !ok {
		t.Fatal("dynamoTableToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type: "AWS::DynamoDB::Table",
		// Primary path returns empty, exactly like CloudControl's silent miss.
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 table from the fallback, got %d", len(res.resources))
	}
	got := res.resources[0]
	if got.Type != "AWS::DynamoDB::Table" || got.ID != "cbx-sessions" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
	if got.Inputs["BillingMode"] != "PROVISIONED" {
		t.Errorf("BillingMode: got %v, want PROVISIONED", got.Inputs["BillingMode"])
	}
	if v, ok := got.Inputs["DeletionProtectionEnabled"].(bool); !ok || v {
		t.Errorf("DeletionProtectionEnabled: got %v, want false", got.Inputs["DeletionProtectionEnabled"])
	}
}

// A FallbackLister that recovers tables BUT hits a DescribeContinuousBackups
// failure must surface the error (so --diagnose sees the permission gap) while
// still delivering the tables — never trade the three DescribeTable findings for
// one secondary-call failure. This mirrors runJob's contract: a non-empty
// fallback with a non-nil error keeps the resources and collects the error.
func TestRunJob_DynamoDBFallbackSurfacesPITRErrorButKeepsTable(t *testing.T) {
	td := dynamodbtypes.TableDescription{TableName: strp("cbx-sessions")}
	fallbackRaw, ok := dynamoTableToRaw(td, nil, "eu-central-1") // PITR unread
	if !ok {
		t.Fatal("dynamoTableToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type:         "AWS::DynamoDB::Table",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, &PermissionError{
				Service: "dynamodb", Action: "dynamodb:DescribeContinuousBackups", Region: "eu-central-1",
			}
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected the table to survive the PITR error, got %d resources", len(res.resources))
	}
	if len(res.permErrs) != 1 {
		t.Fatalf("expected the PITR permission error collected for --diagnose, got %d", len(res.permErrs))
	}
	if res.listErr != nil {
		t.Errorf("listErr should be cleared once the fallback recovered tables, got %v", res.listErr)
	}
}
