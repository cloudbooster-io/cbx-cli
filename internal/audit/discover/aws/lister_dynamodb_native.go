package aws

import (
	"context"

	dynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// listDynamoDBTablesNative is the FallbackLister for AWS::DynamoDB::Table.
// AWS::DynamoDB::Table is CloudControl-listable and strongly consistent, yet
// the v2 clean-baseline sweep (2026-06-03) watched it vanish from the
// audit-time list in two variants — 00 (−2 findings) and 03 (−3), two runs
// 75 min apart — with zero DynamoDB lines in either raw-audit.json and
// permission_errors=[]. The same non-deterministic CloudControl silent-empty
// defect ECR / ECS-TaskDefinition / Backup already carry fallbacks for, now
// hitting a type that carries CB-curated findings: no point-in-time recovery,
// provisioned (vs on-demand) capacity, AWS-owned-key (non-CMK) encryption, and
// no deletion protection. dynamodb:ListTables + DescribeTable is the
// authoritative, strongly-consistent enumeration and fires only when
// CloudControl returned nothing — inert (and can't regress) whenever
// CloudControl does list the table.
//
// There is no DynamoDB describer; the synthesised CFN-shape Properties are read
// directly by the grounded LLM (buildGroundedPrompt's DynamoDB rule), so
// dynamoTableToRaw must carry every finding-bearing field. Point-in-time
// recovery is the one field DescribeTable does not return — it lives behind a
// separate DescribeContinuousBackups call — so we probe it best-effort per
// table (see below) and thread the result into the mapper.
func listDynamoDBTablesNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	client := dynamodb.NewFromConfig(c.withRegion(region).cfg)

	// ListTables paginates via ExclusiveStartTableName ← LastEvaluatedTableName,
	// NOT a NextToken (unlike the other native listers) — the paginator hides
	// that token plumbing.
	var names []string
	pager := dynamodb.NewListTablesPaginator(client, &dynamodb.ListTablesInput{})
	for pager.HasMorePages() {
		out, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAWSError(err, "dynamodb", "dynamodb:ListTables", region)
		}
		names = append(names, out.TableNames...)
	}

	var results []rawResource
	// pitrErr holds the first DescribeContinuousBackups failure. PITR is a
	// secondary enrichment behind its own call/permission, so a failure there
	// must NOT drop the table (and the provisioned-capacity / AWS-owned-key /
	// no-deletion-protection findings DescribeTable already carries). We keep
	// the table and return this error alongside the results: runJob uses the
	// resources (non-empty fallback clears the primary's emptiness) while still
	// collecting the error for --diagnose. See discover.go:runJob.
	var pitrErr error
	for _, name := range names {
		n := name
		out, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &n})
		if err != nil {
			return nil, classifyAWSError(err, "dynamodb", "dynamodb:DescribeTable", region)
		}
		if out.Table == nil {
			continue
		}
		pitr, perr := describeTablePITR(ctx, client, n, region)
		if perr != nil && pitrErr == nil {
			pitrErr = perr
		}
		if raw, ok := dynamoTableToRaw(*out.Table, pitr, region); ok {
			results = append(results, raw)
		}
	}
	return results, pitrErr
}

// describeTablePITR reads a table's point-in-time-recovery state via
// dynamodb:DescribeContinuousBackups (DescribeTable does not return it).
// Returns (*bool, nil) on success, (nil, nil) when the response carries no PITR
// description, and (nil, err) on failure — so the caller leaves
// PointInTimeRecoverySpecification absent rather than asserting a PITR state it
// never read, and surfaces the error without dropping the table.
func describeTablePITR(ctx context.Context, client *dynamodb.Client, tableName, region string) (*bool, error) {
	out, err := client.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: &tableName})
	if err != nil {
		return nil, classifyAWSError(err, "dynamodb", "dynamodb:DescribeContinuousBackups", region)
	}
	if out.ContinuousBackupsDescription == nil || out.ContinuousBackupsDescription.PointInTimeRecoveryDescription == nil {
		return nil, nil
	}
	enabled := out.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dynamodbtypes.PointInTimeRecoveryStatusEnabled
	return &enabled, nil
}

// dynamoTableToRaw maps an SDK DynamoDB TableDescription into CloudControl's CFN
// shape so the synthesised resource flows through mapToDiscovered and the
// grounded LLM reads the same posture fields. There is no DynamoDB describer, so
// these props are the sole signal for the planted findings:
//
//   - BillingMode / ProvisionedThroughput → the provisioned-capacity cost
//     finding. PROVISIONED is the default when billing mode was never set, so a
//     nil BillingModeSummary means provisioned; only an explicit PAY_PER_REQUEST
//     flips it to on-demand. ProvisionedThroughput is emitted only when non-zero
//     (on-demand reports 0/0) so on-demand tables don't carry misleading zeros.
//   - AWS-owned-key (non-CMK) encryption → cb_describer_dynamodb_sse_aws_owned:
//     true. DynamoDB encryption is always on, in three tiers: AWS-owned
//     (DescribeTable returns NO SSEDescription), AWS-managed `aws/dynamodb`, and
//     customer-managed CMK (the latter two both populate SSEDescription with
//     SSEType=KMS). Rather than make the grounded rule infer the gap from an
//     ABSENT SSESpecification — the prompt forbids inferring from a missing key
//     everywhere else — we emit a POSITIVE field whenever there is no KMS
//     SSEType (absent SSEDescription, or a legacy AES256 type): exactly the
//     AWS-owned tier, the only one whose key usage is NOT logged to CloudTrail.
//     For both KMS tiers we emit SSESpecification with SSEType + KMSMasterKeyId
//     (the latter also feeds the DynamoDB → KMS CMK diagram edge) and leave the
//     positive field unset.
//   - DeletionProtectionEnabled: false → the no-deletion-protection finding.
//   - PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled → the no-PITR
//     finding. Set ONLY when the caller successfully read it (pitrEnabled
//     non-nil); left absent otherwise so a table we couldn't probe never reads
//     as a false "no PITR". Explicit-and-present is strictly safer than absence
//     for firing the finding, which is why we probe it at all.
//
// pitrEnabled is threaded in (rather than read here) because PITR lives behind a
// separate DescribeContinuousBackups call; keeping this mapper pure (no SDK
// client) lets the round-trip unit test exercise the full CFN shape. TableName
// is the identifier (CloudControl's primary id for this type).
func dynamoTableToRaw(t dynamodbtypes.TableDescription, pitrEnabled *bool, region string) (rawResource, bool) {
	if t.TableName == nil || *t.TableName == "" {
		return rawResource{}, false
	}
	id := *t.TableName

	props := map[string]any{"TableName": id}
	putStr(props, "Arn", t.TableArn)
	putStr(props, "TableId", t.TableId)

	billingMode := string(dynamodbtypes.BillingModeProvisioned)
	if t.BillingModeSummary != nil && t.BillingModeSummary.BillingMode != "" {
		billingMode = string(t.BillingModeSummary.BillingMode)
	}
	props["BillingMode"] = billingMode

	if t.ProvisionedThroughput != nil {
		var rcu, wcu int64
		if t.ProvisionedThroughput.ReadCapacityUnits != nil {
			rcu = *t.ProvisionedThroughput.ReadCapacityUnits
		}
		if t.ProvisionedThroughput.WriteCapacityUnits != nil {
			wcu = *t.ProvisionedThroughput.WriteCapacityUnits
		}
		if rcu > 0 || wcu > 0 {
			props["ProvisionedThroughput"] = map[string]any{
				"ReadCapacityUnits":  rcu,
				"WriteCapacityUnits": wcu,
			}
		}
	}

	if t.SSEDescription != nil {
		sse := map[string]any{"SSEEnabled": true}
		if t.SSEDescription.SSEType != "" {
			sse["SSEType"] = string(t.SSEDescription.SSEType)
		}
		putStr(sse, "KMSMasterKeyId", t.SSEDescription.KMSMasterKeyArn)
		props["SSESpecification"] = sse
	}

	// Positive AWS-owned-key (non-CMK) signal: true exactly for the tier whose
	// SSEType is not KMS — absent SSEDescription or a legacy AES256 type — so the
	// grounded rule reads a present field instead of inferring from an absent
	// SSESpecification. Both KMS tiers (AWS-managed `aws/dynamodb` and customer
	// CMK) log key usage to CloudTrail, so they must NOT carry this field.
	if t.SSEDescription == nil || t.SSEDescription.SSEType != dynamodbtypes.SSETypeKms {
		props["cb_describer_dynamodb_sse_aws_owned"] = true
	}

	putBool(props, "DeletionProtectionEnabled", t.DeletionProtectionEnabled)

	if pitrEnabled != nil {
		props["PointInTimeRecoverySpecification"] = map[string]any{
			"PointInTimeRecoveryEnabled": *pitrEnabled,
		}
	}

	return marshalRaw("AWS::DynamoDB::Table", id, region, props)
}
