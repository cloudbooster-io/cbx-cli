package aws

import (
	"context"

	lambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// listLambdaFunctionsNative is the FallbackLister for AWS::Lambda::Function. The
// final recall sweep measured variant 03 (serverless) at 3/9 because
// CloudControl's audit-time ListResources silently returned an empty set for
// AWS::Lambda::Function — the same non-deterministic silent-empty miss the
// EC2 / RDS / ECR / ECS / DynamoDB fallbacks already cover — so the shipped Lambda
// DLQ + reserved-concurrency rules had no function to fire on (permission_errors
// was []). lambda:ListFunctions is the authoritative enumeration and fires only
// when CloudControl returned nothing for this type in this region.
//
// UNLIKE the S3 fallback (whose s3BucketDescriber re-fetches every posture field
// live off the bucket name), lambdaFunctionDescriber makes NO SDK call — its
// Enrich signature discards both ctx and awsCfg and reads
// cb_describer_dlq_configured / cb_describer_reserved_concurrency_set /
// cb_describer_role_arn straight out of the CloudControl Properties. So this
// fallback must carry every finding-bearing field in the synthesised props,
// exactly like the DynamoDB native lister — a name-only raw would make the
// describer read absent DLQ / reserved-concurrency as "not configured" and
// false-fire BOTH WARNINGs on functions that actually have them set.
//
// ListFunctions returns the full FunctionConfiguration (Role, Runtime, MemorySize,
// Timeout, DeadLetterConfig, Environment, VpcConfig) inline, so the only
// finding-bearing field needing a second call is ReservedConcurrentExecutions — it
// lives behind GetFunctionConcurrency (mirrors DynamoDB PITR's
// DescribeContinuousBackups). That probe is best-effort per function: a failure
// keeps the function (the DLQ / role findings ListFunctions already carries must
// survive) and records the first error for --diagnose. NOTE the polarity differs
// from DynamoDB PITR — an unread ReservedConcurrentExecutions reads as
// reserved_concurrency_set=false, i.e. the WARNING still FIRES; that matches the
// describer's existing CloudControl contract (CC omits the field when unset), so a
// denied probe degrades to the same finding CC would produce, never to a dropped
// function.
func listLambdaFunctionsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	return collectLambdaFunctions(ctx, lambda.NewFromConfig(c.withRegion(region).cfg), region)
}

// lambdaFallbackAPI is the narrow slice of the Lambda client
// collectLambdaFunctions needs — ListFunctions (the enumeration) plus the
// best-effort GetFunctionConcurrency probe. The concrete *lambda.Client satisfies
// it; the seam lets pagination and the per-function probe's partial-failure
// handling be unit-tested without a live call (mirrors s3FallbackAPI).
type lambdaFallbackAPI interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetFunctionConcurrency(context.Context, *lambda.GetFunctionConcurrencyInput, ...func(*lambda.Options)) (*lambda.GetFunctionConcurrencyOutput, error)
}

// collectLambdaFunctions enumerates functions via ListFunctions (paginated by
// Marker ← NextMarker) and synthesises a CFN-shape raw per function.
//
// A ListFunctions failure is fatal — we have nothing to recover. Per-function
// GetFunctionConcurrency failures are NOT: the function is already fully described
// by ListFunctions, so we keep it (ReservedConcurrentExecutions left absent) and
// record the first error in concErr, returning (results, concErr). That tail
// mirrors listDynamoDBTablesNative's (results, pitrErr) and the runJob fallback
// contract (discover.go:456):
//   - any functions collected   → runJob keeps them and clears the primary's
//     emptiness; concErr (if any) still surfaces to --diagnose so a denied
//     GetFunctionConcurrency isn't silently swallowed.
//   - zero functions, probe err → the error surfaces alone, so an all-deny shows
//     up in --diagnose instead of masquerading as a clean empty account.
//   - zero functions, no error  → a genuinely function-less account/region.
func collectLambdaFunctions(ctx context.Context, client lambdaFallbackAPI, region string) ([]rawResource, error) {
	var results []rawResource
	var concErr error
	var marker *string
	for {
		out, err := client.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, classifyAWSError(err, "lambda", "lambda:ListFunctions", region)
		}
		for _, fn := range out.Functions {
			rc, rerr := readReservedConcurrency(ctx, client, fn, region)
			if rerr != nil && concErr == nil {
				concErr = rerr
			}
			if raw, ok := lambdaFunctionToRaw(fn, rc, region); ok {
				results = append(results, raw)
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return results, concErr
}

// readReservedConcurrency reads a function's reserved-concurrency setting via
// lambda:GetFunctionConcurrency (ListFunctions does not return it). Returns
// (*int32, nil) when a reservation is set, (nil, nil) when none is configured (the
// common default — the field is simply absent), and (nil, err) on failure, so the
// caller leaves ReservedConcurrentExecutions absent rather than asserting a value
// it never read, and surfaces the error without dropping the function.
func readReservedConcurrency(ctx context.Context, client lambdaFallbackAPI, fn lambdatypes.FunctionConfiguration, region string) (*int32, error) {
	if fn.FunctionName == nil || *fn.FunctionName == "" {
		return nil, nil
	}
	out, err := client.GetFunctionConcurrency(ctx, &lambda.GetFunctionConcurrencyInput{FunctionName: fn.FunctionName})
	if err != nil {
		return nil, classifyAWSError(err, "lambda", "lambda:GetFunctionConcurrency", region)
	}
	if out == nil {
		return nil, nil
	}
	return out.ReservedConcurrentExecutions, nil
}

// lambdaFunctionToRaw maps an SDK FunctionConfiguration into CloudControl's
// AWS::Lambda::Function CFN shape so the synthesised resource flows through
// mapToDiscovered + lambdaFunctionDescriber identically to a CC-listed function.
// FunctionName is the identifier (CloudControl's primary id for this type). The
// load-bearing fields:
//
//   - DeadLetterConfig.TargetArn → cb_describer_dlq_configured. Emitted ONLY when a
//     real target is set, so its absence is the missing-DLQ WARNING signal (mirrors
//     lambdaHasDLQ, which treats an empty/absent TargetArn as "no DLQ").
//   - ReservedConcurrentExecutions → cb_describer_reserved_concurrency_set.
//     Threaded in from the best-effort probe; emitted only when set, so absence
//     fires the no-reserved-concurrency WARNING (the describer's existing CC
//     contract).
//   - Role → cb_describer_role_arn plus the Lambda→IAM-role cross-reference
//     (crossReferenceLambdaRole) backing the "unauthenticated API + admin Lambda"
//     CRITICAL compound finding.
//
// Runtime / MemorySize / Timeout / VpcConfig / Environment.Variables are copied too
// so the describer's secondary signals (vpc-attached, plaintext-secret-env
// heuristic) read the same whether the function came from CloudControl or this
// fallback. Pure (no SDK client) for unit testing; mirrors dynamoTableToRaw.
func lambdaFunctionToRaw(fn lambdatypes.FunctionConfiguration, reservedConcurrency *int32, region string) (rawResource, bool) {
	if fn.FunctionName == nil || *fn.FunctionName == "" {
		return rawResource{}, false
	}
	id := *fn.FunctionName

	props := map[string]any{"FunctionName": id}
	putStr(props, "Arn", fn.FunctionArn)
	putStr(props, "Role", fn.Role)
	if fn.Runtime != "" {
		props["Runtime"] = string(fn.Runtime)
	}
	putInt32(props, "MemorySize", fn.MemorySize)
	putInt32(props, "Timeout", fn.Timeout)

	// KmsKeyArn is the CFN property crossReferenceKMS walks (isKMSFieldName) —
	// note the SDK field is fn.KMSKeyArn (all-caps KMS) but the stored key must
	// be the walked literal "KmsKeyArn", or the cross-reference pass won't see
	// it. GetFunctionConfiguration populates KMSKeyArn ONLY when a customer CMK
	// encrypts the function's env vars (the AWS-managed default key returns nil),
	// so storing it when present is FP-safe by direction: it can only count a
	// real reference (flip cb_describer_is_unused true→false), never invent one.
	// Harmless on the CC path (CC carries KmsKeyArn itself); this fallback fired
	// because CC returned nothing, so it must carry the reference on its own.
	putStr(props, "KmsKeyArn", fn.KMSKeyArn)

	// DeadLetterConfig is emitted only when a real target ARN is set — its
	// absence is exactly the missing-DLQ signal lambdaHasDLQ keys off.
	if fn.DeadLetterConfig != nil && fn.DeadLetterConfig.TargetArn != nil && *fn.DeadLetterConfig.TargetArn != "" {
		props["DeadLetterConfig"] = map[string]any{"TargetArn": *fn.DeadLetterConfig.TargetArn}
	}
	// Threaded in from the best-effort probe; absent when unset or unread, which
	// the describer reads as reserved_concurrency_set=false (the WARNING fires).
	if reservedConcurrency != nil {
		props["ReservedConcurrentExecutions"] = *reservedConcurrency
	}
	// SubnetIds / Variables are passed through as the SDK slice/map; marshalRaw's
	// JSON round-trip normalises them to []any / map[string]any before the
	// describer (lambdaSubnetIDs / lambdaEnvVars) reads them. Variables may carry
	// live secret VALUES here — that's fine: every synthesised raw flows through
	// lambdaFunctionDescriber.Enrich (runJob enriches fallback raws identically to
	// CloudControl-listed ones), whose redactSecretEnvValues masks secret-shaped
	// values before the Inputs reach the grounded prompt.
	if fn.VpcConfig != nil && len(fn.VpcConfig.SubnetIds) > 0 {
		props["VpcConfig"] = map[string]any{"SubnetIds": fn.VpcConfig.SubnetIds}
	}
	if fn.Environment != nil && len(fn.Environment.Variables) > 0 {
		props["Environment"] = map[string]any{"Variables": fn.Environment.Variables}
	}

	return marshalRaw("AWS::Lambda::Function", id, region, props)
}
