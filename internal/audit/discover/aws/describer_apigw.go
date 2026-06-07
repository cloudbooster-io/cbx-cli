package aws

import (
	"context"
	"fmt"
	"sort"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

// apiGatewayV2ApiDescriber enriches AWS::ApiGatewayV2::Api resources with
// access-logging posture that CloudControl can't surface on the Api
// alone. Access logging is configured per-STAGE (AccessLogSettings on
// AWS::ApiGatewayV2::Stage), and CloudControl cannot ListResources the
// Stage type without the parent ApiId, so the $default stage of a quick-
// created HTTP API never appears in the discovered set. Without this
// describer the audit has zero signal about whether any stage logs
// requests.
//
// So the describer makes one apigatewayv2:GetStages call (authorized by
// the apigateway:GET grant already in docs/cbx-audit-aws-iam.json) and
// folds every stage's AccessLogSettings.DestinationArn into a single
// boolean the grounded prompt's baseline rule keys off:
//
//	cb_describer_stage_count           — number of stages on the API
//	cb_describer_access_logging_enabled — true iff >=1 stage AND every
//	                                      stage has a log destination
//	cb_describer_stages_without_access_log — sorted names of the stages
//	                                      missing a destination (when any)
//
// FP-safety: the access-logging boolean is set ONLY when at least one
// stage exists. Zero stages (nothing serving traffic) or a GetStages
// error leaves the field unset, so the LLM never reports "logging
// disabled" off a fetch failure — absence of the key means "not
// assessed," a present false means "assessed and disabled."
type apiGatewayV2ApiDescriber struct{}

func (apiGatewayV2ApiDescriber) CFNType() string { return "AWS::ApiGatewayV2::Api" }

func (apiGatewayV2ApiDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	// CloudControl's primary identifier for AWS::ApiGatewayV2::Api is the
	// ApiId (e.g. "ghv0blt39d"), carried on the discovered resource's ID.
	apiID := r.ID
	if apiID == "" {
		return nil
	}

	// The awsCfg handed to Enrich is the BASE config (runJob passes the
	// region separately to the lister, not pinned onto c) — so we MUST
	// re-pin to the resource's region here. Unlike S3, this is a
	// correctness requirement, not an optimization: apigatewayv2:GetStages
	// is region-bound, and calling it against the wrong region returns a
	// NotFoundException / empty set, which would silently suppress the
	// access-logging finding. r.Region is populated by mapToDiscovered.
	if r.Region != "" {
		c = c.withRegion(r.Region)
	}
	client := apigatewayv2.NewFromConfig(c.cfg)
	out, err := client.GetStages(ctx, &apigatewayv2.GetStagesInput{ApiId: &apiID})
	if err != nil {
		// Non-fatal per the Describer contract: collects into the
		// discovery error streams and the resource keeps CC's data. We
		// deliberately set no describer key so a permission/throttle
		// error can't masquerade as "access logging disabled."
		return fmt.Errorf("apigatewayv2 GetStages %s: %w", apiID, err)
	}

	stages := make([]stageAccessLog, 0, len(out.Items))
	for _, s := range out.Items {
		hasDest := s.AccessLogSettings != nil &&
			sdkaws.ToString(s.AccessLogSettings.DestinationArn) != ""
		stages = append(stages, stageAccessLog{
			name:       sdkaws.ToString(s.StageName),
			hasLogDest: hasDest,
		})
	}
	applyStageAccessLogging(r.Inputs, stages)
	return nil
}

// stageAccessLog is the SDK-free view of one stage's access-log posture,
// so the decision logic below is a pure function the unit tests exercise
// without standing up an apigatewayv2 client.
type stageAccessLog struct {
	name       string
	hasLogDest bool
}

// applyStageAccessLogging folds the normalized stage list into the
// cb_describer_* keys. Pure (no SDK) and deterministic — the
// without-access-log name list is sorted so the grounded prompt is
// byte-stable across runs. See the type comment for the FP-safety
// contract on when cb_describer_access_logging_enabled is set.
func applyStageAccessLogging(inputs map[string]any, stages []stageAccessLog) {
	inputs["cb_describer_stage_count"] = float64(len(stages))
	if len(stages) == 0 {
		return
	}
	enabled := true
	missing := make([]string, 0, len(stages))
	for _, s := range stages {
		if !s.hasLogDest {
			enabled = false
			missing = append(missing, s.name)
		}
	}
	inputs["cb_describer_access_logging_enabled"] = enabled
	if len(missing) > 0 {
		sort.Strings(missing)
		anyMissing := make([]any, len(missing))
		for i, n := range missing {
			anyMissing[i] = n
		}
		inputs["cb_describer_stages_without_access_log"] = anyMissing
	}
}
