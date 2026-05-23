package aws

import (
	"context"
	"regexp"
)

// lambdaFunctionDescriber post-processes CloudControl's
// AWS::Lambda::Function Properties into the cb_describer_* namespace
// the audit's downstream rules and grounded analyzer consume. CC's
// schema for this type is broad — Runtime, Role, Environment.Variables,
// VpcConfig, MemorySize, Timeout, EphemeralStorage, Architectures,
// Layers, KmsKeyArn, LoggingConfig are all in CC's response — so the
// describer makes no SDK call and reads only from r.Inputs.
//
// One detection lives here that CC can't compute on its own:
// cb_describer_env_has_plaintext_secrets. It's a key-shape heuristic
// over Environment.Variables — env keys that look like secrets when
// stored in cleartext (DB_PASSWORD, API_KEY, BEARER_TOKEN, …) are a
// common Lambda footgun. The check is intentionally over the *keys*,
// never the values: a secret value could be a perfectly fine pointer
// like "arn:aws:secretsmanager:...". Naming the variable
// "DB_PASSWORD" still telegraphs a cleartext store; naming it
// "DB_PASSWORD_ARN" suggests indirection through Secrets Manager,
// which the heuristic intentionally skips.
type lambdaFunctionDescriber struct{}

func (lambdaFunctionDescriber) CFNType() string { return "AWS::Lambda::Function" }

func (lambdaFunctionDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	copyStr(r.Inputs, "Runtime", "cb_describer_runtime")
	copyStr(r.Inputs, "Role", "cb_describer_role_arn")
	copyNumeric(r.Inputs, "MemorySize", "cb_describer_memory_size_mb")
	copyNumeric(r.Inputs, "Timeout", "cb_describer_timeout_seconds")

	if subnets := lambdaSubnetIDs(r.Inputs); len(subnets) > 0 {
		r.Inputs["cb_describer_vpc_attached"] = true
	} else {
		r.Inputs["cb_describer_vpc_attached"] = false
	}

	envVars := lambdaEnvVars(r.Inputs)
	r.Inputs["cb_describer_env_var_count"] = float64(len(envVars))
	r.Inputs["cb_describer_env_has_plaintext_secrets"] = anyKeyLooksLikeSecret(envVars)
	return nil
}

// lambdaSubnetIDs returns the subnet-id list under VpcConfig.SubnetIds
// when present. Empty/missing means "not VPC-attached" — Lambda's
// default network mode.
func lambdaSubnetIDs(m map[string]any) []string {
	vpc, ok := m["VpcConfig"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := vpc["SubnetIds"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// lambdaEnvVars extracts Environment.Variables as a map. CC returns
// the CFN-shape Environment.Variables (a flat string→string map). When
// the function has no env vars at all, the key is absent — return nil
// so the count is 0 and the secret-detector trivially short-circuits.
func lambdaEnvVars(m map[string]any) map[string]string {
	env, ok := m["Environment"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := env["Variables"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		s, _ := v.(string)
		out[k] = s
	}
	return out
}

// secretKeyHeuristic catches the common cleartext-secret-in-Lambda-env
// naming patterns. We deliberately suffix-test "_arn" / "_id" / "_uri"
// /"_url" via a negative lookbehind-equivalent regex (Go has no lookaround,
// so we post-filter) so DB_PASSWORD trips the rule but DB_PASSWORD_ARN
// does not — the latter is the canonical indirection-via-Secrets-Manager
// shape.
var secretKeyHeuristic = regexp.MustCompile(`(?i)(secret|password|passwd|token|api[_-]?key|credential|private[_-]?key)`)

// secretKeySafeSuffix matches the trailing form that means "this is a
// reference, not a value." Order matters — list longest first to avoid
// partial-match surprises.
//
// Known false-positive class: keys ending in _PATH / _FILE / _CONFIG /
// _TYPE that legitimately point at non-secret artefacts but still match
// the heuristic root (e.g. OAUTH_TOKEN_PATH for a JWKS file path). The
// finding is info-severity so the noise cost is bounded; tighten this
// suffix list when real users surface specific false positives rather
// than guessing.
var secretKeySafeSuffix = regexp.MustCompile(`(?i)(_arn|_id|_uri|_url)$`)

func anyKeyLooksLikeSecret(env map[string]string) bool {
	for k := range env {
		if secretKeyHeuristic.MatchString(k) && !secretKeySafeSuffix.MatchString(k) {
			return true
		}
	}
	return false
}
