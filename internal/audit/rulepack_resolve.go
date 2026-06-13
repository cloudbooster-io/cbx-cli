package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// Rulepack resolution for the grounded audit path (P1).
//
// The network fetch runs EXACTLY ONCE per process, from the CLI's
// pre-discovery preflight (pkg/cmd/audit_aws.go calls ResolveRulePack
// before any AWS spend); the result is memoized and the LLM analyzer
// consumes the memo. An analyzer constructed without that preflight
// (library callers, unit tests) resolves WITHOUT the network rung —
// override file → on-disk cache — so no library or test path ever
// dials out implicitly. The pack is API-distributed with no embedded
// floor: a no-preflight construction with a cold cache and no override
// is abort-class (rulesbundle.ErrNoRulePack) — library callers run
// ResolveRulePack themselves, set CBX_AUDIT_RULES_FILE, or rely on a
// previously populated cache. This split is deliberate: the only
// component allowed to spend network on rules is the CLI preflight,
// where a failure can still abort before discovery costs anything.
var (
	rulePackMu    sync.Mutex
	rulePackDone  bool
	rulePackPack  *rulesbundle.RulePack
	rulePackProv  rulesbundle.Provenance
	engineVersion string
)

// SetEngineVersion records the running cbx version (the ldflags-
// injected pkg/cmd.Version) for the rulepack min_engine_version
// handshake. Unset (or any non-semver value, e.g. "dev") satisfies
// every constraint.
func SetEngineVersion(v string) {
	rulePackMu.Lock()
	defer rulePackMu.Unlock()
	engineVersion = v
}

// ResolveRulePack resolves the audit rule pack through the full ladder
// (CBX_AUDIT_RULES_FILE override → registry fetch with ETag
// revalidation → on-disk cache) and memoizes the result for
// the rest of the process. pin > 0 pins an exact pack_version (the
// --rulepack-version flag); pin 0 defers to CBX_RULEPACK_VERSION, then
// "latest". Errors are abort-class only (see rulesbundle.Resolve);
// call it BEFORE discovery so they cost nothing.
func ResolveRulePack(ctx context.Context, pin int) (*rulesbundle.RulePack, rulesbundle.Provenance, error) {
	return resolveRulePack(ctx, pin, true)
}

// currentRulePack is the analyzer-side accessor: the memo when the CLI
// preflight ran, a network-less resolution otherwise.
func currentRulePack(ctx context.Context) (*rulesbundle.RulePack, rulesbundle.Provenance, error) {
	return resolveRulePack(ctx, 0, false)
}

func resolveRulePack(ctx context.Context, pin int, network bool) (*rulesbundle.RulePack, rulesbundle.Provenance, error) {
	rulePackMu.Lock()
	defer rulePackMu.Unlock()
	if rulePackDone {
		return rulePackPack, rulePackProv, nil
	}

	if pin == 0 {
		if v := config.Env("RULEPACK_VERSION"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, rulesbundle.Provenance{}, fmt.Errorf("audit: invalid CBX_RULEPACK_VERSION %q (want a non-negative pack_version integer)", v)
			}
			pin = n
		}
	}

	opts := rulesbundle.ResolveOptions{
		Channel:       config.Env("RULEPACK_CHANNEL"),
		PinVersion:    pin,
		OverrideFile:  config.Env("AUDIT_RULES_FILE"),
		EngineVersion: engineVersion,
	}
	if network {
		kc := knowledge.New(resolvedCBAPIURL())
		opts.Fetch = func(ctx context.Context, channel, etag string, pin int) ([]byte, string, error) {
			raw, newETag, err := kc.RulePack(ctx, channel, etag, pin)
			switch {
			case errors.Is(err, knowledge.ErrNotModified):
				return nil, etag, rulesbundle.ErrNotModified
			case errors.Is(err, knowledge.ErrNotAuthored):
				return nil, "", rulesbundle.ErrNotAuthored
			}
			return raw, newETag, err
		}
	}

	pack, prov, err := rulesbundle.Resolve(ctx, opts)
	if err != nil {
		// Abort-class failures are NOT memoized: the caller aborts the
		// run, and a later caller with a fixed environment should get a
		// fresh resolution.
		return nil, rulesbundle.Provenance{}, err
	}
	rulePackPack, rulePackProv, rulePackDone = pack, prov, true
	return pack, prov, nil
}

// resetRulePackForTests clears the process memo + engine version.
func resetRulePackForTests() {
	rulePackMu.Lock()
	defer rulePackMu.Unlock()
	rulePackDone = false
	rulePackPack = nil
	rulePackProv = rulesbundle.Provenance{}
	engineVersion = ""
}

// appendRulesProvenanceFindings emits the rulepack meta-finding trio
// after a grounded scan (plan §E P1), mirroring the LLM-CB-TRUNCATED /
// LLM-CB-KNOWLEDGE-PARTIAL posture above:
//
//   - LLM-CB-RULES-PROVENANCE (info, every grounded run): names the
//     pack version, source rung, and content hash that grounded THIS
//     audit — a sweep verdict that can't name its pack is unscoreable.
//   - LLM-CB-RULES-STALE (warning, exit 2): the resolve ladder degraded
//     — the registry fetch failed transiently and/or the cache served
//     is older than the grace window. The audit ran on rules that may
//     lag CB's current set; CI gating on exit codes must see that.
//   - LLM-CB-RULES-AHEAD (info): the resolved pack has rules whose
//     requires_fields name cb_describer_* keys this engine never emits
//     (pack is ahead of the engine). Those rules stay inert via the
//     prose's skip-when-absent discipline; the finding makes the silent
//     non-firing visible.
//
// No-op for analyzers constructed without a resolved pack (zero-value
// provenance): direct test constructions inject a pack explicitly and
// have no ladder state to report.
func (l *llmAnalyzer) appendRulesProvenanceFindings(findings []Finding) []Finding {
	prov := l.rulesProv
	if prov.Source == "" {
		return findings
	}

	shortHash := prov.ContentSHA256
	if len(shortHash) > 12 {
		shortHash = shortHash[:12]
	}
	pinNote := ""
	if prov.PinnedVersion > 0 {
		pinNote = fmt.Sprintf(", pinned to version %d", prov.PinnedVersion)
	}
	findings = append(findings, Finding{
		RuleID:      "LLM-CB-RULES-PROVENANCE",
		Title:       fmt.Sprintf("Audit rules: pack v%d from %s", prov.PackVersion, prov.Source),
		Description: fmt.Sprintf("This audit was grounded by the cb-aws-audit rule pack version %d (schema %d), served from the %q rung of the resolve ladder%s. Canonical content sha256: %s.", prov.PackVersion, prov.SchemaVersion, prov.Source, pinNote, prov.ContentSHA256),
		Severity:    SeverityInfo,
		Resource:    l.providerForRuleID,
		Service:     "LLM",
		Remediation: "None — provenance record. Pin a pack for reproducible runs with --rulepack-version / CBX_RULEPACK_VERSION; override locally with CBX_AUDIT_RULES_FILE.",
	})

	if prov.Degraded || prov.Stale {
		var why []string
		if prov.Degraded {
			why = append(why, fmt.Sprintf("the registry fetch failed transiently (%s)", prov.FetchError))
		}
		if prov.Stale {
			why = append(why, fmt.Sprintf("the on-disk cache served was last confirmed current at %s, older than the staleness grace window", prov.FetchedAt))
		}
		findings = append(findings, Finding{
			RuleID:      "LLM-CB-RULES-STALE",
			Title:       fmt.Sprintf("Audit rules may be outdated (served from %s)", prov.Source),
			Description: fmt.Sprintf("The rule-pack resolve ladder degraded: %s. The audit still ran on a validated pack (version %d, sha256 %s…), but it may lag CloudBooster's current rule set — newly published detections would be missing from this run.", strings.Join(why, "; "), prov.PackVersion, shortHash),
			Severity:    SeverityWarning,
			Resource:    l.providerForRuleID,
			Service:     "LLM",
			Remediation: "Re-run when the CloudBooster registry is reachable (check CB_API_URL / network); the fetch revalidates per run and refreshes the cache automatically.",
		})
	}

	if ahead := rulesAheadOfEngine(l.rules); len(ahead) > 0 {
		findings = append(findings, Finding{
			RuleID:      "LLM-CB-RULES-AHEAD",
			Title:       fmt.Sprintf("%d rule(s) in the pack are ahead of this engine build", len(ahead)),
			Description: fmt.Sprintf("The following rules require describer fields this cbx build never emits, so they cannot fire on this run (they stay inert via their skip-when-absent guards):\n  - %s", strings.Join(ahead, "\n  - ")),
			Severity:    SeverityInfo,
			Resource:    l.providerForRuleID,
			Service:     "LLM",
			Remediation: "Run `cbx upgrade` — a newer engine emits the missing fields and activates these rules.",
		})
	}
	return findings
}

// rulesAheadOfEngine lists pack rules whose requires_fields name keys
// outside the generated describer-field manifest, one
// "<rule-id>: <field>[, <field>...]" entry per affected rule. Empty
// when the pack is nil or fully within the engine's emit set (the
// e2e_staging tier pins this for the pack the registry serves).
func rulesAheadOfEngine(pack *rulesbundle.RulePack) []string {
	if pack == nil {
		return nil
	}
	var ahead []string
	for _, r := range pack.Rules {
		var unknown []string
		for _, f := range r.RequiresFields {
			if !parsers.DescriberFieldKnown(f) {
				unknown = append(unknown, f)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			ahead = append(ahead, r.ID+": "+strings.Join(unknown, ", "))
		}
	}
	return ahead
}
