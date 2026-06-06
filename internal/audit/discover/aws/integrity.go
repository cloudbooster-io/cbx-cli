package aws

import (
	"context"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
)

// The discovery-integrity probe is the generic backstop for CloudControl's
// non-deterministic silent-empty defect — the same defect the native-Describe
// fallbacks in lister_native.go heal per-type. The fallbacks can only ever
// cover the handful of types our fixtures exercise; every OTHER type that
// carries CB-curated findings but has no fallback is still exposed: a silent
// ListResources miss drops the resource with permission_errors == 0, the audit
// reports clean, and the operator is told they're secure when they aren't —
// the worst outcome for a security audit.
//
// This probe converts that invisible miss into a VISIBLE warning finding for
// the bare (no-fallback) tail. After the primary discovery pass, every
// in-scope type that came back EMPTY with no error is independently re-listed.
// If the second read sees resources the audit set is missing, an
// IntegrityWarning is recorded and surfaced as a deterministic, Go-side
// `warning` finding (no LLM involvement — see audit.DiscoveryIntegrityFinding).
//
// Why CloudControl-vs-CloudControl rather than a genuinely independent reader
// (e.g. the Resource Groups Tagging API): the "NO new false alarms" guarantee
// is the load-bearing requirement, and it rests on IDENTICAL list semantics.
// The reprobe uses the same TypeName and the same KeepIdentifier as the
// primary read, so the only way its count can EXCEED discovery's is a genuine
// silent-empty on the primary — never a filter / type-mapping / granularity
// mismatch. A cross-service inventory would add an ARN→CFN-type mapping table
// and tag-coverage gaps (each a new false-positive surface) and require a new
// IAM grant that would leave the probe inert until operators re-provision.
// cloudcontrol is already a dependency; resourcegroupstaggingapi is not.
//
// The cost of CC-vs-CC is the false-NEGATIVE window it cannot close: when the
// primary AND the reprobe both flake empty in the same window, there is no
// disagreement to detect. That window is narrow for the in-scope set, which is
// dominated by strongly-consistent types (S3, KMS, Lambda, DynamoDB, SQS/SNS,
// ALB, SecurityGroup, VPC, CloudTrail, LogGroup, …) — the eventual-consistency
// workload types that race on fresh-create mostly already carry fallbacks and
// fall out of scope here. The probe is strictly better than the status quo (no
// check at all) and needs no new permissions, so it protects every existing
// operator immediately.

// IntegrityWarning records a discovery-integrity discrepancy: an independent
// re-list of a CFN type found resources the audit's primary discovery pass
// missed entirely. Emitted deterministically (no LLM) and converted into a
// `warning` audit Finding by the command layer.
type IntegrityWarning struct {
	Type   string // CFN type, e.g. "AWS::S3::Bucket"
	Region string // region the discrepancy was seen in; "" for Global types
	Count  int    // resources the independent re-list saw that discovery missed
}

// integrityCandidate is one (region, type) the probe will independently
// re-list because the primary pass returned a clean empty for it.
type integrityCandidate struct {
	region string
	spec   cfnTypeSpec
}

// integrityProbeEligible reports whether a type qualifies for the
// discovery-integrity reprobe. The scope is deliberately narrow:
//
//   - The type must carry CB-curated findings (audit.CFNTypeToCBPrimitive != "").
//     A silent miss on a type with no curated knowledge darkens no finding, so
//     probing it would only add cost and false-alarm surface for no audit gain.
//   - The type must have NO FallbackLister and NO CustomLister. Those types
//     already self-heal against the silent-empty defect (lister_native.go), so
//     reprobing them would be redundant work that can never change the outcome.
//
// Restricting to (curated ∧ no-fallback) keeps the reprobe off all ~50
// discoverable types and on only the bare tail where a silent miss would
// actually cost the audit a finding.
func integrityProbeEligible(spec cfnTypeSpec) bool {
	if spec.FallbackLister != nil || spec.CustomLister != nil {
		return false
	}
	return audit.CFNTypeToCBPrimitive(spec.Type) != ""
}

// isIntegrityCandidate reports whether a completed discovery job should be
// independently re-listed. The condition mirrors the exact silent-empty
// failure mode and nothing else:
//
//   - in scope (curated, no fallback), and
//   - the primary list returned NO error (an errored list is already surfaced
//     as a permission/other advisory — a reprobe failure there is not a
//     disagreement and must not double-warn), and
//   - the audit set has zero resources of this type (a fully empty result, not
//     a partial-count mismatch — that matches the observed defect and is
//     maximally false-positive-safe).
//
// For eligible types there is no fallback/custom lister, so an empty
// r.resources with a nil listErr is exactly "the primary CloudControl list
// returned a clean empty."
func isIntegrityCandidate(r jobResult) bool {
	return integrityProbeEligible(r.spec) && r.listErr == nil && len(r.resources) == 0
}

// reprobeFunc is the independent second read. Returns the number of
// identifiers the reader saw for (region, type), or a non-nil error meaning
// "no signal" — a failed reprobe is NOT a disagreement and must not warn.
// Pulled out as a type so probeDiscoveryIntegrity can take a deterministic
// fake in tests (live CloudControl flakiness cannot be forced).
type reprobeFunc func(ctx context.Context, c awsCfg, region string, spec cfnTypeSpec) (int, error)

// reprobeIdentifierCount is the production reprobeFunc: an independent
// CloudControl ListResources for the type, counting identifiers AFTER applying
// the same spec.KeepIdentifier filter the primary discovery list used. Reusing
// KeepIdentifier is load-bearing for false-positive safety — without it, a type
// like AWS::IAM::Role (whose discovery filters out AWSServiceRoleFor* /
// AWSReservedSSO_* service-linked roles) would re-list those AWS-managed roles
// and warn spuriously in an account that has only service-linked roles.
//
// Returns (0, nil) when the type is genuinely absent or not supported in the
// region — both are "no disagreement." Only a successful re-list with a
// positive kept-identifier count is a signal.
func reprobeIdentifierCount(ctx context.Context, c awsCfg, region string, spec cfnTypeSpec) (int, error) {
	client := cloudcontrol.NewFromConfig(c.withRegion(region).cfg)
	cfnType := spec.Type

	count := 0
	var nextToken *string
	for {
		out, err := client.ListResources(ctx, &cloudcontrol.ListResourcesInput{
			TypeName:  &cfnType,
			NextToken: nextToken,
		})
		if err != nil {
			if isUnsupportedType(err) {
				return 0, nil
			}
			return 0, classifyCloudControlError(err, cfnType, region, "cloudformation:ListResources")
		}
		for _, d := range out.ResourceDescriptions {
			if d.Identifier == nil {
				continue
			}
			if spec.KeepIdentifier != nil && !spec.KeepIdentifier(*d.Identifier) {
				continue
			}
			count++
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return count, nil
}

// probeDiscoveryIntegrity independently re-lists every candidate and returns
// one IntegrityWarning per (region, type) where the second read disagreed with
// the audit set — i.e. the reprobe succeeded with a positive count while the
// primary pass had zero. The comparison is strictly asymmetric (warn only when
// reprobe > 0 against a discovered 0), which is what makes the probe
// false-positive-safe: a type that is legitimately absent re-lists empty too
// and stays silent.
//
// reprobe is injected so tests can supply a deterministic counter; nil falls
// back to the live CloudControl reprobeIdentifierCount. Work is fanned out over
// a bounded worker pool mirroring fanOutDiscovery, and the result is sorted so
// the emitted findings are byte-stable across runs.
func probeDiscoveryIntegrity(ctx context.Context, c awsCfg, candidates []integrityCandidate, concurrency int, reprobe reprobeFunc) []IntegrityWarning {
	if len(candidates) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 4
	}
	if reprobe == nil {
		reprobe = reprobeIdentifierCount
	}

	jobCh := make(chan integrityCandidate)
	resCh := make(chan *IntegrityWarning, len(candidates))

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cand := range jobCh {
				count, err := reprobe(ctx, c, cand.region, cand.spec)
				if err != nil || count <= 0 {
					// Reprobe error → no signal. Count 0 → agreement
					// (genuinely absent, or both reads flaked). Neither warns.
					resCh <- nil
					continue
				}
				region := cand.region
				if cand.spec.Global {
					region = ""
				}
				resCh <- &IntegrityWarning{Type: cand.spec.Type, Region: region, Count: count}
			}
		}()
	}

	go func() {
		for _, cand := range candidates {
			select {
			case <-ctx.Done():
				close(jobCh)
				return
			case jobCh <- cand:
			}
		}
		close(jobCh)
	}()

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var warnings []IntegrityWarning
	for w := range resCh {
		if w != nil {
			warnings = append(warnings, *w)
		}
	}

	sort.Slice(warnings, func(i, j int) bool {
		if warnings[i].Type != warnings[j].Type {
			return warnings[i].Type < warnings[j].Type
		}
		return warnings[i].Region < warnings[j].Region
	})
	return warnings
}
