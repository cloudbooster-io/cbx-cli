package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
)

// DiscoverParams is the input to Discover. Kept as a struct so the
// signature stays stable as we add knobs without touching call sites.
type DiscoverParams struct {
	Profile         string
	CredentialsFile string
	Regions         []string
	Concurrency     int
	Diagnose        bool

	// PromptForRegions is the hook for the interactive region picker.
	// When nil, ResolveRegions' ErrNoRegion propagates up unchanged.
	// Wired by the CLI layer so the discovery package doesn't pull
	// Bubble Tea into non-interactive callers.
	PromptForRegions func(ctx context.Context, enabled []string) ([]string, error)

	// OnProgress, if non-nil, receives ProgressEvent updates throughout
	// the discovery lifecycle (preflight → regions → per-job → done).
	// The callback may be invoked from multiple goroutines concurrently
	// during the fan-out phase, so implementations must be safe for
	// concurrent use. Wired by the CLI for the live progress display;
	// library callers (downstream consumers, tests) typically leave this nil.
	OnProgress func(ProgressEvent)

	// Types overrides the curated CFN type list (discoverableCFNTypes).
	// Used by tests; production callers leave this nil.
	Types []cfnTypeSpec

	// ScoutOnly, when true, stops the pipeline after the scout phase
	// (preflight + region resolution + cheap region probe). The
	// fan-out CloudControl Discover and per-resource enrichment are
	// skipped entirely. Used by `cbx audit aws --dry-run` to surface
	// what the audit would do without actually firing the heavy
	// per-region × per-type list+get pass. EventCount still reflects
	// the structural estimate for the planned (post-scout) regions.
	ScoutOnly bool
}

// DiscoverResult is what Discover returns. PermissionErr is collected
// across all per-type and per-region failures attributable to missing
// IAM permissions, for the --diagnose path to summarise at the end.
// OtherErrs collects non-permission failures (throttling, malformed
// responses) — these don't block the run but are surfaced as warnings.
type DiscoverResult struct {
	Identity      Identity
	Regions       []string
	Resources     []DiscoveredResource
	PermissionErr []*PermissionError
	OtherErrs     []error

	// IntegrityWarnings flags types the discovery-integrity probe found
	// the primary pass silently dropped: a CB-curated type with no
	// native-Describe fallback that came back empty from CloudControl,
	// yet an independent re-list saw resources for. Each becomes a
	// deterministic `warning` finding so a silent false-clean surfaces
	// instead of staying invisible. Nil when the probe found no
	// disagreement (the common, healthy case) or for ScoutOnly runs.
	// See integrity.go.
	IntegrityWarnings []IntegrityWarning

	// EventCount is an approximation of the CloudTrail Read events this
	// audit emitted into the audited account. The number is a structural
	// estimate (list calls × types × regions, plus get + describer calls
	// per resource) — not an exact counter — because the dominant cost
	// is the API call sites, not the discovery pipeline's branching, and
	// users typically want order-of-magnitude rather than ±1 fidelity.
	// Plan §7.7.
	EventCount int

	// AccountPosture carries account-level configuration probes (default
	// EBS encryption per region, IAM account summary, password policy
	// presence). These are inputs to findings that don't live on any
	// single resource — see gatherAccountPosture. Nil for ScoutOnly
	// runs where the posture pass is skipped. Owned by internal/audit
	// (shared shape) rather than this package so the LLM prompt
	// builder can render it without an import cycle.
	AccountPosture *audit.AccountPosture
}

// Discover runs the live-AWS discovery pipeline:
//  1. Load AWS config from the requested profile / credentials file
//  2. STS preflight (GetCallerIdentity) — fails closed on bad creds
//  3. Region resolution (with interactive prompt if no default)
//  4. Per-region × per-type CloudControl list+get fan-out
//  5. Map to DiscoveredResource + dedupe global services
//
// Per-resource failures collect into PermissionErr / OtherErrs without
// killing the run; only the preflight / region resolution / config-load
// failures cause Discover to return an error.
func Discover(ctx context.Context, p DiscoverParams) (*DiscoverResult, error) {
	cfg, err := LoadAWSConfig(ctx, p.Profile, p.CredentialsFile)
	if err != nil {
		return nil, err
	}

	identity, err := Preflight(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("AWS preflight failed: %w", err)
	}
	emitProgress(p.OnProgress, ProgressEvent{Phase: ProgressPhasePreflight, Identity: &identity})

	regions, err := ResolveRegions(ctx, cfg, p.Regions)
	if err != nil {
		if err != ErrNoRegion {
			return nil, err
		}
		if p.PromptForRegions == nil {
			return nil, fmt.Errorf("%w (pass --regions or set AWS_REGION)", err)
		}
		enabled, listErr := describeRegionsLive(ctx, cfg)
		if listErr != nil {
			return nil, fmt.Errorf("enumerating regions for prompt: %w", listErr)
		}
		picked, pickErr := p.PromptForRegions(ctx, enabled)
		if pickErr != nil {
			return nil, pickErr
		}
		regions, err = ResolveRegions(ctx, cfg, picked)
		if err != nil {
			return nil, err
		}
	}

	emitProgress(p.OnProgress, ProgressEvent{Phase: ProgressPhaseRegions, Regions: regions})

	// Region scout: when the user asked for --regions all, probe each
	// enabled region in parallel for any sign of life and narrow the
	// deep-scan to active regions only. This typically drops 17→3-5
	// regions and cuts the run by 5-10×. Single-region runs and
	// explicit lists skip the scout — the user already told us where
	// to look.
	var scoutPermErrs []*PermissionError
	var scoutOtherErrs []error
	if isAllRegionsRequest(p.Regions) && len(regions) > 1 {
		active, sperms, sothers := scoutRegions(ctx, cfg, regions, p.OnProgress)
		scoutPermErrs = sperms
		scoutOtherErrs = sothers
		if len(active) > 0 {
			regions = active
		}
		// If the scout found nothing anywhere, keep the original
		// region list: the deep scan will run end-to-end and confirm
		// the account is empty — better than silently skipping it.
	}

	types := p.Types
	if len(types) == 0 {
		types = discoverableCFNTypes
	}
	concurrency := p.Concurrency
	if concurrency < 1 {
		concurrency = 4
	}

	// --dry-run: bail before the expensive per-(region × type) fan-out
	// and per-resource describer work. Caller gets the resolved regions
	// and an event-count estimate based on the planned types, which is
	// the entire point of the dry run.
	if p.ScoutOnly {
		emitProgress(p.OnProgress, ProgressEvent{Phase: ProgressPhaseDiscoverDone})
		return &DiscoverResult{
			Identity:      identity,
			Regions:       regions,
			Resources:     nil,
			PermissionErr: scoutPermErrs,
			OtherErrs:     scoutOtherErrs,
			EventCount:    estimateEventCount(types, regions, nil),
		}, nil
	}

	resources, permErrs, otherErrs, integrityCandidates := fanOutDiscovery(ctx, cfg, regions, types, concurrency, p.OnProgress)
	permErrs = append(scoutPermErrs, permErrs...)
	otherErrs = append(scoutOtherErrs, otherErrs...)
	deduped := dedupeByURN(resources)

	// Discovery-integrity probe: for every CB-curated type with no
	// native fallback that came back empty (CloudControl's silent miss),
	// independently re-list it and warn when the second read disagrees.
	// The generic backstop for the long tail the per-type fallbacks can't
	// cover — see integrity.go. Deterministic, no LLM.
	integrityWarnings := probeDiscoveryIntegrity(ctx, cfg, integrityCandidates, concurrency, reprobeIdentifierCount)

	// Cross-resource KMS pass: annotate every AWS::KMS::Key with the
	// list of other resources referencing it (cb_describer_referenced_by)
	// and a derived cb_describer_is_unused boolean. Runs after dedupe
	// so global-service collapsing doesn't double-count cross-region
	// references.
	crossReferenceKMS(deduped)

	// Network reachability pass: pre-compute cb_describer_internet_routable
	// on Subnets and cb_describer_effectively_public on RDS/EC2 so the
	// LLM doesn't have to walk subnet→route-table→IGW chains itself.
	crossReferenceNetwork(deduped)

	// Lambda execution-role privilege: copy admin-policy flags from
	// IAM roles onto their consuming Lambda functions for the
	// "API GW + admin Lambda" CRITICAL pattern.
	crossReferenceLambdaRole(deduped)

	// Account-posture pass runs after fan-out so it shares the cfg
	// already authenticated by Preflight. Cheap (~4 API calls total)
	// and parallel with itself; doesn't gate the discovery result.
	posture := gatherAccountPosture(ctx, cfg, regions)

	// Trail coverage is computed from the already-discovered
	// CloudTrail::Trail resources — no extra API call needed.
	// Surfaces per-region "is any trail covering this region?" so
	// the LLM has a deterministic signal for the account-level
	// "no trail in <region>" finding.
	computeTrailCoverage(deduped, regions, posture)

	// VPC flow-log coverage: probe ec2:DescribeFlowLogs in each region
	// that hosts a discovered VPC and annotate cb_describer_flow_logs_enabled.
	// One extra API call per VPC-bearing region — deliberately left out
	// of estimateEventCount (like the other posture probes) since the
	// estimate targets order-of-magnitude, not ±1.
	annotateFlowLogs(ctx, cfg, deduped, posture)

	emitProgress(p.OnProgress, ProgressEvent{Phase: ProgressPhaseDiscoverDone})

	return &DiscoverResult{
		Identity:      identity,
		Regions:       regions,
		Resources:     deduped,
		PermissionErr: permErrs,
		OtherErrs:     otherErrs,
		// The integrity probe issues one extra cloudformation:ListResources
		// per candidate (an empty bare-curated type×region), so fold that
		// into the structural event-count estimate — same colocated-cost
		// discipline perResourceDescriberCost enforces for describers.
		EventCount:        estimateEventCount(types, regions, deduped) + len(integrityCandidates),
		AccountPosture:    posture,
		IntegrityWarnings: integrityWarnings,
	}, nil
}

// estimateEventCount approximates the number of CloudTrail Read events
// this audit emitted into the audited account. The number is a function
// of the API call sites discovery + describers traverse, not an atomic
// counter — instrumenting every SDK call would add cross-package
// plumbing for a value the user wants at order-of-magnitude precision
// ("~120 events"), not ±1.
//
// Cost model:
//   - 1 sts:GetCallerIdentity preflight call.
//   - 1 cloudformation:ListResources per (region × type) pair; Global
//     types collapse to a single region. Per-region pagination is
//     ignored (most accounts list a single page per type).
//   - 1 cloudformation:GetResource per discovered resource.
//   - Per-describer fixed cost × number of resources of that CFN type.
//     The S3 ListBuckets is shared by the once-cached fetch and so is
//     counted exactly once when any S3 buckets were discovered.
//   - ec2:DescribeRegions is omitted; it runs only when --regions wasn't
//     explicit and is bounded at 1 per audit anyway.
func estimateEventCount(types []cfnTypeSpec, regions []string, resources []DiscoveredResource) int {
	count := 1 // sts:GetCallerIdentity

	for _, t := range types {
		if t.Global {
			count++
			continue
		}
		count += len(regions)
	}

	count += len(resources)

	hasS3 := false
	for _, r := range resources {
		count += perResourceDescriberCost(r.Type)
		if r.Type == "AWS::S3::Bucket" {
			hasS3 = true
		}
	}
	if hasS3 {
		count++ // shared s3:ListBuckets (cached for the bucket-creation-date hydration)
	}

	return count
}

// perResourceDescriberCost returns the number of AWS SDK calls a single
// describer makes per resource. Kept colocated with the estimator so
// adding a new describer in the same MR forces the author to update
// the cost table.
func perResourceDescriberCost(cfnType string) int {
	switch cfnType {
	case "AWS::S3::Bucket":
		// GetPublicAccessBlock + GetBucketVersioning + GetBucketEncryption
		// + GetBucketPolicy + ListObjectsV2. (ListBuckets is global-once,
		// added separately.)
		return 5
	case "AWS::IAM::Role":
		// GetRole + ListAttachedRolePolicies + ListRolePolicies.
		// Inline GetRolePolicy fan-out is proportional to inline-policy
		// count and not folded in here — usually 0-2 per role; coarse
		// estimate stays useful at order-of-magnitude.
		return 3
	case "AWS::IAM::Group":
		// iamGroupDescriber: ListAttachedGroupPolicies.
		return 1
	case "AWS::ECR::Repository":
		// ecrRepositoryDescriber: GetLifecyclePolicy.
		return 1
	case "AWS::Backup::BackupVault":
		// backupVaultDescriber: DescribeBackupVault + GetBackupVaultAccessPolicy,
		// plus a conditional kms:DescribeKey (only when AWS omits
		// EncryptionKeyType but the vault has an EncryptionKeyArn — the default
		// `aws/backup`-key shape). Coarse upper bound: 3.
		return 3
	case "AWS::Backup::BackupPlan":
		// backupPlanDescriber: GetBackupPlan.
		return 1
	case "AWS::EKS::Cluster":
		// eksClusterDescriber: iam:ListOpenIDConnectProviders (IRSA) +
		// eks:ListPodIdentityAssociations (Pod Identity). One call each per
		// cluster; the Pod-Identity walk is usually a single page.
		return 2
	}
	// Pure-normalization describers (RDS instance/cluster, Lambda, EC2,
	// Athena workgroup) make no SDK calls.
	return 0
}

// fanOutDiscovery runs (region, type) pairs through a worker pool of
// size `concurrency`. Global types are only queried once via
// pickRegionForGlobal so we don't N×-fan IAM / CloudFront / Route53.
// Per-job errors collect into the returned slices; the function never
// returns a non-nil error itself.
func fanOutDiscovery(ctx context.Context, c awsCfg, regions []string, types []cfnTypeSpec, concurrency int, onProgress func(ProgressEvent)) (
	resources []DiscoveredResource, permErrs []*PermissionError, otherErrs []error, integrityCandidates []integrityCandidate,
) {
	type job struct {
		region string
		spec   cfnTypeSpec
	}

	var jobs []job
	for _, t := range types {
		if t.Global {
			jobs = append(jobs, job{region: pickRegionForGlobal(regions), spec: t})
			continue
		}
		for _, r := range regions {
			jobs = append(jobs, job{region: r, spec: t})
		}
	}

	if len(jobs) == 0 {
		return nil, nil, nil, nil
	}

	emitProgress(onProgress, ProgressEvent{Phase: ProgressPhaseDiscoverStart, Total: len(jobs)})

	jobCh := make(chan job)
	resCh := make(chan jobResult, len(jobs))

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				resCh <- runJob(ctx, c, j.region, j.spec, onProgress)
			}
		}()
	}

	go func() {
		for _, j := range jobs {
			select {
			case <-ctx.Done():
				close(jobCh)
				return
			case jobCh <- j:
			}
		}
		close(jobCh)
	}()

	go func() {
		wg.Wait()
		close(resCh)
	}()

	done := 0
	for r := range resCh {
		resources = append(resources, r.resources...)
		permErrs = append(permErrs, r.permErrs...)
		otherErrs = append(otherErrs, r.otherErrs...)
		if r.listErr != nil {
			if pe, ok := asPermissionError(r.listErr); ok {
				permErrs = append(permErrs, pe)
			} else {
				otherErrs = append(otherErrs, r.listErr)
			}
		}
		// A clean-empty result for a bare CB-curated type is a
		// discovery-integrity candidate: re-list it independently after
		// the fan-out to catch CloudControl's silent miss.
		if isIntegrityCandidate(r) {
			integrityCandidates = append(integrityCandidates, integrityCandidate{region: r.region, spec: r.spec})
		}
		done++
		emitProgress(onProgress, ProgressEvent{
			Phase:  ProgressPhaseJobDone,
			Region: r.region,
			Type:   r.spec.Type,
			Found:  len(r.resources),
			Done:   done,
			Total:  len(jobs),
		})
	}
	return
}

// jobResult is the per-job payload workers ship back to the
// collector: a fully-enriched resource slice plus any errors picked up
// during list+get or per-resource enrichment.
type jobResult struct {
	region    string
	spec      cfnTypeSpec
	resources []DiscoveredResource
	listErr   error
	permErrs  []*PermissionError
	otherErrs []error
}

// runJob executes one (region, type) discovery job end-to-end: list +
// get + per-resource enrichment. Returning a fully-enriched slice from
// the worker (rather than enriching serially in the collector) means
// describer-heavy types like S3 don't block other jobs' progress.
// In-job progress events fire after each resource is enriched so the
// UI can show "enriching X/N" during a long describer run.
func runJob(ctx context.Context, c awsCfg, region string, spec cfnTypeSpec, onProgress func(ProgressEvent)) jobResult {
	r := jobResult{region: region, spec: spec}

	emitProgress(onProgress, ProgressEvent{Phase: ProgressPhaseJobStart, Region: region, Type: spec.Type})

	var raws []rawResource
	var lerr error
	if spec.CustomLister != nil {
		raws, lerr = spec.CustomLister(ctx, c, region)
	} else {
		raws, lerr = listAndGet(ctx, c, region, spec)
	}
	if lerr != nil {
		r.listErr = lerr
	}

	// Fallback-on-empty: CloudControl's ListResources silently returns an
	// empty set (not an error) for freshly-created workload resources and a
	// couple of persistently under-returned types. When the primary path found
	// nothing and a strongly-consistent native Describe is wired for this type,
	// try it. Only firing on a genuinely empty result means CloudControl's
	// richer payload wins whenever it does list the type, and there's no
	// double-counting. See cfnTypeSpec.FallbackLister.
	if len(raws) == 0 && spec.FallbackLister != nil {
		fraws, ferr := spec.FallbackLister(ctx, c, region)
		if ferr != nil {
			if pe, ok := asPermissionError(ferr); ok {
				r.permErrs = append(r.permErrs, pe)
			} else {
				r.otherErrs = append(r.otherErrs, ferr)
			}
		}
		if len(fraws) > 0 {
			raws = fraws
			// The fallback recovered the resources, so the primary's
			// emptiness wasn't a fatal miss — don't surface its error.
			r.listErr = nil
		}
	}

	total := len(raws)
	d := describerFor(spec.Type)
	for i, raw := range raws {
		dr, mapErr := raw.mapToDiscovered()
		if mapErr != nil {
			r.otherErrs = append(r.otherErrs, mapErr)
			continue
		}
		if d != nil {
			if eErr := d.Enrich(ctx, c, &dr); eErr != nil {
				if pe, ok := asPermissionError(eErr); ok {
					r.permErrs = append(r.permErrs, pe)
				} else {
					r.otherErrs = append(r.otherErrs, eErr)
				}
			}
			// Per-resource progress is only useful for types with a
			// real describer — for pure-normalization types it'd just
			// be noise.
			emitProgress(onProgress, ProgressEvent{
				Phase:  ProgressPhaseEnrichProgress,
				Region: region,
				Type:   spec.Type,
				Done:   i + 1,
				Found:  total,
			})
		}
		r.resources = append(r.resources, dr)
	}
	return r
}

// emitProgress is a nil-safe shim around the OnProgress callback. Kept
// trivial so call sites stay one-liners.
func emitProgress(cb func(ProgressEvent), ev ProgressEvent) {
	if cb != nil {
		cb(ev)
	}
}

// asPermissionError type-asserts err down to *PermissionError, returning
// false if the chain doesn't contain one. Convenience around errors.As
// so call sites stay tidy.
func asPermissionError(err error) (*PermissionError, bool) {
	var pe *PermissionError
	if aerrAs(err, &pe) {
		return pe, true
	}
	return nil, false
}
