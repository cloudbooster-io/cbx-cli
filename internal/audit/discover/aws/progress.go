package aws

// ProgressPhase enumerates the discovery lifecycle stages the
// OnProgress callback receives. Kept as a typed string so callers can
// switch on it and so adding a phase doesn't change the callback's
// type signature.
type ProgressPhase string

const (
	// ProgressPhasePreflight fires once after STS GetCallerIdentity
	// returns; Identity is populated.
	ProgressPhasePreflight ProgressPhase = "preflight"
	// ProgressPhaseRegions fires once after region resolution; Regions
	// is populated.
	ProgressPhaseRegions ProgressPhase = "regions"
	// ProgressPhaseScoutStart fires once just before the region scout
	// begins; Total is the number of regions to probe.
	ProgressPhaseScoutStart ProgressPhase = "scout-start"
	// ProgressPhaseScoutRegionDone fires after each region's probe
	// completes. Region, Found (count of resources across probe types),
	// Done, Total are populated.
	ProgressPhaseScoutRegionDone ProgressPhase = "scout-region-done"
	// ProgressPhaseScoutDone fires after the scout completes. Regions
	// is the narrowed list of active regions that will be deep-scanned.
	ProgressPhaseScoutDone ProgressPhase = "scout-done"
	// ProgressPhaseDiscoverStart fires once just before the per-region
	// per-type fan-out begins; Total is the total job count.
	ProgressPhaseDiscoverStart ProgressPhase = "discover-start"
	// ProgressPhaseJobStart fires when a worker picks up a job, before
	// any AWS call. Region and Type are populated. Lets the UI track
	// which (region,type) tuples are currently in-flight so a hung job
	// (e.g. throttled API, network stall) becomes visible instead of
	// hiding behind a stalled progress counter.
	ProgressPhaseJobStart ProgressPhase = "job-start"
	// ProgressPhaseEnrichProgress fires mid-job, once per enriched
	// resource, when a describer is running. Region, Type, Done (=
	// resources enriched so far in this job), Found (= resources in
	// this job) are populated. Lets the UI distinguish "stuck" from
	// "still enriching N S3 buckets".
	ProgressPhaseEnrichProgress ProgressPhase = "enrich-progress"
	// ProgressPhaseJobDone fires after each (region, type) job
	// completes (success or per-call error). Region, Type, Found,
	// Done, Total are populated.
	ProgressPhaseJobDone ProgressPhase = "job-done"
	// ProgressPhaseDiscoverDone fires once after fan-out completes.
	ProgressPhaseDiscoverDone ProgressPhase = "discover-done"
)

// ProgressEvent is the payload the OnProgress callback receives. Only
// fields relevant to the current Phase are populated.
type ProgressEvent struct {
	Phase    ProgressPhase
	Region   string    // job-done
	Type     string    // job-done (CFN type, e.g. "AWS::S3::Bucket")
	Found    int       // job-done: resources returned by this job
	Done     int       // job-done: jobs completed so far (1..Total)
	Total    int       // discover-start, job-done: total jobs
	Identity *Identity // preflight
	Regions  []string  // regions
}
