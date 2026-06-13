package rulesbundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Resolve implements the rulepack failure ladder (plan §B.3; API-only
// — the embedded copy was removed, the registry is the sole content
// source):
//
//	override file → network (ETag-revalidated) → on-disk cache
//
// The ladder never yields an empty ruleset — a rule-less grounded
// prompt would still produce plausible findings ("the list is NOT
// exhaustive"), which is the false-green failure mode the registry
// design exists to prevent. When every rung comes up empty, Resolve
// returns ErrNoRulePack rather than degrading further. The other
// abort-class conditions where running anyway would be wrong:
//
//   - an explicit CBX_AUDIT_RULES_FILE override that cannot be loaded
//     (a broken dev/sweep lever must fail loud, not silently fall back);
//   - a version pin no source can satisfy (a sweep running unpinned
//     rules is unscoreable — the false-green again);
//   - a pack whose min_engine_version this engine does not satisfy
//     ("upgrade cbx", plan §B.4 — the pack may reference describer
//     fields this engine never emits).
//
// Transient failures with a usable cache degrade onto it and are
// reported in Provenance, which callers surface in the report header,
// --json, .state.json, and the LLM-CB-RULES-* meta-findings.

// ErrNotModified mirrors the knowledge client's 304 sentinel without
// importing it — rulesbundle stays dependency-free of the HTTP layer.
// The FetchFunc adapter in internal/audit maps one onto the other.
var ErrNotModified = errors.New("rulesbundle: not modified")

// ErrNotAuthored mirrors the knowledge client's 404 sentinel: the
// registry does not have what was asked for (unknown channel/schema,
// or a pinned version it doesn't hold). Falls to the on-disk cache;
// with no usable cache the ladder exhausts into ErrNoRulePack.
var ErrNotAuthored = errors.New("rulesbundle: not authored")

// ErrNoRulePack reports that every rung of the ladder came up empty:
// no override file, no (or failed) network fetch, no usable cache.
// The pack is API-distributed with no embedded floor, so this is
// abort-class — the grounded audit must not run without a validated
// pack.
var ErrNoRulePack = errors.New("rulesbundle: no rule pack available")

// FetchFunc fetches the artifact bytes for (channel, etag, pin). It is
// the seam between this package and the HTTP client: return
// ErrNotModified for a 304 (etag still current) and ErrNotAuthored for
// a 404. nil FetchFunc means "no network" — the ladder starts at the
// cache. Implementations must return the served bytes verbatim.
type FetchFunc func(ctx context.Context, channel, etag string, pin int) (raw []byte, newETag string, err error)

// defaultGraceWindow is how old a cache may grow before serving it is
// flagged Stale (escalated to the LLM-CB-RULES-STALE warning). Matches
// the 7-day grace the plan's endgame option (b) names.
const defaultGraceWindow = 7 * 24 * time.Hour

// ResolveOptions configures one resolution. Zero value = stable
// channel, latest version, no network — which can resolve only via
// an override file or a previously populated cache.
type ResolveOptions struct {
	// Channel selects the pack channel; "" means "stable".
	Channel string
	// PinVersion pins an exact pack_version (sweep bisection lever);
	// 0 means latest. A pin no source satisfies is an error.
	PinVersion int
	// OverrideFile, when non-empty (CBX_AUDIT_RULES_FILE), bypasses
	// network and cache entirely. Load failures are errors.
	OverrideFile string
	// EngineVersion is the running cbx version (ldflags-injected,
	// e.g. "v0.4.1"; "dev" and other non-semver builds satisfy every
	// constraint). Compared against manifest.min_engine_version.
	EngineVersion string
	// GraceWindow overrides the cache staleness window; 0 = 7 days.
	GraceWindow time.Duration
	// Fetch performs the network fetch; nil disables the network rung.
	Fetch FetchFunc
}

// Provenance records which rung of the ladder served the pack — every
// audit output names it so a sweep verdict is always scoped to an
// exact pack (an unscoped verdict is unscoreable).
type Provenance struct {
	// Source is the ladder rung: "network", "cache", "file".
	Source string `json:"source"`
	// Channel is the pack channel requested ("" only for file source).
	Channel string `json:"channel,omitempty"`
	// PackVersion / SchemaVersion / ContentSHA256 identify the pack.
	PackVersion   int    `json:"pack_version"`
	SchemaVersion int    `json:"schema_version"`
	ContentSHA256 string `json:"content_sha256"`
	// PinnedVersion echoes ResolveOptions.PinVersion when set.
	PinnedVersion int `json:"pinned_version,omitempty"`
	// FetchedAt is when the served bytes were last confirmed current
	// against the registry (network fetch or 304 revalidation), RFC3339.
	// Empty for the file source.
	FetchedAt string `json:"fetched_at,omitempty"`
	// Stale marks a cache older than the grace window.
	Stale bool `json:"stale,omitempty"`
	// Degraded marks that a network fetch was attempted and failed
	// transiently (NOT a 404 — an unknown channel/version is a
	// deterministic registry answer, not degradation).
	Degraded bool `json:"degraded,omitempty"`
	// FetchError carries the stringified network failure when Degraded
	// (or the 404 note when the ladder fell through one).
	FetchError string `json:"fetch_error,omitempty"`
}

// Resolve runs the ladder and returns the pack to ground the audit
// with. See the package comment above for the abort-class error cases;
// the returned pack is always validated.
func Resolve(ctx context.Context, opts ResolveOptions) (*RulePack, Provenance, error) {
	channel := opts.Channel
	if channel == "" {
		channel = "stable"
	}
	grace := opts.GraceWindow
	if grace == 0 {
		grace = defaultGraceWindow
	}

	// Rung 0 — explicit local override (dev / sweep-bisection lever).
	if opts.OverrideFile != "" {
		raw, err := os.ReadFile(opts.OverrideFile)
		if err != nil {
			return nil, Provenance{}, fmt.Errorf("rulesbundle: CBX_AUDIT_RULES_FILE: %w", err)
		}
		pack, err := Parse(raw)
		if err != nil {
			return nil, Provenance{}, fmt.Errorf("rulesbundle: CBX_AUDIT_RULES_FILE %s: %w", opts.OverrideFile, err)
		}
		if err := checkPin(opts.PinVersion, pack, "override file"); err != nil {
			return nil, Provenance{}, err
		}
		if err := checkEngine(opts.EngineVersion, pack, "override file"); err != nil {
			return nil, Provenance{}, err
		}
		return pack, provenanceFor("file", "", pack, opts.PinVersion), nil
	}

	var (
		degraded   bool
		fetchError string
	)

	// Rung 1 — network, revalidated against the cache's ETag.
	if opts.Fetch != nil {
		etag := ""
		cachedPack, cachedMeta, cacheOK := loadCachedPack(channel)
		if cacheOK && (opts.PinVersion == 0 || cachedMeta.PackVersion == opts.PinVersion) {
			etag = cachedMeta.ETag
		}

		raw, newETag, err := opts.Fetch(ctx, channel, etag, opts.PinVersion)
		switch {
		case err == nil:
			pack, perr := Parse(raw)
			if perr != nil {
				// A served-but-invalid artifact is degradation, not a 404:
				// record it and fall down the ladder.
				degraded, fetchError = true, perr.Error()
				break
			}
			if opts.PinVersion > 0 && pack.Manifest.PackVersion != opts.PinVersion {
				degraded, fetchError = true, fmt.Sprintf("registry served pack_version %d for pinned version %d", pack.Manifest.PackVersion, opts.PinVersion)
				break
			}
			if err := checkEngine(opts.EngineVersion, pack, "registry pack"); err != nil {
				return nil, Provenance{}, err
			}
			now := timeNow()
			// Cache write is best-effort: a read-only HOME must not fail
			// the audit. The pack in hand is already validated.
			_ = storeCachedPack(channel, raw, newETag, pack, now)
			prov := provenanceFor("network", channel, pack, opts.PinVersion)
			prov.FetchedAt = now.UTC().Format(time.RFC3339)
			return pack, prov, nil

		case errors.Is(err, ErrNotModified):
			// The pin guard mirrors rung 2: the ETag gate above already
			// withholds the ETag on a pin mismatch (so a conforming
			// fetcher never 304s here), but a FetchFunc that ignores the
			// etag argument must not be able to smuggle the wrong
			// version past the pin.
			if cacheOK && (opts.PinVersion == 0 || cachedMeta.PackVersion == opts.PinVersion) {
				if err := checkEngine(opts.EngineVersion, cachedPack, "cached pack"); err != nil {
					return nil, Provenance{}, err
				}
				now := timeNow()
				_ = refreshCachedMeta(channel, cachedMeta, now)
				prov := provenanceFor("cache", channel, cachedPack, opts.PinVersion)
				prov.FetchedAt = now.UTC().Format(time.RFC3339)
				return cachedPack, prov, nil
			}
			// 304 against a cache that vanished mid-run (or one that
			// cannot satisfy the pin): refetch unconditionally once,
			// then fall through on failure.
			raw, newETag, err = opts.Fetch(ctx, channel, "", opts.PinVersion)
			if err == nil {
				if pack, perr := Parse(raw); perr == nil && (opts.PinVersion == 0 || pack.Manifest.PackVersion == opts.PinVersion) {
					if err := checkEngine(opts.EngineVersion, pack, "registry pack"); err != nil {
						return nil, Provenance{}, err
					}
					now := timeNow()
					_ = storeCachedPack(channel, raw, newETag, pack, now)
					prov := provenanceFor("network", channel, pack, opts.PinVersion)
					prov.FetchedAt = now.UTC().Format(time.RFC3339)
					return pack, prov, nil
				}
			}
			degraded, fetchError = true, "304 revalidation with no readable cache"

		case errors.Is(err, ErrNotAuthored):
			// Deterministic registry miss (unknown channel/schema, or a
			// pinned version it doesn't hold). Not degradation; note it
			// and fall to the cache.
			fetchError = err.Error()

		default:
			degraded, fetchError = true, err.Error()
		}
	}

	// Rung 2 — on-disk cache.
	cacheNote := "no usable cache"
	if pack, meta, ok := loadCachedPack(channel); ok {
		if opts.PinVersion == 0 || meta.PackVersion == opts.PinVersion {
			if err := checkEngine(opts.EngineVersion, pack, "cached pack"); err != nil {
				return nil, Provenance{}, err
			}
			prov := provenanceFor("cache", channel, pack, opts.PinVersion)
			prov.FetchedAt = meta.FetchedAt.UTC().Format(time.RFC3339)
			prov.Stale = timeNow().Sub(meta.FetchedAt) > grace
			prov.Degraded = degraded
			prov.FetchError = fetchError
			return pack, prov, nil
		}
		cacheNote = fmt.Sprintf("cache holds pack_version %d", meta.PackVersion)
	}

	// Ladder exhausted. The pack is API-distributed and nothing local
	// can serve it — running anyway is the false-green failure mode, so
	// abort with each rung's reason and the way out.
	artifactPath, _ := cachePaths(channel)
	var why []string
	if opts.PinVersion > 0 {
		why = append(why, fmt.Sprintf("pinned pack_version %d unsatisfied", opts.PinVersion))
	}
	switch {
	case opts.Fetch == nil:
		why = append(why, "network rung disabled in this construction")
	case fetchError != "":
		why = append(why, "registry: "+fetchError)
	default:
		why = append(why, "registry fetch returned no pack")
	}
	why = append(why, fmt.Sprintf("%s (%s)", cacheNote, artifactPath))
	return nil, Provenance{}, fmt.Errorf("%w for channel %q: %s — retry when the registry is reachable (one online `cbx audit aws` run populates the cache), or set CBX_AUDIT_RULES_FILE to a local pack file",
		ErrNoRulePack, channel, strings.Join(why, "; "))
}

func provenanceFor(source, channel string, pack *RulePack, pin int) Provenance {
	return Provenance{
		Source:        source,
		Channel:       channel,
		PackVersion:   pack.Manifest.PackVersion,
		SchemaVersion: pack.Manifest.SchemaVersion,
		ContentSHA256: pack.Manifest.ContentSHA256,
		PinnedVersion: pin,
	}
}

func checkPin(pin int, pack *RulePack, source string) error {
	if pin == 0 || pack.Manifest.PackVersion == pin {
		return nil
	}
	return fmt.Errorf("rulesbundle: pinned rulepack version %d unavailable (%s is version %d)", pin, source, pack.Manifest.PackVersion)
}

// checkEngine enforces the manifest's min_engine_version handshake
// (plan §B.4): a pack that needs a newer engine may reference
// cb_describer_* fields this build never emits, so running it would
// silently miss findings — abort with an actionable upgrade message
// instead. Non-semver engine versions (dev builds) satisfy everything.
func checkEngine(engine string, pack *RulePack, source string) error {
	min := pack.Manifest.MinEngineVersion
	if min == "" {
		return nil
	}
	e, m := ensureV(engine), ensureV(min)
	if !semver.IsValid(e) || !semver.IsValid(m) {
		return nil
	}
	if semver.Compare(e, m) < 0 {
		return fmt.Errorf("rulesbundle: %s (pack_version %d) requires cbx %s or newer, this build is %s — run `cbx upgrade`",
			source, pack.Manifest.PackVersion, min, engine)
	}
	return nil
}

func ensureV(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
