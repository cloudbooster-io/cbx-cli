package rulesbundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// On-disk cache for fetched rule packs (plan §B.3). Layout, mirroring
// the update checker's XDG convention (internal/update/update.go):
//
//	$XDG_CACHE_HOME|$HOME/.cache / cbx/rulepack/
//	    aws-<channel>-schema1.json       — the artifact bytes VERBATIM
//	    aws-<channel>-schema1.meta.json  — revalidation sidecar
//
// The artifact is cached byte-exact (never re-marshalled): P3 signature
// verification must run over the same bytes the server signed. Both
// files are written atomically (temp + rename) so a crash mid-write
// can never leave a torn artifact that parses but lies.
//
// Read errors degrade to a cache miss; write errors propagate to the
// caller (which treats them as best-effort — a read-only HOME must not
// break the audit).

// timeNow is swappable in tests (staleness windows, fetched_at stamps).
var timeNow = time.Now

// cacheMeta is the revalidation sidecar persisted next to the cached
// artifact. PackVersion and ContentSHA256 duplicate manifest fields so
// pin checks and provenance reads don't need to parse the artifact.
type cacheMeta struct {
	ETag          string    `json:"etag,omitempty"`
	FetchedAt     time.Time `json:"fetched_at"`
	PackVersion   int       `json:"pack_version"`
	ContentSHA256 string    `json:"content_sha256"`
}

// cacheBaseDir resolves the rulepack cache directory: $XDG_CACHE_HOME
// wins, falling back to $HOME/.cache — the exact shape the update
// checker uses, so cbx keeps one predictable cache tree.
func cacheBaseDir() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "cbx", "rulepack")
}

func cachePaths(channel string) (artifact, meta string) {
	name := fmt.Sprintf("aws-%s-schema%d.json", channel, 1)
	return filepath.Join(cacheBaseDir(), name),
		filepath.Join(cacheBaseDir(), fmt.Sprintf("aws-%s-schema%d.meta.json", channel, 1))
}

// loadCachedPack reads and validates the cached artifact for channel.
// Any failure — missing files, torn meta, an artifact that no longer
// passes Validate — is a plain cache miss (ok=false), never an error:
// the resolve ladder has lower rungs.
func loadCachedPack(channel string) (pack *RulePack, meta cacheMeta, ok bool) {
	artifactPath, metaPath := cachePaths(channel)
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, cacheMeta{}, false
	}
	metaRaw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, cacheMeta{}, false
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return nil, cacheMeta{}, false
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, cacheMeta{}, false
	}
	return p, meta, true
}

// storeCachedPack persists the fetched artifact bytes verbatim plus the
// revalidation sidecar. fetchedAt is stamped by the caller (timeNow).
func storeCachedPack(channel string, raw []byte, etag string, pack *RulePack, fetchedAt time.Time) error {
	artifactPath, metaPath := cachePaths(channel)
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(artifactPath, raw, 0o644); err != nil {
		return err
	}
	metaRaw, err := json.MarshalIndent(cacheMeta{
		ETag:          etag,
		FetchedAt:     fetchedAt.UTC(),
		PackVersion:   pack.Manifest.PackVersion,
		ContentSHA256: pack.Manifest.ContentSHA256,
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(metaPath, metaRaw, 0o644)
}

// refreshCachedMeta re-stamps fetched_at after a 304 revalidation: the
// artifact bytes are untouched, but the cache is now known-current.
func refreshCachedMeta(channel string, meta cacheMeta, revalidatedAt time.Time) error {
	_, metaPath := cachePaths(channel)
	meta.FetchedAt = revalidatedAt.UTC()
	metaRaw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(metaPath, metaRaw, 0o644)
}

// writeFileAtomic writes via a temp file in the target directory and
// renames into place — readers never observe a torn file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Cleanup calls on the failure paths are best-effort by design —
	// the write error is the one worth reporting.
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
