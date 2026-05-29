// Package update checks for newer versions of cbx on GitHub Releases,
// caches the result, and detects the current install method.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// ErrNoReleases is returned by Check when the upstream project has no
// releases published yet (HTTP 404 on the releases permalink endpoint).
// Callers can treat this as a non-failure — there is simply nothing to
// compare against.
var ErrNoReleases = errors.New("no releases published yet")

const (
	// githubRepo is the owner/repo of the cbx-cli project on github.com.
	// Used as <owner>/<repo> in /repos/<owner>/<repo>/releases/latest.
	githubRepo = "cloudbooster-io/cbx-cli"
	// defaultReleasesAPI is the public GitHub REST releases endpoint base.
	// Override via $CBX_RELEASES_URL (no trailing slash) for tests or a
	// GitHub Enterprise host.
	defaultReleasesAPI = "https://api.github.com/repos"
	// fallbackHTMLURL is shown when we don't have a release-specific URL
	// (e.g. in upgrade hints).
	fallbackHTMLURL = "https://github.com/cloudbooster-io/cbx-cli/releases"
	cacheFile       = "update-check.json"
	cacheDir        = "cbx"
	cacheTTL        = 24 * time.Hour
)

// InstallMethod describes how cbx was installed.
type InstallMethod string

const (
	InstallBrew    InstallMethod = "brew"
	InstallScoop   InstallMethod = "scoop"
	InstallDirect  InstallMethod = "direct"
	InstallUnknown InstallMethod = "unknown"
)

// Result holds the outcome of a version check.
type Result struct {
	CurrentVersion string        `json:"current_version"`
	LatestVersion  string        `json:"latest_version"`
	HasUpdate      bool          `json:"has_update"`
	ReleaseURL     string        `json:"release_url"`
	InstallMethod  InstallMethod `json:"install_method"`
}

// Checker queries GitHub Releases for updates.
type Checker struct {
	CurrentVersion string
	HTTPClient     *http.Client
	// IgnoreCache forces a fresh network check; the result is still
	// written back so subsequent reads pick it up. Used by `cbx upgrade`
	// where the user explicitly asked for current state.
	IgnoreCache bool
}

// NewChecker creates a Checker for the given current version.
func NewChecker(currentVersion string) *Checker {
	return &Checker{
		CurrentVersion: currentVersion,
		HTTPClient:     &http.Client{Timeout: 5 * time.Second},
	}
}

// Check returns the latest release information, using the on-disk cache when
// it is still fresh.
func (c *Checker) Check(ctx context.Context) (*Result, error) {
	if !c.IgnoreCache {
		if entry, ok := readCache(); ok {
			return c.resultFromCache(entry), nil
		}
	}

	release, err := c.fetchLatest(ctx)
	if err != nil {
		return nil, err
	}

	entry := &cacheEntry{
		CheckedAt:     time.Now().UTC(),
		LatestVersion: release.TagName,
		ReleaseURL:    release.HTMLURL,
	}
	_ = writeCache(entry)

	return c.buildResult(release.TagName, release.HTMLURL), nil
}

// IsDisabled returns true when the background update check should be skipped.
func IsDisabled() bool {
	if os.Getenv("CI") == "true" {
		return true
	}
	if config.Env("NO_UPDATE_CHECK") == "1" {
		return true
	}
	return false
}

// DetectInstallMethod returns how cbx appears to have been installed.
func DetectInstallMethod() InstallMethod {
	exe, err := os.Executable()
	if err != nil {
		return InstallUnknown
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		exe, _ = os.Executable()
	}

	// Brew detection
	if strings.Contains(exe, "/Cellar/") || strings.Contains(exe, "/homebrew/Cellar/") {
		return InstallBrew
	}
	if _, err := exec.LookPath("brew"); err == nil {
		// Heuristic: binary is inside brew prefix
		out, _ := exec.Command("brew", "--prefix").Output()
		prefix := strings.TrimSpace(string(out))
		if prefix != "" && strings.HasPrefix(exe, prefix) {
			return InstallBrew
		}
	}

	// Scoop detection (Windows)
	if strings.Contains(exe, `\scoop\apps\`) || strings.Contains(exe, "/scoop/apps/") {
		return InstallScoop
	}

	return InstallDirect
}

// Upgrade attempts an in-place upgrade using the detected install method.
func Upgrade(ctx context.Context, result *Result) error {
	switch result.InstallMethod {
	case InstallBrew:
		return upgradeBrew(ctx)
	case InstallScoop:
		return upgradeScoop(ctx)
	case InstallDirect:
		return upgradeDirect(ctx, result)
	default:
		return fmt.Errorf("unable to detect install method; install manually from %s", result.ReleaseURL)
	}
}

// UpgradeCommand returns the shell command a user should run to upgrade.
func UpgradeCommand(result *Result) string {
	switch result.InstallMethod {
	case InstallBrew:
		return "brew upgrade cbx-cli"
	case InstallScoop:
		return "scoop update cbx-cli"
	default:
		return fmt.Sprintf("curl -fsSL %s | tar -xz && mv cbx $(which cbx)", directAssetURL(result))
	}
}

// releasesAPIBase returns the GitHub API base for releases, respecting the
// CBX_RELEASES_URL override (used for tests or a GitHub Enterprise host).
func releasesAPIBase() string {
	if v := config.Env("RELEASES_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultReleasesAPI
}

func (c *Checker) fetchLatest(ctx context.Context) (*release, error) {
	endpoint := fmt.Sprintf("%s/%s/releases/latest",
		releasesAPIBase(),
		githubRepo,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoReleases
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding release: %w", err)
	}
	// GitHub returns the human-facing release URL under html_url.
	if rel.HTMLURL == "" {
		rel.HTMLURL = fallbackHTMLURL
	}
	return &rel, nil
}

func (c *Checker) buildResult(latestVersion, releaseURL string) *Result {
	return &Result{
		CurrentVersion: c.CurrentVersion,
		LatestVersion:  latestVersion,
		HasUpdate:      semverGreaterThan(latestVersion, c.CurrentVersion),
		ReleaseURL:     releaseURL,
		InstallMethod:  DetectInstallMethod(),
	}
}

func (c *Checker) resultFromCache(entry *cacheEntry) *Result {
	return c.buildResult(entry.LatestVersion, entry.ReleaseURL)
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

type cacheEntry struct {
	CheckedAt     time.Time `json:"checked_at"`
	LatestVersion string    `json:"latest_version"`
	ReleaseURL    string    `json:"release_url"`
}

func cachePath() string {
	// XDG-compliant: $XDG_CACHE_HOME wins, falling back to
	// $HOME/.cache. Same shape as `cbx-cli`'s config-dir lookup so
	// the directory layout stays predictable.
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, cacheDir, cacheFile)
}

func readCache() (*cacheEntry, bool) {
	data, err := os.ReadFile(cachePath())
	if err != nil {
		return nil, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}
	if time.Since(entry.CheckedAt) > cacheTTL {
		return nil, false
	}
	return &entry, true
}

func writeCache(entry *cacheEntry) error {
	path := cachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ---------------------------------------------------------------------------
// GitHub types
// ---------------------------------------------------------------------------

// release matches the GitHub releases JSON shape: tag_name plus the
// human-facing html_url.
type release struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// ---------------------------------------------------------------------------
// Semver
// ---------------------------------------------------------------------------

func semverGreaterThan(a, b string) bool {
	// "dev" or empty never counts as newer than a release.
	if b == "dev" || b == "" || b == "unknown" {
		return a != "dev" && a != "" && a != "unknown"
	}
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		var ai, bi int
		if i < len(aParts) {
			ai, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bi, _ = strconv.Atoi(bParts[i])
		}
		if ai != bi {
			return ai > bi
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Upgrade helpers
// ---------------------------------------------------------------------------

func upgradeBrew(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "brew", "upgrade", "cbx-cli")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func upgradeScoop(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "scoop", "update", "cbx-cli")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func upgradeDirect(ctx context.Context, result *Result) error {
	_ = ctx
	_ = result
	return fmt.Errorf("direct in-place upgrade not yet implemented; download from %s", result.ReleaseURL)
}

func directAssetURL(result *Result) string {
	// Best-effort asset URL construction matching the GoReleaser archive
	// naming convention. GitHub release-asset URL pattern is:
	//   https://github.com/<owner>/<repo>/releases/download/<tag>/<filename>
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	if goos == "darwin" {
		goos = "Darwin"
	} else if goos == "linux" {
		goos = "Linux"
	} else if goos == "windows" {
		goos = "Windows"
	}
	if goarch == "amd64" {
		goarch = "x86_64"
	} else if goarch == "arm64" {
		goarch = "arm64"
	}
	return fmt.Sprintf("%s/download/%s/cbx-cli_%s_%s.tar.gz",
		fallbackHTMLURL, result.LatestVersion, goos, goarch)
}
