# Maintainers

This file lists the people responsible for `cbx-cli`. Maintainers review and
merge pull requests, cut releases, and triage the issue tracker. For how to
propose changes, see [`CONTRIBUTING.md`](./CONTRIBUTING.md); for security
reports, see [`SECURITY.md`](./SECURITY.md).

## Current maintainers

| Maintainer | GitHub | Area |
|---|---|---|
| Radek Forgáč | [@rforgac](https://github.com/rforgac) | CLI, audit pipeline, releases |
| Dominik | [@snopedom](https://github.com/snopedom) | CLI, platform integration |

The same set of maintainers is encoded in
[`.github/CODEOWNERS`](./.github/CODEOWNERS) for automatic review requests.

## Decision making

Changes land through pull requests against `main`. Every PR requires at least
one approving review from a maintainer and a green CI run before it can be
merged (branch protection enforces this for everyone, including maintainers).
The `pkg/` and `core/` trees are a semver-public library surface consumed by
downstream tools — changes there get extra scrutiny.

## Releases

Releases are cut by pushing a `vX.Y.Z` tag, which triggers the GoReleaser
workflow. Only maintainers (and the `cbx-release-bot` GitHub App) can create
release tags; the bot publishes the GitHub Release and the Homebrew cask and
Scoop manifests. See [`.github/workflows/release.yml`](./.github/workflows/release.yml).

## Becoming a maintainer

Sustained, high-quality contributions are the path to maintainership. If you
are interested, open a discussion or reach out to an existing maintainer.
