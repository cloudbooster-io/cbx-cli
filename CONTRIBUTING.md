# Contributing to cbx-cli

Thanks for your interest in `cbx-cli`. This document covers the basics for
filing issues and proposing changes.

## Filing issues

Please open issues on GitHub:
<https://github.com/cloudbooster-io/cbx-cli/issues>

When reporting a bug, include:

- `cbx version` output
- OS / architecture
- The exact command you ran and the output you saw
- What you expected to happen instead

For security-sensitive reports, do **not** open a public issue — see
[`SECURITY.md`](./SECURITY.md).

## Proposing changes

1. Fork the repository (or create a branch if you have push access).
2. Create a topic branch off `main`.
3. Make your change. Keep commits focused; one logical change per commit.
4. Run the local checks before pushing:

   ```sh
   make lint
   make test
   ```

5. Open a Pull Request against `main`. Reference any related GitHub
   issue (e.g. `#123`) in the title and description.
6. The CI pipeline must pass before review. It runs vet + build,
   `golangci-lint`, a generated-code drift check, unit tests, and the e2e
   suite. (Releases are cut by a separate tag-triggered GoReleaser job;
   contributors never need to touch it.)

## Development setup

Build and test locally:

```sh
make build   # produces ./bin/cbx
make test
```

For deeper architecture and module layout, see the project README.

## Code style

- Go: standard `gofmt` / `goimports`. CI runs `golangci-lint`.
- Keep public-facing CLI output stable; user-visible string changes should
  be flagged in the PR description.

## Licensing of contributions

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](./LICENSE), the same license as the project.
