# Implementation Plan — CB-392

## Type refactor
- [ ] `internal/audit/types.go` — rename `Resource` → `DiscoveredResource`, add JSON tags, `Region`, `Tags`, add `Yes` to `Options`
- [ ] `internal/audit/scanner.go` — update all `Resource` references → `DiscoveredResource`
- [ ] `internal/audit/scanner_test.go` — update test literals

## Parser extraction
- [ ] `internal/audit/parsers/pulumi_state.go` — `ParsePulumiState`, tag/region extraction
- [ ] `internal/audit/parsers/terraform_state.go` — `ParseTerraformState`, tag/region extraction, provisioner/remote-exec denylist
- [ ] `internal/audit/parser.go` — refactor `ParseState` to accept `Options`, add 100MB guard + confirmation prompt, three-line errors, delegate to new parsers
- [ ] `internal/audit/runner.go` — pass `opts` to `ParseState`

## CLI wiring
- [ ] `cmd/cbx/audit.go` — add `--yes` flag, thread into `Options`

## Tests
- [ ] `internal/audit/parser_test.go` — update existing tests, add size-guard + malformed-input + denylist tests
- [ ] `internal/audit/parsers/pulumi_state_test.go` — new unit tests with fixtures
- [ ] `internal/audit/parsers/terraform_state_test.go` — new unit tests with fixtures
- [ ] `e2e/audit_test.go` — add large-file + `--yes` test, malicious fixture test

## Verification
- [ ] `go test ./internal/audit/...` — all pass
- [ ] `go test ./e2e/...` — all pass
- [ ] `go vet ./internal/audit/...` — clean
