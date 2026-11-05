# AGENTS.md

scrub is a local metadata stripper CLI. Go, stdlib only, no network. Public repo.

## Commands

- Build: `go build ./cmd/scrub`
- Test: `go test -count=1 ./...`
- Vet: `go vet ./...`
- Format check: `test -z "$(gofmt -l .)"`
- Fuzz: `go test -run=^$ -fuzz=FuzzSanitize -fuzztime=30s ./pkg/sanitize` (also `FuzzScan`)
- Self-test: `go build -o scrub ./cmd/scrub && ./scrub --offline-check`
- Network gate: `go list -deps ./... | grep -E '^net(/|$)|^crypto/tls$'` must print nothing

## Layout

- `pkg/sanitize/`: the audited core. Library first. No CLI concerns, no printing, `io.Reader` and `io.Writer` only.
- `pkg/sanitize/verify.go`: the independent re-scan of output bytes.
- `cmd/scrub/`: thin CLI. Flags, formatting and exit codes only.
- `.github/workflows/ci.yml`: the gates listed below.

## Rules

Security invariants are release blockers. Never break them.

1. Zero network. No `net` package may appear anywhere in the build graph. CI enforces this.
2. Process in memory, locally. No temp files.
3. No silent failure. If sanitization cannot be verified, fail loudly, exit non-zero and write nothing.
4. Verify, do not trust. Every `Sanitize` ends with a re-scan of the output bytes. A handler never marks its own work clean.
5. Stdlib only. CI fails on any third-party import. Add a dependency only after a vetting checklist the maintainer approves.
6. Never overwrite the user's original file.

Conventions:

- Exit codes: 0 ok, 1 error, 2 residue, 3 unsupported.
- Build dirty test fixtures in code (`pkg/sanitize/fixtures_test.go`). Do not commit binary fixtures.
- Prefer reconstruction (re-encode, rebuild) over tag deletion wherever the format allows.
- Every bug fix lands with a regression test.
- No internal hostnames, employer names, debug prints or commented-out code. Comments say why, not what.

## Before you open a PR

CI runs these. Run them locally first.

1. `go vet ./...`
2. `test -z "$(gofmt -l .)"`
3. `go build ./...`
4. `go test -count=1 ./...` (CI runs it in a no-network namespace)
5. The fuzz targets `FuzzScan` and `FuzzSanitize`, 20 seconds each.
6. The network gate and the third-party import gate (see `ci.yml`).
7. `govulncheck ./...`
8. `./scrub --offline-check`
