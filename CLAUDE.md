# CLAUDE.md — scrub

Local metadata stripper CLI. Go, stdlib only, public repo.

## Security invariants (release blockers, never violate)

1. Zero network: no net packages anywhere in the build graph. CI
   gate in `.github/workflows/ci.yml` enforces this.
2. Local-only processing, in memory. No temp files.
3. No silent failure: if sanitization can't be verified, fail loudly,
   exit non-zero, write nothing.
4. Verify, don't trust: every Sanitize ends with an independent
   re-scan of output bytes (`pkg/sanitize/verify.go`). Handlers can
   never mark their own work clean.
5. No new dependencies without the vetting checklist in the project
   plan (`~/omnidim/_research/` context). v0.1 is stdlib-only and CI
   fails on any third-party import.
6. Never overwrite the user's original file.

## Layout

- `pkg/sanitize/` — the audited core. Library-first; no CLI concerns,
  no printing, io.Reader/io.Writer only.
- `cmd/scrub/` — thin CLI. Flags, formatting, exit codes only.
  Exit codes: 0 ok, 1 error, 2 residue, 3 unsupported.

## Commands

- Test: `go test ./...`
- Fuzz: `go test -run=^$ -fuzz=FuzzSanitize -fuzztime=30s ./pkg/sanitize`
- Build: `go build ./cmd/scrub`

## Conventions

- Public repo hygiene: no internal hostnames, employer names, debug
  prints, commented-out code, or narrative comments. Comments say why,
  not what.
- Dirty test fixtures are constructed in code
  (`pkg/sanitize/fixtures_test.go`), not committed as binaries, so
  they stay reviewable.
- Sanitization strategy is reconstruction (re-encode, rebuild), not
  tag deletion, wherever the format allows.
- Every bug fix lands with a regression test.
