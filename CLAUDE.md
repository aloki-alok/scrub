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

## Roadmap / TODO

Phase 1 (JPEG/PNG/GIF/WEBP + OOXML strip + verifier + CLI + CI) is
complete and verified. Pending, roughly in priority order:

- [ ] Redaction library + self-host HTTP service. Promote `pkg/sanitize`
      into a stable, documented public API (the library others import),
      and ship an optional self-hostable HTTP service that strips
      uploads in-memory and streams the clean file back. Same invariants
      apply: zero net in the core, no temp files, verify-before-return,
      never persist the upload. Service is a thin handler over the
      library, behind a flag/separate binary so the CLI stays dependency
      free. (Paused; resume here.)
- [ ] PDF support — spike pdfcpu vs rasterize, pick per the no-net /
      stdlib-leaning constraint.
- [ ] Audio/video via an ffmpeg subprocess (out-of-process, so the core
      stays stdlib-only).
- [ ] WASM build (run the sanitizer fully client-side in a browser).
- [ ] Signed releases.
