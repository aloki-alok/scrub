# scrub

Strip metadata from files, entirely on your machine.

`scrub` removes hidden metadata (EXIF, GPS coordinates, author names,
edit history, timestamps) from files before you share them. It is
built for people who cannot afford to leak who they are: sources,
whistleblowers, and anyone sharing files anonymously.

## The promise

- **100% local.** Every byte is processed on your device. Nothing is
  ever uploaded. The binary contains no networking code, which is
  enforced mechanically in CI, not just promised here.
- **No telemetry, no update checks, no phoning home.** The program
  cannot make network connections.
- **Verified, not trusted.** After sanitizing, scrub re-scans the
  output with an independent verifier and proves the metadata is
  gone. If anything remains, it fails loudly, exits non-zero, and
  writes nothing.
- **Your original is never touched.** Output always goes to a new
  file.

## Usage

```
scrub photo.jpg                 # writes photo.clean.jpg
scrub photo.jpg --verify        # also prints the before/after report
scrub photo.jpg -o safe.png --png   # lossless PNG output
scrub --scan report.docx        # dry run: list metadata, change nothing
scrub --offline-check           # built-in self-test
```

Exit codes: `0` success, `1` error, `2` metadata residue detected
(no output written), `3` unsupported format.

## Supported formats (v0.1)

| Format | Method | Lossless |
|---|---|---|
| JPEG | decode + re-encode (drops EXIF/XMP/ICC/comments structurally) | no, see below |
| PNG | decode + re-encode | yes |
| GIF | decode + re-encode (drops comments, keeps animation) | yes |
| WEBP | RIFF container chunk removal (EXIF/XMP/ICCP) | yes |
| docx / xlsx / pptx | archive rebuild: empties core and app properties, removes custom properties and thumbnails, zeroes zip timestamps | yes |

PDF, audio, and video are planned. See the roadmap in the issues.

### The JPEG trade-off

JPEG re-encoding is lossy (default quality 92, tune with
`--quality`). This is deliberate: re-encoding through a fresh pixel
buffer makes it structurally impossible for metadata to survive,
rather than depending on remove-this-tag logic being complete. For
pixel-perfect output use `--png`, which converts to lossless PNG.

### What scrub does NOT do (yet)

- It does not redact content. Faces, names, and text inside the
  image or document body are untouched.
- It does not remove identifying *patterns* such as camera sensor
  noise or writing style.
- Office sanitization covers package metadata (docProps, zip
  timestamps). It does not yet strip tracked changes, comments, or
  revision identifiers inside the document body. Use `--scan` and
  read the report so you know what was and wasn't covered.

## Design

```
input -> detect (magic bytes) -> handler -> verify (independent re-scan) -> output + report
```

- Formats are detected by content, never by file extension.
- Each handler strips by reconstruction, not by tag deletion,
  wherever the format allows it.
- The verifier shares no state with handlers. A buggy handler cannot
  mark its own work clean.
- The core engine is an importable, dependency-free Go library:
  `github.com/ryu-ryuk/scrub/pkg/sanitize`. The CLI is a thin
  consumer. `Sanitize` and `Scan` work on `io.Reader`/`io.Writer`.

```go
import "github.com/ryu-ryuk/scrub/pkg/sanitize"

report, err := sanitize.Scan(file)                    // inspect
result, err := sanitize.Sanitize(in, out, sanitize.Options{})  // clean + verify
```

## Trust

- v0.1 has **zero third-party dependencies**: Go standard library
  only. CI fails if any dependency, or any networking package,
  enters the build graph.
- The full test suite runs inside a no-network namespace in CI.
- Read the verifier yourself: `pkg/sanitize/verify.go` is exactly
  what stands between a buggy handler and your output file.

## License

Apache-2.0. See [LICENSE](LICENSE).
