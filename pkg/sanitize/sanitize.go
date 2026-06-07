// Package sanitize strips metadata from files entirely in memory.
//
// The package never opens network connections, never writes temporary
// files, and never trusts its own handlers: every sanitized output is
// re-scanned by an independent verifier before it is released to the
// caller. If any metadata residue remains, Sanitize returns
// ErrVerificationFailed and writes nothing.
package sanitize

import (
	"errors"
	"fmt"
	"io"
)

var (
	// ErrUnsupportedFormat is returned when the input format is not
	// recognized or not yet supported.
	ErrUnsupportedFormat = errors.New("unsupported or unrecognized format")

	// ErrVerificationFailed is returned when the post-sanitization
	// re-scan finds metadata residue in the output. No output is
	// written in that case.
	ErrVerificationFailed = errors.New("output failed post-sanitization verification")

	// ErrInputTooLarge is returned when the input exceeds
	// Options.MaxInputBytes.
	ErrInputTooLarge = errors.New("input exceeds maximum allowed size")
)

// DefaultJPEGQuality is the JPEG re-encode quality used when
// Options.JPEGQuality is zero.
const DefaultJPEGQuality = 92

// DefaultMaxInputBytes caps input size at 1 GiB unless overridden.
const DefaultMaxInputBytes = 1 << 30

// Options controls sanitization behavior.
type Options struct {
	// JPEGQuality sets the re-encode quality (1-100) for JPEG output.
	// Zero means DefaultJPEGQuality. JPEG re-encoding is lossy; use
	// PNGOutput for lossless output.
	JPEGQuality int

	// PNGOutput re-encodes JPEG input to PNG for lossless output.
	PNGOutput bool

	// MaxInputBytes caps how much input is read. Zero means
	// DefaultMaxInputBytes.
	MaxInputBytes int64
}

// Finding is one piece of metadata located in a file.
type Finding struct {
	Location string // where in the file, e.g. "APP1 segment", "docProps/core.xml"
	Kind     string // what it is, e.g. "EXIF", "XMP", "author"
	Detail   string // human-readable specifics, possibly truncated
}

// Report is the result of scanning a single file for metadata.
type Report struct {
	Format   Format
	Findings []Finding
}

// Clean reports whether the scan found no metadata.
func (r Report) Clean() bool { return len(r.Findings) == 0 }

// Result describes a completed sanitization run.
type Result struct {
	Format       Format // detected input format
	OutputFormat Format // format of the written output
	Before       Report // metadata present in the input
	After        Report // metadata remaining in the output; empty on success
}

// Scan reads r and reports all metadata found, changing nothing.
func Scan(r io.Reader) (Report, error) {
	data, err := readCapped(r, DefaultMaxInputBytes)
	if err != nil {
		return Report{}, err
	}
	format := Detect(data)
	return scanBytes(format, data)
}

// Sanitize reads a file from r, strips its metadata, verifies the
// result with an independent re-scan, and writes the verified output
// to w. Nothing is written unless verification passes.
func Sanitize(r io.Reader, w io.Writer, opts Options) (Result, error) {
	maxBytes := opts.MaxInputBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxInputBytes
	}
	data, err := readCapped(r, maxBytes)
	if err != nil {
		return Result{}, err
	}

	format := Detect(data)
	res := Result{Format: format}

	before, err := scanBytes(format, data)
	if err != nil {
		return res, err
	}
	res.Before = before

	out, outFormat, err := dispatch(format, data, opts)
	if err != nil {
		return res, err
	}
	res.OutputFormat = outFormat

	after, err := scanBytes(outFormat, out)
	if err != nil {
		return res, fmt.Errorf("verifying output: %w", err)
	}
	res.After = after
	if !after.Clean() {
		return res, fmt.Errorf("%w: %d finding(s) remain", ErrVerificationFailed, len(after.Findings))
	}

	if _, err := w.Write(out); err != nil {
		return res, fmt.Errorf("writing output: %w", err)
	}
	return res, nil
}

func dispatch(format Format, data []byte, opts Options) (out []byte, outFormat Format, err error) {
	return nil, FormatUnknown, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
}

func scanBytes(format Format, data []byte) (Report, error) {
	rep := Report{Format: format}
	return rep, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
}

func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrInputTooLarge
	}
	return data, nil
}
