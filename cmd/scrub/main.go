// Command scrub strips metadata from files locally. It never opens
// network connections; CI enforces that no networking packages are
// linked into this binary.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ryu-ryuk/scrub/pkg/sanitize"
)

const (
	exitOK          = 0
	exitError       = 1
	exitResidue     = 2
	exitUnsupported = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("scrub", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		output       = fs.String("o", "", "output path (default: <input>.clean.<ext>)")
		scanOnly     = fs.Bool("scan", false, "report metadata without changing anything")
		verbose      = fs.Bool("verify", false, "print the full before/after verification report")
		quality      = fs.Int("quality", sanitize.DefaultJPEGQuality, "JPEG re-encode quality (1-100)")
		pngOut       = fs.Bool("png", false, "write lossless PNG output for JPEG input")
		offlineCheck = fs.Bool("offline-check", false, "run the built-in self-test and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: scrub [flags] <file>\n\n")
		fmt.Fprintf(stderr, "Strips metadata from a file, writes a sanitized copy, and verifies\n")
		fmt.Fprintf(stderr, "the result. The original file is never modified. Exit codes:\n")
		fmt.Fprintf(stderr, "0 clean, 1 error, 2 metadata residue, 3 unsupported format.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	if *offlineCheck {
		return selfTest(stdout, stderr)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return exitError
	}
	path := fs.Arg(0)

	in, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "scrub: %v\n", err)
		return exitError
	}
	defer in.Close()

	if *scanOnly {
		report, err := sanitize.Scan(in)
		if err != nil {
			return reportError(stderr, err)
		}
		printReport(stdout, path, report)
		if !report.Clean() {
			return exitResidue
		}
		return exitOK
	}

	opts := sanitize.Options{JPEGQuality: *quality, PNGOutput: *pngOut}

	var buf bytes.Buffer
	result, err := sanitize.Sanitize(in, &buf, opts)
	if err != nil {
		return reportError(stderr, err)
	}

	outPath := *output
	if outPath == "" {
		outPath = defaultOutputPath(path, result.OutputFormat)
	}
	if samePath(path, outPath) {
		fmt.Fprintf(stderr, "scrub: refusing to overwrite the input file; pass a different -o path\n")
		return exitError
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(stderr, "scrub: %v\n", err)
		return exitError
	}

	fmt.Fprintf(stdout, "%s: %d metadata item(s) removed, output verified clean\n", path, len(result.Before.Findings))
	fmt.Fprintf(stdout, "wrote %s\n", outPath)
	if *verbose {
		fmt.Fprintln(stdout)
		printReport(stdout, "before", result.Before)
		printReport(stdout, "after", result.After)
	}
	return exitOK
}

func reportError(stderr *os.File, err error) int {
	fmt.Fprintf(stderr, "scrub: %v\n", err)
	switch {
	case errors.Is(err, sanitize.ErrUnsupportedFormat):
		return exitUnsupported
	case errors.Is(err, sanitize.ErrVerificationFailed):
		fmt.Fprintf(stderr, "scrub: NO output was written\n")
		return exitResidue
	}
	return exitError
}

func printReport(w *os.File, label string, report sanitize.Report) {
	if report.Clean() {
		fmt.Fprintf(w, "%s: no metadata found (format: %s)\n", label, report.Format)
		return
	}
	fmt.Fprintf(w, "%s: %d metadata item(s) (format: %s)\n", label, len(report.Findings), report.Format)
	for _, f := range report.Findings {
		fmt.Fprintf(w, "  %-24s %-26s %s\n", f.Location, f.Kind, f.Detail)
	}
}

func defaultOutputPath(input string, format sanitize.Format) string {
	ext := filepath.Ext(input)
	base := strings.TrimSuffix(input, ext)
	switch format {
	case sanitize.FormatPNG:
		ext = ".png"
	case sanitize.FormatJPEG:
		if ext == "" {
			ext = ".jpg"
		}
	}
	if ext == "" {
		ext = ".out"
	}
	return base + ".clean" + ext
}

func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return aa == bb
}
