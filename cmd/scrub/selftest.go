package main

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"os"

	"github.com/aloki-alok/scrub/pkg/sanitize"
)

// selfTest builds a deliberately dirty JPEG in memory, confirms Scan
// detects the planted metadata, sanitizes it, and confirms the
// verifier reports the output clean. Everything happens in memory;
// nothing touches disk or the network.
func selfTest(stdout, stderr *os.File) int {
	dirty, err := dirtyJPEG()
	if err != nil {
		fmt.Fprintf(stderr, "scrub: self-test setup failed: %v\n", err)
		return exitError
	}

	report, err := sanitize.Scan(bytes.NewReader(dirty))
	if err != nil {
		fmt.Fprintf(stderr, "scrub: self-test scan failed: %v\n", err)
		return exitError
	}
	if report.Clean() {
		fmt.Fprintf(stderr, "scrub: self-test FAILED: scanner missed planted EXIF metadata\n")
		return exitResidue
	}

	var out bytes.Buffer
	result, err := sanitize.Sanitize(bytes.NewReader(dirty), &out, sanitize.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "scrub: self-test sanitize failed: %v\n", err)
		return exitResidue
	}
	if !result.After.Clean() {
		fmt.Fprintf(stderr, "scrub: self-test FAILED: residue after sanitization\n")
		return exitResidue
	}

	fmt.Fprintf(stdout, "self-test passed: planted metadata detected and removed, output verified clean\n")
	fmt.Fprintf(stdout, "network: this binary links no networking packages (enforced at build time in CI)\n")
	return exitOK
}

// dirtyJPEG encodes a small image and splices a fake EXIF APP1
// segment after the SOI marker.
func dirtyJPEG() ([]byte, error) {
	img := image.NewGray(image.Rect(0, 0, 8, 8))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		return nil, err
	}
	clean := buf.Bytes()

	payload := append([]byte("Exif\x00\x00"), []byte("MM\x00\x2A\x00\x00\x00\x08planted-by-self-test")...)
	seg := []byte{0xFF, 0xE1, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)}
	seg = append(seg, payload...)

	dirty := make([]byte, 0, len(clean)+len(seg))
	dirty = append(dirty, clean[:2]...) // SOI
	dirty = append(dirty, seg...)
	dirty = append(dirty, clean[2:]...)
	return dirty, nil
}
