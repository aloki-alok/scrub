package sanitize

import (
	"archive/zip"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want Format
	}{
		{"jpeg", dirtyJPEG(t), FormatJPEG},
		{"png", dirtyPNG(t), FormatPNG},
		{"gif", dirtyGIF(t), FormatGIF},
		{"webp", dirtyWEBP(t), FormatWEBP},
		{"docx", dirtyDOCX(t), FormatOffice},
		{"empty", nil, FormatUnknown},
		{"text", []byte("hello world"), FormatUnknown},
		{"extension lies", []byte("not really a jpeg"), FormatUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Detect(c.data); got != c.want {
				t.Errorf("Detect() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSanitizeRemovesAllMetadata(t *testing.T) {
	cases := []struct {
		name      string
		data      []byte
		format    Format
		wantKinds []string
	}{
		{"jpeg", dirtyJPEG(t), FormatJPEG, []string{"EXIF", "XMP", "comment"}},
		{"png", dirtyPNG(t), FormatPNG, []string{"text metadata", "modification timestamp"}},
		{"gif", dirtyGIF(t), FormatGIF, []string{"comment"}},
		{"webp", dirtyWEBP(t), FormatWEBP, []string{"EXIF", "XMP"}},
		{"docx", dirtyDOCX(t), FormatOffice, []string{"author", "company", "custom properties", "timestamps"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			res, err := Sanitize(bytes.NewReader(c.data), &out, Options{})
			if err != nil {
				t.Fatalf("Sanitize: %v", err)
			}
			if res.Format != c.format {
				t.Errorf("detected format %q, want %q", res.Format, c.format)
			}
			if res.Before.Clean() {
				t.Fatal("fixture produced no findings; fixture is broken")
			}
			for _, kind := range c.wantKinds {
				if !hasKind(res.Before.Findings, kind) {
					t.Errorf("expected before-report to contain kind %q, got %v", kind, kinds(res.Before.Findings))
				}
			}
			if !res.After.Clean() {
				t.Errorf("residue after sanitization: %v", res.After.Findings)
			}
			if out.Len() == 0 {
				t.Error("no output written")
			}

			// Independent confirmation: a fresh scan of the output
			// must agree with the embedded verification.
			rescan, err := Scan(bytes.NewReader(out.Bytes()))
			if err != nil {
				t.Fatalf("re-scanning output: %v", err)
			}
			if !rescan.Clean() {
				t.Errorf("fresh scan of output found residue: %v", rescan.Findings)
			}
		})
	}
}

func TestScanReportsDirtyInput(t *testing.T) {
	report, err := Scan(bytes.NewReader(dirtyJPEG(t)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Clean() {
		t.Fatal("Scan reported a dirty file as clean")
	}
}

// TestVerifierIndependence proves the verifier fails dirty bytes. A
// verifier that cannot fail would make every handler look correct.
func TestVerifierIndependence(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		format Format
	}{
		{"jpeg", dirtyJPEG(t), FormatJPEG},
		{"png", dirtyPNG(t), FormatPNG},
		{"gif", dirtyGIF(t), FormatGIF},
		{"webp", dirtyWEBP(t), FormatWEBP},
		{"docx", dirtyDOCX(t), FormatOffice},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			report, err := scanBytes(c.format, c.data)
			if err != nil {
				t.Fatal(err)
			}
			if report.Clean() {
				t.Fatal("verifier passed deliberately dirty bytes; it can no longer catch handler bugs")
			}
		})
	}
}

func TestUnsupportedFormatFailsLoudly(t *testing.T) {
	var out bytes.Buffer
	_, err := Sanitize(strings.NewReader("plain text file"), &out, Options{})
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("err = %v, want ErrUnsupportedFormat", err)
	}
	if out.Len() != 0 {
		t.Error("output written despite unsupported format")
	}
}

func TestCorruptInputFailsLoudly(t *testing.T) {
	cases := map[string][]byte{
		"truncated jpeg": dirtyJPEG(t)[:20],
		"truncated png":  dirtyPNG(t)[:30],
		"truncated webp": dirtyWEBP(t)[:16],
		"corrupt zip":    append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0xFF}, 64)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := Sanitize(bytes.NewReader(data), &out, Options{})
			if err == nil {
				t.Fatal("corrupt input sanitized without error")
			}
			if out.Len() != 0 {
				t.Error("output written despite error")
			}
		})
	}
}

func TestInputSizeCap(t *testing.T) {
	big := append([]byte{0xFF, 0xD8, 0xFF}, bytes.Repeat([]byte{0x00}, 64)...)
	var out bytes.Buffer
	_, err := Sanitize(bytes.NewReader(big), &out, Options{MaxInputBytes: 10})
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("err = %v, want ErrInputTooLarge", err)
	}
}

func TestJPEGQualityValidation(t *testing.T) {
	var out bytes.Buffer
	_, err := Sanitize(bytes.NewReader(dirtyJPEG(t)), &out, Options{JPEGQuality: 150})
	if err == nil {
		t.Fatal("out-of-range quality accepted")
	}
}

func TestJPEGToPNGOutput(t *testing.T) {
	var out bytes.Buffer
	res, err := Sanitize(bytes.NewReader(dirtyJPEG(t)), &out, Options{PNGOutput: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.OutputFormat != FormatPNG {
		t.Errorf("output format %q, want png", res.OutputFormat)
	}
	if Detect(out.Bytes()) != FormatPNG {
		t.Error("output bytes are not a PNG")
	}
}

func TestOfficeOutputStillOpens(t *testing.T) {
	var out bytes.Buffer
	if _, err := Sanitize(bytes.NewReader(dirtyDOCX(t)), &out, Options{}); err != nil {
		t.Fatal(err)
	}
	if Detect(out.Bytes()) != FormatOffice {
		t.Fatal("sanitized docx is no longer a valid OOXML zip")
	}
	// References to the removed custom.xml must be gone or the
	// package is corrupt to strict consumers.
	zr, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name != "[Content_Types].xml" && f.Name != "_rels/.rels" {
			continue
		}
		content, err := readZipEntry(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(content, []byte("custom.xml")) {
			t.Errorf("%s still references removed docProps/custom.xml", f.Name)
		}
	}
}

func hasKind(fs []Finding, kind string) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func kinds(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return out
}
