package sanitize

import (
	"bytes"
	"testing"
)

// Fuzz targets assert one property: hostile bytes may produce errors,
// never panics, and never a claimed-clean sanitized output that a
// fresh scan disagrees with.

func FuzzDetect(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xE0})
	f.Add([]byte("RIFF\x00\x00\x00\x00WEBP"))
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, data []byte) {
		Detect(data)
	})
}

func FuzzScan(f *testing.F) {
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xD9})
	f.Add([]byte("GIF89a\x01\x00\x01\x00\x00\x00\x00\x3B"))
	f.Add(append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0}, 16)...))
	f.Add([]byte("RIFF\x14\x00\x00\x00WEBPVP8 \x04\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		format := Detect(data)
		if format == FormatUnknown {
			return
		}
		_, _ = scanBytes(format, data) // must not panic
	})
}

func FuzzSanitize(f *testing.F) {
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xD9})
	f.Add([]byte("RIFF\x14\x00\x00\x00WEBPVP8 \x04\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		res, err := Sanitize(bytes.NewReader(data), &out, Options{})
		if err != nil {
			if out.Len() != 0 {
				t.Fatal("output written despite error")
			}
			return
		}
		if !res.After.Clean() {
			t.Fatal("Sanitize returned success with residue in After report")
		}
		rescan, err := Scan(bytes.NewReader(out.Bytes()))
		if err != nil {
			t.Fatalf("sanitized output does not re-scan: %v", err)
		}
		if !rescan.Clean() {
			t.Fatalf("fresh scan found residue in claimed-clean output: %v", rescan.Findings)
		}
	})
}
