package sanitize

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// WEBP is sanitized at the RIFF container level: metadata chunks
// (EXIF, XMP, ICCP) are dropped and the VP8X feature flags are
// updated to match. Pixel data is untouched, so the operation is
// lossless. The standard library cannot re-encode WEBP, and decoding
// is unnecessary for container-level chunk removal.

const (
	vp8xFlagICC  = 0x20
	vp8xFlagEXIF = 0x08
	vp8xFlagXMP  = 0x04
)

type riffChunk struct {
	fourCC string
	data   []byte
}

func parseWEBP(data []byte) ([]riffChunk, error) {
	if len(data) < 12 {
		return nil, errors.New("truncated RIFF header")
	}
	declared := int64(binary.LittleEndian.Uint32(data[4:8]))
	if declared+8 > int64(len(data)) {
		return nil, errors.New("RIFF size exceeds file size")
	}
	var chunks []riffChunk
	i := 12
	for i+8 <= len(data) {
		fourCC := string(data[i : i+4])
		size := int64(binary.LittleEndian.Uint32(data[i+4 : i+8]))
		if int64(i)+8+size > int64(len(data)) {
			return nil, fmt.Errorf("chunk %q size exceeds file size", fourCC)
		}
		chunks = append(chunks, riffChunk{fourCC: fourCC, data: data[i+8 : i+8+int(size)]})
		i += 8 + int(size)
		if size%2 == 1 {
			i++ // chunks are padded to even offsets
		}
	}
	return chunks, nil
}

func isWEBPMetadataChunk(fourCC string) bool {
	switch fourCC {
	case "EXIF", "XMP ", "ICCP":
		return true
	}
	return false
}

func sanitizeWEBP(data []byte) ([]byte, error) {
	chunks, err := parseWEBP(data)
	if err != nil {
		return nil, fmt.Errorf("parsing WEBP: %w", err)
	}
	var kept []riffChunk
	for _, c := range chunks {
		if isWEBPMetadataChunk(c.fourCC) {
			continue
		}
		if c.fourCC == "VP8X" && len(c.data) >= 1 {
			flags := make([]byte, len(c.data))
			copy(flags, c.data)
			flags[0] &^= vp8xFlagICC | vp8xFlagEXIF | vp8xFlagXMP
			c.data = flags
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		return nil, errors.New("no image chunks present")
	}

	size := 4 // "WEBP" form type
	for _, c := range kept {
		size += 8 + len(c.data)
		if len(c.data)%2 == 1 {
			size++
		}
	}
	out := make([]byte, 0, size+8)
	out = append(out, "RIFF"...)
	out = binary.LittleEndian.AppendUint32(out, uint32(size))
	out = append(out, "WEBP"...)
	for _, c := range kept {
		out = append(out, c.fourCC...)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(c.data)))
		out = append(out, c.data...)
		if len(c.data)%2 == 1 {
			out = append(out, 0x00)
		}
	}
	return out, nil
}

func scanWEBP(data []byte) ([]Finding, error) {
	chunks, err := parseWEBP(data)
	if err != nil {
		return nil, fmt.Errorf("parsing WEBP: %w", err)
	}
	var fs []Finding
	for _, c := range chunks {
		switch c.fourCC {
		case "EXIF":
			fs = append(fs, Finding{Location: "EXIF chunk", Kind: "EXIF", Detail: fmt.Sprintf("%d bytes", len(c.data))})
		case "XMP ":
			fs = append(fs, Finding{Location: "XMP chunk", Kind: "XMP", Detail: fmt.Sprintf("%d bytes", len(c.data))})
		case "ICCP":
			fs = append(fs, Finding{Location: "ICCP chunk", Kind: "ICC profile", Detail: fmt.Sprintf("%d bytes", len(c.data))})
		case "VP8X":
			if len(c.data) >= 1 && c.data[0]&(vp8xFlagICC|vp8xFlagEXIF|vp8xFlagXMP) != 0 {
				fs = append(fs, Finding{Location: "VP8X header", Kind: "metadata flags", Detail: "feature flags claim ICC/EXIF/XMP present"})
			}
		}
	}
	return fs, nil
}
