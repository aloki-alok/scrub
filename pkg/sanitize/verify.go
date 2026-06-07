package sanitize

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// The scanners in this file are the verifier: they re-parse raw
// output bytes with no knowledge of what any handler did. Sanitize
// only releases output these scanners report as clean. The same
// scanners back the public Scan API, so what users can audit is
// exactly what the verifier enforces.

func scanJPEG(data []byte) ([]Finding, error) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, errors.New("missing JPEG SOI marker")
	}
	var fs []Finding
	i := 2
scan:
	for i+2 <= len(data) {
		if data[i] != 0xFF {
			return nil, fmt.Errorf("corrupt marker at offset %d", i)
		}
		marker := data[i+1]
		switch {
		case marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7):
			i += 2 // standalone markers carry no payload
			continue
		case marker == 0xD9: // EOI
			break scan
		case marker == 0xDA: // SOS: entropy-coded data follows
			break scan
		}
		if i+4 > len(data) {
			return nil, errors.New("truncated segment header")
		}
		length := int(data[i+2])<<8 | int(data[i+3])
		if length < 2 || i+2+length > len(data) {
			return nil, fmt.Errorf("corrupt segment length at offset %d", i)
		}
		seg := data[i+4 : i+2+length]
		if f, found := classifyJPEGSegment(marker, seg); found {
			fs = append(fs, f)
		}
		i += 2 + length
	}
	if idx := bytes.LastIndex(data, []byte{0xFF, 0xD9}); idx >= 0 && idx+2 < len(data) {
		fs = append(fs, Finding{
			Location: "after EOI",
			Kind:     "trailing data",
			Detail:   fmt.Sprintf("%d bytes after end of image", len(data)-idx-2),
		})
	}
	return fs, nil
}

func classifyJPEGSegment(marker byte, seg []byte) (Finding, bool) {
	preview := func(b []byte) string {
		const n = 48
		if len(b) > n {
			b = b[:n]
		}
		return fmt.Sprintf("%q", b)
	}
	switch {
	case marker == 0xE1 && bytes.HasPrefix(seg, []byte("Exif\x00")):
		return Finding{Location: "APP1 segment", Kind: "EXIF", Detail: fmt.Sprintf("%d bytes", len(seg))}, true
	case marker == 0xE1 && bytes.Contains(seg, []byte("ns.adobe.com/xap")):
		return Finding{Location: "APP1 segment", Kind: "XMP", Detail: fmt.Sprintf("%d bytes", len(seg))}, true
	case marker == 0xE2 && bytes.HasPrefix(seg, []byte("ICC_PROFILE\x00")):
		return Finding{Location: "APP2 segment", Kind: "ICC profile", Detail: fmt.Sprintf("%d bytes", len(seg))}, true
	case marker == 0xED && bytes.HasPrefix(seg, []byte("Photoshop 3.0")):
		return Finding{Location: "APP13 segment", Kind: "IPTC/Photoshop", Detail: fmt.Sprintf("%d bytes", len(seg))}, true
	case marker == 0xFE:
		return Finding{Location: "COM segment", Kind: "comment", Detail: preview(seg)}, true
	case marker >= 0xE1 && marker <= 0xEF:
		// Any application segment other than APP0/JFIF is treated as
		// metadata. Fail-safe: unknown payloads count as findings.
		return Finding{Location: fmt.Sprintf("APP%d segment", marker-0xE0), Kind: "application data", Detail: preview(seg)}, true
	}
	return Finding{}, false
}

var pngMetadataChunks = map[string]string{
	"tEXt": "text metadata",
	"zTXt": "compressed text metadata",
	"iTXt": "international text metadata",
	"eXIf": "EXIF",
	"tIME": "modification timestamp",
	"iCCP": "ICC profile",
}

func scanPNG(data []byte) ([]Finding, error) {
	if !bytes.HasPrefix(data, magicPNG) {
		return nil, errors.New("missing PNG signature")
	}
	var fs []Finding
	i := len(magicPNG)
	for i+12 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[i:]))
		typ := string(data[i+4 : i+8])
		if i+12+length > len(data) || length < 0 {
			return nil, fmt.Errorf("corrupt chunk %q at offset %d", typ, i)
		}
		if kind, ok := pngMetadataChunks[typ]; ok {
			detail := fmt.Sprintf("%d bytes", length)
			if typ == "tEXt" || typ == "iTXt" {
				detail = previewText(data[i+8 : i+8+length])
			}
			fs = append(fs, Finding{Location: typ + " chunk", Kind: kind, Detail: detail})
		}
		i += 12 + length
		if typ == "IEND" {
			if i < len(data) {
				fs = append(fs, Finding{
					Location: "after IEND",
					Kind:     "trailing data",
					Detail:   fmt.Sprintf("%d bytes after end of image", len(data)-i),
				})
			}
			return fs, nil
		}
	}
	return nil, errors.New("missing IEND chunk")
}

func scanGIF(data []byte) ([]Finding, error) {
	if len(data) < 14 || (!bytes.HasPrefix(data, magicGIF7) && !bytes.HasPrefix(data, magicGIF9)) {
		return nil, errors.New("missing GIF header")
	}
	var fs []Finding
	i := 13
	if data[10]&0x80 != 0 {
		i += 3 * (1 << ((data[10] & 0x07) + 1)) // global color table
	}
	for i < len(data) {
		switch data[i] {
		case 0x3B: // trailer
			if i+1 < len(data) {
				fs = append(fs, Finding{
					Location: "after trailer",
					Kind:     "trailing data",
					Detail:   fmt.Sprintf("%d bytes after end of image", len(data)-i-1),
				})
			}
			return fs, nil
		case 0x21: // extension block
			if i+2 > len(data) {
				return nil, errors.New("truncated extension block")
			}
			label := data[i+1]
			content, next, err := gifSubBlocks(data, i+2)
			if err != nil {
				return nil, err
			}
			switch label {
			case 0xFE:
				fs = append(fs, Finding{Location: "comment extension", Kind: "comment", Detail: previewText(content)})
			case 0x01:
				fs = append(fs, Finding{Location: "plain text extension", Kind: "embedded text", Detail: previewText(content)})
			case 0xFF:
				if !bytes.HasPrefix(content, []byte("NETSCAPE2.0")) && !bytes.HasPrefix(content, []byte("ANIMEXTS1.0")) {
					fs = append(fs, Finding{Location: "application extension", Kind: "application data", Detail: previewText(content)})
				}
			}
			i = next
		case 0x2C: // image descriptor
			if i+10 > len(data) {
				return nil, errors.New("truncated image descriptor")
			}
			packed := data[i+9]
			i += 10
			if packed&0x80 != 0 {
				i += 3 * (1 << ((packed & 0x07) + 1)) // local color table
			}
			if i >= len(data) {
				return nil, errors.New("truncated image data")
			}
			i++ // LZW minimum code size
			_, next, err := gifSubBlocks(data, i)
			if err != nil {
				return nil, err
			}
			i = next
		default:
			return nil, fmt.Errorf("unexpected GIF block 0x%02X at offset %d", data[i], i)
		}
	}
	return nil, errors.New("missing GIF trailer")
}

// gifSubBlocks walks a GIF sub-block sequence starting at offset i,
// returning the concatenated content and the offset just past the
// block terminator.
func gifSubBlocks(data []byte, i int) (content []byte, next int, err error) {
	for {
		if i >= len(data) {
			return nil, 0, errors.New("truncated sub-block sequence")
		}
		size := int(data[i])
		if size == 0 {
			return content, i + 1, nil
		}
		if i+1+size > len(data) {
			return nil, 0, errors.New("truncated sub-block")
		}
		content = append(content, data[i+1:i+1+size]...)
		i += 1 + size
	}
}

func previewText(b []byte) string {
	const n = 48
	if len(b) > n {
		return fmt.Sprintf("%q...", b[:n])
	}
	return fmt.Sprintf("%q", b)
}
