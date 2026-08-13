package sanitize

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
	"time"
)

// Fixtures are constructed programmatically so the dirty bytes are
// reviewable in source instead of opaque committed binaries. Each
// helper produces a structurally valid file with metadata planted in
// the places real tools put it.

func testImage() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 16), G: uint8(y * 16), B: 128, A: 255})
		}
	}
	return img
}

func dirtyJPEG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, testImage(), nil); err != nil {
		t.Fatal(err)
	}
	clean := buf.Bytes()

	exif := append([]byte("Exif\x00\x00"), []byte("MM\x00\x2A\x00\x00\x00\x08GPS 51.5074 -0.1278 author Jane Doe")...)
	xmp := append([]byte("http://ns.adobe.com/xap/1.0/\x00"), []byte(`<x:xmpmeta><dc:creator>Jane Doe</dc:creator></x:xmpmeta>`)...)
	comment := []byte("shot on Jane's phone")

	var out bytes.Buffer
	out.Write(clean[:2]) // SOI
	writeJPEGSegment(&out, 0xE1, exif)
	writeJPEGSegment(&out, 0xE1, xmp)
	writeJPEGSegment(&out, 0xFE, comment)
	out.Write(clean[2:])
	return out.Bytes()
}

func writeJPEGSegment(buf *bytes.Buffer, marker byte, payload []byte) {
	buf.WriteByte(0xFF)
	buf.WriteByte(marker)
	length := len(payload) + 2
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))
	buf.Write(payload)
}

func dirtyPNG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, testImage()); err != nil {
		t.Fatal(err)
	}
	clean := buf.Bytes()

	// Splice a tEXt chunk right after IHDR (8-byte signature +
	// 25-byte IHDR chunk).
	const ihdrEnd = 8 + 25
	text := buildPNGChunk("tEXt", []byte("Author\x00Jane Doe"))
	timeChunk := buildPNGChunk("tIME", []byte{0x07, 0xE8, 0x06, 0x01, 0x0C, 0x00, 0x00})

	var out bytes.Buffer
	out.Write(clean[:ihdrEnd])
	out.Write(text)
	out.Write(timeChunk)
	out.Write(clean[ihdrEnd:])
	return out.Bytes()
}

func buildPNGChunk(typ string, data []byte) []byte {
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint32(len(data)))
	out.WriteString(typ)
	out.Write(data)
	// CRC over type + data, per the PNG spec.
	crc := crc32.ChecksumIEEE(append([]byte(typ), data...))
	binary.Write(&out, binary.BigEndian, crc)
	return out.Bytes()
}

func dirtyGIF(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	pal := color.Palette{color.Black, color.White}
	frame := image.NewPaletted(image.Rect(0, 0, 8, 8), pal)
	if err := gif.EncodeAll(&buf, &gif.GIF{Image: []*image.Paletted{frame}, Delay: []int{0}}); err != nil {
		t.Fatal(err)
	}
	clean := buf.Bytes()
	if clean[len(clean)-1] != 0x3B {
		t.Fatal("expected GIF trailer as last byte")
	}

	comment := []byte("made by Jane Doe")
	var ext bytes.Buffer
	ext.WriteByte(0x21)
	ext.WriteByte(0xFE)
	ext.WriteByte(byte(len(comment)))
	ext.Write(comment)
	ext.WriteByte(0x00)

	var out bytes.Buffer
	out.Write(clean[:len(clean)-1])
	out.Write(ext.Bytes())
	out.WriteByte(0x3B)
	return out.Bytes()
}

func dirtyWEBP(t *testing.T) []byte {
	t.Helper()
	// Container-level fixture: VP8X declaring EXIF+XMP, a dummy VP8
	// image chunk, then EXIF and XMP chunks. The WEBP handler and
	// scanner operate on the RIFF container without decoding pixels.
	vp8x := []byte{vp8xFlagEXIF | vp8xFlagXMP, 0, 0, 0, 7, 0, 0, 7, 0, 0}
	vp8 := bytes.Repeat([]byte{0xAB}, 32)
	exif := []byte("MM\x00\x2AGPS 51.5074 -0.1278")
	xmp := []byte("<x:xmpmeta>Jane Doe</x:xmpmeta>")

	var body bytes.Buffer
	body.WriteString("WEBP")
	writeRIFFChunk(&body, "VP8X", vp8x)
	writeRIFFChunk(&body, "VP8 ", vp8)
	writeRIFFChunk(&body, "EXIF", exif)
	writeRIFFChunk(&body, "XMP ", xmp)

	var out bytes.Buffer
	out.WriteString("RIFF")
	binary.Write(&out, binary.LittleEndian, uint32(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// privateWEBP builds a valid WEBP whose only non-image chunk is a
// non-standard fourCC carrying data. It is the container-surgery blind
// spot: a metadata denylist that only drops EXIF/XMP/ICCP leaves this
// chunk in place.
func privateWEBP(t *testing.T, fourCC string, payload []byte) []byte {
	t.Helper()
	vp8x := []byte{0, 0, 0, 0, 7, 0, 0, 7, 0, 0}
	vp8 := bytes.Repeat([]byte{0xAB}, 32)

	var body bytes.Buffer
	body.WriteString("WEBP")
	writeRIFFChunk(&body, "VP8X", vp8x)
	writeRIFFChunk(&body, "VP8 ", vp8)
	writeRIFFChunk(&body, fourCC, payload)

	var out bytes.Buffer
	out.WriteString("RIFF")
	binary.Write(&out, binary.LittleEndian, uint32(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// privatePNG builds a valid PNG carrying a private ancillary chunk (a
// non-standard type that is neither a rendering chunk nor a known
// metadata chunk). A metadata allowlist that only knows tEXt/eXIf/etc.
// would miss it.
func privatePNG(t *testing.T, typ string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, testImage()); err != nil {
		t.Fatal(err)
	}
	clean := buf.Bytes()
	const ihdrEnd = 8 + 25
	chunk := buildPNGChunk(typ, payload)

	var out bytes.Buffer
	out.Write(clean[:ihdrEnd])
	out.Write(chunk)
	out.Write(clean[ihdrEnd:])
	return out.Bytes()
}

func writeRIFFChunk(buf *bytes.Buffer, fourCC string, data []byte) {
	buf.WriteString(fourCC)
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	buf.Write(data)
	if len(data)%2 == 1 {
		buf.WriteByte(0x00)
	}
}

func dirtyDOCX(t *testing.T) []byte {
	t.Helper()
	parts := []struct{ name, content string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
			`<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>` +
			`<Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>` +
			`</Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
			`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>` +
			`<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>` +
			`</Relationships>`},
		{"docProps/core.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
			`<dc:title>Internal Memo</dc:title>` +
			`<dc:creator>Jane Doe</dc:creator>` +
			`<cp:lastModifiedBy>Jane Doe</cp:lastModifiedBy>` +
			`<dcterms:created xsi:type="dcterms:W3CDTF">2026-01-15T09:30:00Z</dcterms:created>` +
			`<dcterms:modified xsi:type="dcterms:W3CDTF">2026-02-20T17:45:00Z</dcterms:modified>` +
			`</cp:coreProperties>`},
		{"docProps/app.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">` +
			`<Application>Microsoft Office Word</Application>` +
			`<Company>Acme Corp</Company>` +
			`<TotalTime>95</TotalTime>` +
			`</Properties>`},
		{"docProps/custom.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties">` +
			`<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Department"><vt:lpwstr xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">Legal</vt:lpwstr></property>` +
			`</Properties>`},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
			`<w:body><w:p><w:r><w:t>Hello.</w:t></w:r></w:p></w:body></w:document>`},
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	modified := time.Date(2026, 2, 20, 17, 45, 0, 0, time.UTC)
	for _, p := range parts {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: p.name, Method: zip.Deflate, Modified: modified})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(p.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
