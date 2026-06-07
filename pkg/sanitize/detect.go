package sanitize

import (
	"archive/zip"
	"bytes"
)

// Format identifies a file format detected from content, never from
// file extension.
type Format string

const (
	FormatUnknown Format = ""
	FormatJPEG    Format = "jpeg"
	FormatPNG     Format = "png"
	FormatGIF     Format = "gif"
	FormatWEBP    Format = "webp"
	FormatOffice  Format = "office" // OOXML container: docx, xlsx, pptx
	FormatZIP     Format = "zip"    // zip that is not an OOXML document
)

var (
	magicJPEG = []byte{0xFF, 0xD8, 0xFF}
	magicPNG  = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	magicGIF7 = []byte("GIF87a")
	magicGIF9 = []byte("GIF89a")
	magicZIP  = []byte{'P', 'K', 0x03, 0x04}
)

// Detect identifies the format of data by magic bytes and, for zip
// containers, by inspecting the archive structure.
func Detect(data []byte) Format {
	switch {
	case bytes.HasPrefix(data, magicJPEG):
		return FormatJPEG
	case bytes.HasPrefix(data, magicPNG):
		return FormatPNG
	case bytes.HasPrefix(data, magicGIF7), bytes.HasPrefix(data, magicGIF9):
		return FormatGIF
	case len(data) >= 12 && bytes.Equal(data[0:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		return FormatWEBP
	case bytes.HasPrefix(data, magicZIP):
		if isOfficeZip(data) {
			return FormatOffice
		}
		return FormatZIP
	}
	return FormatUnknown
}

func isOfficeZip(data []byte) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if f.Name == "[Content_Types].xml" {
			return true
		}
	}
	return false
}
