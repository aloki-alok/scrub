package sanitize

import (
	"bytes"
	"fmt"
	"image/gif"
	"image/jpeg"
	"image/png"
)

// Raster images are sanitized by decoding the pixel data with the Go
// standard library and re-encoding to a fresh file. Re-encoding
// structurally cannot carry EXIF, XMP, ICC, or comment segments
// forward, so there is no remove-this-tag logic to get wrong.

func sanitizeJPEG(data []byte, opts Options) ([]byte, Format, error) {
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, FormatUnknown, fmt.Errorf("decoding JPEG: %w", err)
	}
	var buf bytes.Buffer
	if opts.PNGOutput {
		if err := png.Encode(&buf, img); err != nil {
			return nil, FormatUnknown, fmt.Errorf("encoding PNG: %w", err)
		}
		return buf.Bytes(), FormatPNG, nil
	}
	quality := opts.JPEGQuality
	if quality == 0 {
		quality = DefaultJPEGQuality
	}
	if quality < 1 || quality > 100 {
		return nil, FormatUnknown, fmt.Errorf("JPEG quality %d out of range 1-100", quality)
	}
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, FormatUnknown, fmt.Errorf("encoding JPEG: %w", err)
	}
	return buf.Bytes(), FormatJPEG, nil
}

func sanitizePNG(data []byte) ([]byte, error) {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decoding PNG: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("encoding PNG: %w", err)
	}
	return buf.Bytes(), nil
}

func sanitizeGIF(data []byte) ([]byte, error) {
	g, err := gif.DecodeAll(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decoding GIF: %w", err)
	}
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, g); err != nil {
		return nil, fmt.Errorf("encoding GIF: %w", err)
	}
	return buf.Bytes(), nil
}
