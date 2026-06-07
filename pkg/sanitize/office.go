package sanitize

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// OOXML documents (docx, xlsx, pptx) are zip archives. Sanitization
// rebuilds the archive: docProps/core.xml and docProps/app.xml are
// replaced with empty property sets (keeping the package structurally
// valid for strict consumers), docProps/custom.xml and thumbnails are
// removed along with their package references, and every zip entry
// timestamp is zeroed.

const (
	emptyCoreXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\r\n" +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>`

	emptyAppXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\r\n" +
		`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>`
)

var (
	reCustomPropsOverride = regexp.MustCompile(`<Override[^>]*PartName="/docProps/custom\.xml"[^>]*/>`)
	reThumbnailOverride   = regexp.MustCompile(`<Override[^>]*PartName="/docProps/thumbnail\.[^"]*"[^>]*/>`)
	reCustomPropsRel      = regexp.MustCompile(`<Relationship[^>]*Target="/?docProps/custom\.xml"[^>]*/>`)
	reThumbnailRel        = regexp.MustCompile(`<Relationship[^>]*Target="/?docProps/thumbnail\.[^"]*"[^>]*/>`)
)

func sanitizeOffice(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		if isDroppedOfficePart(f.Name) {
			continue
		}
		content, err := readZipEntry(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f.Name, err)
		}
		switch f.Name {
		case "docProps/core.xml":
			content = []byte(emptyCoreXML)
		case "docProps/app.xml":
			content = []byte(emptyAppXML)
		case "[Content_Types].xml":
			content = reThumbnailOverride.ReplaceAll(reCustomPropsOverride.ReplaceAll(content, nil), nil)
		case "_rels/.rels":
			content = reThumbnailRel.ReplaceAll(reCustomPropsRel.ReplaceAll(content, nil), nil)
		}
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:     f.Name,
			Method:   zip.Deflate,
			Modified: time.Time{},
		})
		if err != nil {
			return nil, fmt.Errorf("writing %s: %w", f.Name, err)
		}
		if _, err := w.Write(content); err != nil {
			return nil, fmt.Errorf("writing %s: %w", f.Name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("finalizing zip: %w", err)
	}
	return buf.Bytes(), nil
}

func isDroppedOfficePart(name string) bool {
	return name == "docProps/custom.xml" || strings.HasPrefix(name, "docProps/thumbnail.")
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Sensitive property elements by local XML name. Values found in
// these elements are reported as findings.
var officeSensitiveProps = map[string]string{
	"creator":        "author",
	"lastModifiedBy": "last modified by",
	"title":          "title",
	"subject":        "subject",
	"description":    "description",
	"keywords":       "keywords",
	"category":       "category",
	"contentStatus":  "content status",
	"created":        "creation timestamp",
	"modified":       "modification timestamp",
	"lastPrinted":    "last printed timestamp",
	"revision":       "revision number",
	"Company":        "company",
	"Manager":        "manager",
	"Application":    "creating application",
	"AppVersion":     "application version",
	"Template":       "template name",
	"TotalTime":      "total editing time",
	"HyperlinkBase":  "hyperlink base",
}

func scanOffice(data []byte) ([]Finding, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}
	var fs []Finding
	timestamped := 0
	for _, f := range zr.File {
		if f.Modified.Year() > 1980 {
			timestamped++
		}
		switch {
		case f.Name == "docProps/custom.xml":
			fs = append(fs, Finding{Location: f.Name, Kind: "custom properties", Detail: "custom document properties part present"})
		case strings.HasPrefix(f.Name, "docProps/thumbnail."):
			fs = append(fs, Finding{Location: f.Name, Kind: "thumbnail", Detail: "embedded preview image present"})
		case f.Name == "docProps/core.xml" || f.Name == "docProps/app.xml":
			content, err := readZipEntry(f)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", f.Name, err)
			}
			propFindings, err := scanPropsXML(f.Name, content)
			if err != nil {
				return nil, err
			}
			fs = append(fs, propFindings...)
		}
	}
	if timestamped > 0 {
		fs = append(fs, Finding{
			Location: "zip entry headers",
			Kind:     "timestamps",
			Detail:   fmt.Sprintf("%d entries carry modification timestamps", timestamped),
		})
	}
	return fs, nil
}

func scanPropsXML(partName string, content []byte) ([]Finding, error) {
	var fs []Finding
	dec := xml.NewDecoder(bytes.NewReader(content))
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", partName, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			value := strings.TrimSpace(text.String())
			if kind, ok := officeSensitiveProps[t.Name.Local]; ok && value != "" {
				fs = append(fs, Finding{Location: partName, Kind: kind, Detail: previewText([]byte(value))})
			}
			text.Reset()
		}
	}
	return fs, nil
}
