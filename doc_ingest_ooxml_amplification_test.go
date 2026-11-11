//go:build !cli

package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Untrusted DOCX/PPTX parts are parsed in the app process. Names and ids
// that end up copied into every block's citation or every element's index
// key must stay small: a 78 KB file with a 64 KiB footnote id and 2,000
// empty paragraphs retained 140 MB, and a long xmlns URI was copied for
// every element.
func TestOOXMLRefusesNamesAndIDsThatAmplify(t *testing.T) {
	ingest := func(body string) error {
		t.Helper()
		data := testDOCX(t, body, "", "")
		_, err := IngestDOCX(bytes.NewReader(data), int64(len(data)), IngestLimits{})
		return err
	}
	longID := strings.Repeat("9", 64<<10)
	for name, body := range map[string]string{
		"long footnote id":    `<footnote xmlns:w="` + testWordNS + `" w:id="` + longID + `">` + strings.Repeat(`<p/>`, 50) + `</footnote>`,
		"non-numeric id":      `<comment xmlns:w="` + testWordNS + `" w:id="]/footnote[id=1"><p><r><t>x</t></r></p></comment>`,
		"missing footnote id": `<footnote><p><r><t>fake</t></r></p></footnote><p><r><t>real</t></r></p>`,
		"long namespace":      `<x:a xmlns:x="urn:` + strings.Repeat("n", 600) + `"/><p><r><t>x</t></r></p>`,
		"long element name":   `<` + strings.Repeat("a", 200) + `/><p><r><t>x</t></r></p>`,
	} {
		if err := ingest(body); !errors.Is(err, ErrIngestCorrupt) {
			t.Errorf("%s: err = %v, want ErrIngestCorrupt", name, err)
		}
	}
	// Ordinary content, including a numbered note, still parses.
	if err := ingest(`<footnote xmlns:w="` + testWordNS + `" w:id="-1"><p><r><t>note</t></r></p></footnote><p><r><t>body</t></r></p>`); err != nil {
		t.Fatalf("numbered footnote: %v", err)
	}
	if err := ingest(`<p><r><t>plain</t></r></p>`); err != nil {
		t.Fatalf("plain document: %v", err)
	}
}

// Package lookups ignore case, so two relationships to header1.xml and
// HEADER1.xml name one part; the package must be refused, not parsed twice.
func TestOOXMLDuplicatePartCheckIgnoresCase(t *testing.T) {
	rels := `<Relationship Id="h1" Type="` + ooxmlWordRelBase + `header" Target="header1.xml"/>` +
		`<Relationship Id="h2" Type="` + ooxmlWordRelBase + `header" Target="HEADER1.xml"/>`
	data := testDOCX(t, `<p><r><t>body</t></r></p>`, rels, `<Override PartName="/word/header1.xml" ContentType="`+ooxmlWordCTBase+`header+xml"/>`)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var entries []ingEntry
	for _, f := range zr.File {
		rc, _ := f.Open()
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(rc)
		_ = rc.Close()
		entries = append(entries, ingEntry{f.Name, b.String()})
	}
	entries = append(entries, ingEntry{"word/header1.xml", `<hdr xmlns="` + testWordNS + `"><p><r><t>Header</t></r></p></hdr>`})
	data = ooxmlTestZip(t, entries...)
	if _, err := IngestDOCX(bytes.NewReader(data), int64(len(data)), IngestLimits{}); !errors.Is(err, ErrIngestCorrupt) {
		t.Fatalf("case-variant duplicate header: err = %v, want ErrIngestCorrupt", err)
	}
}
