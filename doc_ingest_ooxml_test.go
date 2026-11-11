//go:build !cli && !windows

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testWordNS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
	testRelNS  = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	testPptNS  = "http://schemas.openxmlformats.org/presentationml/2006/main"
	testDrawNS = "http://schemas.openxmlformats.org/drawingml/2006/main"
)

func ooxmlTestZip(t *testing.T, entries ...ingEntry) []byte {
	t.Helper()
	return ingZip(t, entries...)
}

func ooxmlAppendEntry(t *testing.T, data []byte, entry ingEntry) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]ingEntry, 0, len(zr.File)+1)
	for _, file := range zr.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read test ZIP entry: %v", errors.Join(readErr, closeErr))
		}
		entries = append(entries, ingEntry{file.Name, string(b)})
	}
	entries = append(entries, entry)
	return ooxmlTestZip(t, entries...)
}

func testDOCX(t *testing.T, body, relationships, extras string) []byte {
	t.Helper()
	ct := `<Types xmlns="` + ooxmlContentTypesNS + `"><Override PartName="/word/document.xml" ContentType="` + ooxmlWordMainCT + `"/>` + extras + `</Types>`
	rootRels := `<Relationships xmlns="` + ooxmlRelationshipsNS + `"><Relationship Id="rId1" Type="` + ooxmlOfficeDocumentRel + `" Target="word/document.xml"/></Relationships>`
	docRels := `<Relationships xmlns="` + ooxmlRelationshipsNS + `">` + relationships + `</Relationships>`
	document := `<document xmlns="` + testWordNS + `"><body>` + body + `</body></document>`
	return ooxmlTestZip(t,
		ingEntry{"[Content_Types].xml", ct},
		ingEntry{"_rels/.rels", rootRels},
		ingEntry{"word/document.xml", document},
		ingEntry{"word/_rels/document.xml.rels", docRels},
	)
}

func testPPTX(t *testing.T, presentation, presentationRels string, entries ...ingEntry) []byte {
	t.Helper()
	ct := `<Types xmlns="` + ooxmlContentTypesNS + `"><Override PartName="/ppt/presentation.xml" ContentType="` + ooxmlPresentationMainCT + `"/>` +
		`<Override PartName="/ppt/slides/slide7.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>` +
		`<Override PartName="/ppt/slides/slide2.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>`
	for _, e := range entries {
		if strings.HasSuffix(e.name, ".xml") && strings.Contains(e.name, "notesSlides/") {
			ct += `<Override PartName="/` + e.name + `" ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>`
		}
	}
	ct += `</Types>`
	rootRels := `<Relationships xmlns="` + ooxmlRelationshipsNS + `"><Relationship Id="root" Type="` + ooxmlOfficeDocumentRel + `" Target="ppt/presentation.xml"/></Relationships>`
	entries = append([]ingEntry{
		{"[Content_Types].xml", ct},
		{"_rels/.rels", rootRels},
		{"ppt/presentation.xml", presentation},
		{"ppt/_rels/presentation.xml.rels", `<Relationships xmlns="` + ooxmlRelationshipsNS + `">` + presentationRels + `</Relationships>`},
	}, entries...)
	return ooxmlTestZip(t, entries...)
}

func ooxmlCorruptCRC(data []byte, name string) []byte {
	out := append([]byte(nil), data...)
	for i := 0; i+46 <= len(out); i++ {
		if !bytes.Equal(out[i:i+4], []byte{'P', 'K', 1, 2}) {
			continue
		}
		nameLen := int(binary.LittleEndian.Uint16(out[i+28 : i+30]))
		extraLen := int(binary.LittleEndian.Uint16(out[i+30 : i+32]))
		commentLen := int(binary.LittleEndian.Uint16(out[i+32 : i+34]))
		end := i + 46 + nameLen + extraLen + commentLen
		if end > len(out) {
			return out
		}
		if string(out[i+46:i+46+nameLen]) == name {
			out[i+16] ^= 0xff
			return out
		}
		i = end - 1
	}
	return out
}

func ooxmlMarkEncrypted(data []byte) []byte {
	out := append([]byte(nil), data...)
	for i := 0; i+30 <= len(out); i++ {
		if bytes.Equal(out[i:i+4], []byte{'P', 'K', 3, 4}) {
			flags := binary.LittleEndian.Uint16(out[i+6:i+8]) | 1
			binary.LittleEndian.PutUint16(out[i+6:i+8], flags)
		} else if i+10 <= len(out) && bytes.Equal(out[i:i+4], []byte{'P', 'K', 1, 2}) {
			flags := binary.LittleEndian.Uint16(out[i+8:i+10]) | 1
			binary.LittleEndian.PutUint16(out[i+8:i+10], flags)
		}
	}
	return out
}

func ooxmlAddSymlink(t *testing.T, data []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		w, err := zw.CreateHeader(&f.FileHeader)
		if err != nil {
			_ = rc.Close()
			t.Fatal(err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			_ = rc.Close()
			t.Fatal(err)
		}
		if err := rc.Close(); err != nil {
			t.Fatal(err)
		}
	}
	header := &zip.FileHeader{Name: "word/linked.xml", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("document.xml"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestIngestDOCXTextScopeAndSeparateAnnotationParts(t *testing.T) {
	body := `<p><r><t xml:space="preserve">North </t></r><r><t>Star</t><tab/><t>☀</t><br/><t>Power</t></r></p>` +
		`<tbl><tr><tc><p><r><t>Table</t></r></p><p><r><t>cell</t></r></p></tc><tc><p/></tc></tr></tbl>`
	rels := `<Relationship Id="header" Type="` + ooxmlWordRelBase + `header" Target="header1.xml"/>` +
		`<Relationship Id="notes" Type="` + ooxmlWordRelBase + `footnotes" Target="footnotes.xml"/>` +
		`<Relationship Id="comments" Type="` + ooxmlWordRelBase + `comments" Target="comments.xml"/>`
	data := testDOCX(t, body, rels,
		`<Override PartName="/word/header1.xml" ContentType="`+ooxmlWordCTBase+`header+xml"/>`+
			`<Override PartName="/word/footnotes.xml" ContentType="`+ooxmlWordCTBase+`footnotes+xml"/>`+
			`<Override PartName="/word/comments.xml" ContentType="`+ooxmlWordCTBase+`comments+xml"/>`)
	data = append([]byte(nil), data...)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var extra []ingEntry
	for _, f := range zr.File {
		rc, _ := f.Open()
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(rc)
		_ = rc.Close()
		extra = append(extra, ingEntry{f.Name, b.String()})
	}
	for i := range extra {
		switch extra[i].name {
		case "word/header1.xml":
			extra[i].body = `<hdr xmlns="` + testWordNS + `"><p><r><t>Header only</t></r></p></hdr>`
		case "word/footnotes.xml":
			extra[i].body = `<footnotes xmlns="` + testWordNS + `" xmlns:w="` + testWordNS + `"><footnote w:id="7"><p><r><t>Footnote separate</t></r></p></footnote></footnotes>`
		case "word/comments.xml":
			extra[i].body = `<comments xmlns="` + testWordNS + `" xmlns:w="` + testWordNS + `"><comment w:id="3"><p><r><t>Reviewer note</t></r></p></comment></comments>`
		}
	}
	extra = append(extra,
		ingEntry{"word/header1.xml", `<hdr xmlns="` + testWordNS + `"><p><r><t>Header only</t></r></p></hdr>`},
		ingEntry{"word/footnotes.xml", `<footnotes xmlns="` + testWordNS + `" xmlns:w="` + testWordNS + `"><footnote w:id="7"><p><r><t>Footnote separate</t></r></p></footnote></footnotes>`},
		ingEntry{"word/comments.xml", `<comments xmlns="` + testWordNS + `" xmlns:w="` + testWordNS + `"><comment w:id="3"><p><r><t>Reviewer note</t></r></p></comment></comments>`},
	)
	data = ooxmlTestZip(t, extra...)
	res, err := IngestDOCX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if err != nil || !res.Complete || res.ParserVersion != IngestOOXMLTextParserVersion || res.Format != IngestFormatDOCX {
		t.Fatalf("DOCX result complete=%v version=%q format=%q err=%v", res.Complete, res.ParserVersion, res.Format, err)
	}
	if !VerifySpan(res, "word/document.xml", "body/p[1]", "North Star\t☀\nPower") {
		t.Fatalf("body paragraph not preserved exactly: %+v", res.Blocks)
	}
	if !VerifySpan(res, "word/document.xml", "body/table[1]/row[1]/cell[1]/p[2]", "cell") {
		t.Fatalf("table cell paragraph reference not stable: %+v", res.Blocks)
	}
	if !VerifySpan(res, "word/footnotes.xml", "body/footnote[id=7]/p[1]", "Footnote separate") || !VerifySpan(res, "word/comments.xml", "body/comment[id=3]/p[1]", "Reviewer note") {
		t.Fatalf("annotation stories were not kept separate: %+v", res.Blocks)
	}
	if len(res.Sheets) != 4 || !strings.Contains(strings.Join(res.Quality, ","), QualityTextOnly) || !strings.Contains(strings.Join(res.Quality, ","), QualityLayoutNotReconstructed) {
		t.Fatalf("story/limitation metadata = %+v %+v", res.Sheets, res.Quality)
	}
}

func TestOOXMLImageOnlyDOCXRetainsEmptyBlockAndReportsNoExtractableText(t *testing.T) {
	data := testDOCX(t, `<p><r><drawing><inline/></drawing></r></p>`, "", "")
	result, err := IngestDOCX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if err != nil || !result.Complete || len(result.Blocks) != 1 || result.Blocks[0].Value != "" {
		t.Fatalf("image-only paragraph structure: complete=%v blocks=%d err=%v", result.Complete, len(result.Blocks), err)
	}
	flags := strings.Join(result.Quality, ",")
	if !strings.Contains(flags, QualityNoExtractableText) || !strings.Contains(flags, QualityImagesNotExtracted) {
		t.Fatalf("image-only quality flags: %v", result.Quality)
	}
}

func TestOOXMLExternalTextRelationshipsFailClosedButExternalHyperlinksAreFlagged(t *testing.T) {
	docx := testDOCX(t, `<p><r><t>visible text</t></r></p>`, `<Relationship Id="external-header" Type="`+ooxmlWordRelBase+`header" Target="https://example.invalid/header.xml" TargetMode="External"/>`, "")
	result, err := IngestDOCX(bytes.NewReader(docx), int64(len(docx)), DefaultIngestLimits())
	if !errors.Is(err, ErrIngestUnsupported) || result.Complete || len(result.Blocks) != 0 {
		t.Fatalf("external Word text relationship did not fail closed: complete=%v blocks=%d err=%v", result.Complete, len(result.Blocks), err)
	}
	hyperlink := testDOCX(t, `<p><r><t>visible hyperlink text</t></r></p>`, `<Relationship Id="link" Type="`+ooxmlWordRelBase+`hyperlink" Target="https://example.invalid/" TargetMode="External"/>`, "")
	result, err = IngestDOCX(bytes.NewReader(hyperlink), int64(len(hyperlink)), DefaultIngestLimits())
	if err != nil || !result.Complete || !strings.Contains(strings.Join(result.Quality, ","), QualityExternalLinksNotFetch) {
		t.Fatalf("ordinary external hyperlink was not retained as a flag: complete=%v quality=%v err=%v", result.Complete, result.Quality, err)
	}
	pres := `<presentation xmlns="` + testPptNS + `" xmlns:r="` + testRelNS + `"><sldIdLst><sldId id="1" r:id="slide"/></sldIdLst></presentation>`
	rels := `<Relationship Id="slide" Type="` + ooxmlOfficeRelNS + `/slide" Target="slides/slide7.xml"/>`
	slide := `<sld xmlns="` + testPptNS + `" xmlns:a="` + testDrawNS + `"><cSld><spTree><sp><txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>visible text</a:t></a:r></a:p></txBody></sp></spTree></cSld></sld>`
	externalNotes := `<Relationships xmlns="` + ooxmlRelationshipsNS + `"><Relationship Id="notes" Type="` + ooxmlOfficeRelNS + `/notesSlide" Target="https://example.invalid/notes.xml" TargetMode="External"/></Relationships>`
	pptx := testPPTX(t, pres, rels, ingEntry{"ppt/slides/slide7.xml", slide}, ingEntry{"ppt/slides/_rels/slide7.xml.rels", externalNotes})
	presentation, err := IngestPPTX(bytes.NewReader(pptx), int64(len(pptx)), DefaultIngestLimits())
	if !errors.Is(err, ErrIngestUnsupported) || presentation.Complete || len(presentation.Blocks) != 0 {
		t.Fatalf("external PPTX notes relationship did not fail closed: complete=%v blocks=%d err=%v", presentation.Complete, len(presentation.Blocks), err)
	}
}

func TestIngestPPTXUsesPresentationOrderAndCapturesHiddenAndNotes(t *testing.T) {
	pres := `<presentation xmlns="` + testPptNS + `" xmlns:r="` + testRelNS + `"><sldIdLst><sldId id="300" r:id="rIdFirst"/><sldId id="301" r:id="rIdHidden"/></sldIdLst></presentation>`
	rels := `<Relationship Id="rIdHidden" Type="` + ooxmlOfficeRelNS + `/slide" Target="slides/slide2.xml"/><Relationship Id="rIdFirst" Type="` + ooxmlOfficeRelNS + `/slide" Target="slides/slide7.xml"/>`
	slide7 := `<sld xmlns="` + testPptNS + `" xmlns:a="` + testDrawNS + `" show="1"><cSld><spTree><sp><txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>first in presentation order</a:t></a:r></a:p></txBody></sp><graphicFrame><graphic><graphicData><a:tbl><a:tr><a:tc><txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>table text</a:t></a:r></a:p></txBody></a:tc></a:tr></a:tbl></graphicData></graphic></graphicFrame></spTree></cSld></sld>`
	slide2 := `<sld xmlns="` + testPptNS + `" xmlns:a="` + testDrawNS + `" show="0"><cSld><spTree><sp><txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>hidden second</a:t></a:r></a:p></txBody></sp></spTree></cSld></sld>`
	slideRels := `<Relationships xmlns="` + ooxmlRelationshipsNS + `"><Relationship Id="notes" Type="` + ooxmlOfficeRelNS + `/notesSlide" Target="../notesSlides/notesSlide5.xml"/></Relationships>`
	notes := `<notes xmlns="` + testPptNS + `" xmlns:a="` + testDrawNS + `"><cSld><spTree><sp><txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>speaker notes</a:t></a:r></a:p></txBody></sp></spTree></cSld></notes>`
	data := testPPTX(t, pres, rels,
		ingEntry{"ppt/slides/slide7.xml", slide7}, ingEntry{"ppt/slides/slide2.xml", slide2},
		ingEntry{"ppt/slides/_rels/slide7.xml.rels", slideRels}, ingEntry{"ppt/notesSlides/notesSlide5.xml", notes})
	res, err := IngestPPTX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if err != nil || !res.Complete || res.Format != IngestFormatPPTX || res.ParserVersion != IngestOOXMLTextParserVersion {
		t.Fatalf("PPTX result complete=%v version=%q format=%q err=%v", res.Complete, res.ParserVersion, res.Format, err)
	}
	if !VerifySpan(res, "slide:1", "ppt/slides/slide7.xml#shape[1]/p[1]", "first in presentation order") || !VerifySpan(res, "slide:1", "ppt/slides/slide7.xml#shape[2]/table/row[1]/cell[1]/p[1]", "table text") {
		t.Fatalf("PPTX slide order or text references differ: %+v", res.Blocks)
	}
	if !VerifySpan(res, "slide:1:notes", "ppt/notesSlides/notesSlide5.xml#shape[1]/p[1]", "speaker notes") || !VerifySpan(res, "slide:2", "ppt/slides/slide2.xml#shape[1]/p[1]", "hidden second") {
		t.Fatalf("notes or hidden slide text missing: %+v", res.Blocks)
	}
	if len(res.Sheets) != 3 || res.Sheets[2].State != "hidden" || !strings.Contains(strings.Join(res.Blocks[3].Quality, ","), QualityHiddenSlide) {
		t.Fatalf("hidden slide identity is not exposed: %+v %+v", res.Sheets, res.Blocks)
	}
}

func TestOOXMLParserRejectsAmbiguousOrUnsupportedPackagesWithoutPartialBlocks(t *testing.T) {
	base := testDOCX(t, `<p><r><t>before</t></r></p><p><r><t>after</t></r></p>`, "", "")
	mutate := func(name, value string) []byte {
		zr, err := zip.NewReader(bytes.NewReader(base), int64(len(base)))
		if err != nil {
			t.Fatal(err)
		}
		entries := []ingEntry{}
		for _, f := range zr.File {
			rc, _ := f.Open()
			b := new(bytes.Buffer)
			_, _ = b.ReadFrom(rc)
			_ = rc.Close()
			content := b.String()
			if f.Name == name {
				content = value
			}
			entries = append(entries, ingEntry{f.Name, content})
		}
		return ooxmlTestZip(t, entries...)
	}
	cases := []struct {
		name string
		data []byte
		err  error
	}{
		{"tracked insertion", mutate("word/document.xml", `<document xmlns="`+testWordNS+`"><body><p><r><t>before</t></r></p><ins><p/></ins></body></document>`), ErrIngestUnsupported},
		{"cross-paragraph field", mutate("word/document.xml", `<document xmlns="`+testWordNS+`"><body><p><r><fldChar w:fldCharType="begin" xmlns:w="`+testWordNS+`"/></r></p><p><r><fldChar w:fldCharType="separate" xmlns:w="`+testWordNS+`"/><t>cached</t><fldChar w:fldCharType="end" xmlns:w="`+testWordNS+`"/></r></p></body></document>`), ErrIngestUnsupported},
		{"altChunk", mutate("word/document.xml", `<document xmlns="`+testWordNS+`"><body><altChunk/></body></document>`), ErrIngestUnsupported},
		{"alternate content", mutate("word/document.xml", `<document xmlns="`+testWordNS+`" xmlns:mc="urn:spoof"><body><mc:AlternateContent/></body></document>`), ErrIngestUnsupported},
		{"namespace spoof", mutate("word/document.xml", `<document xmlns="urn:spoof"><body><p><r><t>spoofed</t></r></p></body></document>`), ErrIngestCorrupt},
		{"duplicate external relationship id", mutate("word/_rels/document.xml.rels", `<Relationships xmlns="`+ooxmlRelationshipsNS+`"><Relationship Id="x" Type="`+ooxmlWordRelBase+`hyperlink" Target="https://example.invalid" TargetMode="External"/><Relationship Id="x" Type="`+ooxmlWordRelBase+`hyperlink" Target="https://example.invalid" TargetMode="External"/></Relationships>`), ErrIngestCorrupt},
		{"unsafe relationship target", mutate("word/_rels/document.xml.rels", `<Relationships xmlns="`+ooxmlRelationshipsNS+`"><Relationship Id="x" Type="`+ooxmlWordRelBase+`header" Target="https://example.invalid/a.xml"/></Relationships>`), ErrIngestCorrupt},
		{"macro content type", mutate("[Content_Types].xml", `<Types xmlns="`+ooxmlContentTypesNS+`"><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>`), ErrIngestUnsupported},
		{"encrypted package entry", ooxmlMarkEncrypted(base), ErrIngestEncrypted},
		{"encrypted OLE wrapper", ingOLE("EncryptedPackage"), ErrIngestEncrypted},
		{"corrupt XML CRC", ooxmlCorruptCRC(base, "word/document.xml"), ErrIngestCorrupt},
		{"truncated XML tail", mutate("word/document.xml", `<document xmlns="`+testWordNS+`"><body><p><r><t>tail`), ErrIngestCorrupt},
	}
	for _, tc := range cases {
		res, err := IngestDOCX(bytes.NewReader(tc.data), int64(len(tc.data)), DefaultIngestLimits())
		if !errors.Is(err, tc.err) || res.Complete || len(res.Blocks) != 0 {
			t.Errorf("%s: complete=%v blocks=%d err=%v", tc.name, res.Complete, len(res.Blocks), err)
		}
	}
	macroPart := append([]ingEntry{}, func() []ingEntry {
		zr, err := zip.NewReader(bytes.NewReader(base), int64(len(base)))
		if err != nil {
			t.Fatal(err)
		}
		entries := []ingEntry{}
		for _, f := range zr.File {
			rc, _ := f.Open()
			b := new(bytes.Buffer)
			_, _ = b.ReadFrom(rc)
			_ = rc.Close()
			entries = append(entries, ingEntry{f.Name, b.String()})
		}
		return entries
	}()...)
	macroPart = append(macroPart, ingEntry{"word/vbaProject.bin", "not code"})
	macroArchive := ooxmlTestZip(t, macroPart...)
	if res, err := IngestDOCX(bytes.NewReader(macroArchive), int64(len(macroArchive)), DefaultIngestLimits()); !errors.Is(err, ErrIngestUnsupported) || res.Complete || len(res.Blocks) != 0 {
		t.Fatalf("macro part was accepted or returned partial text: %+v err=%v", res, err)
	}
	symlink := ooxmlAddSymlink(t, base)
	if res, err := IngestDOCX(bytes.NewReader(symlink), int64(len(symlink)), DefaultIngestLimits()); !errors.Is(err, ErrIngestUnsupported) || res.Complete || len(res.Blocks) != 0 {
		t.Fatalf("symlink package entry was accepted: %+v err=%v", res, err)
	}
	duplicatePath := append([]ingEntry{}, func() []ingEntry {
		zr, err := zip.NewReader(bytes.NewReader(base), int64(len(base)))
		if err != nil {
			t.Fatal(err)
		}
		entries := []ingEntry{}
		for _, f := range zr.File {
			rc, _ := f.Open()
			b := new(bytes.Buffer)
			_, _ = b.ReadFrom(rc)
			_ = rc.Close()
			entries = append(entries, ingEntry{f.Name, b.String()})
		}
		return entries
	}()...)
	duplicatePath = append(duplicatePath, ingEntry{"WORD/document.xml", `<document/>`})
	duplicateArchive := ooxmlTestZip(t, duplicatePath...)
	if res, err := IngestDOCX(bytes.NewReader(duplicateArchive), int64(len(duplicateArchive)), DefaultIngestLimits()); !errors.Is(err, ErrIngestCorrupt) || res.Complete || len(res.Blocks) != 0 {
		t.Fatalf("case-ambiguous package entry was accepted: %+v err=%v", res, err)
	}
	limits := DefaultIngestLimits()
	limits.MaxCells = 1
	res, err := IngestDOCX(bytes.NewReader(base), int64(len(base)), limits)
	var limitErr *IngestLimitError
	if !errors.As(err, &limitErr) || limitErr.Limit != "MaxCells" || res.Complete || len(res.Blocks) != 0 {
		t.Fatalf("paragraph count limit returned partial blocks: %+v err=%v", res, err)
	}
	tooSmall := DefaultIngestLimits()
	tooSmall.MaxFileBytes = int64(len(base) - 1)
	if result, parseErr := IngestDOCX(bytes.NewReader(base), int64(len(base)), tooSmall); !errors.Is(parseErr, ErrIngestTooLarge) || result.Complete || len(result.Blocks) != 0 {
		t.Fatalf("file size limit returned partial blocks: complete=%v blocks=%d err=%v", result.Complete, len(result.Blocks), parseErr)
	}
	for _, tc := range []struct {
		name   string
		limits IngestLimits
		want   string
	}{
		{"entry bytes", IngestLimits{MaxEntryBytes: 20}, "MaxEntryBytes"},
		{"decompressed bytes", IngestLimits{MaxDecompressedBytes: 100}, "MaxDecompressedBytes"},
		{"ZIP entries", IngestLimits{MaxZipEntries: 2}, "MaxZipEntries"},
		{"XML depth", IngestLimits{MaxXMLDepth: 3}, "MaxXMLDepth"},
		{"XML tokens", IngestLimits{MaxXMLTokens: 5}, "MaxXMLTokens"},
		{"field bytes", IngestLimits{MaxFieldBytes: 3}, "MaxFieldBytes"},
		{"extracted bytes", IngestLimits{MaxExtractedBytes: 4}, "MaxExtractedBytes"},
	} {
		result, parseErr := IngestDOCX(bytes.NewReader(base), int64(len(base)), tc.limits)
		var got *IngestLimitError
		if !errors.As(parseErr, &got) || got.Limit != tc.want || result.Complete || len(result.Blocks) != 0 {
			t.Errorf("%s: complete=%v blocks=%d err=%v, want %s", tc.name, result.Complete, len(result.Blocks), parseErr, tc.want)
		}
	}
	withHeader := testDOCX(t,
		`<p><r><t>body</t></r></p>`,
		`<Relationship Id="h" Type="`+ooxmlWordRelBase+`header" Target="header1.xml"/>`,
		`<Override PartName="/word/header1.xml" ContentType="`+ooxmlWordCTBase+`header+xml"/>`,
	)
	withHeader = ooxmlAppendEntry(t, withHeader, ingEntry{"word/header1.xml", `<hdr xmlns="` + testWordNS + `"><p><r><t>header</t></r></p></hdr>`})
	maxStories := DefaultIngestLimits()
	maxStories.MaxSheets = 1
	if result, parseErr := IngestDOCX(bytes.NewReader(withHeader), int64(len(withHeader)), maxStories); !errors.As(parseErr, &limitErr) || limitErr.Limit != "MaxSheets" || result.Complete || len(result.Blocks) != 0 {
		t.Fatalf("story limit returned partial blocks: complete=%v blocks=%d err=%v", result.Complete, len(result.Blocks), parseErr)
	}
	largeText := strings.Repeat("x", 1<<20)
	compressed := testDOCX(t, `<p><r><t>`+largeText+`</t></r></p>`, "", "")
	ratioLimit := DefaultIngestLimits()
	ratioLimit.MaxCompressionRatio = 2
	if result, parseErr := IngestDOCX(bytes.NewReader(compressed), int64(len(compressed)), ratioLimit); !errors.As(parseErr, &limitErr) || limitErr.Limit != "MaxCompressionRatio" || result.Complete || len(result.Blocks) != 0 {
		t.Fatalf("compression ratio limit returned partial blocks: complete=%v blocks=%d err=%v", result.Complete, len(result.Blocks), parseErr)
	}
}

func TestOOXMLWordFieldKeepsOnlyCachedTextAndMarksItUnevaluated(t *testing.T) {
	data := testDOCX(t, `<p><r><fldChar w:fldCharType="begin" xmlns:w="`+testWordNS+`"/><instrText>DATE</instrText><fldChar w:fldCharType="separate" xmlns:w="`+testWordNS+`"/><t>cached date</t><fldChar w:fldCharType="end" xmlns:w="`+testWordNS+`"/></r></p>`, "", "")
	result, err := IngestDOCX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if err != nil || !result.Complete || len(result.Blocks) != 1 || result.Blocks[0].Value != "cached date" || !strings.Contains(strings.Join(result.Blocks[0].Quality, ","), "field_cached_text_unevaluated") || !strings.Contains(strings.Join(result.Quality, ","), QualityFieldsUnevaluated) {
		t.Fatalf("cached Word field handling: complete=%v blocks=%d err=%v", result.Complete, len(result.Blocks), err)
	}
}

func TestOOXMLParserIdentityAndHistoricalStatusLimits(t *testing.T) {
	for _, file := range []string{"a.docx", "b.PPTX"} {
		parser, encoded, err := appMCPFileParserAndLimits(file, DefaultIngestLimits())
		if err != nil || parser != IngestOOXMLTextParserVersion {
			t.Fatalf("%s parser identity=%q err=%v", file, parser, err)
		}
		if _, err := appMCPDecodeFileProcessingLimits(parser, string(encoded)); err != nil {
			t.Fatalf("OOXML limits decode: %v", err)
		}
	}
	oldParser, oldLimits, err := appMCPFileParserAndLimits("legacy.csv", DefaultIngestLimits())
	if err != nil || oldParser != IngestParserVersion {
		t.Fatalf("historical parser identity: %q %v", oldParser, err)
	}
	if _, err := appMCPDecodeFileProcessingLimits(oldParser, string(oldLimits)); err != nil {
		t.Fatalf("historical parser status no longer decodes: %v", err)
	}
}

func TestOOXMLNativeFileHandlerIngestVerifyReuseAndStatus(t *testing.T) {
	app, pair := appMCPFileRuntimeFixture(t)
	base := testDOCX(t, `<p><r><t>Exact source text</t></r></p>`, "", "")
	writeTestFile(t, app.Dir, "uploads/private/source.docx", string(base))
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, "uploads/private/source.docx"); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	input := map[string]any{"file_ref": "uploads/private/source.docx", "record_id": "1"}
	first, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", input)
	if err != nil {
		t.Fatalf("native DOCX ingest: %v", err)
	}
	data, ok := first.Data.(map[string]any)
	if !ok || data["complete"] != true {
		t.Fatalf("native DOCX projection: %#v", first.Data)
	}
	blocks, ok := data["blocks"].([]any)
	if !ok || len(blocks) != 1 {
		t.Fatalf("native DOCX blocks: %#v", data["blocks"])
	}
	block, ok := blocks[0].(map[string]any)
	if !ok || block["sheet"] != "word/document.xml" || block["ref"] != "body/p[1]" || block["value"] != "Exact source text" {
		t.Fatalf("native DOCX source block: %#v", blocks[0])
	}
	second, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", input)
	if err != nil || first.ProcessingID != second.ProcessingID {
		t.Fatalf("identical source did not reuse immutable snapshot: ids=%q,%q err=%v", first.ProcessingID, second.ProcessingID, err)
	}
	verifyInput := map[string]any{"file_ref": "uploads/private/source.docx", "record_id": "1", "processing_id": first.ProcessingID, "sheet": "word/document.xml", "ref": "body/p[1]", "expected": "Exact source text"}
	verified, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verifyInput)
	if err != nil || verified.Data.(map[string]any)["valid"] != true {
		t.Fatalf("native DOCX verify: %#v %v", verified, err)
	}
	var userID int64
	if err := app.DB.QueryRow(`SELECT user_id FROM _benmore_mcp_grants WHERE id=?`, pair.GrantID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	grant, err := readAppMCPAccessGrant(context.Background(), app, func() string { h, _ := appMCPCredentialHash(pair.AccessToken, "access"); return h }(), grantFixtureResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, err := appMCPReadFileProcessingStatus(context.Background(), app, first.ProcessingID, userID, grant.UserCreated, grant.Tenant, "notes", "1", "uploads/private/source.docx")
	if err != nil || status["parser_version"] != IngestOOXMLTextParserVersion {
		t.Fatalf("native status: %#v err=%v", status, err)
	}
	limits, ok := status["limits"].(map[string]any)
	if !ok || limits["MaxFileBytes"] != json.Number("26214400") || limits["MaxXMLTokens"] != json.Number("10000000") {
		t.Fatalf("status limits projection: %#v", status["limits"])
	}
	if encoded, err := json.Marshal(status); err != nil || !strings.Contains(string(encoded), "doc-ooxml-text/1") {
		t.Fatalf("bounded status encoding: %s err=%v", encoded, err)
	}
	pptx := testPPTX(t,
		`<presentation xmlns="`+testPptNS+`" xmlns:r="`+testRelNS+`"><sldIdLst><sldId id="256" r:id="slide"/></sldIdLst></presentation>`,
		`<Relationship Id="slide" Type="`+ooxmlOfficeRelNS+`/slide" Target="slides/slide7.xml"/>`,
		ingEntry{"ppt/slides/slide7.xml", `<sld xmlns="` + testPptNS + `" xmlns:a="` + testDrawNS + `"><cSld><spTree><sp><txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>Native presentation text</a:t></a:r></a:p></txBody></sp></spTree></cSld></sld>`},
	)
	writeTestFile(t, app.Dir, "uploads/private/source.pptx", string(pptx))
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, "uploads/private/source.pptx"); err != nil {
		t.Fatal(err)
	}
	pptxInput := map[string]any{"file_ref": "uploads/private/source.pptx", "record_id": "1"}
	pptxResult, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", pptxInput)
	if err != nil {
		t.Fatalf("native PPTX ingest: %v", err)
	}
	pptxData, ok := pptxResult.Data.(map[string]any)
	if !ok || pptxData["complete"] != true {
		t.Fatalf("native PPTX result: %#v", pptxResult.Data)
	}
	pptxBlocks, ok := pptxData["blocks"].([]any)
	if !ok || len(pptxBlocks) != 1 {
		t.Fatalf("native PPTX blocks: %#v", pptxData["blocks"])
	}
	pptxBlock, ok := pptxBlocks[0].(map[string]any)
	if !ok || pptxBlock["sheet"] != "slide:1" || pptxBlock["value"] != "Native presentation text" {
		t.Fatalf("native PPTX block: %#v", pptxBlocks[0])
	}
	verified, err = runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", map[string]any{"file_ref": "uploads/private/source.pptx", "record_id": "1", "processing_id": pptxResult.ProcessingID, "sheet": "slide:1", "ref": "ppt/slides/slide7.xml#shape[1]/p[1]", "expected": "Native presentation text"})
	if err != nil || verified.Data.(map[string]any)["valid"] != true {
		t.Fatalf("native PPTX verify: %#v %v", verified, err)
	}
}

func TestOOXMLApprovedLocalOfficeDocumentsNativeHandler(t *testing.T) {
	paths := []string{}
	paths = append(paths, filepath.SplitList(os.Getenv("BENMORE_OOXML_FIXTURE_DOCX_PATHS"))...)
	if pptx := os.Getenv("BENMORE_OOXML_FIXTURE_PPTX_PATH"); pptx != "" {
		paths = append(paths, pptx)
	}
	if len(paths) == 0 {
		t.Skip("approved local Office fixtures were not configured")
	}
	for index, sourcePath := range paths {
		ext := strings.ToLower(filepath.Ext(sourcePath))
		if ext != ".docx" && ext != ".pptx" {
			t.Fatalf("approved fixture %d has unsupported extension", index)
		}
		original, err := os.ReadFile(sourcePath)
		if err != nil || len(original) == 0 {
			t.Fatalf("approved fixture %d could not be read", index)
		}
		app, pair := appMCPFileRuntimeFixture(t)
		logical := "uploads/private/approved" + ext
		writeTestFile(t, app.Dir, logical, string(original))
		if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, logical); err != nil {
			t.Fatalf("approved fixture %d could not be attached", index)
		}
		generation := snapshotAppMCPGeneration(app)
		input := map[string]any{"file_ref": logical, "record_id": "1", "per_page": json.Number("3")}
		ingested, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", input)
		if err != nil {
			var resultErr *appMCPResultError
			code := "unknown"
			if errors.As(err, &resultErr) {
				code = resultErr.Code
			}
			t.Fatalf("approved fixture %d native ingest failed (%s)", index, code)
		}
		data, ok := ingested.Data.(map[string]any)
		if !ok || data["complete"] != true {
			t.Fatalf("approved fixture %d did not produce a complete text-only snapshot", index)
		}
		blocks, ok := data["blocks"].([]any)
		if !ok || len(blocks) == 0 {
			t.Fatalf("approved fixture %d produced no paged source blocks", index)
		}
		var selected map[string]any
		for _, value := range blocks {
			candidate, ok := value.(map[string]any)
			if ok && candidate["sheet"] != "" && candidate["ref"] != "" {
				selected = candidate
				break
			}
		}
		if selected == nil {
			t.Fatalf("approved fixture %d did not expose stable source coordinates", index)
		}
		verify := map[string]any{
			"file_ref": logical, "record_id": "1", "processing_id": ingested.ProcessingID,
			"sheet": selected["sheet"], "ref": selected["ref"], "expected": selected["value"],
		}
		verified, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verify)
		verifiedData, valid := map[string]any(nil), false
		if err == nil {
			verifiedData, valid = verified.Data.(map[string]any)
		}
		if !valid || verifiedData["valid"] != true {
			t.Fatalf("approved fixture %d exact-span verification failed", index)
		}
		hash, err := appMCPCredentialHash(pair.AccessToken, "access")
		if err != nil {
			t.Fatalf("approved fixture %d authority lookup failed", index)
		}
		grant, err := readAppMCPAccessGrant(context.Background(), app, hash, grantFixtureResource, time.Now())
		if err != nil {
			t.Fatalf("approved fixture %d grant lookup failed", index)
		}
		status, err := appMCPReadFileProcessingStatus(context.Background(), app, ingested.ProcessingID, grant.UserID, grant.UserCreated, grant.Tenant, "notes", "1", logical)
		if err != nil || status["parser_version"] != IngestOOXMLTextParserVersion || status["complete"] != true {
			t.Fatalf("approved fixture %d status did not preserve parser provenance", index)
		}
		// The immutable snapshot must continue to verify its original evidence even
		// after the bytes at the authorized path have changed.
		writeTestFile(t, app.Dir, logical, "changed-after-capture")
		verified, err = runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verify)
		verifiedData, valid = map[string]any(nil), false
		if err == nil {
			verifiedData, valid = verified.Data.(map[string]any)
		}
		if !valid || verifiedData["valid"] != true {
			t.Fatalf("approved fixture %d historical snapshot changed with source bytes", index)
		}
		if _, err := app.DB.Exec(`UPDATE _benmore_mcp_grants SET revoked=1 WHERE id=?`, grant.ID); err != nil {
			t.Fatalf("approved fixture %d grant revocation failed", index)
		}
		if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verify); err == nil {
			t.Fatalf("approved fixture %d retained access after grant revocation", index)
		}
	}
}

func TestOOXMLApprovedUnsupportedSalesProcessFailsClosed(t *testing.T) {
	path := os.Getenv("BENMORE_OOXML_NEGATIVE_DOCX_PATH")
	if path == "" {
		t.Skip("approved known-unsupported DOCX fixture was not configured")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatal("approved known-unsupported DOCX fixture could not be read")
	}
	result, parseErr := IngestDOCX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if !errors.Is(parseErr, ErrIngestUnsupported) || result.Complete || len(result.Blocks) != 0 {
		t.Fatalf("known unsupported feature did not fail closed with the unsupported classification: complete=%v blocks=%d unsupported=%v corrupt=%v", result.Complete, len(result.Blocks), errors.Is(parseErr, ErrIngestUnsupported), errors.Is(parseErr, ErrIngestCorrupt))
	}
	app, pair := appMCPFileRuntimeFixture(t)
	logical := "uploads/private/approved-sales-process.docx"
	writeTestFile(t, app.Dir, logical, string(data))
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, logical); err != nil {
		t.Fatal("could not attach known unsupported fixture")
	}
	_, handlerErr := runAppMCPFileTool(context.Background(), app, snapshotAppMCPGeneration(app), pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": logical, "record_id": "1"})
	var failure *appMCPResultError
	if !errors.As(handlerErr, &failure) || failure.Code != "incomplete_result" {
		t.Fatal("native handler did not report the unsupported document as incomplete")
	}
	var completeSnapshots int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_file_processings WHERE parser_version=? AND complete=1`, IngestOOXMLTextParserVersion).Scan(&completeSnapshots); err != nil || completeSnapshots != 0 {
		t.Fatalf("unsupported document published a complete snapshot: count=%d", completeSnapshots)
	}
}

func TestOOXMLPPTXDispatchRejectsMIMEExtensionMismatch(t *testing.T) {
	data := testPPTX(t, `<presentation xmlns="`+testPptNS+`"/>`, "")
	if _, err := appMCPParsePrivateUpload("uploads/private/file.docx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", data, DefaultIngestLimits()); !errors.Is(err, ErrIngestUnsupported) {
		t.Fatalf("MIME/extension mismatch accepted: %v", err)
	}
	if _, err := appMCPParsePrivateUpload("uploads/private/file.pptx", "application/zip", data, DefaultIngestLimits()); !errors.Is(err, ErrIngestUnsupported) {
		t.Fatalf("generic ZIP MIME was accepted: %v", err)
	}
}

func ExampleIngestOOXMLTextParserVersion() {
	fmt.Println(IngestOOXMLTextParserVersion)
	// Output: doc-ooxml-text/1
}
