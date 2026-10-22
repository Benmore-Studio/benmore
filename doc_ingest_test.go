//go:build !cli

package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

// ---- in-memory OOXML fixtures (no binary files) ----------------------------

const ingNS = `xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"`

type ingEntry struct{ name, body string }

func ingZip(t testing.TB, entries ...ingEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type ingSheet struct{ name, state, rows string } // rows: <row>…</row> markup

type ingWB struct {
	sheets   []ingSheet
	sst      []string // raw <si> inner markup
	styles   string   // full styleSheet XML, "" for none
	date1904 bool
	mainCT   string // override the workbook content type
	vba      bool
	extPart  bool
	extRef   bool
	extra    []ingEntry
}

func (o ingWB) build(t testing.TB) []byte {
	mainCT := o.mainCT
	if mainCT == "" {
		mainCT = ingestCTXLSX
	}
	ct := `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/xl/workbook.xml" ContentType="` + mainCT + `"/></Types>`
	rels := `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
	var sheets, wbrels strings.Builder
	var files []ingEntry
	for i, s := range o.sheets {
		id := "rId" + strconv.Itoa(i+1)
		state := ""
		if s.state != "" {
			state = ` state="` + s.state + `"`
		}
		fmt.Fprintf(&sheets, `<sheet name="%s" sheetId="%d"%s r:id="%s"/>`, s.name, i+1, state, id)
		fmt.Fprintf(&wbrels, `<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, id, i+1)
		files = append(files, ingEntry{fmt.Sprintf("xl/worksheets/sheet%d.xml", i+1),
			`<?xml version="1.0"?><worksheet ` + ingNS + `><sheetData>` + s.rows + `</sheetData></worksheet>`})
	}
	if len(o.sst) > 0 {
		wbrels.WriteString(`<Relationship Id="rIdS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>`)
		files = append(files, ingEntry{"xl/sharedStrings.xml", `<sst ` + ingNS + `><si>` + strings.Join(o.sst, `</si><si>`) + `</si></sst>`})
	}
	if o.styles != "" {
		wbrels.WriteString(`<Relationship Id="rIdT" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`)
		files = append(files, ingEntry{"xl/styles.xml", o.styles})
	}
	pr := ""
	if o.date1904 {
		pr = `<workbookPr date1904="1"/>`
	}
	ext := ""
	if o.extRef {
		ext = `<externalReferences><externalReference r:id="rIdX"/></externalReferences>`
	}
	wb := `<?xml version="1.0"?><workbook ` + ingNS + ` xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
		pr + `<sheets>` + sheets.String() + `</sheets>` + ext + `</workbook>`
	out := []ingEntry{
		{"[Content_Types].xml", ct},
		{"_rels/.rels", rels + `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
		{"xl/workbook.xml", wb},
		{"xl/_rels/workbook.xml.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + wbrels.String() + `</Relationships>`},
	}
	out = append(out, files...)
	if o.vba {
		out = append(out, ingEntry{"xl/vbaProject.bin", "not really a macro"})
	}
	if o.extPart {
		out = append(out, ingEntry{"xl/externalLinks/externalLink1.xml", `<externalLink ` + ingNS + `/>`})
	}
	return ingZip(t, append(out, o.extra...)...)
}

func ingOne(rows string) ingWB { return ingWB{sheets: []ingSheet{{"Sheet1", "", rows}}} }

func ingRun(t testing.TB, data []byte, lim IngestLimits) (IngestResult, error) {
	t.Helper()
	return IngestXLSX(bytes.NewReader(data), int64(len(data)), lim)
}

func ingBlock(t testing.TB, res IngestResult, sheet, ref string) SourceBlock {
	t.Helper()
	for _, b := range res.Blocks {
		if b.Sheet == sheet && b.Ref == ref {
			return b
		}
	}
	t.Fatalf("no block %s!%s in %d blocks", sheet, ref, len(res.Blocks))
	return SourceBlock{}
}

const ingStyles = `<styleSheet ` + ingNS + `>` +
	`<numFmts count="2"><numFmt numFmtId="164" formatCode="yyyy\-mm\-dd"/><numFmt numFmtId="165" formatCode="0.00&quot; kg&quot;"/></numFmts>` +
	`<cellStyleXfs count="1"><xf numFmtId="14"/></cellStyleXfs>` +
	`<cellXfs count="5"><xf numFmtId="0"/><xf numFmtId="14"/><xf numFmtId="164"/><xf numFmtId="165"/><xf numFmtId="9"/></cellXfs></styleSheet>`

// ---- CSV -------------------------------------------------------------------

func TestIngestCSVQuotingBOMCRLF(t *testing.T) {
	in := "\xEF\xBB\xBFname,note\r\n\"Smith, J\",\"say \"\"hi\"\"\"\r\n\"multi\nline\",00123\r\n"
	res, err := IngestCSV(strings.NewReader(in), DefaultIngestLimits())
	if err != nil || !res.Complete {
		t.Fatalf("err=%v complete=%v", err, res.Complete)
	}
	want := map[string]string{"A1": "name", "B1": "note", "A2": "Smith, J", "B2": `say "hi"`, "A3": "multi\nline", "B3": "00123"}
	if len(res.Blocks) != len(want) {
		t.Fatalf("got %d blocks, want %d", len(res.Blocks), len(want))
	}
	for ref, v := range want {
		b := ingBlock(t, res, "csv", ref)
		if b.Value != v || b.Type != CellTypeString || b.Kind != BlockKindCell {
			t.Errorf("%s = %+v, want value %q string cell", ref, b, v)
		}
	}
	if res.Format != IngestFormatCSV || res.ParserVersion != IngestParserVersion || len(res.SHA256) != 64 {
		t.Errorf("metadata: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Warnings, ","), "utf8_bom_stripped") {
		t.Errorf("BOM not noted: %v", res.Warnings)
	}
	if s := res.Sheets[0]; s.MaxRow != 3 || s.MaxCol != 2 || s.Cells != 6 {
		t.Errorf("sheet info %+v", s)
	}
}

func TestIngestCSVErrors(t *testing.T) {
	lim := DefaultIngestLimits()
	lim.MaxFieldBytes = 10
	cases := []struct {
		name string
		in   string
		lim  IngestLimits
		is   error
	}{
		{"oversized field", "a," + strings.Repeat("x", 11) + "\n", lim, ErrIngestLimit},
		{"too many rows", "a\nb\nc\n", IngestLimits{MaxCSVRows: 2}, ErrIngestLimit},
		{"too many cells", "a,b\nc,d\n", IngestLimits{MaxCells: 3}, ErrIngestLimit},
		{"file too large", "abcdef\n", IngestLimits{MaxFileBytes: 5}, ErrIngestTooLarge},
		{"bare quote", "a,b\"c\n", DefaultIngestLimits(), ErrIngestCorrupt},
		{"empty", " \n", DefaultIngestLimits(), ErrIngestCorrupt},
		{"utf16", "\xFF\xFEa\x00", DefaultIngestLimits(), ErrIngestUnsupported},
		{"invalid utf8", "a,\xff\n", DefaultIngestLimits(), ErrIngestUnsupported},
		{"nul byte", "a,\x00\n", DefaultIngestLimits(), ErrIngestUnsupported},
	}
	for _, tc := range cases {
		res, err := IngestCSV(strings.NewReader(tc.in), tc.lim)
		if !errors.Is(err, tc.is) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.is)
		}
		ingExpectFailed(t, tc.name, res)
	}
	var le *IngestLimitError
	_, err := IngestCSV(strings.NewReader("a\nb\nc\n"), IngestLimits{MaxCSVRows: 2})
	if !errors.As(err, &le) || le.Limit != "MaxCSVRows" || le.Max != 2 {
		t.Errorf("limit error does not name the limit: %v", err)
	}
}

func ingExpectFailed(t testing.TB, name string, res IngestResult) {
	t.Helper()
	if res.Complete || len(res.Blocks) != 0 || len(res.Sheets) != 0 {
		t.Errorf("%s: error path returned complete=%v blocks=%d sheets=%d", name, res.Complete, len(res.Blocks), len(res.Sheets))
	}
}

func TestIngestCSVCellLimitIsExact(t *testing.T) {
	row := func(n int) string { return strings.TrimSuffix(strings.Repeat("v,", n), ",") + "\n" }
	// 1000 rows x 100 columns = 100,000 cells.
	ok := strings.Repeat(row(100), 1000)
	res, err := IngestCSV(strings.NewReader(ok), DefaultIngestLimits())
	if err != nil || !res.Complete || len(res.Blocks) != 100_000 {
		t.Fatalf("100,000 cells: err=%v complete=%v blocks=%d", err, res.Complete, len(res.Blocks))
	}
	res, err = IngestCSV(strings.NewReader(ok+"v\n"), DefaultIngestLimits())
	if !errors.Is(err, ErrIngestLimit) || res.Complete {
		t.Fatalf("100,001 cells: err=%v complete=%v", err, res.Complete)
	}
}

// ---- XLSX ------------------------------------------------------------------

func TestIngestXLSXValues(t *testing.T) {
	o := ingWB{
		styles: ingStyles,
		sst:    []string{`<t>Alpha</t>`, `<r><t>Hel</t></r><r><t xml:space="preserve">lo </t></r><rPh sb="0" eb="1"><t>IGNORED</t></rPh>`},
		sheets: []ingSheet{
			{"Data", "", `<row r="1">` +
				`<c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c>` +
				`<c r="C1" t="inlineStr"><is><t>inline</t></is></c>` +
				`<c r="D1"><v>3.14</v></c><c r="E1" t="b"><v>1</v></c><c r="F1" t="b"><v>0</v></c>` +
				`<c r="G1" t="e"><v>#DIV/0!</v></c></row>` +
				`<row r="2"><c r="A2" s="1"><v>45000</v></c><c r="B2" s="2"><v>45000.5</v></c>` +
				`<c r="C2" s="3"><v>12.5</v></c><c r="D2" s="4"><v>0.25</v></c><c r="E2" s="1"><v>60</v></c>` +
				`<c r="F2" s="1"><v>61</v></c><c r="G2" s="1"><v>0.75</v></c><c r="H2" s="1"><v>1</v></c></row>` +
				`<row r="3"><c r="A3"><f>SUM(D1:D1)</f><v>3.14</v></c><c r="B3" t="str"><f>A1&amp;"!"</f><v>Alpha!</v></c>` +
				`<c r="C3"><f>NOW()</f></c><c r="D3" s="1"/><c r="E3" t="d"><v>2024-02-29T10:00:00Z</v></c></row>`},
			{"Hidden one", "hidden", `<row><c t="inlineStr"><is><t>h</t></is></c><c><v>7</v></c></row>`},
		},
	}
	res, err := ingRun(t, o.build(t), DefaultIngestLimits())
	if err != nil || !res.Complete || res.Format != IngestFormatXLSX {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if len(res.Sheets) != 2 || res.Sheets[0].Name != "Data" || res.Sheets[1].State != "hidden" {
		t.Fatalf("sheets: %+v", res.Sheets)
	}
	type want struct{ val, typ string }
	for ref, w := range map[string]want{
		"A1": {"Alpha", CellTypeString}, "B1": {"Hello ", CellTypeString}, "C1": {"inline", CellTypeString},
		"D1": {"3.14", CellTypeNumber}, "E1": {"true", CellTypeBool}, "F1": {"false", CellTypeBool},
		"G1": {"#DIV/0!", CellTypeError},
		"A2": {"2023-03-15", CellTypeDate}, "B2": {"2023-03-15", CellTypeDate},
		"C2": {"12.5", CellTypeNumber}, "D2": {"0.25", CellTypeNumber},
		"E2": {"1900-02-29", CellTypeDate}, "F2": {"1900-03-01", CellTypeDate},
		"G2": {"18:00:00", CellTypeDate}, "H2": {"1900-01-01", CellTypeDate},
		"E3": {"2024-02-29T10:00:00Z", CellTypeDate},
	} {
		b := ingBlock(t, res, "Data", ref)
		if ref == "B2" { // custom yyyy-mm-dd format with a time fraction keeps the time
			w.val = "2023-03-15T12:00:00"
		}
		if b.Value != w.val || b.Type != w.typ {
			t.Errorf("%s = (%q,%s), want (%q,%s)", ref, b.Value, b.Type, w.val, w.typ)
		}
	}
	if b := ingBlock(t, res, "Data", "C2"); b.NumFmt != `0.00" kg"` {
		t.Errorf("declared unit lost: %q", b.NumFmt)
	}
	if b := ingBlock(t, res, "Data", "D2"); b.NumFmt != "0%" {
		t.Errorf("percent format lost: %q", b.NumFmt)
	}
	if b := ingBlock(t, res, "Data", "E2"); !strings.Contains(strings.Join(b.Quality, ","), QualityDate1900LeapBug) {
		t.Errorf("serial 60 not flagged: %+v", b)
	}
	// Formulas: cached values labelled, never evaluated.
	for _, ref := range []string{"A3", "B3"} {
		b := ingBlock(t, res, "Data", ref)
		if !b.Formula || !b.CachedFormula || !strings.Contains(strings.Join(b.Quality, ","), QualityCachedFormulaResult) ||
			!strings.Contains(strings.Join(b.Quality, ","), QualityFreshnessNotVerified) {
			t.Errorf("%s not labelled as cached formula: %+v", ref, b)
		}
	}
	if b := ingBlock(t, res, "Data", "C3"); b.Type != CellTypeEmpty || !b.Formula || b.CachedFormula || b.Quality[0] != QualityFormulaNoCachedValue {
		t.Errorf("formula without cache: %+v", b)
	}
	for _, b := range res.Blocks {
		if b.Ref == "D3" {
			t.Errorf("blank styled cell emitted: %+v", b)
		}
	}
	// Cells without r= get sequential positions on the second sheet.
	if b := ingBlock(t, res, "Hidden one", "B1"); b.Value != "7" {
		t.Errorf("positional cell: %+v", b)
	}
	if len(res.Quality) != 0 {
		t.Errorf("unexpected file flags %v", res.Quality)
	}
}

func TestIngestXLSXDate1904(t *testing.T) {
	o := ingWB{styles: ingStyles, date1904: true, sheets: []ingSheet{{"S", "", `<row r="1"><c r="A1" s="1"><v>0</v></c><c r="B1" s="1"><v>43538</v></c></row>`}}}
	res, err := ingRun(t, o.build(t), DefaultIngestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if v := ingBlock(t, res, "S", "A1").Value; v != "1904-01-01" {
		t.Errorf("1904 epoch = %q", v)
	}
	if v := ingBlock(t, res, "S", "B1").Value; v != "2023-03-15" {
		t.Errorf("1904 date = %q", v)
	}
}

func TestIngestXLSMAndExternalLinksFlagged(t *testing.T) {
	o := ingOne(`<row r="1"><c r="A1"><v>1</v></c></row>`)
	o.mainCT = ingestCTXLSM
	o.vba = true
	res, err := ingRun(t, o.build(t), DefaultIngestLimits())
	if err != nil || res.Format != IngestFormatXLSM || len(res.Quality) != 1 || res.Quality[0] != QualityMacrosNotExecuted {
		t.Fatalf("xlsm: err=%v format=%s quality=%v", err, res.Format, res.Quality)
	}
	for name, o := range map[string]ingWB{"part": {extPart: true}, "reference": {extRef: true}} {
		o.sheets = []ingSheet{{"S", "", `<row r="1"><c r="A1"><f>[1]Sheet1!A1</f><v>9</v></c></row>`}}
		res, err := ingRun(t, o.build(t), DefaultIngestLimits())
		if err != nil || len(res.Quality) != 1 || res.Quality[0] != QualityExternalLinksNotFetch {
			t.Errorf("%s: err=%v quality=%v", name, err, res.Quality)
		}
		if b := ingBlock(t, res, "S", "A1"); b.Value != "9" || !b.CachedFormula {
			t.Errorf("%s: external formula must keep only its cached value: %+v", name, b)
		}
	}
}

func TestIngestXLSXCellLimitIsExact(t *testing.T) {
	rows := func(cells int) string {
		var b strings.Builder
		for r := 1; cells > 0; r++ {
			fmt.Fprintf(&b, `<row r="%d">`, r)
			for c := 0; c < 100 && cells > 0; c, cells = c+1, cells-1 {
				fmt.Fprintf(&b, `<c r="%s%d"><v>1</v></c>`, colLetter(c), r)
			}
			b.WriteString(`</row>`)
		}
		return b.String()
	}
	res, err := ingRun(t, ingOne(rows(100_000)).build(t), DefaultIngestLimits())
	if err != nil || !res.Complete || len(res.Blocks) != 100_000 {
		t.Fatalf("100,000 cells: err=%v complete=%v blocks=%d", err, res.Complete, len(res.Blocks))
	}
	res, err = ingRun(t, ingOne(rows(100_001)).build(t), DefaultIngestLimits())
	var le *IngestLimitError
	if !errors.As(err, &le) || le.Limit != "MaxCells" || res.Complete {
		t.Fatalf("100,001 cells: err=%v complete=%v", err, res.Complete)
	}
}

func ingOLE(extra string) []byte {
	b := append([]byte{}, ingestOLEMagic...)
	b = append(b, make([]byte, 4096)...)
	b = append(b, ingestUTF16LE(extra)...)
	return append(b, make([]byte, 600)...)
}

func TestIngestXLSXErrorPaths(t *testing.T) {
	good := ingOne(`<row r="1"><c r="A1"><v>1</v></c></row>`).build(t)
	sheetXML := func(body string) []byte {
		return ingZip(t, ingEntries(t, ingOne(""), "xl/worksheets/sheet1.xml", `<worksheet `+ingNS+`>`+body)...)
	}
	small := DefaultIngestLimits()
	bomb := ingOne(`<row r="1"><c r="A1"><v>1</v></c></row>`)
	bomb.extra = []ingEntry{{"xl/media/zeros.bin", strings.Repeat("\x00", 8<<20)}}
	many := ingOne(`<row r="1"><c r="A1"><v>1</v></c></row>`)
	for i := 0; i < 2100; i++ {
		many.extra = append(many.extra, ingEntry{fmt.Sprintf("xl/media/m%d.bin", i), "x"})
	}
	traversal := ingOne("")
	traversal.extra = []ingEntry{{"../evil.xml", "x"}}
	absolute := ingOne("")
	absolute.extra = []ingEntry{{"/etc/passwd", "x"}}
	dup := ingOne("")
	dup.extra = []ingEntry{{"XL/Workbook.xml", "<workbook/>"}}
	doctype := ingZip(t, ingEntries(t, ingOne(""), "xl/worksheets/sheet1.xml",
		`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><worksheet `+ingNS+`><sheetData/></worksheet>`)...)
	docx := ingOne("")
	docx.mainCT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
	xlsb := ingOne("")
	xlsb.mainCT = ingestCTXLSB
	badSST := ingWB{sst: []string{"<t>a</t>"}, sheets: []ingSheet{{"S", "", `<row r="1"><c r="A1" t="s"><v>5</v></c></row>`}}}
	dupCell := ingOne(`<row r="1"><c r="A1"><v>1</v></c><c r="A1"><v>2</v></c></row>`)
	badRef := ingOne(`<row r="1"><c r="ZZZZ1"><v>1</v></c></row>`)
	dupSheet := ingWB{sheets: []ingSheet{{"S", "", ""}, {"s", "", ""}}}
	sst := ingWB{sst: []string{"<t>a</t>", "<t>b</t>", "<t>c</t>"}, sheets: []ingSheet{{"S", "", ""}}}
	deep := ingOne(strings.Repeat("<a>", 80) + strings.Repeat("</a>", 80))

	cases := []struct {
		name string
		data []byte
		lim  IngestLimits
		is   error
		lm   string // expected IngestLimitError.Limit, when is == ErrIngestLimit
	}{
		{"zip bomb ratio", bomb.build(t), small, ErrIngestLimit, "MaxCompressionRatio"},
		{"too many entries", many.build(t), small, ErrIngestLimit, "MaxZipEntries"},
		{"entry too big", good, IngestLimits{MaxEntryBytes: 50}, ErrIngestLimit, "MaxEntryBytes"},
		{"total inflate too big", good, IngestLimits{MaxDecompressedBytes: 1000}, ErrIngestLimit, "MaxDecompressedBytes"},
		{"file too large", good, IngestLimits{MaxFileBytes: 100}, ErrIngestTooLarge, ""},
		{"shared strings limit", sst.build(t), IngestLimits{MaxSharedStrings: 2}, ErrIngestLimit, "MaxSharedStrings"},
		{"sheet limit", dupSheet.build(t), IngestLimits{MaxSheets: 1}, ErrIngestLimit, "MaxSheets"},
		{"xml depth", deep.build(t), IngestLimits{MaxXMLDepth: 16}, ErrIngestLimit, "MaxXMLDepth"},
		{"xml tokens", good, IngestLimits{MaxXMLTokens: 3}, ErrIngestLimit, "MaxXMLTokens"},
		{"field too long", ingOne(`<row r="1"><c r="A1" t="inlineStr"><is><t>` + strings.Repeat("x", 50) + `</t></is></c></row>`).build(t), IngestLimits{MaxFieldBytes: 10}, ErrIngestLimit, "MaxFieldBytes"},
		{"extracted bytes", ingOne(`<row r="1"><c r="A1" t="inlineStr"><is><t>0123456789</t></is></c><c r="B1" t="inlineStr"><is><t>0123456789</t></is></c></row>`).build(t), IngestLimits{MaxExtractedBytes: 15}, ErrIngestLimit, "MaxExtractedBytes"},
		{"encrypted OLE", ingOLE("EncryptedPackage"), small, ErrIngestEncrypted, ""},
		{"encrypted OLE info only", ingOLE("EncryptionInfo"), small, ErrIngestEncrypted, ""},
		{"legacy xls OLE", ingOLE("Workbook"), small, ErrIngestUnsupported, ""},
		{"not a zip", []byte("PK nonsense, definitely not an archive"), small, ErrIngestCorrupt, ""},
		{"empty input", nil, small, ErrIngestCorrupt, ""},
		{"truncated zip", good[:len(good)/2], small, ErrIngestCorrupt, ""},
		{"truncated xml", sheetXML(`<sheetData><row r="1"><c r="A1"><v>1</v>`), small, ErrIngestCorrupt, ""},
		{"mismatched xml", sheetXML(`<sheetData><row></c></sheetData></worksheet>`), small, ErrIngestCorrupt, ""},
		{"path traversal entry", traversal.build(t), small, ErrIngestCorrupt, ""},
		{"absolute entry", absolute.build(t), small, ErrIngestCorrupt, ""},
		{"duplicate entry (case)", dup.build(t), small, ErrIngestCorrupt, ""},
		{"DTD refused", doctype, small, ErrIngestUnsupported, ""},
		{"docx", docx.build(t), small, ErrIngestUnsupported, ""},
		{"xlsb", xlsb.build(t), small, ErrIngestUnsupported, ""},
		{"bad shared string index", badSST.build(t), small, ErrIngestCorrupt, ""},
		{"duplicate cell", dupCell.build(t), small, ErrIngestCorrupt, ""},
		{"bad cell ref", badRef.build(t), small, ErrIngestCorrupt, ""},
		{"duplicate sheet name", dupSheet.build(t), small, ErrIngestCorrupt, ""},
		{"zip without workbook", ingZip(t, ingEntry{"a.txt", "hi"}), small, ErrIngestUnsupported, ""},
	}
	for _, tc := range cases {
		res, err := ingRun(t, tc.data, tc.lim)
		if !errors.Is(err, tc.is) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.is)
			continue
		}
		ingExpectFailed(t, tc.name, res)
		if tc.lm != "" {
			var le *IngestLimitError
			if !errors.As(err, &le) || le.Limit != tc.lm {
				t.Errorf("%s: limit = %v, want %s", tc.name, err, tc.lm)
			}
		}
	}
}

// ingEntries rebuilds the entry list of a workbook fixture with one part replaced.
func ingEntries(t testing.TB, o ingWB, name, body string) []ingEntry {
	t.Helper()
	data := o.build(t)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out []ingEntry
	for _, f := range zr.File {
		if f.Name == name {
			out = append(out, ingEntry{name, body})
			continue
		}
		rc, _ := f.Open()
		var b bytes.Buffer
		b.ReadFrom(rc)
		rc.Close()
		out = append(out, ingEntry{f.Name, b.String()})
	}
	return out
}

// A header that understates the size must be rejected: Go's zip reader refuses
// to inflate past the declared size (ErrFormat) and our byte budget backs it up.
func TestIngestXLSXLyingHeaderCannotInflatePastBudget(t *testing.T) {
	data := ingOne(strings.Repeat("<row/>", 300_000)).build(t) // ~1.8 MB of sheet XML
	// Patch the central-directory uncompressed size of sheet1.xml to 10 bytes so
	// the declared-size and ratio pre-checks pass.
	sig := []byte{0x50, 0x4b, 0x01, 0x02}
	patched := 0
	for i := 0; ; {
		j := bytes.Index(data[i:], sig)
		if j < 0 {
			break
		}
		at := i + j
		nameLen := int(binary.LittleEndian.Uint16(data[at+28:]))
		if string(data[at+46:at+46+nameLen]) == "xl/worksheets/sheet1.xml" {
			binary.LittleEndian.PutUint32(data[at+24:], 10)
			patched++
		}
		i = at + 4
	}
	if patched != 1 {
		t.Fatalf("patched %d headers", patched)
	}
	res, err := ingRun(t, data, IngestLimits{MaxEntryBytes: 1 << 20})
	if !errors.Is(err, ErrIngestCorrupt) && !errors.Is(err, ErrIngestLimit) || res.Complete {
		t.Fatalf("lying header: err=%v complete=%v", err, res.Complete)
	}
}

func TestIngestDefaultLimitsFrozen(t *testing.T) {
	d := DefaultIngestLimits()
	if d.MaxFileBytes != 25<<20 || d.MaxCells != 100_000 {
		t.Fatalf("per-file defaults changed: %+v", d)
	}
	if z := (IngestLimits{}).normalize(); z != d {
		t.Fatalf("zero limits must normalize to the defaults: %+v", z)
	}
}

func TestVerifySpan(t *testing.T) {
	res, err := ingRun(t, ingWB{sheets: []ingSheet{{"S", "", `<row r="1"><c r="B2" t="inlineStr"><is><t>42 units</t></is></c></row>`}}}.build(t), DefaultIngestLimits())
	if err != nil {
		t.Fatal(err)
	}
	// B2 comes from the cell's own r attribute even though it sits in row 1's element.
	if !VerifySpan(res, "S", "B2", "42 units") {
		t.Error("exact value must verify")
	}
	for _, c := range []struct{ sheet, ref, v string }{
		{"S", "B2", "42"}, {"S", "B2", "42 units "}, {"S", "B3", "42 units"}, {"T", "B2", "42 units"},
	} {
		if VerifySpan(res, c.sheet, c.ref, c.v) {
			t.Errorf("VerifySpan(%q,%q,%q) = true", c.sheet, c.ref, c.v)
		}
	}
	res.Complete = false
	if VerifySpan(res, "S", "B2", "42 units") {
		t.Error("an incomplete result must never verify")
	}
}

func TestBudgetReaderFailsInsteadOfEOF(t *testing.T) {
	var total int64
	br := &budgetReader{r: bytes.NewReader(make([]byte, 100)), maxEntry: 40, total: &total, maxTotal: 1000}
	_, err := io.ReadAll(br)
	var le *IngestLimitError
	if !errors.As(err, &le) || le.Limit != "MaxEntryBytes" {
		t.Fatalf("entry budget: %v", err)
	}
	total = 0
	br = &budgetReader{r: bytes.NewReader(make([]byte, 100)), maxEntry: 1000, total: &total, maxTotal: 40}
	if _, err = io.ReadAll(br); !errors.As(err, &le) || le.Limit != "MaxDecompressedBytes" {
		t.Fatalf("total budget: %v", err)
	}
}

// ---- fuzz ------------------------------------------------------------------

func ingCheckInvariants(t *testing.T, res IngestResult, err error) {
	t.Helper()
	if err == nil {
		if !res.Complete || res.ParserVersion == "" {
			t.Fatalf("success without Complete: %+v", res)
		}
		return
	}
	if res.Complete || len(res.Blocks) != 0 {
		t.Fatalf("error %v returned complete=%v blocks=%d", err, res.Complete, len(res.Blocks))
	}
	for _, s := range []error{ErrIngestTooLarge, ErrIngestEncrypted, ErrIngestCorrupt, ErrIngestUnsupported, ErrIngestLimit} {
		if errors.Is(err, s) {
			return
		}
	}
	t.Fatalf("untyped error: %v", err)
}

func ingFuzzLimits() IngestLimits {
	l := DefaultIngestLimits()
	l.MaxFileBytes = 1 << 20
	l.MaxCells = 2000
	l.MaxDecompressedBytes = 4 << 20
	l.MaxEntryBytes = 2 << 20
	return l
}

func FuzzIngestXLSX(f *testing.F) {
	o := ingWB{styles: ingStyles, sst: []string{"<t>x</t>"}, sheets: []ingSheet{{"S", "", `<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" s="1"><v>45000</v></c><c r="C1"><f>1+1</f><v>2</v></c></row>`}}}
	f.Add(o.build(f))
	o.mainCT = ingestCTXLSM
	o.vba = true
	f.Add(o.build(f))
	f.Add(ingOLE("EncryptedPackage"))
	f.Add(ingOLE("Workbook"))
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	good := ingOne(`<row r="1"><c r="A1"><v>1</v></c></row>`).build(f)
	f.Add(good[:len(good)/2])
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := IngestXLSX(bytes.NewReader(data), int64(len(data)), ingFuzzLimits())
		ingCheckInvariants(t, res, err)
	})
}

func FuzzIngestCSV(f *testing.F) {
	for _, s := range []string{"a,b\n1,2\n", "\xEF\xBB\xBF\"q\"\"x\",\r\n", "a,\"unterminated\n", "", "\xff\xfe", "a\x00b", ",,,\n,,,\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := IngestCSV(bytes.NewReader(data), ingFuzzLimits())
		ingCheckInvariants(t, res, err)
	})
}
