//go:build !cli

package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
)

// Workbook main-part content types.
const (
	ingestCTXLSX    = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
	ingestCTXLTX    = "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml"
	ingestCTXLSM    = "application/vnd.ms-excel.sheet.macroenabled.main+xml"
	ingestCTXLTM    = "application/vnd.ms-excel.template.macroenabled.main+xml"
	ingestCTXLSB    = "application/vnd.ms-excel.sheet.binary.macroenabled.main"
	ingestMaxRow    = 1048576
	ingestMaxCol    = 16384
	maxExcelSerial  = 2958465 // 9999-12-31
	ingestRelOffice = "/officedocument"
)

var ingestOLEMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

func ingestUTF16LE(s string) []byte {
	b := make([]byte, 0, 2*len(s))
	for i := 0; i < len(s); i++ {
		b = append(b, s[i], 0)
	}
	return b
}

// ingestSniffOLE detects an OLE compound file. Password-protected OOXML is
// stored as one (EncryptionInfo + EncryptedPackage streams), so those names in
// the directory mean "encrypted"; any other OLE file is legacy .xls.
func ingestSniffOLE(r io.ReaderAt, size int64) error {
	var head [8]byte
	if n, _ := r.ReadAt(head[:], 0); n < len(head) || !bytes.Equal(head[:], ingestOLEMagic) {
		return nil
	}
	pats := [][]byte{ingestUTF16LE("EncryptedPackage"), ingestUTF16LE("EncryptionInfo")}
	sr := io.NewSectionReader(r, 0, size)
	chunk := make([]byte, 1<<16)
	var tail []byte
	for {
		n, err := sr.Read(chunk)
		window := append(tail, chunk[:n]...)
		for _, p := range pats {
			if bytes.Contains(window, p) {
				return fmt.Errorf("%w: password-protected Office document (OLE container)", ErrIngestEncrypted)
			}
		}
		keep := len(window)
		if keep > 31 {
			keep = 31
		}
		tail = append([]byte(nil), window[len(window)-keep:]...)
		if err != nil {
			break
		}
	}
	return fmt.Errorf("%w: legacy OLE container (.xls); save as .xlsx or .csv", ErrIngestUnsupported)
}

// IngestXLSX reads an XLSX/XLSM workbook into cell blocks without executing
// anything: formulas are never evaluated (cached results are labelled), macros
// and external links are only flagged. See doc_ingest.go for the contract.
func IngestXLSX(r io.ReaderAt, size int64, limits IngestLimits) (IngestResult, error) {
	lim := limits.normalize()
	res := failedIngest(IngestFormatXLSX)
	if size < 0 {
		return res, fmt.Errorf("%w: negative size", ErrIngestCorrupt)
	}
	if size > lim.MaxFileBytes {
		return res, fmt.Errorf("%w: %d bytes exceeds %d", ErrIngestTooLarge, size, lim.MaxFileBytes)
	}
	sum, err := ingestSHA256(r, size)
	if err != nil {
		return res, err
	}
	res.SHA256 = sum
	if err := ingestSniffOLE(r, size); err != nil {
		return res, err
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return res, fmt.Errorf("%w: not a ZIP/OOXML package: %v", ErrIngestCorrupt, err)
	}
	pkg, err := newIngestPkg(zr, lim)
	if err != nil {
		return res, err
	}
	out, err := ingestWorkbook(pkg, res)
	if err != nil {
		return res, err // res still carries only format, hash and version
	}
	out.Complete = true
	return out, nil
}

type ingestSheetRef struct{ name, state, rid string }

func ingestWorkbook(pkg *ingestPkg, res IngestResult) (IngestResult, error) {
	lim := pkg.lim
	// 1. main document part and its content type.
	rootRels, err := pkg.rels("_rels/.rels")
	if err != nil {
		return res, err
	}
	wbPath := ""
	for _, rel := range rootRels {
		if strings.HasSuffix(strings.ToLower(rel.Type), ingestRelOffice) && rel.Target != "" {
			if wbPath != "" {
				return res, fmt.Errorf("%w: several main documents", ErrIngestCorrupt)
			}
			if wbPath, err = ingestResolve("", rel.Target); err != nil {
				return res, err
			}
		}
	}
	if wbPath == "" {
		return res, fmt.Errorf("%w: not an Office package (no main document)", ErrIngestUnsupported)
	}
	ct, err := pkg.contentType(wbPath)
	if err != nil {
		return res, err
	}
	switch ct {
	case ingestCTXLSX, ingestCTXLTX:
		res.Format = IngestFormatXLSX
	case ingestCTXLSM, ingestCTXLTM:
		res.Format = IngestFormatXLSM
	case ingestCTXLSB:
		return res, fmt.Errorf("%w: binary workbook (.xlsb)", ErrIngestUnsupported)
	default:
		return res, fmt.Errorf("%w: main part is %q, not a spreadsheet", ErrIngestUnsupported, ct)
	}

	// 2. file-level flags that never need a part to be inflated.
	for key := range pkg.files {
		if strings.HasSuffix(key, "vbaproject.bin") {
			res.Quality = appendOnce(res.Quality, QualityMacrosNotExecuted)
		}
		if strings.HasPrefix(key, "xl/externallinks/") {
			res.Quality = appendOnce(res.Quality, QualityExternalLinksNotFetch)
		}
	}

	// 3. workbook: sheets, date system.
	var sheets []ingestSheetRef
	date1904 := false
	err = pkg.withPart(wbPath, func(r io.Reader) error {
		x := newIngestXML(r, lim, "workbook")
		for {
			tok, err := x.next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			se, ok := tok.(xml.StartElement)
			if !ok {
				continue
			}
			switch se.Name.Local {
			case "workbookPr":
				v := strings.ToLower(ingestAttr(se, "date1904"))
				date1904 = v == "1" || v == "true"
			case "externalReference":
				res.Quality = appendOnce(res.Quality, QualityExternalLinksNotFetch)
			case "sheet":
				if len(sheets) >= lim.MaxSheets {
					return ingestLimit("MaxSheets", int64(lim.MaxSheets), int64(len(sheets)+1))
				}
				sheets = append(sheets, ingestSheetRef{ingestAttr(se, "name"), ingestAttr(se, "state"), ingestAttrNS(se, "id")})
			}
		}
	})
	if err != nil {
		return res, err
	}
	wbDir := path.Dir(wbPath)
	if wbDir == "." {
		wbDir = ""
	}
	wbRels, err := pkg.rels(relsPathFor(wbPath))
	if err != nil {
		return res, err
	}
	var sstPath, stylesPath string
	for _, rel := range wbRels {
		t := strings.ToLower(rel.Type)
		switch {
		case strings.HasSuffix(t, "/sharedstrings"):
			if sstPath != "" {
				return res, fmt.Errorf("%w: several shared string tables", ErrIngestCorrupt)
			}
			if sstPath, err = ingestResolve(wbDir, rel.Target); err != nil {
				return res, err
			}
		case strings.HasSuffix(t, "/styles"):
			if stylesPath != "" {
				return res, fmt.Errorf("%w: several style parts", ErrIngestCorrupt)
			}
			if stylesPath, err = ingestResolve(wbDir, rel.Target); err != nil {
				return res, err
			}
		case strings.HasSuffix(t, "/externallink"):
			res.Quality = appendOnce(res.Quality, QualityExternalLinksNotFetch)
		}
	}

	// 4. styles and shared strings (both optional parts).
	var styles ingestStyles
	if stylesPath != "" && pkg.has(stylesPath) {
		if styles, err = pkg.parseStyles(stylesPath); err != nil {
			return res, err
		}
	}
	var sst []string
	if sstPath != "" && pkg.has(sstPath) {
		if sst, err = pkg.parseSharedStrings(sstPath); err != nil {
			return res, err
		}
	}

	// 5. worksheets, in workbook order.
	acc := &ingestAcc{lim: lim}
	var blocks []SourceBlock
	seenNames := map[string]bool{}
	for _, sh := range sheets {
		lname := strings.ToLower(sh.name)
		if sh.name == "" || seenNames[lname] {
			return res, fmt.Errorf("%w: empty or duplicate sheet name %q", ErrIngestCorrupt, sh.name)
		}
		seenNames[lname] = true
		rel, ok := wbRels[sh.rid]
		if !ok || rel.Target == "" {
			return res, fmt.Errorf("%w: sheet %q has no relationship", ErrIngestCorrupt, sh.name)
		}
		info := SheetInfo{Name: sh.name}
		if st := strings.ToLower(sh.state); st == "hidden" || st == "veryhidden" {
			info.State = sh.state
		}
		t := strings.ToLower(rel.Type)
		switch {
		case strings.HasSuffix(t, "/worksheet"):
		case strings.HasSuffix(t, "/chartsheet"), strings.HasSuffix(t, "/dialogsheet"):
			// No cells to read; recorded so the omission is visible.
			info.State = "non_worksheet"
			res.Sheets = append(res.Sheets, info)
			res.Warnings = append(res.Warnings, "sheet_without_cells_skipped: "+sh.name)
			continue
		default:
			return res, fmt.Errorf("%w: sheet %q has unsupported type %q", ErrIngestUnsupported, sh.name, rel.Type)
		}
		part, err := ingestResolve(wbDir, rel.Target)
		if err != nil {
			return res, err
		}
		sp := &ingestSheetParser{pkg: pkg, acc: acc, sst: sst, styles: styles, date1904: date1904, info: &info}
		if blocks, err = sp.parse(part, blocks); err != nil {
			return res, err
		}
		res.Sheets = append(res.Sheets, info)
	}
	res.Blocks = blocks
	return res, nil
}

func appendOnce(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

// contentType returns the lower-cased Override content type of a part.
func (p *ingestPkg) contentType(part string) (string, error) {
	want := ingestKey("/" + part)
	found := ""
	err := p.withPart("[Content_Types].xml", func(r io.Reader) error {
		x := newIngestXML(r, p.lim, "Types")
		for {
			tok, err := x.next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "Override" && ingestKey(ingestAttr(se, "PartName")) == want {
				found = strings.ToLower(strings.TrimSpace(ingestAttr(se, "ContentType")))
			}
		}
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("%w: no content type for %q", ErrIngestUnsupported, part)
	}
	return found, nil
}

// ---- styles ----------------------------------------------------------------

type ingestStyleFmt struct {
	code string // declared number format; "" for General
	date bool
}

type ingestStyles []ingestStyleFmt

func (s ingestStyles) lookup(i int) ingestStyleFmt {
	if i < 0 || i >= len(s) {
		return ingestStyleFmt{}
	}
	return s[i]
}

var ingestBuiltinFmt = map[int]string{
	1: "0", 2: "0.00", 3: "#,##0", 4: "#,##0.00", 9: "0%", 10: "0.00%", 11: "0.00E+00",
	12: "# ?/?", 13: "# ??/??", 37: "#,##0 ;(#,##0)", 38: "#,##0 ;[Red](#,##0)",
	39: "#,##0.00;(#,##0.00)", 40: "#,##0.00;[Red](#,##0.00)", 48: "##0.0E+0", 49: "@",
}

func ingestBuiltinIsDate(id int) bool {
	return (id >= 14 && id <= 22) || (id >= 27 && id <= 36) || (id >= 45 && id <= 47) || (id >= 50 && id <= 58)
}

// ingestCodeIsDate decides whether a custom format code renders dates/times:
// after removing quoted text, escapes, [colors/locales] and [h]/[m]/[s] elapsed
// markers' brackets, any of y m d h s means a date or time.
func ingestCodeIsDate(code string) bool {
	var b strings.Builder
	inQuote, inBracket := false, false
	var bracket strings.Builder
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case inQuote:
			if c == '"' {
				inQuote = false
			}
		case inBracket:
			if c != ']' {
				bracket.WriteByte(c | 0x20)
				continue
			}
			inBracket = false
			// Only elapsed-time markers ([h], [mm], [ss]) count; [Red], [$-409] do not.
			if e := bracket.String(); e != "" && strings.Trim(e, e[:1]) == "" && strings.ContainsAny(e[:1], "hms") {
				b.WriteString(e[:1])
			}
		case c == '"':
			inQuote = true
		case c == '[':
			inBracket = true
			bracket.Reset()
		case c == '\\' || c == '_' || c == '*':
			i++ // escaped / padding character
		default:
			b.WriteByte(c | 0x20)
		}
	}
	return strings.ContainsAny(b.String(), "ymdhs")
}

func (p *ingestPkg) parseStyles(part string) (ingestStyles, error) {
	codes := map[int]string{}
	var ids []int
	err := p.withPart(part, func(r io.Reader) error {
		x := newIngestXML(r, p.lim, "styleSheet")
		inCellXfs := false
		for {
			tok, err := x.next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				switch t.Name.Local {
				case "numFmt":
					if id, err := strconv.Atoi(ingestAttr(t, "numFmtId")); err == nil {
						codes[id] = ingestAttr(t, "formatCode")
					}
				case "cellXfs":
					inCellXfs = true
				case "xf":
					if inCellXfs {
						id, _ := strconv.Atoi(ingestAttr(t, "numFmtId"))
						ids = append(ids, id)
					}
				}
			case xml.EndElement:
				if t.Name.Local == "cellXfs" {
					inCellXfs = false
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	out := make(ingestStyles, len(ids))
	for i, id := range ids {
		if id == 0 {
			continue
		}
		if code, ok := codes[id]; ok {
			out[i] = ingestStyleFmt{code: code, date: ingestCodeIsDate(code)}
		} else if ingestBuiltinIsDate(id) {
			out[i] = ingestStyleFmt{code: "builtin:" + strconv.Itoa(id), date: true}
		} else if code, ok := ingestBuiltinFmt[id]; ok {
			out[i] = ingestStyleFmt{code: code}
		} else {
			out[i] = ingestStyleFmt{code: "builtin:" + strconv.Itoa(id)}
		}
	}
	return out, nil
}

// ---- shared strings --------------------------------------------------------

func (p *ingestPkg) parseSharedStrings(part string) ([]string, error) {
	var out []string
	err := p.withPart(part, func(r io.Reader) error {
		x := newIngestXML(r, p.lim, "sst")
		var cur strings.Builder
		inSI, inT := false, false
		phonetic := 0
		for {
			tok, err := x.next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				switch t.Name.Local {
				case "si":
					inSI = true
					cur.Reset()
				case "t":
					inT = inSI
				case "rPh":
					phonetic++
				}
			case xml.CharData:
				if inT && phonetic == 0 {
					cur.Write(t)
					if cur.Len() > p.lim.MaxFieldBytes {
						return ingestLimit("MaxFieldBytes", int64(p.lim.MaxFieldBytes), int64(cur.Len()))
					}
				}
			case xml.EndElement:
				switch t.Name.Local {
				case "t":
					inT = false
				case "rPh":
					phonetic--
				case "si":
					if len(out) >= p.lim.MaxSharedStrings {
						return ingestLimit("MaxSharedStrings", int64(p.lim.MaxSharedStrings), int64(len(out)+1))
					}
					out = append(out, cur.String())
					inSI = false
				}
			}
		}
	})
	return out, err
}

// ---- worksheets ------------------------------------------------------------

type ingestSheetParser struct {
	pkg      *ingestPkg
	acc      *ingestAcc
	sst      []string
	styles   ingestStyles
	date1904 bool
	info     *SheetInfo
}

type ingestCell struct {
	row, col int
	typ      string
	style    int
	v, is    strings.Builder
	hasF     bool
}

func ingestParseRef(s string) (row, col int, ok bool) {
	i := 0
	for i < len(s) && s[i] >= 'A' && s[i] <= 'Z' && i < 4 {
		col = col*26 + int(s[i]-'A') + 1
		i++
	}
	if i == 0 || i == len(s) || col > ingestMaxCol {
		return 0, 0, false
	}
	row, err := strconv.Atoi(s[i:])
	if err != nil || row < 1 || row > ingestMaxRow || s[i] == '+' || s[i] == '-' {
		return 0, 0, false
	}
	return row, col, true
}

func (sp *ingestSheetParser) parse(part string, blocks []SourceBlock) ([]SourceBlock, error) {
	lim := sp.pkg.lim
	seen := map[uint64]struct{}{}
	curRow, curCol := 0, 0
	var cell *ingestCell
	inV, inT, inIS, inF := false, false, false, false
	phonetic := 0
	err := sp.pkg.withPart(part, func(r io.Reader) error {
		x := newIngestXML(r, lim, "worksheet")
		for {
			tok, err := x.next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				switch t.Name.Local {
				case "row":
					if v := ingestAttr(t, "r"); v != "" {
						n, err := strconv.Atoi(v)
						if err != nil || n < 1 || n > ingestMaxRow {
							return fmt.Errorf("%w: bad row index %q", ErrIngestCorrupt, v)
						}
						curRow = n
					} else {
						curRow++
					}
					curCol = 0
				case "c":
					if err := sp.acc.countCell(); err != nil {
						return err
					}
					c := &ingestCell{typ: ingestAttr(t, "t")}
					c.style, _ = strconv.Atoi(ingestAttr(t, "s"))
					if ref := ingestAttr(t, "r"); ref != "" {
						row, col, ok := ingestParseRef(ref)
						if !ok {
							return fmt.Errorf("%w: bad cell reference %q", ErrIngestCorrupt, ref)
						}
						c.row, c.col = row, col
					} else {
						c.row, c.col = curRow, curCol+1
						if c.row < 1 || c.col > ingestMaxCol {
							return fmt.Errorf("%w: cell without a valid position", ErrIngestCorrupt)
						}
					}
					curRow, curCol = c.row, c.col
					key := uint64(c.row)<<14 | uint64(c.col)
					if _, dup := seen[key]; dup {
						return fmt.Errorf("%w: duplicate cell %s%d", ErrIngestCorrupt, colLetter(c.col-1), c.row)
					}
					seen[key] = struct{}{}
					cell = c
				case "v":
					inV = cell != nil
				case "f":
					if cell != nil {
						cell.hasF = true
					}
					inF = true
				case "is":
					inIS = cell != nil
				case "t":
					inT = inIS
				case "rPh":
					phonetic++
				}
			case xml.CharData:
				if cell == nil || inF {
					continue
				}
				if inV {
					cell.v.Write(t)
					if cell.v.Len() > lim.MaxFieldBytes {
						return ingestLimit("MaxFieldBytes", int64(lim.MaxFieldBytes), int64(cell.v.Len()))
					}
				} else if inT && phonetic == 0 {
					cell.is.Write(t)
					if cell.is.Len() > lim.MaxFieldBytes {
						return ingestLimit("MaxFieldBytes", int64(lim.MaxFieldBytes), int64(cell.is.Len()))
					}
				}
			case xml.EndElement:
				switch t.Name.Local {
				case "v":
					inV = false
				case "f":
					inF = false
				case "is":
					inIS = false
				case "t":
					inT = false
				case "rPh":
					phonetic--
				case "c":
					if cell != nil {
						b, emit, err := sp.finish(cell)
						if err != nil {
							return err
						}
						if emit {
							blocks = append(blocks, b)
							sp.info.Cells++
							if b.Row > sp.info.MaxRow {
								sp.info.MaxRow = b.Row
							}
							if b.Col > sp.info.MaxCol {
								sp.info.MaxCol = b.Col
							}
						}
						cell = nil
					}
				}
			}
		}
	})
	return blocks, err
}

// finish converts a parsed <c> into a block. emit is false for a blank cell.
func (sp *ingestSheetParser) finish(c *ingestCell) (SourceBlock, bool, error) {
	b := SourceBlock{
		Kind: BlockKindCell, Sheet: sp.info.Name,
		Ref: colLetter(c.col-1) + strconv.Itoa(c.row), Row: c.row, Col: c.col,
		Formula: c.hasF,
	}
	raw := c.v.String()
	switch c.typ {
	case "inlineStr":
		raw = c.is.String()
		b.Type = CellTypeString
	case "s":
		b.Type = CellTypeString
		if strings.TrimSpace(raw) != "" {
			idx, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil || idx < 0 || idx >= len(sp.sst) {
				return b, false, fmt.Errorf("%w: shared string index %q out of range at %s", ErrIngestCorrupt, raw, b.Ref)
			}
			raw = sp.sst[idx]
		} else {
			raw = ""
		}
	case "str":
		b.Type = CellTypeString
	case "b":
		b.Type = CellTypeBool
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "1", "true":
			raw = "true"
		case "0", "false":
			raw = "false"
		case "":
		default:
			b.Type = CellTypeString
			b.Quality = append(b.Quality, QualityInvalidBool)
		}
	case "e":
		b.Type = CellTypeError
	case "d":
		b.Type = CellTypeDate
		raw = strings.TrimSpace(raw)
	case "", "n":
		raw = strings.TrimSpace(raw)
		sp.numeric(&b, &raw, sp.styles.lookup(c.style))
	default:
		b.Type = CellTypeString
		b.Quality = append(b.Quality, QualityUnknownCellType)
	}
	if raw == "" {
		if !c.hasF {
			return b, false, nil // blank styled cell
		}
		b = SourceBlock{Kind: b.Kind, Sheet: b.Sheet, Ref: b.Ref, Row: b.Row, Col: b.Col, Type: CellTypeEmpty,
			Formula: true, Quality: []string{QualityFormulaNoCachedValue}}
		return b, true, nil
	}
	if err := sp.acc.addValue(raw); err != nil {
		return b, false, err
	}
	b.Value = raw
	if c.hasF {
		b.CachedFormula = true
		b.Quality = append(b.Quality, QualityCachedFormulaResult, QualityFreshnessNotVerified)
	}
	return b, true, nil
}

// numeric fills in a number or date block from a raw <v> and its style.
func (sp *ingestSheetParser) numeric(b *SourceBlock, raw *string, f ingestStyleFmt) {
	b.Type = CellTypeNumber
	b.NumFmt = f.code
	if *raw == "" {
		return
	}
	if !ingestIsDecimal(*raw) {
		b.Type = CellTypeString
		b.Quality = append(b.Quality, QualityUnparseableNumber)
		return
	}
	if !f.date {
		return
	}
	serial, err := strconv.ParseFloat(*raw, 64)
	if err != nil {
		b.Type = CellTypeString
		b.Quality = append(b.Quality, QualityUnparseableNumber)
		return
	}
	s, leap, ok := ingestExcelDate(serial, sp.date1904)
	if !ok {
		b.Quality = append(b.Quality, QualityDateOutOfRange)
		return
	}
	b.Type = CellTypeDate
	*raw = s
	if leap {
		b.Quality = append(b.Quality, QualityDate1900LeapBug)
	}
}

// ingestIsDecimal accepts plain decimal/scientific numbers only (no NaN, Inf or hex).
func ingestIsDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c == '.', c == '+', c == '-', c == 'e', c == 'E':
		default:
			return false
		}
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// ingestExcelDate converts a serial to ISO-8601 text. In the 1900 system serial
// 60 is the non-existent 1900-02-29 (reported with leap=true) and serials below
// 1 are times of day.
func ingestExcelDate(serial float64, date1904 bool) (text string, leap, ok bool) {
	if math.IsNaN(serial) || serial < 0 || serial > maxExcelSerial+0.99999 {
		return "", false, false
	}
	days := int(math.Floor(serial))
	secs := int(math.Round((serial - float64(days)) * 86400))
	if secs == 86400 {
		days++
		secs = 0
	}
	clock := fmt.Sprintf("%02d:%02d:%02d", secs/3600, secs%3600/60, secs%60)
	var date string
	switch {
	case date1904:
		date = time.Date(1904, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days).Format("2006-01-02")
	case days == 0:
		return clock, false, true
	case days == 60:
		date, leap = "1900-02-29", true
	case days < 60:
		date = time.Date(1899, 12, 31, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days).Format("2006-01-02")
	default:
		date = time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days).Format("2006-01-02")
	}
	if secs > 0 {
		return date + "T" + clock, leap, true
	}
	return date, leap, true
}
