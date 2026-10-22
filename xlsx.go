//go:build !cli

package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Minimal .xlsx writer for data export. No dependencies.
// The .xlsx format is a ZIP of XML files (OOXML ISO 29500).
// This handles simple tabular data - no formulas, charts, or formatting.

// WriteXLSX generates an .xlsx file from column headers and rows.
func WriteXLSX(headers []string, rows [][]string) ([]byte, error) {
	return WriteXLSXSheets([]XLSXSheet{{Name: "Sheet1", Headers: headers, Rows: rows}})
}

// XLSXSheet is one sheet in a generated workbook. Rows are strings; without
// Formats a cell that looks like a number is written as one (the legacy export
// behaviour), with Formats the column's declared type decides instead.
type XLSXSheet struct {
	Name    string
	Headers []string
	Rows    [][]string
	// Formats types each column by index: xlsxText, xlsxInteger, xlsxNumber,
	// xlsxMoney, xlsxPercent, xlsxDate or xlsxDateTime ("" is text). A typed
	// cell must already hold a plain number literal (a date or datetime holds
	// its Excel serial, see xlsxSerial); text is never sniffed, so "007" stays
	// text. nil keeps the legacy sniffing.
	Formats []string
	// FreezeHeader bolds row 1 and keeps it in view while scrolling.
	FreezeHeader bool
}

// Column formats of a typed sheet.
const (
	xlsxText     = "text"
	xlsxInteger  = "integer"
	xlsxNumber   = "number"
	xlsxMoney    = "money"
	xlsxPercent  = "percent" // the cell holds a fraction: 0.0525 shows as 5.25%
	xlsxDate     = "date"
	xlsxDateTime = "datetime"
)

// xlsxStyleIndex is the cellXfs index of each format in stylesXML. Index 0 is
// the default style and 1 the frozen header's.
var xlsxStyleIndex = map[string]int{xlsxInteger: 2, xlsxMoney: 3, xlsxPercent: 4, xlsxDate: 5, xlsxDateTime: 6}

// xlsxSerial is the Excel serial number of t (days since 1899-12-30, UTC), the
// value a date cell stores. Dates before 1900-03-01 are refused: Excel's
// serial numbering has a phantom 1900-02-29 there.
func xlsxSerial(t time.Time) (string, error) {
	t = t.UTC()
	if t.Before(time.Date(1900, 3, 1, 0, 0, 0, 0, time.UTC)) || t.After(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)) {
		return "", fmt.Errorf("a date is outside the range a spreadsheet can store")
	}
	secs := t.Unix() - time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC).Unix()
	if secs%86400 == 0 {
		return strconv.FormatInt(secs/86400, 10), nil
	}
	return strconv.FormatFloat(float64(secs)/86400, 'f', -1, 64), nil
}

// WriteXLSXSheets generates a workbook with multiple simple tabular sheets.
func WriteXLSXSheets(sheets []XLSXSheet) ([]byte, error) {
	if len(sheets) == 0 {
		return nil, fmt.Errorf("xlsx requires at least one sheet")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// [Content_Types].xml
	writeZipFile(zw, "[Content_Types].xml", contentTypesForSheets(len(sheets)))

	// _rels/.rels
	writeZipFile(zw, "_rels/.rels", relsXML)

	// xl/workbook.xml
	writeZipFile(zw, "xl/workbook.xml", workbookForSheets(sheets))

	// xl/_rels/workbook.xml.rels
	writeZipFile(zw, "xl/_rels/workbook.xml.rels", workbookRelsForSheets(len(sheets)))

	// xl/styles.xml
	writeZipFile(zw, "xl/styles.xml", stylesXML)

	for i, sheet := range sheets {
		name := strings.TrimSpace(sheet.Name)
		if name == "" || len(name) > 31 || strings.ContainsAny(name, `[]:*?/\\`) {
			return nil, fmt.Errorf("invalid xlsx sheet name %q", sheet.Name)
		}
		for j := 0; j < i; j++ {
			if strings.EqualFold(name, strings.TrimSpace(sheets[j].Name)) {
				return nil, fmt.Errorf("duplicate xlsx sheet name %q", name)
			}
		}
		writeZipFile(zw, fmt.Sprintf("xl/worksheets/sheet%d.xml", i+1), buildSheet(sheet))
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func contentTypesForSheets(count int) string {
	s := strings.Replace(contentTypesXML, `  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, "", 1)
	var b strings.Builder
	b.WriteString(strings.TrimSuffix(s, "</Types>"))
	for i := 1; i <= count; i++ {
		fmt.Fprintf(&b, `  <Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`+"\n", i)
	}
	b.WriteString("</Types>")
	return b.String()
}

func workbookForSheets(sheets []XLSXSheet) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>`)
	for i, sheet := range sheets {
		fmt.Fprintf(&b, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, xmlEscape(strings.TrimSpace(sheet.Name)), i+1, i+1)
	}
	b.WriteString(`</sheets></workbook>`)
	return b.String()
}

func workbookRelsForSheets(count int) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for i := 1; i <= count; i++ {
		fmt.Fprintf(&b, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, i, i)
	}
	fmt.Fprintf(&b, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`, count+1)
	return b.String()
}

func writeZipFile(zw *zip.Writer, name, content string) {
	w, _ := zw.Create(name)
	w.Write([]byte(content))
}

func buildSheet(sheet XLSXSheet) string {
	headers, rows := sheet.Headers, sheet.Rows
	typed := sheet.Formats != nil
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	sb.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	// Element order is fixed by the schema: sheetViews, cols, then sheetData.
	if sheet.FreezeHeader {
		sb.WriteString(`<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>`)
	}
	if typed {
		sb.WriteString(`<cols>`)
		for i := range headers {
			width := utf8.RuneCountInString(headers[i])
			for _, row := range rows[:min(len(rows), 200)] {
				if i < len(row) {
					width = max(width, utf8.RuneCountInString(row[i]))
				}
			}
			fmt.Fprintf(&sb, `<col min="%d" max="%d" width="%d" customWidth="1"/>`, i+1, i+1, min(max(width+2, 10), 60))
		}
		sb.WriteString(`</cols>`)
	}
	sb.WriteString(`<sheetData>`)

	// Header row
	sb.WriteString(`<row r="1">`)
	headerStyle := ""
	if sheet.FreezeHeader {
		headerStyle = ` s="1"`
	}
	for i, h := range headers {
		col := colLetter(i)
		sb.WriteString(fmt.Sprintf(`<c r="%s1"%s t="inlineStr"><is><t>%s</t></is></c>`, col, headerStyle, xmlEscape(h)))
	}
	sb.WriteString(`</row>`)

	// Data rows
	for rowIdx, row := range rows {
		rowNum := rowIdx + 2
		sb.WriteString(fmt.Sprintf(`<row r="%d">`, rowNum))
		for colIdx, val := range row {
			col := colLetter(colIdx)
			ref := fmt.Sprintf("%s%d", col, rowNum)
			format := xlsxText
			if typed && colIdx < len(sheet.Formats) && sheet.Formats[colIdx] != "" {
				format = sheet.Formats[colIdx]
			}
			if typed && format != xlsxText {
				if val == "" {
					continue // an absent value is an empty cell, not a zero
				}
				if f, err := strconv.ParseFloat(val, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					style := ""
					if idx := xlsxStyleIndex[format]; idx > 0 {
						style = fmt.Sprintf(` s="%d"`, idx)
					}
					sb.WriteString(fmt.Sprintf(`<c r="%s"%s><v>%s</v></c>`, ref, style, xmlEscape(val)))
					continue
				}
				// Not a number after all: keep the text rather than lose it.
			} else if !typed && isNumeric(val) {
				// Try as number, otherwise inline string
				sb.WriteString(fmt.Sprintf(`<c r="%s"><v>%s</v></c>`, ref, val))
				continue
			}
			// csvSafeCell neutralizes formula injection (a cell starting
			// with = + - @ becomes a live formula in Excel); xmlEscape then
			// keeps the XML well-formed. Mirrors the CSV export path.
			sb.WriteString(fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t>%s</t></is></c>`, ref, xmlEscape(csvSafeCell(val))))
		}
		sb.WriteString(`</row>`)
	}

	sb.WriteString(`</sheetData></worksheet>`)
	return sb.String()
}

// colLetter converts a 0-based column index to Excel column letters (A, B, ..., Z, AA, AB, ...).
func colLetter(i int) string {
	result := ""
	for {
		result = string(rune('A'+i%26)) + result
		i = i/26 - 1
		if i < 0 {
			break
		}
	}
	return result
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	dotSeen := false
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c == '.' && !dotSeen {
			dotSeen = true
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// Static XML templates for the xlsx structure

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>`

const relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`

const workbookXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>`

const workbookRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`

// Fixed cellXfs: 0 default, 1 bold header on a grey fill, then one per number
// format (xlsxStyleIndex): #,##0 (3), #,##0.00 (4), 0.00% (10), custom dates.
const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <numFmts count="2"><numFmt numFmtId="164" formatCode="yyyy\-mm\-dd"/><numFmt numFmtId="165" formatCode="yyyy\-mm\-dd\ hh:mm"/></numFmts>
  <fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE7E9EE"/><bgColor indexed="64"/></patternFill></fill></fills>
  <borders count="1"><border/></borders>
  <cellStyleXfs count="1"><xf/></cellStyleXfs>
  <cellXfs count="7"><xf/><xf numFmtId="0" fontId="1" fillId="2" applyFont="1" applyFill="1"/><xf numFmtId="3" applyNumberFormat="1"/><xf numFmtId="4" applyNumberFormat="1"/><xf numFmtId="10" applyNumberFormat="1"/><xf numFmtId="164" applyNumberFormat="1"/><xf numFmtId="165" applyNumberFormat="1"/></cellXfs>
</styleSheet>`
