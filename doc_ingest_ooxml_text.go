//go:build !cli

package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

type ooxmlMode int

const (
	ooxmlWord ooxmlMode = iota
	ooxmlPresentation
)

type ooxmlNode struct {
	name  xml.Name
	index int
	shape int
	attrs []xml.Attr
	// counts numbers this element's children of the only kinds whose index
	// a citation reads (ooxmlCountedChild). A map keyed by every child name
	// let a small part declare millions of distinct names under one parent
	// and hold them all: a 1.4 MB DOCX grew memory by 732 MiB in testing
	// (round-2 review, 2026-10-23), past a hosted app's limit.
	counts [6]int
}

// ooxmlCountedChild is the counter slot of an element whose position is part
// of a citation - a Word or DrawingML table, row or cell - or -1.
func ooxmlCountedChild(n xml.Name) int {
	base := 0
	switch n.Space {
	case ooxmlWordNS:
	case ooxmlDrawingNS:
		base = 3
	default:
		return -1
	}
	switch n.Local {
	case "tbl":
		return base
	case "tr":
		return base + 1
	case "tc":
		return base + 2
	}
	return -1
}

type ooxmlParagraph struct {
	text       strings.Builder
	ref        string
	kind       string
	row, col   int
	quality    []string
	fieldDepth int
	fieldValue []bool
}

// Element names are bounded: real OOXML namespace URIs are under 100 bytes and
// local names are short. A multi-megabyte xmlns or tag name otherwise turned a
// small part into gigabytes of copies (out of memory, or minutes of CPU).
const (
	ooxmlMaxNamespaceBytes = 512
	ooxmlMaxLocalNameBytes = 128
	ooxmlMaxPartNameBytes  = 512
)

func ooxmlDecimalID(id string) bool {
	if id == "" || len(id) > 11 {
		return false
	}
	for i, c := range id {
		if !(c >= '0' && c <= '9') && !(i == 0 && c == '-') {
			return false
		}
	}
	return id != "-"
}

func ooxmlHas(stack []ooxmlNode, namespace, local string) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].name.Space == namespace && stack[i].name.Local == local {
			return true
		}
	}
	return false
}

func ooxmlNearest(stack []ooxmlNode, namespace, local string) (ooxmlNode, bool) {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].name.Space == namespace && stack[i].name.Local == local {
			return stack[i], true
		}
	}
	return ooxmlNode{}, false
}

func ooxmlAttribute(attrs []xml.Attr, namespace, local string) string {
	for _, a := range attrs {
		if a.Name.Space == namespace && a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

func ooxmlPath(stack []ooxmlNode, mode ooxmlMode, paragraphIndex int, part string) (string, string, int, int, error) {
	if mode == ooxmlWord {
		segments := []string{"body"}
		var row, col int
		for _, n := range stack {
			if n.name.Space != ooxmlWordNS {
				continue
			}
			switch n.name.Local {
			case "tbl":
				segments = append(segments, fmt.Sprintf("table[%d]", n.index))
			case "tr":
				row = n.index
				segments = append(segments, fmt.Sprintf("row[%d]", n.index))
			case "tc":
				col = n.index
				segments = append(segments, fmt.Sprintf("cell[%d]", n.index))
			case "footnote", "endnote", "comment":
				// The id becomes part of every paragraph's citation, so it must
				// be what the format defines: a short decimal number. A long
				// or missing one made each paragraph carry a megabyte copy (an
				// out-of-memory from a small file) or let two paragraphs share
				// one citation.
				id := ooxmlAttribute(n.attrs, ooxmlWordNS, "id")
				if !ooxmlDecimalID(id) {
					return "", "", 0, 0, fmt.Errorf("%w: %s id is missing or not a number", ErrIngestCorrupt, n.name.Local)
				}
				segments = append(segments, n.name.Local+"[id="+id+"]")
			}
		}
		segments = append(segments, fmt.Sprintf("p[%d]", paragraphIndex))
		kind := "paragraph"
		if col > 0 {
			kind = "table_paragraph"
		}
		if row > 0 && col > 0 {
			return strings.Join(segments, "/"), kind, row, col, nil
		}
		return strings.Join(segments, "/"), kind, 0, 0, nil
	}
	shape, ok := ooxmlNearest(stack, ooxmlPresentationNS, "sp")
	if !ok {
		shape, ok = ooxmlNearest(stack, ooxmlPresentationNS, "graphicFrame")
	}
	if !ok || shape.shape <= 0 {
		return "", "", 0, 0, fmt.Errorf("%w: presentation paragraph is outside a supported shape", ErrIngestUnsupported)
	}
	prefix := fmt.Sprintf("%s#shape[%d]", part, shape.shape)
	if cell, inTable := ooxmlNearest(stack, ooxmlDrawingNS, "tc"); inTable {
		rowNode, rowOK := ooxmlNearest(stack, ooxmlDrawingNS, "tr")
		tableNode, tableOK := ooxmlNearest(stack, ooxmlDrawingNS, "tbl")
		if !rowOK || !tableOK {
			return "", "", 0, 0, fmt.Errorf("%w: malformed presentation table path", ErrIngestCorrupt)
		}
		_ = tableNode
		return fmt.Sprintf("%s/table/row[%d]/cell[%d]/p[%d]", prefix, rowNode.index, cell.index, paragraphIndex), "table_paragraph", rowNode.index, cell.index, nil
	}
	return fmt.Sprintf("%s/p[%d]", prefix, paragraphIndex), "paragraph", 0, 0, nil
}

func ooxmlAppendText(p *ooxmlParagraph, text string, lim IngestLimits) error {
	if p.text.Len()+len(text) > lim.MaxFieldBytes {
		return ingestLimit("MaxFieldBytes", int64(lim.MaxFieldBytes), int64(p.text.Len()+len(text)))
	}
	p.text.WriteString(text)
	return nil
}

// ooxmlParseTextPart streams one declared text part. It never builds a DOM or
// retains XML tokens, and it emits empty paragraph blocks so the structural
// count remains bounded as well as the text bytes.
func ooxmlParseTextPart(pkg *ingestPkg, part, rootName, rootNS, sheet string, hidden bool, mode ooxmlMode, acc *ingestAcc) ([]SourceBlock, SheetInfo, []string, bool, error) {
	blocks := []SourceBlock{}
	info := SheetInfo{Name: sheet}
	if hidden {
		info.State = "hidden"
	}
	quality := []string{}
	// The part name prefixes every citation in the part.
	if len(part) > ooxmlMaxPartNameBytes {
		return blocks, info, quality, false, fmt.Errorf("%w: part name is implausibly long", ErrIngestCorrupt)
	}
	err := pkg.withPart(part, func(r io.Reader) error {
		x := newIngestXML(r, pkg.lim, rootName)
		stack := make([]ooxmlNode, 0, 16)
		var paragraph *ooxmlParagraph
		paragraphCounts := map[string]int{}
		shapeCount := 0
		rootSeen := false
		for {
			tok, err := x.next()
			if err == io.EOF {
				if !rootSeen || len(stack) != 0 || paragraph != nil {
					return fmt.Errorf("%w: incomplete OOXML story", ErrIngestCorrupt)
				}
				return nil
			}
			if err != nil {
				return err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if len(t.Name.Space) > ooxmlMaxNamespaceBytes || len(t.Name.Local) > ooxmlMaxLocalNameBytes {
					return fmt.Errorf("%w: element name or namespace is implausibly long", ErrIngestCorrupt)
				}
				if strings.EqualFold(t.Name.Local, "AlternateContent") {
					return fmt.Errorf("%w: alternate-content representation is unsupported", ErrIngestUnsupported)
				}
				textNS := ooxmlWordNS
				if mode == ooxmlPresentation {
					textNS = ooxmlDrawingNS
				}
				if (t.Name.Local == "p" || t.Name.Local == "t") && t.Name.Space != textNS {
					if mode == ooxmlWord && t.Name.Space == ooxmlDrawingNS {
						return fmt.Errorf("%w: drawing text is outside the supported Word text scope", ErrIngestUnsupported)
					}
					return fmt.Errorf("%w: paragraph/text element namespace spoof", ErrIngestCorrupt)
				}
				if len(stack) == 0 {
					rootSeen = true
					if t.Name.Space != rootNS {
						return fmt.Errorf("%w: OOXML story namespace mismatch", ErrIngestCorrupt)
					}
					if mode == ooxmlPresentation && (ooxmlAttr(t, "show") == "0" || strings.EqualFold(ooxmlAttr(t, "show"), "false")) {
						hidden = true
						info.State = "hidden"
					}
				}
				index := 1
				if slot := ooxmlCountedChild(t.Name); slot >= 0 && len(stack) > 0 {
					parent := &stack[len(stack)-1]
					parent.counts[slot]++
					index = parent.counts[slot]
				}
				node := ooxmlNode{name: t.Name, index: index, attrs: append([]xml.Attr(nil), t.Attr...)}
				if mode == ooxmlPresentation && t.Name.Space == ooxmlPresentationNS {
					switch t.Name.Local {
					case "sp", "pic", "graphicFrame", "cxnSp", "grpSp":
						shapeCount++
						node.shape = shapeCount
					}
				}
				if mode == ooxmlWord && t.Name.Space == ooxmlWordNS {
					switch t.Name.Local {
					case "footnote", "endnote", "comment":
						if !ooxmlDecimalID(ooxmlAttrNS(t, ooxmlWordNS, "id")) {
							return fmt.Errorf("%w: %s id is missing or not a number", ErrIngestCorrupt, t.Name.Local)
						}
					case "ins", "del", "moveTo", "moveFrom", "moveFromRangeStart", "moveToRangeStart", "moveFromRangeEnd", "moveToRangeEnd", "customXmlInsRangeStart", "customXmlInsRangeEnd", "customXmlDelRangeStart", "customXmlDelRangeEnd", "conflictIns", "conflictDel":
						return fmt.Errorf("%w: tracked changes are unsupported", ErrIngestUnsupported)
					case "altChunk":
						return fmt.Errorf("%w: altChunk content is unsupported", ErrIngestUnsupported)
					case "drawing", "pict":
						quality = appendOnce(quality, QualityImagesNotExtracted)
					case "object":
						return fmt.Errorf("%w: embedded object content is unsupported", ErrIngestUnsupported)
					case "txbxContent", "sym":
						return fmt.Errorf("%w: unsupported alternate text representation", ErrIngestUnsupported)
					case "fldSimple":
						if paragraph != nil {
							paragraph.fieldDepth++
							paragraph.fieldValue = append(paragraph.fieldValue, true)
							paragraph.quality = appendOnce(paragraph.quality, "field_cached_text_unevaluated")
							quality = appendOnce(quality, QualityFieldsUnevaluated)
						}
					case "fldChar":
						if paragraph != nil {
							switch ooxmlAttribute(t.Attr, ooxmlWordNS, "fldCharType") {
							case "begin":
								paragraph.fieldDepth++
								paragraph.fieldValue = append(paragraph.fieldValue, false)
								paragraph.quality = appendOnce(paragraph.quality, "field_cached_text_unevaluated")
								quality = appendOnce(quality, QualityFieldsUnevaluated)
							case "separate":
								if len(paragraph.fieldValue) > 0 {
									paragraph.fieldValue[len(paragraph.fieldValue)-1] = true
								}
							case "end":
								if paragraph.fieldDepth > 0 {
									paragraph.fieldDepth--
									paragraph.fieldValue = paragraph.fieldValue[:len(paragraph.fieldValue)-1]
								}
							}
						}
					case "tab":
						if paragraph != nil {
							if err := ooxmlAppendText(paragraph, "\t", pkg.lim); err != nil {
								return err
							}
						}
					case "br", "cr":
						if paragraph != nil {
							if err := ooxmlAppendText(paragraph, "\n", pkg.lim); err != nil {
								return err
							}
						}
					case "noBreakHyphen":
						if paragraph != nil {
							if err := ooxmlAppendText(paragraph, "‑", pkg.lim); err != nil {
								return err
							}
						}
					case "softHyphen":
						if paragraph != nil {
							if err := ooxmlAppendText(paragraph, "\u00ad", pkg.lim); err != nil {
								return err
							}
						}
					}
				}
				if mode == ooxmlPresentation && t.Name.Space == ooxmlDrawingNS {
					switch t.Name.Local {
					case "fld":
						if paragraph != nil {
							paragraph.quality = appendOnce(paragraph.quality, "field_cached_text_unevaluated")
							quality = appendOnce(quality, QualityFieldsUnevaluated)
						}
					case "tab":
						if paragraph != nil {
							if err := ooxmlAppendText(paragraph, "\t", pkg.lim); err != nil {
								return err
							}
						}
					case "br":
						if paragraph != nil {
							if err := ooxmlAppendText(paragraph, "\n", pkg.lim); err != nil {
								return err
							}
						}
					}
				}
				if mode == ooxmlPresentation && t.Name.Space == ooxmlPresentationNS {
					switch t.Name.Local {
					case "pic":
						quality = appendOnce(quality, QualityImagesNotExtracted)
					case "graphicFrame":
						// Tables are parsed below. Other frames may contain charts or SmartArt.
					case "oleObj":
						return fmt.Errorf("%w: embedded object content is unsupported", ErrIngestUnsupported)
					}
				}
				stack = append(stack, node)
				isParagraph := mode == ooxmlWord && t.Name.Space == ooxmlWordNS && t.Name.Local == "p" || mode == ooxmlPresentation && t.Name.Space == ooxmlDrawingNS && t.Name.Local == "p"
				if isParagraph {
					if paragraph != nil {
						return fmt.Errorf("%w: nested paragraph", ErrIngestCorrupt)
					}
					if mode == ooxmlPresentation && !ooxmlHas(stack, ooxmlPresentationNS, "sp") && !ooxmlHas(stack, ooxmlPresentationNS, "graphicFrame") {
						continue
					}
					paragraphKey := ooxmlParagraphKey(stack[:len(stack)-1], mode, part)
					paragraphCounts[paragraphKey]++
					paragraphIndex := paragraphCounts[paragraphKey]
					ref, kind, row, col, err := ooxmlPath(stack[:len(stack)-1], mode, paragraphIndex, part)
					if err != nil {
						return err
					}
					paragraph = &ooxmlParagraph{ref: ref, kind: kind, row: row, col: col}
					if hidden {
						paragraph.quality = appendOnce(paragraph.quality, QualityHiddenSlide)
					}
				}
			case xml.CharData:
				if paragraph == nil {
					continue
				}
				name := xml.Name{}
				if len(stack) > 0 {
					name = stack[len(stack)-1].name
				}
				isText := mode == ooxmlWord && name.Space == ooxmlWordNS && name.Local == "t" || mode == ooxmlPresentation && name.Space == ooxmlDrawingNS && name.Local == "t"
				if !isText {
					continue
				}
				if mode == ooxmlWord && paragraph.fieldDepth > 0 && (len(paragraph.fieldValue) == 0 || !paragraph.fieldValue[len(paragraph.fieldValue)-1]) {
					continue
				}
				if err := ooxmlAppendText(paragraph, string(t), pkg.lim); err != nil {
					return err
				}
			case xml.EndElement:
				if len(stack) == 0 || stack[len(stack)-1].name != t.Name {
					return fmt.Errorf("%w: OOXML element stack mismatch", ErrIngestCorrupt)
				}
				if mode == ooxmlWord && t.Name.Space == ooxmlWordNS && t.Name.Local == "fldSimple" && paragraph != nil && paragraph.fieldDepth > 0 {
					paragraph.fieldDepth--
					paragraph.fieldValue = paragraph.fieldValue[:len(paragraph.fieldValue)-1]
				}
				isParagraph := mode == ooxmlWord && t.Name.Space == ooxmlWordNS && t.Name.Local == "p" || mode == ooxmlPresentation && t.Name.Space == ooxmlDrawingNS && t.Name.Local == "p"
				if isParagraph && paragraph != nil {
					if paragraph.fieldDepth != 0 {
						return fmt.Errorf("%w: Word field spans paragraph boundaries", ErrIngestUnsupported)
					}
					if err := acc.countCell(); err != nil {
						return err
					}
					value := paragraph.text.String()
					if err := acc.addValue(value); err != nil {
						return err
					}
					blocks = append(blocks, SourceBlock{Kind: paragraph.kind, Sheet: sheet, Ref: paragraph.ref, Row: paragraph.row, Col: paragraph.col, Value: value, Type: "text", Quality: paragraph.quality})
					info.Cells++
					if paragraph.row > info.MaxRow {
						info.MaxRow = paragraph.row
					}
					if paragraph.col > info.MaxCol {
						info.MaxCol = paragraph.col
					}
					paragraph = nil
				}
				stack = stack[:len(stack)-1]
			}
		}
	})
	return blocks, info, quality, hidden, err
}

func ooxmlParagraphKey(stack []ooxmlNode, mode ooxmlMode, part string) string {
	segments := []string{part}
	if mode == ooxmlWord {
		for _, n := range stack {
			if n.name.Space != ooxmlWordNS {
				continue
			}
			switch n.name.Local {
			case "tbl":
				segments = append(segments, fmt.Sprintf("table:%d", n.index))
			case "tr":
				segments = append(segments, fmt.Sprintf("row:%d", n.index))
			case "tc":
				segments = append(segments, fmt.Sprintf("cell:%d", n.index))
			case "footnote", "endnote", "comment":
				segments = append(segments, n.name.Local+":"+ooxmlAttribute(n.attrs, ooxmlWordNS, "id"))
			}
		}
	} else {
		if shape, ok := ooxmlNearest(stack, ooxmlPresentationNS, "sp"); ok {
			segments = append(segments, fmt.Sprintf("shape:%d", shape.shape))
		} else if shape, ok := ooxmlNearest(stack, ooxmlPresentationNS, "graphicFrame"); ok {
			segments = append(segments, fmt.Sprintf("shape:%d", shape.shape))
		}
		if row, ok := ooxmlNearest(stack, ooxmlDrawingNS, "tr"); ok {
			segments = append(segments, fmt.Sprintf("row:%d", row.index))
		}
		if cell, ok := ooxmlNearest(stack, ooxmlDrawingNS, "tc"); ok {
			segments = append(segments, fmt.Sprintf("cell:%d", cell.index))
		}
	}
	return strings.Join(segments, "/")
}

func IngestDOCX(r io.ReaderAt, size int64, limits IngestLimits) (IngestResult, error) {
	return ingestOOXML(r, size, limits, IngestFormatDOCX, ooxmlWord)
}

func IngestPPTX(r io.ReaderAt, size int64, limits IngestLimits) (IngestResult, error) {
	return ingestOOXML(r, size, limits, IngestFormatPPTX, ooxmlPresentation)
}

func ingestOOXML(r io.ReaderAt, size int64, limits IngestLimits, format string, mode ooxmlMode) (IngestResult, error) {
	lim := limits.normalize()
	res := IngestResult{Format: format, ParserVersion: IngestOOXMLTextParserVersion}
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
	if err := ooxmlValidateArchive(zr); err != nil {
		return res, err
	}
	pkg, err := newIngestPkg(zr, lim)
	if err != nil {
		return res, err
	}
	if mode == ooxmlWord {
		res, err = ingestDOCXPackage(pkg, res)
	} else {
		res, err = ingestPPTXPackage(pkg, res)
	}
	if err != nil {
		return IngestResult{Format: format, ParserVersion: IngestOOXMLTextParserVersion, SHA256: sum}, err
	}
	res.Complete = true
	res.Quality = appendOnce(res.Quality, QualityTextOnly)
	res.Quality = appendOnce(res.Quality, QualityLayoutNotReconstructed)
	res.Quality = appendOnce(res.Quality, QualityInheritedTextNotExtracted)
	if mode == ooxmlWord {
		res.Quality = appendOnce(res.Quality, QualityNumberingNotComputed)
	}
	if !ooxmlHasExtractableText(res.Blocks) {
		res.Quality = appendOnce(res.Quality, QualityNoExtractableText)
	}
	return res, nil
}

func ooxmlHasExtractableText(blocks []SourceBlock) bool {
	for _, block := range blocks {
		if strings.TrimSpace(block.Value) != "" {
			return true
		}
	}
	return false
}

func ooxmlPackage(data []byte, lim IngestLimits) (*ingestPkg, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	if err := ooxmlValidateArchive(zr); err != nil {
		return nil, err
	}
	return newIngestPkg(zr, lim.normalize())
}
