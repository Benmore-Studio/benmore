//go:build !cli

package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	ooxmlWordRelBase = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
	ooxmlWordCTBase  = "application/vnd.openxmlformats-officedocument.wordprocessingml."
)

func ingestDOCXPackage(pkg *ingestPkg, res IngestResult) (IngestResult, error) {
	main, _, cts, err := ooxmlMainPart(pkg, ooxmlWordMainCT)
	if err != nil {
		return res, err
	}
	if !strings.HasPrefix(main, "word/") {
		return res, fmt.Errorf("%w: Word main part is outside word/", ErrIngestUnsupported)
	}
	rels, err := ooxmlParseRels(pkg, relsPathFor(main))
	if err != nil {
		return res, err
	}
	parts := []struct{ path, root, typ string }{}
	for _, rel := range rels {
		if rel.External {
			switch rel.Type {
			case ooxmlWordRelBase + "header", ooxmlWordRelBase + "footer", ooxmlWordRelBase + "footnotes", ooxmlWordRelBase + "endnotes", ooxmlWordRelBase + "comments", ooxmlWordRelBase + "aFChunk":
				return res, fmt.Errorf("%w: external Word text relationship is unsupported", ErrIngestUnsupported)
			case ooxmlWordRelBase + "image":
				res.Quality = appendOnce(res.Quality, QualityImagesNotExtracted)
			case ooxmlWordRelBase + "chart":
				res.Quality = appendOnce(res.Quality, QualityChartsNotExtracted)
			case ooxmlWordRelBase + "diagramData", ooxmlWordRelBase + "diagramDrawing":
				res.Quality = appendOnce(res.Quality, QualitySmartArtNotExtracted)
			}
			res.Quality = appendOnce(res.Quality, QualityExternalLinksNotFetch)
			continue
		}
		target, err := ooxmlResolve(main, rel.Target)
		if err != nil {
			return res, err
		}
		switch rel.Type {
		case ooxmlWordRelBase + "header":
			parts = append(parts, struct{ path, root, typ string }{target, "hdr", "header"})
		case ooxmlWordRelBase + "footer":
			parts = append(parts, struct{ path, root, typ string }{target, "ftr", "footer"})
		case ooxmlWordRelBase + "footnotes":
			parts = append(parts, struct{ path, root, typ string }{target, "footnotes", "footnotes"})
		case ooxmlWordRelBase + "endnotes":
			parts = append(parts, struct{ path, root, typ string }{target, "endnotes", "endnotes"})
		case ooxmlWordRelBase + "comments":
			parts = append(parts, struct{ path, root, typ string }{target, "comments", "comments"})
		case ooxmlWordRelBase + "aFChunk":
			return res, fmt.Errorf("%w: altChunk relationship", ErrIngestUnsupported)
		case ooxmlWordRelBase + "image":
			res.Quality = appendOnce(res.Quality, QualityImagesNotExtracted)
		case ooxmlWordRelBase + "chart":
			res.Quality = appendOnce(res.Quality, QualityChartsNotExtracted)
		case ooxmlWordRelBase + "diagramData", ooxmlWordRelBase + "diagramDrawing":
			res.Quality = appendOnce(res.Quality, QualitySmartArtNotExtracted)
		}
	}
	acc := &ingestAcc{lim: pkg.lim}
	if len(res.Sheets) >= pkg.lim.MaxSheets {
		return res, ingestLimit("MaxSheets", int64(pkg.lim.MaxSheets), int64(len(res.Sheets)+1))
	}
	blocks, info, q, _, err := ooxmlParseTextPart(pkg, main, "document", ooxmlWordNS, main, false, ooxmlWord, acc)
	if err != nil {
		return res, err
	}
	res.Blocks = append(res.Blocks, blocks...)
	res.Sheets = append(res.Sheets, info)
	for _, flag := range q {
		res.Quality = appendOnce(res.Quality, flag)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].path < parts[j].path })
	// Package lookups ignore case, so the duplicate check must too: header1.xml
	// and HEADER1.xml are the same part and would be read twice.
	seen := map[string]bool{strings.ToLower(main): true}
	for _, p := range parts {
		if seen[strings.ToLower(p.path)] {
			return res, fmt.Errorf("%w: duplicate story relationship target", ErrIngestCorrupt)
		}
		seen[strings.ToLower(p.path)] = true
		if !pkg.has(p.path) {
			return res, fmt.Errorf("%w: missing related Word story", ErrIngestCorrupt)
		}
		wantCT := ooxmlWordCTBase + p.typ + "+xml"
		if cts.forPart(p.path) != wantCT {
			return res, fmt.Errorf("%w: related Word story content type mismatch", ErrIngestCorrupt)
		}
		if len(res.Sheets) >= pkg.lim.MaxSheets {
			return res, ingestLimit("MaxSheets", int64(pkg.lim.MaxSheets), int64(len(res.Sheets)+1))
		}
		blocks, info, q, _, err = ooxmlParseTextPart(pkg, p.path, p.root, ooxmlWordNS, p.path, false, ooxmlWord, acc)
		if err != nil {
			return res, err
		}
		res.Blocks = append(res.Blocks, blocks...)
		res.Sheets = append(res.Sheets, info)
		for _, flag := range q {
			res.Quality = appendOnce(res.Quality, flag)
		}
	}
	return res, nil
}
