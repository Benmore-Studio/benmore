//go:build !cli

package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type ooxmlSlideRef struct {
	id    string
	relID string
}

func ooxmlPresentationSlides(pkg *ingestPkg, part string) ([]ooxmlSlideRef, error) {
	slides := []ooxmlSlideRef{}
	err := pkg.withPart(part, func(r io.Reader) error {
		x := newIngestXML(r, pkg.lim, "presentation")
		root := false
		ids := map[string]bool{}
		for {
			tok, err := x.next()
			if err == io.EOF {
				if !root {
					return fmt.Errorf("%w: presentation namespace is invalid", ErrIngestCorrupt)
				}
				return nil
			}
			if err != nil {
				return err
			}
			se, ok := tok.(xml.StartElement)
			if !ok {
				continue
			}
			if !root {
				root = true
				if se.Name.Space != ooxmlPresentationNS {
					return fmt.Errorf("%w: presentation namespace is invalid", ErrIngestCorrupt)
				}
				continue
			}
			if se.Name.Space != ooxmlPresentationNS || se.Name.Local != "sldId" {
				continue
			}
			id := ooxmlAttr(se, "id")
			relID := ooxmlAttrNS(se, ooxmlOfficeRelNS, "id")
			if id == "" || relID == "" || ids[id] {
				return fmt.Errorf("%w: invalid or duplicate slide identity", ErrIngestCorrupt)
			}
			if _, err := strconv.ParseUint(id, 10, 64); err != nil {
				return fmt.Errorf("%w: invalid slide identity", ErrIngestCorrupt)
			}
			// Bound the list here: collecting every sldId before the story
			// limit applied held about three times a 64 MiB part.
			if len(slides) >= pkg.lim.MaxSheets {
				return ingestLimit("MaxSheets", int64(pkg.lim.MaxSheets), int64(len(slides)+1))
			}
			ids[id] = true
			slides = append(slides, ooxmlSlideRef{id: id, relID: relID})
		}
	})
	return slides, err
}

func ingestPPTXPackage(pkg *ingestPkg, res IngestResult) (IngestResult, error) {
	main, _, cts, err := ooxmlMainPart(pkg, ooxmlPresentationMainCT)
	if err != nil {
		return res, err
	}
	if !strings.HasPrefix(main, "ppt/") {
		return res, fmt.Errorf("%w: presentation main part is outside ppt/", ErrIngestUnsupported)
	}
	rels, err := ooxmlParseRels(pkg, relsPathFor(main))
	if err != nil {
		return res, err
	}
	slides, err := ooxmlPresentationSlides(pkg, main)
	if err != nil {
		return res, err
	}
	for _, rel := range rels {
		if rel.External {
			res.Quality = appendOnce(res.Quality, QualityExternalLinksNotFetch)
		}
	}
	acc := &ingestAcc{lim: pkg.lim}
	seenTargets := map[string]bool{}
	for i, slide := range slides {
		rel, ok := rels[slide.relID]
		if !ok || rel.Type != ooxmlOfficeRelNS+"/slide" || rel.External {
			return res, fmt.Errorf("%w: slide relationship is missing or invalid", ErrIngestCorrupt)
		}
		target, err := ooxmlResolve(main, rel.Target)
		if err != nil {
			return res, err
		}
		// Package lookups ignore case; so does the duplicate check.
		if seenTargets[strings.ToLower(target)] {
			return res, fmt.Errorf("%w: slide is referenced more than once", ErrIngestCorrupt)
		}
		seenTargets[strings.ToLower(target)] = true
		if !pkg.has(target) || cts.forPart(target) != "application/vnd.openxmlformats-officedocument.presentationml.slide+xml" {
			return res, fmt.Errorf("%w: slide part is missing or has the wrong content type", ErrIngestCorrupt)
		}
		if len(res.Sheets) >= pkg.lim.MaxSheets {
			return res, ingestLimit("MaxSheets", int64(pkg.lim.MaxSheets), int64(len(res.Sheets)+1))
		}
		sheet := fmt.Sprintf("slide:%d", i+1)
		blocks, info, q, slideHidden, err := ooxmlParseTextPart(pkg, target, "sld", ooxmlPresentationNS, sheet, false, ooxmlPresentation, acc)
		if err != nil {
			return res, err
		}
		res.Blocks = append(res.Blocks, blocks...)
		res.Sheets = append(res.Sheets, info)
		for _, flag := range q {
			res.Quality = appendOnce(res.Quality, flag)
		}

		slideRels, err := ooxmlParseRels(pkg, relsPathFor(target))
		if err != nil {
			return res, err
		}
		notesFound := false
		for _, related := range slideRels {
			if related.External {
				if related.Type == ooxmlOfficeRelNS+"/notesSlide" {
					return res, fmt.Errorf("%w: external notes slide relationship is unsupported", ErrIngestUnsupported)
				}
				res.Quality = appendOnce(res.Quality, QualityExternalLinksNotFetch)
				switch related.Type {
				case ooxmlOfficeRelNS + "/image":
					res.Quality = appendOnce(res.Quality, QualityImagesNotExtracted)
				case ooxmlOfficeRelNS + "/chart":
					res.Quality = appendOnce(res.Quality, QualityChartsNotExtracted)
				case ooxmlOfficeRelNS + "/diagramData", ooxmlOfficeRelNS + "/diagramDrawing":
					res.Quality = appendOnce(res.Quality, QualitySmartArtNotExtracted)
				}
				continue
			}
			switch related.Type {
			case ooxmlOfficeRelNS + "/image":
				res.Quality = appendOnce(res.Quality, QualityImagesNotExtracted)
			case ooxmlOfficeRelNS + "/chart":
				res.Quality = appendOnce(res.Quality, QualityChartsNotExtracted)
			case ooxmlOfficeRelNS + "/diagramData", ooxmlOfficeRelNS + "/diagramDrawing":
				res.Quality = appendOnce(res.Quality, QualitySmartArtNotExtracted)
			case ooxmlOfficeRelNS + "/notesSlide":
				if notesFound {
					return res, fmt.Errorf("%w: several notes slides are linked to one slide", ErrIngestCorrupt)
				}
				notesFound = true
				notes, err := ooxmlResolve(target, related.Target)
				if err != nil {
					return res, err
				}
				if !pkg.has(notes) || cts.forPart(notes) != "application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml" {
					return res, fmt.Errorf("%w: notes slide is missing or has the wrong content type", ErrIngestCorrupt)
				}
				if len(res.Sheets) >= pkg.lim.MaxSheets {
					return res, ingestLimit("MaxSheets", int64(pkg.lim.MaxSheets), int64(len(res.Sheets)+1))
				}
				notesRels, err := ooxmlParseRels(pkg, relsPathFor(notes))
				if err != nil {
					return res, err
				}
				for _, noteRel := range notesRels {
					if noteRel.External {
						res.Quality = appendOnce(res.Quality, QualityExternalLinksNotFetch)
					}
				}
				noteSheet := fmt.Sprintf("slide:%d:notes", i+1)
				noteBlocks, noteInfo, noteQuality, _, err := ooxmlParseTextPart(pkg, notes, "notes", ooxmlPresentationNS, noteSheet, slideHidden, ooxmlPresentation, acc)
				if err != nil {
					return res, err
				}
				res.Blocks = append(res.Blocks, noteBlocks...)
				res.Sheets = append(res.Sheets, noteInfo)
				for _, flag := range noteQuality {
					res.Quality = appendOnce(res.Quality, flag)
				}
			}
		}
	}
	return res, nil
}
