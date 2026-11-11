//go:build !cli

package main

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
)

const (
	ooxmlContentTypesNS     = "http://schemas.openxmlformats.org/package/2006/content-types"
	ooxmlRelationshipsNS    = "http://schemas.openxmlformats.org/package/2006/relationships"
	ooxmlOfficeRelNS        = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	ooxmlWordNS             = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
	ooxmlPresentationNS     = "http://schemas.openxmlformats.org/presentationml/2006/main"
	ooxmlDrawingNS          = "http://schemas.openxmlformats.org/drawingml/2006/main"
	ooxmlWordMainCT         = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
	ooxmlPresentationMainCT = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
	ooxmlOfficeDocumentRel  = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)

type ooxmlContentTypes struct {
	defaults  map[string]string
	overrides map[string]string
}

type ooxmlRelationship struct {
	ID, Type, Target string
	External         bool
}

// ooxmlValidateArchive is stricter than the spreadsheet reader's historic
// package index: document packages must use canonical slash paths and may not
// contain symlinks or special files. Nothing is extracted to disk.
func ooxmlValidateArchive(zr *zip.Reader) error {
	for _, f := range zr.File {
		name := f.Name
		dir := strings.HasSuffix(name, "/")
		clean := path.Clean(strings.TrimSuffix(name, "/"))
		canonical := clean
		if dir {
			canonical += "/"
		}
		if strings.Contains(name, `\`) || canonical != name || strings.HasPrefix(name, "/") {
			return fmt.Errorf("%w: noncanonical package entry path", ErrIngestCorrupt)
		}
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || (mode.Type() != 0 && !mode.IsRegular() && !mode.IsDir()) {
			return fmt.Errorf("%w: nonregular package entry", ErrIngestUnsupported)
		}
	}
	return nil
}

func ooxmlParseContentTypes(pkg *ingestPkg) (ooxmlContentTypes, error) {
	out := ooxmlContentTypes{defaults: map[string]string{}, overrides: map[string]string{}}
	err := pkg.withPart("[Content_Types].xml", func(r io.Reader) error {
		x := newIngestXML(r, pkg.lim, "Types")
		root := false
		for {
			tok, err := x.next()
			if err == io.EOF {
				if !root {
					return fmt.Errorf("%w: content types namespace is invalid", ErrIngestCorrupt)
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
				if se.Name.Space != ooxmlContentTypesNS {
					return fmt.Errorf("%w: content types namespace is invalid", ErrIngestCorrupt)
				}
				continue
			}
			if se.Name.Space != ooxmlContentTypesNS {
				continue
			}
			switch se.Name.Local {
			case "Default":
				ext := strings.ToLower(ooxmlAttr(se, "Extension"))
				ct := ooxmlAttr(se, "ContentType")
				if ext == "" || ct == "" || strings.ContainsAny(ext, "/\\.:\x00") {
					return fmt.Errorf("%w: invalid default content type", ErrIngestCorrupt)
				}
				if _, exists := out.defaults[ext]; exists {
					return fmt.Errorf("%w: duplicate default content type", ErrIngestCorrupt)
				}
				out.defaults[ext] = ct
			case "Override":
				part := ooxmlAttr(se, "PartName")
				ct := ooxmlAttr(se, "ContentType")
				if len(part) < 2 || part[0] != '/' || ct == "" || path.Clean(part[1:]) != part[1:] {
					return fmt.Errorf("%w: invalid content type override", ErrIngestCorrupt)
				}
				if _, exists := out.overrides[part[1:]]; exists {
					return fmt.Errorf("%w: duplicate content type override", ErrIngestCorrupt)
				}
				out.overrides[part[1:]] = ct
			}
		}
	})
	return out, err
}

func (c ooxmlContentTypes) forPart(part string) string {
	if ct := c.overrides[part]; ct != "" {
		return ct
	}
	if i := strings.LastIndexByte(part, '.'); i >= 0 {
		return c.defaults[strings.ToLower(part[i+1:])]
	}
	return ""
}

func ooxmlAttr(se xml.StartElement, local string) string {
	for _, a := range se.Attr {
		if a.Name.Space == "" && a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

func ooxmlAttrNS(se xml.StartElement, namespace, local string) string {
	for _, a := range se.Attr {
		if a.Name.Space == namespace && a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

func ooxmlParseRels(pkg *ingestPkg, relsPath string) (map[string]ooxmlRelationship, error) {
	out := map[string]ooxmlRelationship{}
	if !pkg.has(relsPath) {
		return out, nil
	}
	err := pkg.withPart(relsPath, func(r io.Reader) error {
		x := newIngestXML(r, pkg.lim, "Relationships")
		root := false
		for {
			tok, err := x.next()
			if err == io.EOF {
				if !root {
					return fmt.Errorf("%w: relationships namespace is invalid", ErrIngestCorrupt)
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
				if se.Name.Space != ooxmlRelationshipsNS {
					return fmt.Errorf("%w: relationships namespace is invalid", ErrIngestCorrupt)
				}
				continue
			}
			if se.Name.Space != ooxmlRelationshipsNS || se.Name.Local != "Relationship" {
				continue
			}
			id, typ, target := ooxmlAttr(se, "Id"), ooxmlAttr(se, "Type"), ooxmlAttr(se, "Target")
			if id == "" || typ == "" || target == "" {
				return fmt.Errorf("%w: relationship is missing required attributes", ErrIngestCorrupt)
			}
			if _, duplicate := out[id]; duplicate {
				return fmt.Errorf("%w: duplicate relationship id", ErrIngestCorrupt)
			}
			external := ooxmlAttr(se, "TargetMode") == "External"
			if tm := ooxmlAttr(se, "TargetMode"); tm != "" && tm != "External" && tm != "Internal" {
				return fmt.Errorf("%w: invalid relationship target mode", ErrIngestCorrupt)
			}
			if external {
				out[id] = ooxmlRelationship{ID: id, Type: typ, External: true}
				continue
			}
			out[id] = ooxmlRelationship{ID: id, Type: typ, Target: target}
		}
	})
	return out, err
}

func ooxmlResolve(basePart, target string) (string, error) {
	if target == "" || strings.ContainsAny(target, "\\\\?#:\x00") || strings.HasPrefix(target, "//") {
		return "", fmt.Errorf("%w: unsafe relationship target", ErrIngestCorrupt)
	}
	decoded, err := url.PathUnescape(target)
	if err != nil || strings.ContainsAny(decoded, "\\\\?#:\x00") {
		return "", fmt.Errorf("%w: unsafe relationship target", ErrIngestCorrupt)
	}
	base := path.Dir(basePart)
	if base == "." {
		base = ""
	}
	var resolved string
	if strings.HasPrefix(decoded, "/") {
		resolved = path.Clean(strings.TrimPrefix(decoded, "/"))
	} else {
		resolved = path.Clean(path.Join(base, decoded))
	}
	if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") || strings.HasPrefix(resolved, "/") {
		return "", fmt.Errorf("%w: relationship target escapes package", ErrIngestCorrupt)
	}
	return resolved, nil
}

func ooxmlMainPart(pkg *ingestPkg, expectedContentType string) (string, map[string]ooxmlRelationship, ooxmlContentTypes, error) {
	cts, err := ooxmlParseContentTypes(pkg)
	if err != nil {
		return "", nil, cts, err
	}
	rels, err := ooxmlParseRels(pkg, "_rels/.rels")
	if err != nil {
		return "", nil, cts, err
	}
	main := ""
	for _, rel := range rels {
		if rel.Type != ooxmlOfficeDocumentRel {
			continue
		}
		if rel.External || main != "" {
			return "", nil, cts, fmt.Errorf("%w: invalid office document relationship", ErrIngestCorrupt)
		}
		main, err = ooxmlResolve("", rel.Target)
		if err != nil {
			return "", nil, cts, err
		}
	}
	if main == "" || !pkg.has(main) {
		return "", nil, cts, fmt.Errorf("%w: package has no office document part", ErrIngestUnsupported)
	}
	if cts.forPart(main) != expectedContentType {
		return "", nil, cts, fmt.Errorf("%w: office document content type mismatch", ErrIngestUnsupported)
	}
	for part, ct := range cts.overrides {
		if strings.Contains(strings.ToLower(ct), "macro") || strings.Contains(strings.ToLower(ct), "vbaproject") || strings.Contains(strings.ToLower(part), "vbaproject") {
			return "", nil, cts, fmt.Errorf("%w: macro-enabled package", ErrIngestUnsupported)
		}
	}
	for _, ct := range cts.defaults {
		if strings.Contains(strings.ToLower(ct), "macro") || strings.Contains(strings.ToLower(ct), "vbaproject") {
			return "", nil, cts, fmt.Errorf("%w: macro-enabled package", ErrIngestUnsupported)
		}
	}
	for name := range pkg.files {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "vbaproject") || strings.Contains(lower, "/activex/") || strings.Contains(lower, "/embeddings/") {
			return "", nil, cts, fmt.Errorf("%w: macro or embedded object content", ErrIngestUnsupported)
		}
	}
	return main, rels, cts, nil
}
