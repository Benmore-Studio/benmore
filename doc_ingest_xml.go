//go:build !cli

package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// asIngestErr wraps an arbitrary parser/IO error as ErrIngestCorrupt unless it
// already is one of the typed ingest errors.
func asIngestErr(err error) error {
	switch {
	case err == nil,
		errors.Is(err, ErrIngestLimit), errors.Is(err, ErrIngestTooLarge),
		errors.Is(err, ErrIngestEncrypted), errors.Is(err, ErrIngestCorrupt),
		errors.Is(err, ErrIngestUnsupported):
		return err
	}
	return fmt.Errorf("%w: %v", ErrIngestCorrupt, err)
}

// ingestXML wraps encoding/xml with depth, token-count and structure guards.
// encoding/xml never fetches or expands external entities and only knows the
// five predefined ones; any DOCTYPE/ENTITY directive is refused outright.
type ingestXML struct {
	d        *xml.Decoder
	lim      IngestLimits
	rootName string
	depth    int
	tokens   int
	roots    int
}

func newIngestXML(r io.Reader, lim IngestLimits, rootName string) *ingestXML {
	d := xml.NewDecoder(r)
	d.Strict = true
	return &ingestXML{d: d, lim: lim, rootName: rootName}
}

// next returns the following token (CharData bytes are only valid until the
// next call) or io.EOF after a clean, complete document.
func (x *ingestXML) next() (xml.Token, error) {
	x.tokens++
	if x.tokens > x.lim.MaxXMLTokens {
		return nil, ingestLimit("MaxXMLTokens", int64(x.lim.MaxXMLTokens), int64(x.tokens))
	}
	tok, err := x.d.Token()
	if err != nil {
		if err == io.EOF {
			if x.roots == 0 {
				return nil, fmt.Errorf("%w: XML part has no root element", ErrIngestCorrupt)
			}
			return nil, io.EOF
		}
		return nil, asIngestErr(err)
	}
	switch t := tok.(type) {
	case xml.StartElement:
		x.depth++
		if x.depth > x.lim.MaxXMLDepth {
			return nil, ingestLimit("MaxXMLDepth", int64(x.lim.MaxXMLDepth), int64(x.depth))
		}
		if x.depth == 1 {
			x.roots++
			if x.roots > 1 {
				return nil, fmt.Errorf("%w: XML part has several root elements", ErrIngestCorrupt)
			}
			if x.rootName != "" && t.Name.Local != x.rootName {
				return nil, fmt.Errorf("%w: expected <%s> root, found <%s>", ErrIngestCorrupt, x.rootName, t.Name.Local)
			}
		}
	case xml.EndElement:
		x.depth--
	case xml.Directive:
		return nil, fmt.Errorf("%w: XML DTD/entity declarations", ErrIngestUnsupported)
	case xml.CharData:
		if x.depth == 0 && len(bytes.TrimSpace(t)) > 0 {
			return nil, fmt.Errorf("%w: text outside the XML root", ErrIngestCorrupt)
		}
	}
	return tok, nil
}

// attr returns an un-prefixed attribute; attrNS one that carries a namespace
// (e.g. r:id).
func ingestAttr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name && a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}

func ingestAttrNS(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name && a.Name.Space != "" && a.Name.Space != "xmlns" {
			return a.Value
		}
	}
	return ""
}

// budgetReader counts bytes actually inflated from a ZIP entry and fails (never
// reports EOF) once the per-entry or the package-wide budget is spent, so an
// archive whose headers lie about sizes cannot exhaust memory.
type budgetReader struct {
	r        io.Reader
	entry    int64
	maxEntry int64
	total    *int64
	maxTotal int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.entry += int64(n)
	*b.total += int64(n)
	if b.entry > b.maxEntry {
		return 0, ingestLimit("MaxEntryBytes", b.maxEntry, b.entry)
	}
	if *b.total > b.maxTotal {
		return 0, ingestLimit("MaxDecompressedBytes", b.maxTotal, *b.total)
	}
	return n, err
}

// ingestPkg is a validated OOXML package: unique, safe, indexed entries.
type ingestPkg struct {
	files map[string]*zip.File // key: ingestKey(name)
	lim   IngestLimits
	total int64 // bytes inflated so far across all parts
}

func ingestKey(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, `\`, "/"))
}

// ingestUnsafeName reports an absolute path, a ".." segment, a NUL or a drive prefix.
func ingestUnsafeName(name string) bool {
	if strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return true
	}
	if len(name) >= 2 && name[1] == ':' {
		return true
	}
	for _, seg := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// newIngestPkg applies every archive-level guard before any entry is inflated.
func newIngestPkg(zr *zip.Reader, lim IngestLimits) (*ingestPkg, error) {
	if len(zr.File) > lim.MaxZipEntries {
		return nil, ingestLimit("MaxZipEntries", int64(lim.MaxZipEntries), int64(len(zr.File)))
	}
	p := &ingestPkg{files: make(map[string]*zip.File, len(zr.File)), lim: lim}
	var declared uint64
	for _, f := range zr.File {
		if ingestUnsafeName(f.Name) {
			return nil, fmt.Errorf("%w: unsafe entry path %q", ErrIngestCorrupt, f.Name)
		}
		if f.Flags&0x1 != 0 {
			return nil, fmt.Errorf("%w: ZIP entry %q is encrypted", ErrIngestEncrypted, f.Name)
		}
		key := ingestKey(f.Name)
		if strings.HasSuffix(key, "/") {
			continue // directory entry
		}
		if _, dup := p.files[key]; dup {
			return nil, fmt.Errorf("%w: duplicate entry %q", ErrIngestCorrupt, f.Name)
		}
		if f.Method != zip.Store && f.Method != zip.Deflate {
			return nil, fmt.Errorf("%w: entry %q uses compression method %d", ErrIngestUnsupported, f.Name, f.Method)
		}
		if f.UncompressedSize64 > uint64(lim.MaxEntryBytes) {
			return nil, ingestLimit("MaxEntryBytes", lim.MaxEntryBytes, clampInt64(f.UncompressedSize64))
		}
		declared += f.UncompressedSize64 // each term <= MaxEntryBytes and the loop is bounded, no overflow
		if declared > uint64(lim.MaxDecompressedBytes) {
			return nil, ingestLimit("MaxDecompressedBytes", lim.MaxDecompressedBytes, clampInt64(declared))
		}
		if f.UncompressedSize64 > 1<<20 {
			comp := f.CompressedSize64
			if comp == 0 {
				comp = 1
			}
			if f.UncompressedSize64/comp > uint64(lim.MaxCompressionRatio) {
				return nil, ingestLimit("MaxCompressionRatio", lim.MaxCompressionRatio, clampInt64(f.UncompressedSize64/comp))
			}
		}
		p.files[key] = f
	}
	return p, nil
}

func clampInt64(v uint64) int64 {
	if v > 1<<62 {
		return 1 << 62
	}
	return int64(v)
}

func (p *ingestPkg) has(name string) bool { _, ok := p.files[ingestKey(name)]; return ok }

// withPart opens a part under the inflate budgets and hands it to fn. A part
// that is absent yields ErrIngestCorrupt.
func (p *ingestPkg) withPart(name string, fn func(io.Reader) error) error {
	f, ok := p.files[ingestKey(name)]
	if !ok {
		return fmt.Errorf("%w: missing part %q", ErrIngestCorrupt, name)
	}
	rc, err := f.Open()
	if err != nil {
		return asIngestErr(err)
	}
	defer rc.Close()
	return asIngestErr(fn(&budgetReader{r: rc, maxEntry: p.lim.MaxEntryBytes, total: &p.total, maxTotal: p.lim.MaxDecompressedBytes}))
}

// ingestRel is one relationship from a .rels part.
type ingestRel struct{ ID, Type, Target string }

func (p *ingestPkg) rels(relsPath string) (map[string]ingestRel, error) {
	out := map[string]ingestRel{}
	if !p.has(relsPath) {
		return out, nil
	}
	err := p.withPart(relsPath, func(r io.Reader) error {
		x := newIngestXML(r, p.lim, "Relationships")
		for {
			tok, err := x.next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "Relationship" {
				if strings.EqualFold(ingestAttr(se, "TargetMode"), "External") {
					// External targets are recorded by type only; never resolved.
					out[ingestAttr(se, "Id")] = ingestRel{ID: ingestAttr(se, "Id"), Type: ingestAttr(se, "Type"), Target: ""}
					continue
				}
				id := ingestAttr(se, "Id")
				if _, dup := out[id]; dup {
					return fmt.Errorf("%w: duplicate relationship id %q", ErrIngestCorrupt, id)
				}
				out[id] = ingestRel{ID: id, Type: ingestAttr(se, "Type"), Target: ingestAttr(se, "Target")}
			}
		}
	})
	return out, err
}

// relsPathFor returns the relationships part of a package part.
func relsPathFor(part string) string {
	dir, base := path.Split(part)
	return dir + "_rels/" + base + ".rels"
}

// ingestResolve resolves a relationship target against the directory of its
// source part and refuses anything that leaves the package.
func ingestResolve(baseDir, target string) (string, error) {
	var p string
	if strings.HasPrefix(target, "/") {
		p = path.Clean(target[1:])
	} else {
		p = path.Clean(path.Join(baseDir, target))
	}
	if target == "" || p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: relationship target %q escapes the package", ErrIngestCorrupt, target)
	}
	return p, nil
}
