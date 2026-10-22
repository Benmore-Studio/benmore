//go:build !cli

package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Fuzz targets for the parsers that read Poppler/Tesseract output and the
// private upload reference guard. The tools' output is treated as untrusted:
// a parse either fails or returns blocks whose invariants hold.

func FuzzAppMCPPDFParseBBox(f *testing.F) {
	f.Add([]byte(`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><doc><page width="612" height="792"><flow><block><line><word xMin="10" yMin="20" xMax="40" yMax="30">Hello</word><word xMin="42" yMin="20" xMax="70" yMax="30">world</word></line></block></flow></page><page></page></doc></body></html>`))
	f.Add([]byte(`<doc><page><word xMin="0" yMin="0" xMax="1e308" yMax="1">&amp;&lt;</word><word xMin="1" yMin="1" xMax="1" yMax="1"> </word></page></doc>`))
	f.Add([]byte(`<doc><page><word xMin="0" yMin="0" xMax="2" yMax="1"><page/>x</word></page></doc>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		pages, err := appMCPPDFParseBBox(data)
		if err != nil {
			if pages != nil {
				t.Fatalf("error %v returned pages", err)
			}
			return
		}
		if len(pages) == 0 || len(pages) > appMCPPDFMaxPages+1 {
			t.Fatalf("page count %d", len(pages))
		}
		refs := map[string]bool{}
		total := 0
		for _, page := range pages {
			for _, block := range page {
				total++
				if block.Value == "" || block.Value != strings.TrimSpace(block.Value) || block.BBoxUnit != "points" || !appMCPPDFValidBox(block.BBox.XMin, block.BBox.YMin, block.BBox.XMax, block.BBox.YMax) {
					t.Fatalf("invalid block %#v", block)
				}
				if block.Page < 1 || block.Page > len(pages) || refs[block.Ref] {
					t.Fatalf("block page/ref %#v (pages=%d)", block, len(pages))
				}
				refs[block.Ref] = true
			}
		}
		if total > appMCPPDFMaxBlocks {
			t.Fatalf("%d blocks", total)
		}
	})
}

func FuzzAppMCPPDFParseTSV(f *testing.F) {
	header := "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"
	f.Add([]byte(header+"5\t1\t1\t1\t1\t1\t12\t24\t30\t10\t87.5\tOCR word\n"), 3)
	f.Add([]byte(header+"1\t1\t0\t0\t0\t0\t0\t0\t100\t100\t-1\t\n5\t1\t1\t1\t1\t1\t0\t0\t1\t1\t0\tx\ty\n"), 1)
	f.Add([]byte(header+"5\t1\t1\t1\t1\t1\t9223372036854775807\t0\t1\t1\t90\toverflow\n"), 200)
	f.Fuzz(func(t *testing.T, data []byte, page int) {
		blocks, err := appMCPPDFParseTSV(data, page)
		if err != nil {
			if blocks != nil {
				t.Fatalf("error %v returned blocks", err)
			}
			return
		}
		if page < 1 || page > appMCPPDFMaxPages || len(blocks) > appMCPPDFMaxBlocks {
			t.Fatalf("accepted page %d with %d blocks", page, len(blocks))
		}
		refs := map[string]bool{}
		for _, block := range blocks {
			if block.Page != page || block.Value == "" || block.Confidence == nil || *block.Confidence < 0 || *block.Confidence > 100 || !appMCPPDFValidBox(block.BBox.XMin, block.BBox.YMin, block.BBox.XMax, block.BBox.YMax) || block.BBox.XMax == block.BBox.XMin || refs[block.Ref] {
				t.Fatalf("invalid OCR block %#v", block)
			}
			refs[block.Ref] = true
		}
	})
}

func FuzzAppMCPPDFEncryptedOutput(f *testing.F) {
	for _, s := range []string{"Title: x\nEncrypted:      no\nPages: 1\n", "Encrypted: yes (print:yes)\n", "Title: a\nEncrypted: no\n Encrypted: no\n", "Encrypted:\n", "encrypted: no\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		encrypted, err := appMCPPDFEncryptedOutput(data)
		lines := 0
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Encrypted:") {
				lines++
			}
		}
		if err == nil && lines != 1 {
			t.Fatalf("decided encrypted=%v from %d Encrypted lines", encrypted, lines)
		}
		if err != nil && encrypted {
			t.Fatal("error path reported encrypted=true")
		}
	})
}

func FuzzAppMCPPDFPNGDimensions(f *testing.F) {
	f.Add([]byte{137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0x18, 0xb4, 0, 0, 0x18, 0xb4})
	f.Add([]byte{137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		w, h, err := appMCPPDFPNGDimensions(bytes.NewReader(data))
		if err == nil && (w < 1 || h < 1 || w*h > appMCPPDFMaxPixelsPerPage) {
			t.Fatalf("accepted %dx%d", w, h)
		}
	})
}

// A file_ref accepted as a private upload reference must name a path under
// uploads/private of the app directory, however it is spelled.
func FuzzPrivateLogicalUploadPath(f *testing.F) {
	for _, s := range []string{"uploads/private/a.csv", "/uploads/private/x/y.pdf", "uploads/private/../app.yaml", "uploads/private/./x", "uploads/private//x", "uploads/private/x/..", "uploads/privatex/a", "uploads/private/%2e%2e/a", "uploads/private/a\\..\\b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		logical, err := privateLogicalUploadPath(raw)
		if err != nil {
			return
		}
		root := filepath.Join("/srv", "app", "uploads", "private")
		target := filepath.Join("/srv", "app", filepath.FromSlash(logical))
		if !strings.HasPrefix(logical, "uploads/private/") || target == root || !pathWithinDir(root, target) || filepath.ToSlash(filepath.Clean(logical)) != logical {
			t.Fatalf("accepted %q as %q (target %q)", raw, logical, target)
		}
		if uploadRelPath(logical) != strings.TrimPrefix(logical, "uploads/") {
			t.Fatalf("ownership key for %q is %q", logical, uploadRelPath(logical))
		}
	})
}

// Cell references round-trip through the canonical A1 spelling, so a block's
// Ref (what VerifySpan matches) names exactly the cell that was parsed.
func FuzzIngestParseRef(f *testing.F) {
	for _, s := range []string{"A1", "XFD1048576", "XFE1", "A0", "A+1", "AAAA1", "a1", "A01", "B", "1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ref string) {
		row, col, ok := ingestParseRef(ref)
		if !ok {
			return
		}
		if row < 1 || row > ingestMaxRow || col < 1 || col > ingestMaxCol {
			t.Fatalf("%q parsed to row %d col %d", ref, row, col)
		}
		canonical := colLetter(col-1) + strconv.Itoa(row)
		r2, c2, ok2 := ingestParseRef(canonical)
		if !ok2 || r2 != row || c2 != col {
			t.Fatalf("%q -> %q does not round-trip (%d,%d,%v)", ref, canonical, r2, c2, ok2)
		}
	})
}

func FuzzIngestNumberFormats(f *testing.F) {
	f.Add("yyyy-mm-dd", 45000.5, false)
	f.Add(`[h]:mm:ss;@"x`, 60.0, false)
	f.Add(`0.00\ "kg"_)*`, 2958465.99999, true)
	f.Fuzz(func(t *testing.T, code string, serial float64, date1904 bool) {
		_ = ingestCodeIsDate(code)
		text, _, ok := ingestExcelDate(serial, date1904)
		if ok && text == "" {
			t.Fatalf("serial %v produced an empty date", serial)
		}
		_ = fmt.Sprint(text)
	})
}
