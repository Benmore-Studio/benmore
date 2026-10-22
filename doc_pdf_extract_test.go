//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAppMCPPDFArgsAreLiteralArgv(t *testing.T) {
	path := "/private/tmp/a b;$(touch nope).pdf"
	args := appMCPPDFWorkerArgs(1234, "/private/tmp/run dir", appMCPPDFTextPath, appMCPPDFTextArgs(path))
	want := []string{"1234", "/private/tmp/run dir", appMCPPDFTextPath, "-bbox-layout", "-f", "1", "-l", "201", path, "-"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %#v, want %#v", args, want)
	}
	if appMCPPDFWorkerArgs(0, "/tmp", appMCPPDFTextPath, nil) != nil || appMCPPDFWorkerArgs(1, "/tmp", "/bin/sh", nil) != nil {
		t.Fatal("invalid budget or non-whitelisted binary must not produce worker args")
	}
	ocrArgs := appMCPPDFOCRArgs(path)
	if want := []string{path, "stdout", "-l", "eng", "--tessdata-dir", filepath.Dir(appMCPPDFEnglishData), "-c", "tessedit_create_tsv=1"}; strings.Join(ocrArgs, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("OCR argv = %#v, want %#v", ocrArgs, want)
	}
	testArgs := appMCPPDFWorkerInvocationArgs("/tmp/benmore.test", args)
	if len(testArgs) < 4 || testArgs[0] != "-test.run=^$" || testArgs[1] != "--" || testArgs[2] != appMCPPDFWorkerMarker || testArgs[3] != "1234" {
		t.Fatalf("test helper invocation = %#v", testArgs)
	}
}

func TestAppMCPPDFFrozenLimits(t *testing.T) {
	if appMCPPDFMaxPages != 200 || appMCPPDFMaxPixelsPerPage != 40_000_000 || appMCPPDFPageMemoryBytes != 512<<20 || appMCPPDFMaxTempBytes != 512<<20 || appMCPPDFTotalTimeout.String() != "10m0s" || appMCPPDFPageTimeout.String() != "1m0s" {
		t.Fatal("PDF resource contract changed")
	}
	for _, tc := range []struct {
		input int64
		want  int64
	}{{0, appMCPPDFMaxTempBytes}, {25 << 20, appMCPPDFMaxTempBytes - (25 << 20)}, {appMCPPDFMaxTempBytes, 0}, {-1, 0}} {
		if got := appMCPPDFTempBytes(tc.input); got != tc.want {
			t.Errorf("temp budget for input %d = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestAppMCPPDFProcessingRecordStoresFrozenContract(t *testing.T) {
	app, _, actorID := newCommandProviderTaskFixture(t)
	id, err := appMCPRecordFileProcessing(app, actorID, "uploads/private/document.pdf", "hash", "private_upload", "v1", "application/pdf", DefaultIngestLimits(), false, []string{"provider_unavailable"})
	if err != nil {
		t.Fatal(err)
	}
	var parser, rawLimits string
	if err := app.DB.QueryRow(`SELECT parser_version,limits_json FROM _benmore_mcp_file_processings WHERE id=?`, id).Scan(&parser, &rawLimits); err != nil {
		t.Fatal(err)
	}
	var record struct {
		PDF map[string]any `json:"pdf"`
	}
	if err := json.Unmarshal([]byte(rawLimits), &record); err != nil {
		t.Fatal(err)
	}
	if parser != appMCPPDFParserVersion || record.PDF["max_pages"] != float64(appMCPPDFMaxPages) || record.PDF["max_decoded_pixels_per_page"] != float64(appMCPPDFMaxPixelsPerPage) || record.PDF["max_temp_bytes"] != float64(appMCPPDFMaxTempBytes) {
		t.Fatalf("parser=%q limits=%s", parser, rawLimits)
	}
}

func TestAppMCPPDFParseBBox(t *testing.T) {
	data := []byte(`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><doc><page width="612.000000" height="792.000000"><flow><block xMin="72" yMin="63" xMax="127" yMax="75"><line xMin="72" yMin="63" xMax="127" yMax="75"><word xMin="10" yMin="20" xMax="40" yMax="30">Hello</word><word xMin="42" yMin="20" xMax="70" yMax="30">world</word></line></block></flow></page></doc></body></html>`)
	pages, err := appMCPPDFParseBBox(data)
	if err != nil || len(pages) != 1 || len(pages[0]) != 2 {
		t.Fatalf("pages=%#v err=%v", pages, err)
	}
	if got := pages[0][1]; got.Page != 1 || got.Ref != "p1w2" || got.BBoxUnit != "points" || got.BBox.XMax != 70 || got.Value != "world" {
		t.Fatalf("block = %#v", got)
	}
	for _, invalid := range [][]byte{
		[]byte(`<doc><page><word xMin="NaN" yMin="0" xMax="2" yMax="1">x</word></page></doc>`),
		[]byte(`<doc><page><word xMin="0" xMin="1" yMin="0" xMax="2" yMax="1">x</word></page></doc>`),
		[]byte(`<doc><page><word xMin="3" yMin="0" xMax="2" yMax="1">x</word></page></doc>`),
		[]byte(`<html xmlns="http://www.w3.org/1999/xhtml"><doc><page><word yMin="0" xMax="2" yMax="1">x</word></page></doc></html>`),
	} {
		if _, err := appMCPPDFParseBBox(invalid); err == nil {
			t.Fatalf("accepted invalid bbox: %s", invalid)
		}
	}
}

func TestAppMCPPDFNativeTextPageQuality(t *testing.T) {
	if got := appMCPPDFNativePageQuality(nil); len(got) != 0 {
		t.Fatalf("empty page quality = %#v", got)
	}
	got := appMCPPDFNativePageQuality([]appMCPPDFBlock{{Page: 1, Value: "native"}})
	if len(got) != 1 || got[0] != "native_text_only_pages" {
		t.Fatalf("native page quality = %#v", got)
	}
}

func TestAppMCPPDFFailurePreservesSourceIdentityWithoutPartialBlocks(t *testing.T) {
	failed := appMCPPDFFailureResult(appMCPPDFResult{
		Blocks:        []appMCPPDFBlock{{Page: 1, Value: "partial"}},
		Complete:      true,
		ParserVersion: appMCPPDFParserVersion,
		SHA256:        "source-hash",
		Quality:       []string{"ocr"},
	})
	if failed.Complete || failed.ParserVersion != appMCPPDFParserVersion || failed.SHA256 != "source-hash" || len(failed.Blocks) != 0 || len(failed.Quality) != 0 {
		t.Fatalf("failure result leaked partial data or lost provenance: %#v", failed)
	}
}

func TestAppMCPPDFParseTSV(t *testing.T) {
	data := []byte("level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n" +
		"5\t1\t1\t1\t1\t1\t12\t24\t30\t10\t87.5\tOCR word\n")
	blocks, err := appMCPPDFParseTSV(data, 4)
	if err != nil || len(blocks) != 1 {
		t.Fatalf("blocks=%#v err=%v", blocks, err)
	}
	if got := blocks[0]; got.Page != 4 || got.Ref != "p4w1" || got.BBoxUnit != "pixels" || got.BBox.XMax != 42 || got.BBox.YMax != 34 || got.Confidence == nil || *got.Confidence != 87.5 || len(got.Quality) != 1 || got.Quality[0] != "ocr" {
		t.Fatalf("block = %#v", got)
	}
	if _, err := appMCPPDFParseTSV([]byte("bad"), 1); err == nil {
		t.Fatal("accepted malformed TSV")
	}
	for _, fields := range [][]string{
		{"5", "1", "1", "1", "1", "1", "0", "0", "1", "1", "NaN", "bad"},
		{"5", "1", "1", "1", "1", "1", strconv.Itoa(int(^uint(0) >> 1)), "0", "1", "1", "90", "overflow x"},
		{"5", "1", "1", "1", "1", "1", "0", strconv.Itoa(int(^uint(0) >> 1)), "1", "1", "90", "overflow y"},
		{"5", "2", "1", "1", "1", "1", "0", "0", "1", "1", "90", "wrong page"},
	} {
		bad := []byte("level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n" + strings.Join(fields, "\t") + "\n")
		if _, err := appMCPPDFParseTSV(bad, 1); err == nil {
			t.Errorf("accepted invalid TSV row %q", fields)
		}
	}
}

func TestAppMCPPDFEncryptedOutput(t *testing.T) {
	for _, tc := range []struct {
		out       string
		encrypted bool
		wantErr   bool
	}{{"Encrypted: yes (print:yes copy:yes algorithm:AES-256)\n", true, false}, {"Encrypted: no\n", false, false}, {"unknown", false, true}} {
		got, err := appMCPPDFEncryptedOutput([]byte(tc.out))
		if (err != nil) != tc.wantErr || got != tc.encrypted {
			t.Errorf("encrypted(%q)=(%v,%v), want (%v,error=%v)", tc.out, got, err, tc.encrypted, tc.wantErr)
		}
	}
}

func TestAppMCPPDFPNGDimensions(t *testing.T) {
	header := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0x18, 0xb4, 0, 0, 0x18, 0xb4}
	if w, h, err := appMCPPDFPNGDimensions(bytes.NewReader(header)); err != nil || w != appMCPPDFRenderMaxSide || h != appMCPPDFRenderMaxSide || w*h > appMCPPDFMaxPixelsPerPage {
		t.Fatalf("dimensions = %dx%d err=%v", w, h, err)
	}
	tooWide := append([]byte(nil), header...)
	tooWide[18], tooWide[19], tooWide[20] = 0xff, 0xff, 0xff
	if _, _, err := appMCPPDFPNGDimensions(bytes.NewReader(tooWide)); err == nil {
		t.Fatal("accepted over-limit PNG dimensions")
	}
}

func TestAppMCPPDFIntegration(t *testing.T) {
	appDir := requireAppMCPPDFIntegrationCapability(t)
	data := appMCPTestPDF(t, "Hello PDF")
	result, err := appMCPPDFExtract(context.Background(), appDir, data)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.SHA256 == "" || len(result.Blocks) == 0 {
		t.Fatalf("incomplete extraction: %#v", result)
	}
	if !strings.Contains(strings.ToLower(joinPDFBlockValues(result.Blocks)), "hello") {
		t.Fatalf("extracted text = %q", joinPDFBlockValues(result.Blocks))
	}
}

func TestAppMCPPDFOCRIntegration(t *testing.T) {
	appDir := requireAppMCPPDFIntegrationCapability(t)
	data := appMCPTestPDFFixture(t, "scanned_hello_world.pdf")
	appMCPAssertPDFHasNoNativeText(t, data)
	result, err := appMCPPDFExtract(context.Background(), appDir, data)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToUpper(joinPDFBlockValues(result.Blocks))
	if !result.Complete || !strings.Contains(text, "HELLO") || !strings.Contains(text, "WORLD") {
		t.Fatalf("OCR extraction complete=%v text=%q", result.Complete, text)
	}
	foundOCR := false
	for _, block := range result.Blocks {
		for _, quality := range block.Quality {
			if quality == "ocr" && block.Confidence != nil && *block.Confidence > 0 && *block.Confidence <= 100 && appMCPPDFValidBox(block.BBox.XMin, block.BBox.YMin, block.BBox.XMax, block.BBox.YMax) {
				foundOCR = true
			}
		}
	}
	if !foundOCR {
		t.Fatalf("OCR blocks do not contain confidence and quality metadata: %#v", result.Blocks)
	}
}

func TestAppMCPPDFEncryptedIntegration(t *testing.T) {
	appDir := requireAppMCPPDFIntegrationCapability(t)
	data := appMCPTestPDFFixture(t, "encrypted_scan.pdf")
	result, err := appMCPPDFExtract(context.Background(), appDir, data)
	if !errors.Is(err, ErrIngestEncrypted) || result.Complete || len(result.Blocks) != 0 {
		t.Fatalf("encrypted PDF result=%#v err=%v", result, err)
	}
}

func TestAppMCPPDFRotatedOCRIntegration(t *testing.T) {
	appDir := requireAppMCPPDFIntegrationCapability(t)
	data := appMCPTestPDFFixture(t, "scanned_hello_world_rotated.pdf")
	appMCPAssertPDFHasNoNativeText(t, data)
	result, err := appMCPPDFExtract(context.Background(), appDir, data)
	text := strings.ToUpper(joinPDFBlockValues(result.Blocks))
	if err != nil || !result.Complete || !strings.Contains(text, "HELLO") || !strings.Contains(text, "WORLD") {
		t.Fatalf("rotated OCR extraction complete=%v text=%q err=%v", result.Complete, text, err)
	}
	for _, block := range result.Blocks {
		if block.Confidence == nil || *block.Confidence <= 0 || !appMCPPDFValidBox(block.BBox.XMin, block.BBox.YMin, block.BBox.XMax, block.BBox.YMax) {
			t.Fatalf("rotated OCR block lacks recognized-box confidence: %#v", block)
		}
	}
}

func TestAppMCPPDFMissingProviderFailsClosed(t *testing.T) {
	appDir := appMCPPDFTestAppDir(t)
	if pdfExtractionAvailable(appDir) {
		t.Skip("PDF tools and required isolation are available; CI runs this test again with the fixed OCR binary hidden")
	}
	data := appMCPTestPDF(t, "unavailable")
	result, err := appMCPPDFExtract(context.Background(), appDir, data)
	if !errors.Is(err, errAppMCPPDFUnavailable) || result.Complete || len(result.Blocks) != 0 {
		t.Fatalf("unavailable PDF result=%#v err=%v", result, err)
	}
	sum := sha256.Sum256(data)
	if result.SHA256 != hex.EncodeToString(sum[:]) || result.ParserVersion != appMCPPDFParserVersion {
		t.Fatalf("unavailable result lost source identity: %#v", result)
	}
}

func requireAppMCPPDFIntegrationCapability(t *testing.T) string {
	t.Helper()
	appDir := appMCPPDFTestAppDir(t)
	if !pdfExtractionAvailable(appDir) {
		if os.Getenv("BENMORE_REQUIRE_PDF_INTEGRATION") == "1" {
			t.Fatal("mandatory PDF integration capability is unavailable")
		}
		t.Skip("fixed Poppler/Tesseract binaries, English data, or sandbox probe are unavailable")
	}
	return appDir
}

// appMCPPDFTestAppDir is an app directory holding the files a parser must
// never reach; the sandbox probe proves it unreadable before PDF is available.
func appMCPPDFTestAppDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "data.db", "app data")
	writeTestFile(t, dir, ".benmore/env", "APP_SECRET=1")
	return dir
}

func appMCPTestPDFFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "mcp", name))
	if err != nil {
		t.Fatalf("read PDF fixture %s: %v", name, err)
	}
	return data
}

func appMCPAssertPDFHasNoNativeText(t *testing.T, data []byte) {
	t.Helper()
	dir, err := appMCPPDFCreateTempRunDir()
	if err != nil {
		t.Fatalf("create isolated fixture directory: %v", err)
	}
	defer os.RemoveAll(dir)
	input := filepath.Join(dir, "fixture.pdf")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), appMCPPDFPageTimeout)
	defer cancel()
	out, _, err := appMCPPDFRun(ctx, appMCPPDFTextPath, appMCPPDFTextArgs(input), appMCPPDFTempBytes(int64(len(data))), appMCPPDFMaxExtractedBytes, dir)
	if err != nil {
		t.Fatalf("isolated pdftotext fixture proof: %v", err)
	}
	pages, err := appMCPPDFParseBBox(out)
	if err != nil || len(pages) != 1 || len(pages[0]) != 0 {
		t.Fatalf("fixture has native text: pages=%#v err=%v", pages, err)
	}
}

func TestAppMCPPDFExtractionFailsClosedWithoutIsolation(t *testing.T) {
	appDir := appMCPPDFTestAppDir(t)
	if appMCPPDFIsolationAvailable(appDir) {
		t.Skip("PDF sandbox is available")
	}
	data := appMCPTestPDF(t, "blocked")
	result, err := appMCPPDFExtract(context.Background(), appDir, data)
	if !errors.Is(err, errAppMCPPDFUnavailable) {
		t.Fatalf("extract without an enforced network filter = %v, want unavailable", err)
	}
	sum := sha256.Sum256(data)
	if result.SHA256 != hex.EncodeToString(sum[:]) || result.ParserVersion != appMCPPDFParserVersion || result.Complete || len(result.Blocks) != 0 {
		t.Fatalf("fail-closed result lost provenance or carried partial output: %#v", result)
	}
}

func appMCPTestPDF(t *testing.T, text string) []byte {
	t.Helper()
	content := fmt.Sprintf("BT /F1 12 Tf 72 720 Td (%s) Tj ET", text)
	return appMCPTestPDFContent(content)
}

func appMCPTestPDFContent(content string) []byte {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
	}
	var out strings.Builder
	out.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	for i, object := range objects {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets))
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), xref)
	return []byte(out.String())
}

func joinPDFBlockValues(blocks []appMCPPDFBlock) string {
	values := make([]string, 0, len(blocks))
	for _, block := range blocks {
		values = append(values, block.Value)
	}
	return strings.Join(values, " ")
}
