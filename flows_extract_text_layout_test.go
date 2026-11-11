//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// extractTextBBoxPage renders one page the way `pdftotext -bbox-layout`
// prints it: flows of blocks of lines of words, each with its box. A flow is
// a list of blocks, a block a list of lines, a line its words.
func extractTextBBoxPage(flows ...[][]string) string {
	var out strings.Builder
	out.WriteString("  <page width=\"612.000000\" height=\"792.000000\">\n")
	y := 60.0
	for _, blocks := range flows {
		out.WriteString("    <flow>\n")
		for _, lines := range blocks {
			fmt.Fprintf(&out, "      <block xMin=\"72.000000\" yMin=\"%f\" xMax=\"540.000000\" yMax=\"%f\">\n", y, y+14*float64(len(lines)))
			for _, line := range lines {
				fmt.Fprintf(&out, "        <line xMin=\"72.000000\" yMin=\"%f\" xMax=\"540.000000\" yMax=\"%f\">\n", y, y+12)
				x := 72.0
				for _, word := range strings.Fields(line) {
					width := 6 * float64(len(word))
					fmt.Fprintf(&out, "          <word xMin=\"%f\" yMin=\"%f\" xMax=\"%f\" yMax=\"%f\">%s</word>\n", x, y, x+width, y+12, word)
					x += width + 3
				}
				out.WriteString("        </line>\n")
				y += 14
			}
			out.WriteString("      </block>\n")
			y += 30
		}
		out.WriteString("    </flow>\n")
	}
	out.WriteString("  </page>\n")
	return out.String()
}

func extractTextBBoxDoc(pages ...string) []byte {
	return []byte("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n" +
		"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n<head>\n<title></title>\n</head>\n<body>\n<doc>\n" +
		strings.Join(pages, "") + "</doc>\n</body>\n</html>\n")
}

// extractTextNativeResult is what the extractor returns for native-text
// pages: every page's words in parser order.
func extractTextNativeResult(t *testing.T, bbox []byte) appMCPPDFResult {
	t.Helper()
	pages, err := appMCPPDFParseBBox(bbox)
	if err != nil {
		t.Fatalf("parse bbox: %v", err)
	}
	result := appMCPPDFResult{Complete: true, ParserVersion: appMCPPDFParserVersion, PageCount: len(pages)}
	for _, blocks := range pages {
		result.Blocks = append(result.Blocks, blocks...)
	}
	return result
}

// The builder's report: a page reading "INTAKE-ALPHA-7781 invoice for client
// A" came back as one word per line, so a phrase search over the stored text
// found nothing. Words of a line are joined by a space, lines by a newline
// and blocks by a blank line.
func TestExtractTextNativePagesKeepLinesAndBlocks(t *testing.T) {
	bbox := extractTextBBoxDoc(
		extractTextBBoxPage(
			[][]string{{"INTAKE-ALPHA-7781 invoice for client A", "signed in two copies"}},
			[][]string{{"Total due 1234.56 zebraquartz"}},
		),
		extractTextBBoxPage(
			[][]string{{"MANYPAGE page 2 of 2"}, {"marker-2"}},
		),
		extractTextBBoxPage(),
	)
	result := newExtractTextResult(extractTextNativeResult(t, bbox))
	want := []string{
		"INTAKE-ALPHA-7781 invoice for client A\nsigned in two copies\n\nTotal due 1234.56 zebraquartz",
		"MANYPAGE page 2 of 2\n\nmarker-2",
		"",
	}
	if len(result.pages) != len(want) {
		t.Fatalf("pages = %q, want %q", result.pages, want)
	}
	for i := range want {
		if result.pages[i] != want[i] {
			t.Errorf("page %d text = %q, want %q", i+1, result.pages[i], want[i])
		}
	}
	if !strings.Contains(result.pages[1], "page 2 of") {
		t.Errorf("a phrase of one line is not findable in %q", result.pages[1])
	}
	if result.truncated {
		t.Error("a small result is marked truncated")
	}
}

// Tesseract 5 TSV for a scanned page of two paragraphs of two lines each
// (level 1 page, 2 block, 3 paragraph, 4 line, 5 word).
const extractTextOCRTSV = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n" +
	"1\t1\t0\t0\t0\t0\t0\t0\t1700\t1100\t-1\t\n" +
	"2\t1\t1\t0\t0\t0\t122\t101\t861\t117\t-1\t\n" +
	"3\t1\t1\t1\t0\t0\t122\t101\t861\t117\t-1\t\n" +
	"4\t1\t1\t1\t1\t0\t122\t101\t861\t37\t-1\t\n" +
	"5\t1\t1\t1\t1\t1\t122\t101\t231\t37\t96.628700\tSCANNED\n" +
	"5\t1\t1\t1\t1\t2\t373\t101\t204\t37\t96.657120\tRECEIPT\n" +
	"5\t1\t1\t1\t1\t3\t592\t101\t131\t37\t93.209770\t90210\n" +
	"5\t1\t1\t1\t1\t4\t740\t101\t243\t37\t90.815414\tOCRMARK\n" +
	"4\t1\t1\t1\t2\t0\t122\t171\t705\t47\t-1\t\n" +
	"5\t1\t1\t1\t2\t1\t122\t171\t159\t37\t94.668320\tSecond\n" +
	"5\t1\t1\t1\t2\t2\t300\t172\t71\t36\t95.571899\tline\n" +
	"5\t1\t1\t1\t2\t3\t387\t172\t39\t36\t95.571899\tof\n" +
	"5\t1\t1\t1\t2\t4\t440\t172\t64\t36\t97.001038\tthe\n" +
	"5\t1\t1\t1\t2\t5\t520\t172\t75\t36\t96.750206\tfirst\n" +
	"5\t1\t1\t1\t2\t6\t612\t172\t215\t46\t95.907578\tparagraph\n" +
	"2\t1\t2\t0\t0\t0\t121\t441\t654\t116\t-1\t\n" +
	"3\t1\t2\t1\t0\t0\t121\t441\t654\t116\t-1\t\n" +
	"4\t1\t2\t1\t1\t0\t121\t441\t654\t46\t-1\t\n" +
	"5\t1\t2\t1\t1\t1\t121\t442\t102\t36\t96.459251\tTotal\n" +
	"5\t1\t2\t1\t1\t2\t241\t442\t78\t36\t96.118942\tdue\n" +
	"5\t1\t2\t1\t1\t3\t339\t441\t168\t37\t93.277069\t1234.56\n" +
	"5\t1\t2\t1\t1\t4\t523\t442\t252\t45\t91.908699\tzebraquartz\n" +
	"4\t1\t2\t1\t2\t0\t121\t512\t602\t45\t-1\t\n" +
	"5\t1\t2\t1\t2\t1\t121\t512\t133\t36\t96.700531\tThank\n" +
	"5\t1\t2\t1\t2\t2\t268\t519\t73\t38\t96.667519\tyou\n" +
	"5\t1\t2\t1\t2\t3\t359\t512\t54\t36\t96.196640\tfor\n" +
	"5\t1\t2\t1\t2\t4\t428\t519\t92\t38\t96.196640\tyour\n" +
	"5\t1\t2\t1\t2\t5\t537\t512\t186\t36\t96.789505\tbusiness\n"

func TestExtractTextOCRPagesKeepLinesAndParagraphs(t *testing.T) {
	// Page 1 is native text, page 2 was read by OCR: each page keeps its own
	// structure, and a second paragraph of one OCR block is a paragraph too.
	native := extractTextNativeResult(t, extractTextBBoxDoc(
		extractTextBBoxPage([][]string{{"Cover sheet", "for the scan"}}),
		extractTextBBoxPage(),
	))
	// The same words with the second block's rows numbered block 1, paragraph 2.
	twoParagraphs := extractTextOCRTSV
	for _, level := range []string{"3", "4", "5"} {
		twoParagraphs = strings.ReplaceAll(twoParagraphs, "\n"+level+"\t1\t2\t1\t", "\n"+level+"\t1\t1\t2\t")
	}
	if twoParagraphs == extractTextOCRTSV || strings.Contains(twoParagraphs, "\n5\t1\t2\t") {
		t.Fatal("the two-paragraph TSV was not built")
	}
	for name, tc := range map[string]struct{ tsv, want string }{
		"two blocks":                {extractTextOCRTSV, "SCANNED RECEIPT 90210 OCRMARK\nSecond line of the first paragraph\n\nTotal due 1234.56 zebraquartz\nThank you for your business"},
		"two paragraphs in a block": {twoParagraphs, "SCANNED RECEIPT 90210 OCRMARK\nSecond line of the first paragraph\n\nTotal due 1234.56 zebraquartz\nThank you for your business"},
	} {
		t.Run(name, func(t *testing.T) {
			ocr, err := appMCPPDFParseTSV([]byte(tc.tsv), 2)
			if err != nil || len(ocr) != 19 {
				t.Fatalf("parse TSV: %d words, err=%v", len(ocr), err)
			}
			parsed := native
			parsed.Blocks = append(append([]appMCPPDFBlock(nil), native.Blocks...), ocr...)
			result := newExtractTextResult(parsed)
			if len(result.pages) != 2 || result.pages[0] != "Cover sheet\nfor the scan" || result.pages[1] != tc.want {
				t.Fatalf("pages = %q, want second page %q", result.pages, tc.want)
			}
		})
	}
}

// Parser output that names no line (a word directly under its page) still
// reads as text: the words are separated by spaces.
func TestExtractTextWordsWithoutLinesAreSpaced(t *testing.T) {
	bbox := []byte(`<doc><page><word xMin="0" yMin="0" xMax="2" yMax="1">alpha</word><word xMin="3" yMin="0" xMax="5" yMax="1">beta</word></page></doc>`)
	result := newExtractTextResult(extractTextNativeResult(t, bbox))
	if len(result.pages) != 1 || result.pages[0] != "alpha beta" {
		t.Fatalf("pages = %q", result.pages)
	}
}

// The connector returns the same words: one block per word with its box, and
// no layout fields in the JSON an assistant or a stored snapshot reads.
func TestExtractTextLayoutStaysOutOfConnectorBlocks(t *testing.T) {
	native := extractTextNativeResult(t, extractTextBBoxDoc(extractTextBBoxPage([][]string{{"Hello world", "again"}})))
	if len(native.Blocks) != 3 || native.Blocks[2].Ref != "p1w3" || native.Blocks[2].Value != "again" {
		t.Fatalf("blocks = %#v", native.Blocks)
	}
	raw, err := json.Marshal(native.Blocks[2])
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"page":1,"ref":"p1w3","bbox":{"x_min":72,"y_min":74,"x_max":102,"y_max":86},"bbox_unit":"points","value":"again"}`; string(raw) != want {
		t.Fatalf("native block JSON = %s, want %s", raw, want)
	}
	ocr, err := appMCPPDFParseTSV([]byte(extractTextOCRTSV), 1)
	if err != nil || len(ocr) != 19 {
		t.Fatalf("parse TSV: %d words, err=%v", len(ocr), err)
	}
	raw, err = json.Marshal(ocr[4])
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"page":1,"ref":"p1w5","bbox":{"x_min":122,"y_min":171,"x_max":281,"y_max":208},"bbox_unit":"pixels","value":"Second","confidence":94.66832,"quality":["ocr"]}`; string(raw) != want {
		t.Fatalf("OCR block JSON = %s, want %s", raw, want)
	}
}

// The total text cap still holds with lines kept, and a cut never ends inside
// a character.
func TestExtractTextOutputCapWithLines(t *testing.T) {
	line := strings.Repeat("é", 40) + " " + strings.Repeat("x", 40)
	lines := make([]string, 0, 4096)
	for range 4096 {
		lines = append(lines, line)
	}
	result := newExtractTextResult(extractTextNativeResult(t, extractTextBBoxDoc(
		extractTextBBoxPage([][]string{lines}), extractTextBBoxPage([][]string{lines}), extractTextBBoxPage([][]string{lines}),
	)))
	total := 0
	for _, page := range result.pages {
		total += len(page)
		if strings.ToValidUTF8(page, "") != page {
			t.Fatal("a truncated page ends inside a character")
		}
	}
	if !result.truncated || total > extractTextOutputBytes || len(result.pages) != 3 || !strings.HasPrefix(result.pages[0], line+"\n"+line+"\n") {
		t.Fatalf("truncated=%v total=%d pages=%d", result.truncated, total, len(result.pages))
	}
}

// With the real Poppler binaries: two lines of a native-text page come back
// as two lines of words.
func TestExtractTextKeepsLinesIntegration(t *testing.T) {
	appDir := requireAppMCPPDFIntegrationCapability(t)
	data := appMCPTestPDFContent("BT /F1 12 Tf 72 720 Td (INTAKE-ALPHA-7781 invoice for client A) Tj 0 -300 Td (Total due 1234.56 zebraquartz) Tj ET")
	parsed, err := appMCPPDFExtractOCR(context.Background(), appDir, data, true)
	if err != nil {
		t.Fatal(err)
	}
	result := newExtractTextResult(parsed)
	if len(result.pages) != 1 {
		t.Fatalf("pages = %q", result.pages)
	}
	first, second := "INTAKE-ALPHA-7781 invoice for client A", "Total due 1234.56 zebraquartz"
	text := result.pages[0]
	if !strings.HasPrefix(text, first+"\n") || !strings.HasSuffix(text, "\n"+second) || strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, first), second)) != "" {
		t.Fatalf("page text = %q, want %q and %q on separate lines", text, first, second)
	}
}
