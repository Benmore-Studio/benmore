//go:build !cli

package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// browserOnlyLayoutMarkers are what the page shell adds for a person looking
// at the page in a browser: one marker per injection.
var browserOnlyLayoutMarkers = map[string]string{
	"cookie-consent banner":       `id="bm-cookie"`,
	"consent buttons":             `bm-cookie-accept`,
	"feedback widget":             `bm-fb-root`,
	"analytics beacon":            `/api/_analytics`,
	"service-worker registration": pwaRegisterPath,
	"web app manifest":            `rel="manifest"`,
	"live-update stream":          `/sse/events`,
	"dev reload client":           `__bmDevReloadClient`,
	"session recorder":            `/_internal/recording`,
}

// pdfEverythingOnApp is pdfTestApp with every browser-only injection the page
// shell knows switched on: testing mode (feedback widget, reload client),
// analytics (beacon and consent banner), a PWA section, dev mode (recorder)
// and a page with live components (the update stream).
func pdfEverythingOnApp(t *testing.T) *App {
	t.Helper()
	app := pdfTestApp(t)
	on := true
	app.DevMode = true
	app.Design = &DesignConfig{
		Features: &FeaturesConfig{Testing: &on, Feedback: &on, Analytics: &on},
		PWA:      map[string]string{"name": "Receipts"},
		SEO:      map[string]string{},
		Colors:   map[string]string{},
		Nav:      map[string]string{},
	}
	app.Pages["/receipt"].RawHTML = `<page title="Receipt"><h1>Receipt 0042</h1><div data-live-table="receipts">Total due 12.50</div></page>`
	for name, body := range map[string]string{
		"head.html": `<meta name="x-app-head" content="kept">`,
		"theme.css": `.receipt-theme{color:#123456}`,
	} {
		if err := os.WriteFile(filepath.Join(app.Dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return app
}

// capturingPDFChrome installs a stand-in renderer (a shell script, never a
// browser) that does what Chrome does with its arguments as far as this test
// needs: it fetches the document through the proxy it was given, keeps the
// document and the argument list, and writes a PDF where it was told to.
func capturingPDFChrome(t *testing.T) (docPath, argsPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in renderer is a shell script")
	}
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("the stand-in renderer fetches the document with curl")
	}
	dir := t.TempDir()
	docPath, argsPath = filepath.Join(dir, "doc.html"), filepath.Join(dir, "args")
	fakePDFChrome(t, `out=; proxy=; url=
for a in "$@"; do
  case "$a" in
    --print-to-pdf=*) out="${a#--print-to-pdf=}" ;;
    --proxy-server=*) proxy="${a#--proxy-server=}" ;;
  esac
  url="$a"
done
printf '%s\n' "$@" > '`+argsPath+`'
'`+curl+`' -sS --fail -x "$proxy" -o '`+docPath+`' "$url" || exit 9
printf '%%PDF-1.4\n%%%%EOF\n' > "$out"`, 0o755)
	return docPath, argsPath
}

// A cover sheet printed with GET /pdf/<page> carried the cookie-consent
// banner with its Accept and Decline buttons, the feedback flag of testing
// mode, and on every sheet Chrome's own print header and footer: the date,
// the title, the page count and the renderer's internal address
// (http://pdf.benmore.invalid/<id>). The document the renderer is given is
// the page, and Chrome is told to print no header or footer.
func TestPDFRouteHandsTheRendererOnlyThePage(t *testing.T) {
	docPath, argsPath := capturingPDFChrome(t)
	app := pdfEverythingOnApp(t)
	mux := http.NewServeMux()
	RegisterPDFRoutes(mux, app)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/pdf/receipt", nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pdf" {
		t.Fatalf("GET /pdf/receipt: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}

	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("the renderer never fetched the document: %v", err)
	}
	doc := string(raw)
	for _, want := range []string{"<h1>Receipt 0042</h1>", "Total due 12.50", "<title>Receipt</title>", `content="kept"`, ".receipt-theme{color:#123456}"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the printed document lost %q, which belongs to the page", want)
		}
	}
	for name, marker := range browserOnlyLayoutMarkers {
		if strings.Contains(doc, marker) {
			t.Errorf("the printed document carries the %s (%q)", name, marker)
		}
	}

	rawArgs, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(rawArgs)), "\n")
	count := 0
	for _, arg := range args {
		if arg == "--no-pdf-header-footer" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Chrome prints its default header and footer (date, title, address, page count): want exactly one --no-pdf-header-footer, got %d in %q", count, args)
	}
}

// The print shell against the browser shell of the same page, in every CSS
// mode: the browser shell still carries each injection (so the markers mean
// something and browser pages are unchanged), the print shell none of them.
// The page, the app's head.html and theme, and the free plan's attribution
// stay; page script that asks for the visitor's cookie choice still gets an
// answer, as it does in a browser.
func TestPrintLayoutLeavesOutWhatTheBrowserShellAdds(t *testing.T) {
	const content = `<h1>Receipt 0042</h1><div data-live-table="receipts">Total due 12.50</div>`
	for _, cssMode := range []string{"", "themed", "none"} {
		t.Run("css="+cssMode, func(t *testing.T) {
			app := pdfEverythingOnApp(t)
			app.Design.CSS = cssMode
			app.OwnerPlan = "free"
			page := app.Pages["/receipt"]
			browser := wrapLayoutAt(content, "Receipt", app, nil, page, "/receipt")
			printed := WrapLayoutForPrint(content, "Receipt", app, nil, page)
			for name, marker := range browserOnlyLayoutMarkers {
				if !strings.Contains(browser, marker) {
					t.Errorf("the browser shell lost the %s (%q)", name, marker)
				}
				if strings.Contains(printed, marker) {
					t.Errorf("the print shell carries the %s (%q)", name, marker)
				}
			}
			for _, want := range []string{content, "<title>Receipt</title>", `content="kept"`, ".receipt-theme{color:#123456}", "Built with Benmore", "window.bmCookieConsent=function(){return ''}"} {
				if !strings.Contains(printed, want) {
					t.Errorf("the print shell lost %q", want)
				}
			}
			if strings.Contains(printed, "<script></script>") {
				t.Errorf("the print shell holds an empty script element")
			}
			if hasDefaultJS := strings.Contains(printed, "function filterTable("); hasDefaultJS != (cssMode != "none") {
				t.Errorf("page helper script in the print shell: %v, want it exactly when the browser shell has it", hasDefaultJS)
			}
		})
	}

	// A page that switches the banner off has no consent functions in a
	// browser either.
	app := pdfEverythingOnApp(t)
	optedOut := `<meta name="bm-cookie-banner" content="off">` + content
	if printed := WrapLayoutForPrint(optedOut, "Receipt", app, nil, app.Pages["/receipt"]); strings.Contains(printed, "bmCookieConsent") {
		t.Errorf("a page without the banner got the consent functions when printed")
	}
}

// Both PDF renders (GET /pdf/<page> and a connector PDF artifact) start
// Chrome with these arguments.
func TestPDFChromeArgsPrintNoHeaderOrFooter(t *testing.T) {
	args := pdfChromeArgs("127.0.0.1:4321", "http://document.test/report", "/tmp/report.pdf", "/tmp/profile")
	count := 0
	for _, arg := range args {
		if arg == "--no-pdf-header-footer" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want exactly one --no-pdf-header-footer, got %d in %q", count, args)
	}
	if last := args[len(args)-1]; last != "http://document.test/report" {
		t.Fatalf("the document URL must stay the last argument, got %q", last)
	}
}

var (
	pdfStreamRe    = regexp.MustCompile(`(?s)stream\r?\n(.*?)\r?\nendstream`)
	pdfBfSectionRe = regexp.MustCompile(`(?s)begin(bfchar|bfrange)(.*?)endbf`)
	pdfHexRe       = regexp.MustCompile(`<([0-9A-Fa-f]+)>`)
)

// pdfDrawnCharacters returns, sorted, every character some font in the PDF
// maps a glyph to. Chrome embeds only the glyphs a sheet draws, each with its
// character in the font's ToUnicode map, so this is the set of characters
// printed anywhere in the document: "" for a document without text.
func pdfDrawnCharacters(pdf []byte) string {
	seen := map[rune]bool{}
	for _, stream := range pdfStreamRe.FindAllSubmatch(pdf, -1) {
		cmap := stream[1]
		if zr, err := zlib.NewReader(bytes.NewReader(stream[1])); err == nil {
			cmap, _ = io.ReadAll(zr)
		}
		for _, section := range pdfBfSectionRe.FindAllSubmatch(cmap, -1) {
			width := 2 // bfchar: <glyph> <text>
			if string(section[1]) == "bfrange" {
				width = 3 // <first glyph> <last glyph> <text of the first>
			}
			entry := pdfHexRe.FindAllSubmatch(section[2], -1)
			for i := 0; i+width <= len(entry); i += width {
				raw, err := hex.DecodeString(string(entry[i+width-1][1]))
				if err != nil || len(raw) < 2 {
					continue
				}
				units := make([]uint16, len(raw)/2)
				for j := range units {
					units[j] = uint16(raw[2*j])<<8 | uint16(raw[2*j+1])
				}
				text := utf16.Decode(units)
				more := int64(0)
				if width == 3 {
					first, _ := strconv.ParseInt(string(entry[i][1]), 16, 32)
					last, _ := strconv.ParseInt(string(entry[i+1][1]), 16, 32)
					more = last - first
				}
				for _, r := range text {
					seen[r] = true
				}
				for k := int64(1); k <= more; k++ {
					seen[text[len(text)-1]+rune(k)] = true
				}
			}
		}
	}
	drawn := make([]rune, 0, len(seen))
	for r := range seen {
		drawn = append(drawn, r)
	}
	slices.Sort(drawn)
	return string(drawn)
}

// With a real headless Chrome (skipped when none is installed). A page
// without text prints a PDF that draws no character at all: no date, title,
// address or page count. The same page printed without the flag draws the
// title and the sandbox address, which is what every sheet carried. And a
// page that wants page numbers gets them from a CSS page margin box, as the
// pdf topic says: two sheets draw "1 / 2" and "2 / 2" and nothing else.
func TestPDFPrintsNoBrowserHeaderOrFooter(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome installed")
	}
	warmTestChrome(t, chrome)
	if !headlessPrintWorks(t, chrome) {
		t.Skip("headless Chrome cannot print in this environment")
	}
	render := func(doc string, drop ...string) string {
		t.Helper()
		dir := t.TempDir()
		sb, err := newPDFSandbox([]byte(doc), "default-src 'none'; style-src 'unsafe-inline'", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer sb.Close()
		pdfPath := filepath.Join(dir, "out.pdf")
		args := pdfChromeArgs(sb.ProxyAddr(), sb.DocURL(), pdfPath, filepath.Join(dir, "profile"))
		args = slices.DeleteFunc(args, func(arg string) bool { return slices.Contains(drop, arg) })
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, chrome, args...)
		cmd.WaitDelay = 5 * time.Second
		if out, err := runPDFChrome(ctx, cmd, pdfPath); err != nil {
			t.Fatalf("chrome: %v\n%s", err, out)
		}
		data, err := os.ReadFile(pdfPath)
		if err != nil {
			t.Fatal(err)
		}
		return pdfDrawnCharacters(data)
	}
	const sheets = `<div style="width:40mm;height:20mm;background:#444;break-after:page"></div><div style="width:40mm;height:20mm;background:#444"></div>`
	const textless = `<!doctype html><html><head><title>Cover sheet</title></head><body>` + sheets + `</body></html>`

	if drawn := render(textless); drawn != "" {
		t.Errorf("a page without text printed %q: Chrome's header and footer are back", drawn)
	}
	withDefaults := render(textless, "--no-pdf-header-footer")
	for _, r := range "Coversheet" + pdfOriginHost {
		if !strings.ContainsRune(withDefaults, r) {
			t.Fatalf("without --no-pdf-header-footer the sheets draw %q, not the title and the sandbox address: this test cannot see a header or footer", withDefaults)
		}
	}
	const numbered = `<!doctype html><html><head><title>Cover sheet</title><style>@page { margin: 20mm; @bottom-right { content: counter(page) " / " counter(pages); } }</style></head><body>` + sheets + `</body></html>`
	if drawn := strings.ReplaceAll(render(numbered), " ", ""); drawn != "/12" {
		t.Errorf("page numbers from a CSS page margin box drew %q, want only the characters of \"1 / 2\" and \"2 / 2\"", drawn)
	}
}
