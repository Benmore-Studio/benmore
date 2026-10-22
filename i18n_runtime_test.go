//go:build !cli

package main

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The schema, config, dictionaries and HTML are the actual small reservation
// app that reproduced missing dictionaries/bootstrap in the hosted runtime.
func reservationI18nFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join("testdata", "i18n_reservation")
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		writeTestFile(t, dir, name, string(b))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, false, "https://fixture.example")
}
func i18nGet(mux http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}
func assertI18nDictionary(t *testing.T, rec *httptest.ResponseRecorder, want map[string]string) {
	t.Helper()
	var got map[string]string
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("dictionary: HTTP %d %s; want %+v", rec.Code, rec.Body.String(), want)
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("dictionary headers: %v", rec.Header())
	}
}

var i18nBootstrapRE = regexp.MustCompile(`(?s)<script>window\.__bm_i18n=(.*?);</script>`)

func assertI18nBootstrap(t *testing.T, body, lang string, want map[string]string) {
	t.Helper()
	matches := i18nBootstrapRE.FindAllStringSubmatch(body, -1)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one dictionary bootstrap, got %d: %.450s", len(matches), body)
	}
	var got struct {
		Lang    string            `json:"lang"`
		Strings map[string]string `json:"strings"`
	}
	expression := matches[0][1]
	if !strings.HasPrefix(expression, "JSON.parse(") || !strings.HasSuffix(expression, ")") {
		t.Fatalf("bootstrap must parse JSON instead of an object literal: %s", expression)
	}
	var payload string
	if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(expression, "JSON.parse("), ")")), &payload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatal(err)
	}
	if got.Lang != lang || !reflect.DeepEqual(got.Strings, want) {
		t.Fatalf("bootstrap %+v; want language %s dictionary %+v", got, lang, want)
	}
	if strings.Contains(matches[0][1], "</script>") || strings.Contains(matches[0][1], "<img") {
		t.Fatal("translation crossed the inline script boundary")
	}
}

func TestReservationI18nNativeDictionaryAndRawBootstrap(t *testing.T) {
	app, mux := reservationI18nFixture(t)
	for _, lang := range []string{"en", "es"} {
		t.Run(lang, func(t *testing.T) {
			assertI18nDictionary(t, i18nGet(mux, "/api/_i18n/"+lang), app.i18nConfig().Translations[lang])
		})
	}
	for _, path := range []string{"/api/_i18n/fr", "/api/_i18n/en.yaml", "/api/_i18n/%2e%2e%2fapp.yaml"} {
		rec := i18nGet(mux, path)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") || strings.Contains(rec.Body.String(), "site_name") {
			t.Errorf("unknown locale %s: HTTP %d %s", path, rec.Code, rec.Body.String())
		}
	}
	rec := i18nGet(mux, "/")
	if rec.Code != 200 {
		t.Fatalf("raw page HTTP %d: %s", rec.Code, rec.Body.String())
	}
	assertI18nBootstrap(t, rec.Body.String(), "en", app.i18nConfig().Translations["en"])
	if strings.Index(rec.Body.String(), "window.__bm_i18n") > strings.Index(rec.Body.String(), `src="/static/app.js`) {
		t.Fatal("bootstrap runs after the application script")
	}
}

func TestReservationI18nAppIsolationAndPublishedReload(t *testing.T) {
	app, mux := reservationI18nFixture(t)
	other, otherMux := reservationI18nFixture(t)
	other.mu.Lock()
	other.I18n = &I18n{DefaultLang: "en", Translations: map[string]map[string]string{"en": {"title": "Different app"}}}
	other.mu.Unlock()
	assertI18nDictionary(t, i18nGet(otherMux, "/api/_i18n/en"), map[string]string{"title": "Different app"})
	assertI18nDictionary(t, i18nGet(mux, "/api/_i18n/en"), app.i18nConfig().Translations["en"])
	writeTestFile(t, app.Dir, "i18n/en.yaml", "title: late disk replacement\n")
	assertI18nDictionary(t, i18nGet(mux, "/api/_i18n/en"), app.i18nConfig().Translations["en"])
	app.mu.Lock()
	app.I18n = &I18n{DefaultLang: "es", Translations: map[string]map[string]string{"es": {"title": "Published Spanish"}}}
	app.mu.Unlock()
	assertI18nDictionary(t, i18nGet(mux, "/api/_i18n/es"), map[string]string{"title": "Published Spanish"})
	assertI18nBootstrap(t, i18nGet(mux, "/").Body.String(), "es", map[string]string{"title": "Published Spanish"})
	app.mu.Lock()
	app.I18n = nil
	app.mu.Unlock()
	if rec := i18nGet(mux, "/api/_i18n/es"); rec.Code != 404 {
		t.Fatalf("removed dictionary HTTP %d", rec.Code)
	}
	if strings.Contains(i18nGet(mux, "/").Body.String(), "window.__bm_i18n") {
		t.Fatal("removed translations retained a bootstrap")
	}
}

func TestReservationI18nEmptyLocaleIsAnObject(t *testing.T) {
	app, mux := reservationI18nFixture(t)
	writeTestFile(t, app.Dir, "i18n/empty.yaml", "")
	app.mu.Lock()
	app.I18n = LoadI18n(app.Dir)
	app.mu.Unlock()
	assertI18nDictionary(t, i18nGet(mux, "/api/_i18n/empty"), map[string]string{})
}

func TestReservationI18nReviewedCaptureAndRawPage(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, app.Dir, "index.html", "---\nengine: raw\nauth: none\nlayout: none\n---\n<!doctype html><html><head><script>window.firstDictionary=window.__bm_i18n;</script></head><body>Review</body></html>")
	for _, lang := range []string{"en", "es"} {
		b, err := os.ReadFile(filepath.Join("testdata", "i18n_reservation", "i18n", lang+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, app.Dir, "i18n/"+lang+".yaml", string(b))
	}
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "i18n/en.yaml", "title: unreviewed replacement\n")
	writeTestFile(t, app.Dir, "i18n/fr.yaml", "title: unreviewed addition\n")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	mux := buildAppMux(app, false, "https://fixture.example")
	assertI18nDictionary(t, i18nGet(mux, "/api/_i18n/en"), config.i18n.Translations["en"])
	if rec := i18nGet(mux, "/api/_i18n/fr"); rec.Code != 404 {
		t.Fatalf("unreviewed locale HTTP %d", rec.Code)
	}
	body := i18nGet(mux, "/").Body.String()
	assertI18nBootstrap(t, body, "en", config.i18n.Translations["en"])
	if strings.Index(body, "window.__bm_i18n=") > strings.Index(body, "window.firstDictionary=") {
		t.Fatal("raw inline script ran before dictionary initialization")
	}
}

func TestEmbeddedBMI18nLiteralValues(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "embedded/bm_i18n_test.mjs").CombinedOutput()
	if err != nil {
		t.Fatalf("i18n SDK regression: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "all i18n literal-value assertions passed") {
		t.Fatalf("missing completion: %s", out)
	}
}

func TestReservationI18nBootstrapOwnNamedKeys(t *testing.T) {
	app := &App{I18n: &I18n{DefaultLang: "en", Translations: map[string]map[string]string{"en": {
		"__proto__": "Declared prototype name", "constructor": "Declared constructor name", "toString": "Declared function name",
	}}}}
	body := string(injectI18nBootstrap([]byte("<html><head></head></html>"), app))
	match := i18nBootstrapRE.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("missing emitted bootstrap: %s", body)
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	cmd := exec.Command(node, "embedded/bm_i18n_test.mjs", "--bootstrap")
	cmd.Stdin = strings.NewReader("window.__bm_i18n=" + match[1] + ";")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "emitted bootstrap own-key assertions passed") {
		t.Fatalf("emitted bootstrap lost an own dictionary key: %v\n%s", err, out)
	}
}

func TestReservationI18nBootstrapDocumentShapes(t *testing.T) {
	app := &App{I18n: &I18n{DefaultLang: "en", Translations: map[string]map[string]string{"en": {"message": `</script><img src=x onerror="synthetic()">`}}}}
	for _, tc := range []struct{ name, source, prefix string }{
		{"ordinary", `<!doctype html><html><head><script>app()</script></head></html>`, `<!doctype html><html><head>`},
		{"case and attribute", `<HTML><HEAD data-note=">"><script>app()</script></HEAD></HTML>`, `<HTML><HEAD data-note=">">`},
		{"comment", `<!doctype html><!-- <head> --><html><head><script>app()</script></head></html>`, `<!doctype html><!-- <head> --><html><head>`},
		{"head absent", `<!doctype html><html><body><script>app()</script></body></html>`, `<!doctype html><html>`},
		{"fragment", `<header>Header</header><script>app()</script>`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := string(injectI18nBootstrap([]byte(tc.source), app))
			assertI18nBootstrap(t, body, "en", app.I18n.Translations["en"])
			if !strings.HasPrefix(body, tc.prefix+`<script>window.__bm_i18n=`) {
				t.Fatalf("bootstrap placed inside the wrong HTML context: %s", body)
			}
			if got := i18nBootstrapRE.ReplaceAllString(body, ""); got != strings.Replace(tc.source, tc.prefix, tc.prefix+"\n", 1) {
				t.Fatalf("authored HTML changed outside injected script: %q", got)
			}
		})
	}
	for _, empty := range []*App{nil, {}, {I18n: &I18n{DefaultLang: "en", Translations: map[string]map[string]string{"en": {}}}}} {
		source := []byte("<html><head></head><body>Untranslated</body></html>")
		if got := injectI18nBootstrap(source, empty); string(got) != string(source) {
			t.Fatalf("empty dictionary changed the page: %s", got)
		}
	}
}
