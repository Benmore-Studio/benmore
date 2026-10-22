//go:build !cli

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	// Existing versioning tests edit files and re-render at once; they
	// assert the exact tree version, so the cross-render memo is off by
	// default in tests. TestStaticTreeVersionMemo turns it back on.
	staticTreeVersionTTL = 0
}

// tsxServeApp is an app whose static/app.tsx bundles to more than the gzip
// threshold.
func tsxServeApp(t *testing.T, marker string) *App {
	t.Helper()
	resetTSXCache()
	app := &App{Dir: t.TempDir()}
	static := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(static, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTSXSource(t, app, marker)
	return app
}

func writeTSXSource(t *testing.T, app *App, marker string) {
	t.Helper()
	src := "export const marker = \"" + marker + "\";\nexport const filler = \"" + strings.Repeat("abcdefgh", 400) + "\";\nconsole.log(marker, filler);\n"
	path := filepath.Join(app.Dir, "static", "app.tsx")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// A distinct mtime per write, whatever the filesystem's resolution.
	at := time.Now().Add(time.Duration(len(marker)) * time.Minute)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func serveTSX(t *testing.T, app *App, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range header {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	if !serveTSXIfPresent(w, r, app, "app.js") {
		t.Fatal("serveTSXIfPresent did not handle app.js")
	}
	return w
}

// The unversioned bundle is revalidated, not re-downloaded: browsers may keep
// it (no browser no-store), CDNs may not, and a matching validator is a 304.
func TestTSXServeRevalidatesWithoutBrowserNoStore(t *testing.T) {
	app := tsxServeApp(t, "ONE")
	w := serveTSX(t, app, "/static/app.js", nil)
	cc := w.Header().Get("Cache-Control")
	if w.Code != http.StatusOK || strings.Contains(cc, "no-store") || !strings.Contains(cc, "no-cache") || !strings.Contains(cc, "private") {
		t.Fatalf("status %d Cache-Control %q; want private, no-cache without no-store", w.Code, cc)
	}
	if w.Header().Get("CDN-Cache-Control") != "no-store" || w.Header().Get("Cloudflare-CDN-Cache-Control") != "no-store" {
		t.Fatal("CDNs must still be told not to store the unversioned bundle")
	}
	etag := w.Header().Get("ETag")
	if etag == "" || !strings.Contains(w.Body.String(), "ONE") {
		t.Fatalf("missing ETag or body: %q", etag)
	}
	again := serveTSX(t, app, "/static/app.js", http.Header{"If-None-Match": {etag}})
	if again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Fatalf("conditional request = %d (%d bytes), want empty 304", again.Code, again.Body.Len())
	}
}

// A client that accepts gzip gets the compressed bytes computed at compile
// time; a layer that already encodes the response gets identity bytes.
func TestTSXServePreGzipped(t *testing.T) {
	app := tsxServeApp(t, "GZ")
	plain := serveTSX(t, app, "/static/app.js", nil)
	if plain.Header().Get("Content-Encoding") != "" {
		t.Fatal("identity request got an encoded body")
	}
	gz := serveTSX(t, app, "/static/app.js", http.Header{"Accept-Encoding": {"br, gzip"}})
	if gz.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(gz.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("gzip request headers: %v", gz.Header())
	}
	if gz.Body.Len() >= plain.Body.Len() || !bytes.Equal(gunzipBody(t, gz.Body.Bytes()), plain.Body.Bytes()) {
		t.Fatal("gzip body is not the compressed bundle")
	}
	if gz.Header().Get("ETag") == plain.Header().Get("ETag") {
		t.Fatal("the gzip and identity representations share a strong validator")
	}
	if c := serveTSX(t, app, "/static/app.js", http.Header{"Accept-Encoding": {"gzip"}, "If-None-Match": {plain.Header().Get("ETag")}}); c.Code != http.StatusNotModified {
		t.Fatalf("either representation's validator should revalidate, got %d", c.Code)
	}
	if refused := serveTSX(t, app, "/static/app.js", http.Header{"Accept-Encoding": {"gzip;q=0"}}); refused.Header().Get("Content-Encoding") != "" {
		t.Fatal("gzip;q=0 still got gzip")
	}

	// An outer compressor (one that set Content-Encoding before the handler
	// ran) must receive identity bytes, or the client would get gzip twice.
	r := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	w.Header().Set("Content-Encoding", "gzip")
	serveTSXIfPresent(w, r, app, "app.js")
	if !bytes.Equal(w.Body.Bytes(), plain.Body.Bytes()) {
		t.Fatal("pre-encoded response was handed compressed bytes")
	}
}

// ?v= equal to the tree version the bundle was built from is immutable; any
// other ?v= is revalidated; after an edit the new version is immutable and
// serves the new bytes.
func TestTSXServeVersionedURLIsImmutableOnlyForItsTree(t *testing.T) {
	app := tsxServeApp(t, "V1")
	static := filepath.Join(app.Dir, "static")
	v1, ok := staticSourceTreeVersion(static)
	if !ok {
		t.Fatal("no tree version")
	}
	const immutable = "public, max-age=31536000, immutable"
	w := serveTSX(t, app, "/static/app.js?v="+v1, nil)
	if got := w.Header().Get("Cache-Control"); got != immutable || !strings.Contains(w.Body.String(), "V1") {
		t.Fatalf("current version: Cache-Control %q", got)
	}
	if w.Header().Get("CDN-Cache-Control") != "" {
		t.Fatal("immutable response still forbids CDN storage")
	}
	if got := serveTSX(t, app, "/static/app.js?v=000000000000", nil).Header().Get("Cache-Control"); got == immutable {
		t.Fatal("a forged ?v= was served immutable")
	}

	writeTSXSource(t, app, "V2-EDITED")
	v2, _ := staticSourceTreeVersion(static)
	if v2 == v1 {
		t.Fatal("edit did not change the tree version")
	}
	old := serveTSX(t, app, "/static/app.js?v="+v1, nil)
	if old.Header().Get("Cache-Control") == immutable && strings.Contains(old.Body.String(), "V2-EDITED") {
		t.Fatal("the old version's URL was made immutable with the new bytes")
	}
	// Past the recompile rate limit, the page's new version gets the new
	// bundle, immutable.
	tsxCacheMu.Lock()
	for _, e := range tsxCache {
		e.compiled = e.compiled.Add(-time.Hour)
	}
	tsxCacheMu.Unlock()
	fresh := serveTSX(t, app, "/static/app.js?v="+v2, nil)
	if fresh.Header().Get("Cache-Control") != immutable || !strings.Contains(fresh.Body.String(), "V2-EDITED") {
		t.Fatalf("new version: Cache-Control %q, body has edit=%v", fresh.Header().Get("Cache-Control"), strings.Contains(fresh.Body.String(), "V2-EDITED"))
	}
}

// The request path re-stats a bundle's inputs at most once per
// tsxFreshnessInterval; a direct compile always checks.
func TestTSXServeThrottlesInputChecks(t *testing.T) {
	old := tsxFreshnessInterval
	tsxFreshnessInterval = time.Hour
	t.Cleanup(func() { tsxFreshnessInterval = old })
	app := tsxServeApp(t, "FIRST")
	if body := serveTSX(t, app, "/static/app.js", nil).Body.String(); !strings.Contains(body, "FIRST") {
		t.Fatal("first serve")
	}
	writeTSXSource(t, app, "SECOND-EDIT")
	if body := serveTSX(t, app, "/static/app.js", nil).Body.String(); !strings.Contains(body, "FIRST") {
		t.Fatal("request path re-checked inputs inside the interval")
	}
	if body, _ := compileTSXOrTS(filepath.Join(app.Dir, "static", "app.tsx"), filepath.Join(app.Dir, "static")); !strings.Contains(string(body), "SECOND-EDIT") {
		t.Fatal("direct compile served a stale bundle")
	}
	tsxFreshnessInterval = 0
	if body := serveTSX(t, app, "/static/app.js", nil).Body.String(); !strings.Contains(body, "SECOND-EDIT") {
		t.Fatal("edit not picked up once the interval passed")
	}
}

// Concurrent misses share one build; a full compile budget makes a request
// wait (and give up with its context) instead of starting another build.
func TestTSXCompileSingleflightAndSlots(t *testing.T) {
	app := tsxServeApp(t, "SHARED")
	src := filepath.Join(app.Dir, "static", "app.tsx")
	root := filepath.Join(app.Dir, "static")
	before := tsxCompileRuns.Load()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry, err := compileTSXEntry(context.Background(), src, root, true, "")
			if err == nil && !strings.Contains(string(entry.body), "SHARED") {
				err = io.ErrUnexpectedEOF
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if runs := tsxCompileRuns.Load() - before; runs != 1 {
		t.Fatalf("16 concurrent misses ran %d builds, want 1", runs)
	}

	resetTSXCache()
	held := 0
	for len(tsxCompileSlots) < cap(tsxCompileSlots) {
		tsxCompileSlots <- struct{}{}
		held++
	}
	defer func() {
		for ; held > 0; held-- {
			<-tsxCompileSlots
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := compileTSXEntry(ctx, src, root, true, ""); err == nil {
		t.Fatal("compile ran without a free slot")
	}
}

// One render walks static/ once however many scripts it references, and
// renders within staticTreeVersionTTL reuse it; a hot reload drops it.
func TestStaticTreeVersionMemo(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	static := filepath.Join(app.Dir, "static")
	os.MkdirAll(static, 0o755)
	os.WriteFile(filepath.Join(static, "app.tsx"), []byte("export const a = 1"), 0o644)
	os.WriteFile(filepath.Join(static, "other.tsx"), []byte("export const b = 1"), 0o644)
	html := []byte(`<script src="/static/app.js"></script><script src="/static/other.js"></script><script src="/static/third.js"></script>`)

	before := staticTreeWalks.Load()
	out := versionStaticAssets(html, app)
	if walks := staticTreeWalks.Load() - before; walks != 1 {
		t.Fatalf("one render walked static/ %d times, want 1", walks)
	}
	if strings.Count(string(out), "?v=") != 3 {
		t.Fatalf("not every script versioned: %s", out)
	}

	staticTreeVersionTTL = time.Hour
	t.Cleanup(func() { staticTreeVersionTTL = 0 })
	invalidateStaticTreeVersion(app.Dir)
	first := vQueryRe.FindString(string(versionStaticAssets(html, app)))
	before = staticTreeWalks.Load()
	os.WriteFile(filepath.Join(static, "other.tsx"), []byte("export const b = 2 // edited"), 0o644)
	if got := vQueryRe.FindString(string(versionStaticAssets(html, app))); got != first || staticTreeWalks.Load() != before {
		t.Fatal("a render inside the TTL walked the tree again")
	}
	BroadcastReload(app, "test")
	if got := vQueryRe.FindString(string(versionStaticAssets(html, app))); got == first {
		t.Fatal("hot reload did not drop the memoized tree version")
	}
}
