//go:build !cli

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMediaCDN is an httptest TLS server standing in for the media CDN. It
// serves one object and records what it was asked for.
type fakeMediaCDN struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []*http.Request
}

func (c *fakeMediaCDN) requests() []*http.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*http.Request(nil), c.seen...)
}

func startFakeMediaCDN(t *testing.T, key string, body []byte) *fakeMediaCDN {
	t.Helper()
	c := &fakeMediaCDN{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.seen = append(c.seen, r.Clone(r.Context()))
		c.mu.Unlock()
		if strings.TrimPrefix(r.URL.Path, "/") != key || r.URL.Query().Get("Signature") == "" {
			http.Error(w, "AccessDenied", http.StatusForbidden)
			return
		}
		// The stored object headers: inline, under its storage name.
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "inline")
		http.ServeContent(w, r, "report.pdf", time.Unix(1700000000, 0), bytes.NewReader(body))
	}))
	t.Cleanup(c.srv.Close)
	old := serveFileCDNClient
	serveFileCDNClient = func() *http.Client {
		cl := c.srv.Client()
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return cl
	}
	t.Cleanup(func() { serveFileCDNClient = old })
	return c
}

const cdnDownloadFlow = `on:
  request:
    method: GET
    path: /api/bookings/:id/attachment
jobs:
  file:
    steps:
      - run: serve_file
        with:
          path: /uploads/private/report.pdf
          disposition: ${{ params.dl == '1' && 'attachment' || 'inline' }}
          filename: "Booking ${{ params.id }}.pdf"
`

func runCDNDownloadFlow(t *testing.T, app *App, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "attachment.yaml"), []byte(cdnDownloadFlow))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v", err)
	}
	f := flows[0]
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.SetPathValue("id", "5")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	executeFlowHTTP(app, &f, rec, req)
	return rec
}

// B4: on the hosted media CDN, serve_file answered a download (`?dl=1`)
// with the same inline redirect as a view, so `disposition: attachment` and
// `filename:` never reached the browser. A download now streams through the
// app with both; a view still redirects.
func TestServeFileCDNDownloadCarriesDispositionAndFilename(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	app, cleanup := newTestApp(t)
	defer cleanup()
	key := "private/" + appMediaPrefix(app) + "/uploads/private/report.pdf"
	body := []byte("%PDF-1.4 booking five")
	cdn := startFakeMediaCDN(t, key, body)
	cfg := testMediaConfig(t)
	cfg.CDNDomain = strings.TrimPrefix(cdn.srv.URL, "https://")
	withPlatformMedia(t, cfg)

	rec := runCDNDownloadFlow(t, app, "/api/bookings/5/attachment?dl=1", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
		t.Fatalf("download = %d (Location %q), want 200 streamed: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="Booking 5.pdf"` {
		t.Fatalf("Content-Disposition = %q, want the step's attachment filename", cd)
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatalf("body = %q, want the object bytes", rec.Body.String())
	}
	for k, want := range map[string]string{"Content-Type": "application/pdf", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	seen := cdn.requests()
	if len(seen) != 1 || strings.TrimPrefix(seen[0].URL.Path, "/") != key || seen[0].URL.Query().Get("Key-Pair-Id") != "KLOCAL" {
		t.Fatalf("CDN requests = %v, want one signed GET of %s", seen, key)
	}

	// Range requests pass through (download managers resume).
	rec = runCDNDownloadFlow(t, app, "/api/bookings/5/attachment?dl=1", map[string]string{"Range": "bytes=0-3"})
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "%PDF" || rec.Header().Get("Content-Range") == "" {
		t.Fatalf("ranged download = %d %q (Content-Range %q), want 206 of the first 4 bytes", rec.Code, rec.Body.String(), rec.Header().Get("Content-Range"))
	}

	// A view keeps the redirect to the signed CDN URL; nothing is fetched.
	before := len(cdn.requests())
	rec = runCDNDownloadFlow(t, app, "/api/bookings/5/attachment", nil)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, cdn.srv.URL+"/"+key+"?") || !strings.Contains(loc, "Signature=") {
		t.Fatalf("view = %d %q, want 302 to the signed CDN URL", rec.Code, loc)
	}
	if len(cdn.requests()) != before {
		t.Fatal("a view fetched the object through the app")
	}
}

// A missing object answers 404, never the CDN's error body.
func TestServeFileCDNDownloadMissingObject(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	app, cleanup := newTestApp(t)
	defer cleanup()
	cdn := startFakeMediaCDN(t, "private/someone-else/uploads/private/report.pdf", []byte("x"))
	cfg := testMediaConfig(t)
	cfg.CDNDomain = strings.TrimPrefix(cdn.srv.URL, "https://")
	withPlatformMedia(t, cfg)
	rec := runCDNDownloadFlow(t, app, "/api/bookings/5/attachment?dl=1", nil)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "AccessDenied") {
		t.Fatalf("missing object = %d %q, want 404", rec.Code, rec.Body.String())
	}
}

// A hosted tenant still never signs: the router's broker signs the download
// URL, and an answer that is not on the media CDN is never fetched.
func TestServeFileCDNDownloadSignsThroughBroker(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	app, cleanup := newTestApp(t)
	defer cleanup()
	key := "private/" + appMediaPrefix(app) + "/uploads/private/report.pdf"
	cdn := startFakeMediaCDN(t, key, []byte("%PDF-1.4"))
	cfg := testMediaConfig(t)
	cfg.CDNDomain = strings.TrimPrefix(cdn.srv.URL, "https://")
	withPlatformMedia(t, cfg)

	signed := cdn.srv.URL + "/" + key + "?Expires=1&Signature=router&Key-Pair-Id=ROUTER"
	broker := startFakeMediaBroker(t, map[string]any{"url": signed, "key": key})
	rec := runCDNDownloadFlow(t, app, "/api/bookings/5/attachment?dl=1", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.4" {
		t.Fatalf("hosted download = %d %q", rec.Code, rec.Body.String())
	}
	reqs := broker.requests()
	if len(reqs) != 1 || reqs[0]["operation"] != "sign" || reqs[0]["path"] != key {
		t.Fatalf("broker requests = %#v", reqs)
	}
	if seen := cdn.requests(); len(seen) != 1 || seen[0].URL.Query().Get("Key-Pair-Id") != "ROUTER" {
		t.Fatalf("CDN did not receive the router-signed URL: %v", seen)
	}

	// A signer answer off the media CDN is refused before any fetch.
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fetched a non-CDN URL: %s", r.URL)
	}))
	defer other.Close()
	startFakeMediaBroker(t, map[string]any{"url": other.URL + "/" + key + "?Signature=x", "key": key})
	rec = runCDNDownloadFlow(t, app, "/api/bookings/5/attachment?dl=1", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("off-CDN signer answer = %d, want 500", rec.Code)
	}
}

// filename: is a template now. One whose reference has no value answers the
// usual unresolved-reference error and serves nothing, instead of serving
// the file and then failing the flow on a response already written.
func TestServeFileFilenameTemplate(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "uploads", "report.pdf"), []byte("%PDF-1.4 local"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(filename, query string) *httptest.ResponseRecorder {
		flow := "on:\n  request:\n    method: GET\n    path: /api/file\njobs:\n  file:\n    steps:\n      - run: serve_file\n        with:\n          path: /uploads/report.pdf\n          disposition: attachment\n          filename: \"" + filename + "\"\n"
		flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "file.yaml"), []byte(flow))
		if err != nil || len(flows) != 1 {
			t.Fatalf("parse flow: %v", err)
		}
		f := flows[0]
		rec := httptest.NewRecorder()
		executeFlowHTTP(app, &f, rec, httptest.NewRequest(http.MethodGet, "/api/file"+query, nil))
		return rec
	}
	rec := run("Report ${{ params.n }}.pdf", "?n=7")
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="Report 7.pdf"` {
		t.Fatalf("Content-Disposition = %q, want the rendered filename", cd)
	}
	rec = run("Report ${{ steps.nope.outputs.name }}.pdf", "")
	if rec.Code < 500 || strings.Contains(rec.Body.String(), "%PDF") || rec.Header().Get("Content-Disposition") != "" {
		t.Fatalf("unresolved filename = %d %q (CD %q), want an error and no file", rec.Code, rec.Body.String(), rec.Header().Get("Content-Disposition"))
	}
}
