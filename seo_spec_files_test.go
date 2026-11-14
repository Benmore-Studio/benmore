//go:build !cli

package main

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// atomTestFeed is the part of RFC 4287 the generated feed has to satisfy:
// atom:feed needs id, title, updated and an author (or one on every entry);
// every atom:entry needs id, title, updated and an alternate link.
type atomTestFeed struct {
	XMLName xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
	ID      string   `xml:"id"`
	Title   string   `xml:"title"`
	Updated string   `xml:"updated"`
	Authors []struct {
		Name string `xml:"name"`
	} `xml:"author"`
	Entries []struct {
		ID      string `xml:"id"`
		Title   string `xml:"title"`
		Updated string `xml:"updated"`
		Links   []struct {
			Href string `xml:"href,attr"`
			Rel  string `xml:"rel,attr"`
		} `xml:"link"`
	} `xml:"entry"`
}

func parseAtomTestFeed(t *testing.T, body string) atomTestFeed {
	t.Helper()
	var feed atomTestFeed
	if err := xml.Unmarshal([]byte(body), &feed); err != nil {
		t.Fatalf("feed is not Atom XML: %v\n%s", err, body)
	}
	if feed.ID == "" || feed.Title == "" {
		t.Fatalf("feed lacks id/title: %+v", feed)
	}
	if _, err := time.Parse(time.RFC3339, feed.Updated); err != nil {
		t.Fatalf("feed <updated> %q is not an RFC 3339 date: %v\n%s", feed.Updated, err, body)
	}
	if len(feed.Authors) == 0 || strings.TrimSpace(feed.Authors[0].Name) == "" {
		t.Fatalf("feed has no <author><name> (RFC 4287 4.1.1):\n%s", body)
	}
	for _, e := range feed.Entries {
		if e.ID == "" || e.Title == "" {
			t.Fatalf("entry lacks id/title: %+v", e)
		}
		if _, err := time.Parse(time.RFC3339, e.Updated); err != nil {
			t.Fatalf("entry %s <updated> %q is not an RFC 3339 date: %v", e.ID, e.Updated, err)
		}
		alternate := false
		for _, l := range e.Links {
			if l.Rel == "" || l.Rel == "alternate" {
				alternate = true
			}
		}
		if !alternate {
			t.Fatalf("entry %s has no alternate link", e.ID)
		}
	}
	return feed
}

// /feed.xml had no <updated> on the feed or its entries and no <author>, both
// required by RFC 4287, so feed validators rejected it.
func TestAtomFeedCarriesRequiredUpdatedAndAuthor(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "index.html", "<page title=\"Home\">home</page>")
	writeTestFile(t, dir, "about.html", "<page title=\"About\">about</page>")
	older := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 9, 15, 8, 30, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(dir, "index.html"), older, older); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(dir, "about.html"), newer, newer); err != nil {
		t.Fatal(err)
	}
	app := &App{
		Dir:    dir,
		Design: &DesignConfig{SEO: map[string]string{"site_name": "Events & Co"}},
		Pages: map[string]*Page{
			"/":      {Route: "/", File: "index.html", Title: "Home"},
			"/about": {Route: "/about", File: "about.html", Title: "About"},
		},
	}
	base := "https://events.example.test"
	feed := parseAtomTestFeed(t, GenerateAtomFeed(app, base))
	if feed.Updated != newer.Format(time.RFC3339) {
		t.Fatalf("feed <updated> = %s, want the newest page's change time %s", feed.Updated, newer.Format(time.RFC3339))
	}
	if feed.Authors[0].Name != "Events & Co" {
		t.Fatalf("author falls back to the site name, got %q", feed.Authors[0].Name)
	}
	if len(feed.Entries) != 2 {
		t.Fatalf("entries = %+v", feed.Entries)
	}
	// Newest first, each dated by its own page file.
	if feed.Entries[0].ID != base+"/about" || feed.Entries[0].Updated != newer.Format(time.RFC3339) {
		t.Fatalf("first entry = %+v, want /about at %s", feed.Entries[0], newer.Format(time.RFC3339))
	}
	if feed.Entries[1].ID != base+"/" || feed.Entries[1].Updated != older.Format(time.RFC3339) {
		t.Fatalf("second entry = %+v, want / at %s", feed.Entries[1], older.Format(time.RFC3339))
	}

	// seo.author names the author when set.
	app.Design.SEO["author"] = "Ada Lovelace"
	if feed := parseAtomTestFeed(t, GenerateAtomFeed(app, base)); feed.Authors[0].Name != "Ada Lovelace" {
		t.Fatalf("seo.author ignored: %q", feed.Authors[0].Name)
	}

	// No listable page and no design config: still a valid feed.
	empty := parseAtomTestFeed(t, GenerateAtomFeed(&App{Dir: t.TempDir()}, base))
	if len(empty.Entries) != 0 || empty.Authors[0].Name != "App" {
		t.Fatalf("empty feed = %+v", empty)
	}
}

// security.txt had no Expires (required by RFC 9116) and, without
// seo.security_contact, an empty `Contact: mailto:`.
func TestSecurityTxtIsValidOrAbsent(t *testing.T) {
	now := time.Date(2026, 11, 4, 15, 4, 5, 0, time.UTC)
	if body, ok := GenerateSecurityTxt(&App{}, "https://x.example.test", now); ok {
		t.Fatalf("no contact configured must serve nothing, got:\n%s", body)
	}
	for contact, want := range map[string]string{
		"security@example.test":         "Contact: mailto:security@example.test\n",
		"mailto:sec@example.test":       "Contact: mailto:sec@example.test\n",
		"https://example.test/security": "Contact: https://example.test/security\n",
	} {
		app := &App{Design: &DesignConfig{SEO: map[string]string{"security_contact": contact}}}
		body, ok := GenerateSecurityTxt(app, "https://x.example.test", now)
		if !ok || !strings.HasPrefix(body, want) {
			t.Fatalf("contact %q: ok=%v body:\n%s", contact, ok, body)
		}
		if !strings.Contains(body, "Canonical: https://x.example.test/.well-known/security.txt\n") {
			t.Fatalf("canonical missing:\n%s", body)
		}
		var expires string
		for _, line := range strings.Split(body, "\n") {
			if v, found := strings.CutPrefix(line, "Expires: "); found {
				expires = v
			}
		}
		at, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			t.Fatalf("Expires %q is not RFC 3339: %v\n%s", expires, err, body)
		}
		if !at.After(now) || !at.Before(now.AddDate(1, 0, 0)) {
			t.Fatalf("Expires %s should be in the future and under a year away (RFC 9116 2.5.5)", at)
		}
		// Every request on the same UTC day agrees, so caches do too.
		later, _ := GenerateSecurityTxt(app, "https://x.example.test", now.Add(8*time.Hour))
		if later != body {
			t.Fatalf("security.txt changed within one UTC day:\n%s\n---\n%s", body, later)
		}
	}
	// A contact that would add its own lines is not served.
	app := &App{Design: &DesignConfig{SEO: map[string]string{"security_contact": "a@example.test\nPolicy: https://evil.test"}}}
	if body, ok := GenerateSecurityTxt(app, "https://x.example.test", now); ok {
		t.Fatalf("multi-line contact must not be served:\n%s", body)
	}
}

func TestSecurityTxtRouteServesOverrideOr404(t *testing.T) {
	get := func(t *testing.T, app *App) *httptest.ResponseRecorder {
		t.Helper()
		mux := buildAppMux(app, true, "http://localhost:9999")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://sec.example.test/.well-known/security.txt", nil))
		return rec
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: Sec fixture\n")
	writeTestFile(t, dir, "static/index.html", "<!doctype html><title>x</title>")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if rec := get(t, app); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "Contact:") {
		t.Fatalf("no contact: %d %q", rec.Code, rec.Body.String())
	}

	quiesceTestApp(t, app)
	app.Design.SEO["security_contact"] = "security@example.test"
	rec := get(t, app)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" ||
		!strings.Contains(rec.Body.String(), "Contact: mailto:security@example.test\n") || !strings.Contains(rec.Body.String(), "\nExpires: ") {
		t.Fatalf("configured contact: %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}

	// An app's own static/.well-known/security.txt is served verbatim.
	dir2 := t.TempDir()
	writeTestFile(t, dir2, "app.yaml", "name: Sec fixture two\n")
	writeTestFile(t, dir2, "static/index.html", "<!doctype html><title>x</title>")
	own := "Contact: https://own.example.test/report\nExpires: 2027-01-01T00:00:00Z\nPolicy: https://own.example.test/policy\n"
	writeTestFile(t, dir2, "static/.well-known/security.txt", own)
	app2, err := loadApp(dir2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app2.Shutdown)
	if rec := get(t, app2); rec.Code != http.StatusOK || rec.Body.String() != own {
		t.Fatalf("own security.txt: %d %q", rec.Code, rec.Body.String())
	}
}

// SSR pages linked an icon only from seo.favicon while the scaffold ships
// static/favicon.svg, and /favicon.ico served only .ico/.png: the browser's
// /favicon.ico request answered 404 and failed journeys.
func TestSSRPagesLinkTheStaticFaviconAndFaviconICOFallsBack(t *testing.T) {
	serve := func(t *testing.T, app *App, path string) *httptest.ResponseRecorder {
		t.Helper()
		mux := buildAppMux(app, false, "https://ssr.example.test")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://ssr.example.test"+path, nil))
		return rec
	}
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><circle cx="8" cy="8" r="7"/></svg>`
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: SSR icon fixture\n")
	writeTestFile(t, dir, "index.html", "<page title=\"Home\"><h1>Home</h1></page>")
	writeTestFile(t, dir, "static/favicon.svg", svg)
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)

	page := serve(t, app, "/")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `<link rel="icon" type="image/svg+xml" href="/static/favicon.svg`) {
		t.Fatalf("SSR page %d links no static icon: %.600s", page.Code, page.Body.String())
	}
	ico := serve(t, app, "/favicon.ico")
	if ico.Code != http.StatusOK || ico.Header().Get("Content-Type") != "image/svg+xml" || ico.Body.String() != svg {
		t.Fatalf("/favicon.ico = %d %q %q", ico.Code, ico.Header().Get("Content-Type"), ico.Body.String())
	}

	// seo.favicon still wins, and only one icon is linked.
	quiesceTestApp(t, app)
	app.Design.SEO["favicon"] = "/static/brand.png"
	body := serve(t, app, "/").Body.String()
	if !strings.Contains(body, `<link rel="icon" href="/static/brand.png`) || strings.Count(body, `rel="icon"`) != 1 {
		t.Fatalf("seo.favicon not honoured exactly once: %.600s", body)
	}

	// An app with no icon at all links none and still 404s /favicon.ico.
	dir2 := t.TempDir()
	writeTestFile(t, dir2, "app.yaml", "name: SSR no icon\n")
	writeTestFile(t, dir2, "index.html", "<page title=\"Home\"><h1>Home</h1></page>")
	app2, err := loadAppForServerTests(dir2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app2.Shutdown)
	if body := serve(t, app2, "/").Body.String(); strings.Contains(body, `rel="icon"`) {
		t.Fatalf("icon linked without one: %.600s", body)
	}
	if rec := serve(t, app2, "/favicon.ico"); rec.Code != http.StatusNotFound {
		t.Fatalf("/favicon.ico without an icon = %d", rec.Code)
	}
}
