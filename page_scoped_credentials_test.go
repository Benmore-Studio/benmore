//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// scopedPageFixture is an app with a table the token below is not scoped to
// (ledger) and pages that read it on the server, in both page engines.
func scopedPageFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	old := pdfChromeLocator
	pdfChromeLocator = func() string { return "" }
	t.Cleanup(func() { pdfChromeLocator = old })
	// Each test asks for more PDFs than one caller's per-minute budget.
	limiter := pdfLimiter
	pdfLimiter = NewRateLimiter(1000, time.Minute)
	t.Cleanup(func() { pdfLimiter = limiter })

	app := ssrTestApp(t)
	EnsureAPITokensTable(app.DB)
	crudScopeMustExec(t, app.DB, `CREATE TABLE ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, entry TEXT)`)
	crudScopeMustExec(t, app.DB, `INSERT INTO ledger (user_id, entry) VALUES (1, 'ledger-row-marker')`)
	app.Tables = append(app.Tables, Table{Name: "ledger", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "entry"}}})
	const rows = `<query sql="SELECT entry FROM ledger" as="rows">{{#rows}}<p id="entry">[{{entry}}]</p>{{/rows}}</query>`
	ssrLoadPages(t, app, map[string]string{
		"books.html":       `<page title="Books" auth="required" layout="none">` + rows + `<p id="who">[{{user_email}}]</p></page>`,
		"report.html":      "---\nengine: gotmpl\nlayout: none\nauth: required\nqueries:\n  rows: SELECT entry FROM ledger\n---\n{{range .rows}}<p id=\"entry\">[{{.entry}}]</p>{{end}}<p id=\"who\">[{{.user_email}}]</p>",
		"staff.html":       `<page title="Staff" role="user" layout="none">` + rows + `</page>`,
		"members.html":     `<page title="Members" require="role:user" layout="none">` + rows + `</page>`,
		"broken.html":      `<page title="Broken" auth="required" layout="none"><query sql="SELECT entry FROM no_such_table" as="rows">{{#rows}}{{entry}}{{/rows}}</query></page>`,
		"figures.html":     "---\nengine: gotmpl\nlayout: none\nauth: required\nsources:\n  rows:\n    table: notes\n---\n<pre id=\"figures\">{{ toJson .sources.rows }}</pre>",
		"openfigures.html": "---\nengine: gotmpl\nlayout: none\nsources:\n  rows:\n    table: notes\n---\n<pre id=\"figures\">{{ toJson .sources.rows }}</pre>",
		"open.html":        `<page title="Open" auth="none" layout="none">` + rows + `<p id="who">[{{user_email}}]</p><p id="state">[{{#if current_user}}IN{{else}}OUT{{/if}}]</p></page>`,
		"openlist.html":    "---\nengine: gotmpl\nlayout: none\nauth: none\nqueries:\n  rows: SELECT entry FROM ledger\n---\n{{range .rows}}<p id=\"entry\">[{{.entry}}]</p>{{end}}<p id=\"who\">[{{.user_email}}]</p><p id=\"state\">[{{if .current_user}}IN{{else}}OUT{{end}}]</p>",
	})
	return app, buildAppMux(app, false, "https://fixture.example.com")
}

// scopedPageAPIToken stores an API token for userID the way the mint
// endpoint does (only its hash) and returns the secret.
func scopedPageAPIToken(t *testing.T, app *App, userID int64, name, scopes string) string {
	t.Helper()
	secret := "bmr_" + strings.Repeat(name, 4)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, ?, ?, ?)`, userID, name, hashToken(secret), scopes); err != nil {
		t.Fatal(err)
	}
	return secret
}

func scopedPageGet(mux *http.ServeMux, path, bearer, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", "text/html")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// assertScopedPageRefusal checks the one answer a scoped credential gets
// from a page that requires sign-in: 403, the stable code, a message that
// says why, the docs address, and nothing the page would have rendered.
func assertScopedPageRefusal(t *testing.T, label string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Errorf("%s: status %d, want 403\n%s", label, rec.Code, rec.Body.String())
		return
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Errorf("%s: the 403 body is not JSON: %v\n%s", label, err, rec.Body.String())
		return
	}
	if body["error"] != scopedCredentialPageCode {
		t.Errorf("%s: error = %v, want %q", label, body["error"], scopedCredentialPageCode)
	}
	message, _ := body["message"].(string)
	for _, want := range []string{"browser", "scope"} {
		if !strings.Contains(message, want) {
			t.Errorf("%s: message %q does not mention %q", label, message, want)
		}
	}
	if body["docs"] != "auth.credential_limits" {
		t.Errorf("%s: docs = %v, want auth.credential_limits", label, body["docs"])
	}
	if strings.Contains(rec.Body.String(), "ledger-row-marker") {
		t.Errorf("%s: the refusal carries the page's query result", label)
	}
}

// A token scoped to one table read every other table through a page's
// server-side queries, and through the page's PDF: page gates looked at the
// account and the queries ran as it. A page that requires sign-in now refuses
// a scoped credential before anything is rendered.
func TestScopedCredentialDoesNotRenderSignInPages(t *testing.T) {
	app, mux := scopedPageFixture(t)
	const email = "owner@example.com"
	session := createCrudScopeSession(t, app, email, "user", "", "")
	scopedToken := scopedPageAPIToken(t, app, 1, "scoped", "notes:read")
	scopedSession := CreateSession(app.DB, 1, email, "", time.Hour, "notes:read")

	protected := []string{"/books", "/report", "/staff", "/members", "/broken", "/figures"}
	credentials := []struct{ name, bearer, cookie string }{
		{"scoped API token", scopedToken, ""},
		{"scoped Bearer session", scopedSession, ""},
		{"scoped session as a cookie", "", scopedSession},
	}
	for _, c := range credentials {
		for _, path := range protected {
			assertScopedPageRefusal(t, c.name+" GET "+path, scopedPageGet(mux, path, c.bearer, c.cookie))
			assertScopedPageRefusal(t, c.name+" GET /pdf"+path, scopedPageGet(mux, "/pdf"+path, c.bearer, c.cookie))
		}
	}

	// The broken page shows the query never ran: for the account's own
	// sign-in the same request reaches the query and fails on it.
	if rec := scopedPageGet(mux, "/broken", session, ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("sign-in GET /broken: status %d, want the query's 500", rec.Code)
	}

	// The scoped token still does what its scopes say on the generated API.
	if rec := scopedPageGet(mux, "/api/notes", scopedToken, ""); rec.Code != http.StatusOK {
		t.Errorf("scoped token GET /api/notes: status %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	if rec := scopedPageGet(mux, "/api/ledger", scopedToken, ""); rec.Code == http.StatusOK {
		t.Errorf("scoped token GET /api/ledger: 200, want a refusal\n%s", rec.Body.String())
	}
}

// An unscoped token and the account's own sign-in render pages and reach the
// PDF renderer as before.
func TestUnscopedCredentialsRenderSignInPagesAsBefore(t *testing.T) {
	app, mux := scopedPageFixture(t)
	const email = "owner@example.com"
	session := createCrudScopeSession(t, app, email, "user", "", "")
	credentials := []struct{ name, bearer, cookie string }{
		{"sign-in session (cookie)", "", session},
		{"sign-in session (Bearer)", session, ""},
		{"API token with scopes *", scopedPageAPIToken(t, app, 1, "star", "*"), ""},
		{"API token with empty scopes", scopedPageAPIToken(t, app, 1, "none", ""), ""},
	}
	for _, c := range credentials {
		for _, path := range []string{"/books", "/report", "/staff", "/members"} {
			rec := scopedPageGet(mux, path, c.bearer, c.cookie)
			body := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(body, `<p id="entry">[ledger-row-marker]</p>`) {
				t.Errorf("%s GET %s: status %d, want 200 with the query's row\n%s", c.name, path, rec.Code, pageAuthored(body))
			}
			if path == "/books" || path == "/report" {
				if got := pageElements(body)["who"]; got != "["+email+"]" {
					t.Errorf("%s GET %s: rendered for %s, want [%s]", c.name, path, got, email)
				}
			}
			// 501 is the PDF route's answer once every gate has passed and
			// no browser is installed.
			if pdf := scopedPageGet(mux, "/pdf"+path, c.bearer, c.cookie); pdf.Code != http.StatusNotImplemented {
				t.Errorf("%s GET /pdf%s: status %d, want 501 (gates passed)\n%s", c.name, path, pdf.Code, pdf.Body.String())
			}
		}
	}
}

// A public page renders for a scoped credential exactly as it does for a
// caller with no credential: the token adds nothing to it.
func TestScopedCredentialSeesPublicPagesAsAnonymous(t *testing.T) {
	app, mux := scopedPageFixture(t)
	const email = "owner@example.com"
	session := createCrudScopeSession(t, app, email, "user", "", "")
	scopedToken := scopedPageAPIToken(t, app, 1, "scoped", "notes:read")
	scopedSession := CreateSession(app.DB, 1, email, "", time.Hour, "notes:read")

	// A typed source resolves its caller from the request: on a page with
	// no gate it answers a scoped token what it answers nobody, also when
	// the token's scopes name the table.
	nobody := scopedPageGet(mux, "/openfigures", "", "")
	if nobody.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /openfigures: status %d, want the source's 401\n%s", nobody.Code, nobody.Body.String())
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"scoped API token":           scopedPageGet(mux, "/openfigures", scopedToken, ""),
		"scoped Bearer session":      scopedPageGet(mux, "/openfigures", scopedSession, ""),
		"scoped session as a cookie": scopedPageGet(mux, "/openfigures", "", scopedSession),
	} {
		if rec.Code != nobody.Code || rec.Body.String() != nobody.Body.String() {
			t.Errorf("%s GET /openfigures: %d %q, anonymous gets %d %q", name, rec.Code, rec.Body.String(), nobody.Code, nobody.Body.String())
		}
	}
	if rec := scopedPageGet(mux, "/openfigures", session, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<pre id="figures">`) {
		t.Errorf("sign-in GET /openfigures: status %d, want the rendered source\n%s", rec.Code, rec.Body.String())
	}

	for _, path := range []string{"/open", "/openlist"} {
		anonymous := scopedPageGet(mux, path, "", "")
		if anonymous.Code != http.StatusOK {
			t.Fatalf("anonymous GET %s: status %d\n%s", path, anonymous.Code, anonymous.Body.String())
		}
		want := pageElements(anonymous.Body.String())
		if want["who"] != "[]" || want["state"] != "[OUT]" {
			t.Fatalf("anonymous GET %s rendered a viewer: %v", path, want)
		}
		for name, rec := range map[string]*httptest.ResponseRecorder{
			"scoped API token":           scopedPageGet(mux, path, scopedToken, ""),
			"scoped Bearer session":      scopedPageGet(mux, path, scopedSession, ""),
			"scoped session as a cookie": scopedPageGet(mux, path, "", scopedSession),
		} {
			if rec.Code != http.StatusOK {
				t.Errorf("%s GET %s: status %d, want 200\n%s", name, path, rec.Code, rec.Body.String())
				continue
			}
			got := pageElements(rec.Body.String())
			for id, value := range want {
				if got[id] != value {
					t.Errorf("%s GET %s: %s = %q, anonymous sees %q", name, path, id, got[id], value)
				}
			}
			if strings.Contains(rec.Body.String(), email) {
				t.Errorf("%s GET %s: the page names the token's account", name, path)
			}
		}
		// The account's own sign-in is still the page's viewer.
		signedIn := pageElements(scopedPageGet(mux, path, session, "").Body.String())
		if signedIn["who"] != "["+email+"]" || signedIn["state"] != "[IN]" {
			t.Errorf("sign-in GET %s: who=%q state=%q, want the viewer", path, signedIn["who"], signedIn["state"])
		}
		// Its PDF passes for a scoped token as for an anonymous caller.
		for name, rec := range map[string]*httptest.ResponseRecorder{
			"anonymous":        scopedPageGet(mux, "/pdf"+path, "", ""),
			"scoped API token": scopedPageGet(mux, "/pdf"+path, scopedToken, ""),
		} {
			if rec.Code != http.StatusNotImplemented {
				t.Errorf("%s GET /pdf%s: status %d, want 501 (gates passed)\n%s", name, path, rec.Code, rec.Body.String())
			}
		}
	}
}
