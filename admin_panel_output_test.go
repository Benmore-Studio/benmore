//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// adminPanelApp returns the signed-URL fixture app with a signed-in admin.
func adminPanelApp(t *testing.T) (*App, *http.ServeMux, string, func()) {
	t.Helper()
	app, mux, cleanup := signedURLApp(t)
	if err := EnsureUsersTable(app.DB); err != nil {
		cleanup()
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('boss', 'boss@example.com', 'admin', 1)")
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	return app, mux, CreateSession(app.DB, uid, "boss@example.com", "", time.Hour), cleanup
}

// The list view's pagination links carried the search term into an href
// unescaped, so a link to /_admin/<table>?q="><script>… ran script as the
// admin who opened it (the app CSP allows inline script).
func TestAdminTablePaginationEscapesSearch(t *testing.T) {
	app, mux, admin, cleanup := adminPanelApp(t)
	defer cleanup()
	for i := 0; i < 60; i++ {
		mustExec(t, app.DB, `INSERT INTO docs (user_id, file_url) VALUES (1, 'x')`)
	}
	payload := `"><script>alert(document.cookie)</script>`
	rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/docs?q="+url.QueryEscape(payload), admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin table: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Page 1 of") {
		t.Fatalf("fixture must paginate: %s", body)
	}
	if strings.Contains(body, "<script>alert(") {
		t.Fatalf("search term reflected as markup in the admin panel")
	}
	if !strings.Contains(body, "q="+url.QueryEscape(payload)) {
		t.Errorf("pagination link lost the search term")
	}
	// Page 2 must carry the same search forward.
	rec = crudScopeRequest(t, mux, http.MethodGet, fmt.Sprintf("/_admin/docs?page=2&q=%s", url.QueryEscape(payload)), admin, nil)
	if strings.Contains(rec.Body.String(), "<script>alert(") {
		t.Fatalf("search term reflected as markup on page 2")
	}
}

// The panel printed every column: _benmore_users' bcrypt hashes (60
// characters, exactly the cell cut-off), plaintext TOTP secrets and backup
// codes, and app columns no API response carries (`*_secret`, `*_token`).
// Its search matched them too, a substring oracle.
func TestAdminPanelHidesCredentialColumns(t *testing.T) {
	app, mux, admin, cleanup := adminPanelApp(t)
	defer cleanup()
	const hash = "$2a$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
	for _, col := range []string{"totp_secret", "backup_codes"} {
		if !columnExists(t, app.DB, "_benmore_users", col) {
			mustExec(t, app.DB, "ALTER TABLE _benmore_users ADD COLUMN "+col+" TEXT")
		}
	}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (username, email, role, verified, password_hash, totp_secret, backup_codes)
		VALUES ('victim', 'victim@example.com', 'user', 1, '`+hash+`', 'JBSWY3DPEHPK3PXPTOTPSEED', 'backup-one,backup-two')`)
	mustExec(t, app.DB, `CREATE TABLE integrations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, api_secret TEXT, refresh_token TEXT)`)
	mustExec(t, app.DB, `INSERT INTO integrations (user_id, name, api_secret, refresh_token) VALUES (1, 'stripe', 'sk-integration-secret', 'rt-refresh-value')`)
	mustExec(t, app.DB, `CREATE TABLE docs_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id INTEGER, share_token TEXT, body TEXT)`)
	mustExec(t, app.DB, `INSERT INTO docs_notes (doc_id, share_token, body) VALUES (1, 'share-token-value', 'visible note')`)
	app.Tables = append(app.Tables, Table{Name: "docs_notes", Columns: []Column{{Name: "id"}, {Name: "doc_id"}, {Name: "share_token", Type: "TEXT"}, {Name: "body", Type: "TEXT"}}})

	secrets := []string{hash, "JBSWY3DPEHPK3PXPTOTPSEED", "backup-one", "sk-integration-secret", "rt-refresh-value", "share-token-value"}
	check := func(path, want string) {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, path, admin, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, want) {
			t.Fatalf("%s: expected %q in the page", path, want)
		}
		for _, s := range secrets {
			if strings.Contains(body, s) {
				t.Errorf("%s shows hidden value %q", path, s)
			}
		}
	}
	check("/_admin/_benmore_users", "victim@example.com")
	check("/_admin/_benmore_users/2", "victim@example.com")
	check("/_admin/integrations", "stripe")
	check("/_admin/integrations/1", "stripe")
	check("/_admin/docs/1", "visible note") // related-records table

	// Search no longer matches hidden values.
	rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/integrations?q=sk-integration", admin, nil)
	if strings.Contains(rec.Body.String(), "stripe") {
		t.Errorf("admin search matched a hidden column")
	}
	// The create form still accepts a secret (write-only).
	rec = crudScopeRequest(t, mux, http.MethodGet, "/_admin/integrations", admin, nil)
	if !strings.Contains(rec.Body.String(), `name="api_secret"`) {
		t.Errorf("create form lost the write-only secret input")
	}
}
