//go:build !cli && !windows

package main

import (
	"bytes"
	"database/sql"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// uploadAsFixtureUser stores one file through POST /api/_upload as the
// session's user and returns the stored reference (/uploads/<kind>/<id>.pdf).
func uploadAsFixtureUser(t *testing.T, mux *http.ServeMux, token, kind, content string) string {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("kind", kind); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("file", "fixture.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("%PDF-1.4 " + content)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/_upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload kind=%s: %d %s", kind, rec.Code, rec.Body.String())
	}
	var out map[string]any
	mustDecodeBody(t, rec, &out)
	ref, _ := out["path"].(string)
	if !strings.HasPrefix(ref, "/uploads/"+kind+"/") {
		t.Fatalf("upload kind=%s stored at %q", kind, ref)
	}
	return ref
}

// accountUploadsFixture is an app with two users. "gone" uploaded two private
// files and a public one, "kept" one private file; each private file is
// referenced by a docs row of its uploader, and one of gone's has a signed
// URL minted while the account was alive. "gone" also uploaded one private
// file while it was an admin, attached to a docs row of "kept".
type accountUploadsFixture struct {
	app                              *App
	mux                              *http.ServeMux
	goneID                           int64
	goneToken, keptToken             string
	gonePrivate, gonePrivate2        string
	gonePublic, keptPrivate          string
	goneAdminUpload                  string
	goneSigned, keptSigned           string
	adminUploadSigned                string
	docsBefore, ownershipBeforeCount int
}

func newAccountUploadsFixture(t *testing.T) *accountUploadsFixture {
	t.Helper()
	previous := serverSecret
	serverSecret = "account-upload-cleanup-test-secret-0123456789"
	t.Cleanup(func() { serverSecret = previous })
	// No background workers (the full mux starts them): the erasure and the
	// fixture's writes must not race another connection for the write lock.
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustExec(t, db, `CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, file_url TEXT)`)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{"docs": {OpRead: "self"}}},
		Tables: []Table{{Name: "docs", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "file_url"}}}},
	}
	EnsureAuditLogTable(db)
	EnsurePermissionsTable(db)
	mux := http.NewServeMux()
	RegisterUploadRoute(mux, app)
	RegisterSignedURLRoutes(mux, app)
	mux.HandleFunc("GET /uploads/", func(w http.ResponseWriter, r *http.Request) {
		serveUploadAsset(w, r, app, false, filepath.Clean(strings.TrimPrefix(r.URL.Path, "/uploads/")))
	})
	f := &accountUploadsFixture{app: app, mux: mux}
	goneTok := createCrudScopeSession(t, app, "gone-uploader@example.com", "user", "", "")
	keptTok := createCrudScopeSession(t, app, "kept-uploader@example.com", "user", "", "")
	f.goneToken, f.keptToken = goneTok, keptTok
	var keptID int64
	if err := app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email='gone-uploader@example.com'`).Scan(&f.goneID); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email='kept-uploader@example.com'`).Scan(&keptID); err != nil {
		t.Fatal(err)
	}
	f.gonePrivate = uploadAsFixtureUser(t, mux, goneTok, "private", "gone one")
	f.gonePrivate2 = uploadAsFixtureUser(t, mux, goneTok, "private", "gone two")
	f.gonePublic = uploadAsFixtureUser(t, mux, goneTok, "avatars", "gone public")
	f.keptPrivate = uploadAsFixtureUser(t, mux, keptTok, "private", "kept one")
	// Staff work: while an admin, gone uploads a file for kept's record.
	mustExec(t, db, `UPDATE _benmore_users SET role='admin' WHERE email='gone-uploader@example.com'`)
	f.goneAdminUpload = uploadAsFixtureUser(t, mux, goneTok, "private", "for a client")
	mustExec(t, db, `UPDATE _benmore_users SET role='user' WHERE email='gone-uploader@example.com'`)
	var asAdmin int
	if err := db.QueryRow(`SELECT uploader_admin FROM _benmore_upload_owners WHERE path=? AND user_id=?`, uploadRelPath(f.goneAdminUpload), f.goneID).Scan(&asAdmin); err != nil || asAdmin != 1 {
		t.Fatalf("fixture: the admin upload was recorded with uploader_admin=%d (err=%v)", asAdmin, err)
	}
	for _, row := range []struct {
		id   int
		uid  int64
		file string
	}{{101, f.goneID, f.gonePrivate}, {102, f.goneID, f.gonePrivate2}, {103, f.goneID, f.gonePublic}, {104, keptID, f.keptPrivate}, {105, keptID, f.goneAdminUpload}} {
		if _, err := app.DB.Exec(`INSERT INTO docs (id, user_id, file_url) VALUES (?, ?, ?)`, row.id, row.uid, row.file); err != nil {
			t.Fatal(err)
		}
	}
	var code int
	if code, f.goneSigned = mintSignedURL(t, mux, goneTok, "path="+f.gonePrivate+"&record_table=docs&record_id=101"); code != http.StatusOK {
		t.Fatalf("sign gone's file: %d", code)
	}
	if code, f.keptSigned = mintSignedURL(t, mux, keptTok, "path="+f.keptPrivate+"&record_table=docs&record_id=104"); code != http.StatusOK {
		t.Fatalf("sign kept's file: %d", code)
	}
	if code, f.adminUploadSigned = mintSignedURL(t, mux, keptTok, "path="+f.goneAdminUpload+"&record_table=docs&record_id=105"); code != http.StatusOK {
		t.Fatalf("sign the admin upload on kept's record: %d", code)
	}
	for name, signed := range map[string]string{"gone": f.goneSigned, "kept": f.keptSigned, "admin upload": f.adminUploadSigned} {
		if rec := crudScopeRequest(t, mux, http.MethodGet, signed, "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "%PDF-1.4") {
			t.Fatalf("%s's signed URL before the delete: %d", name, rec.Code)
		}
	}
	f.docsBefore = f.count(t, `SELECT COUNT(*) FROM docs WHERE id BETWEEN 101 AND 105 AND file_url LIKE '/uploads/%'`)
	f.ownershipBeforeCount = f.count(t, `SELECT COUNT(*) FROM _benmore_upload_owners`)
	if f.docsBefore != 5 || f.ownershipBeforeCount != 4 {
		t.Fatalf("fixture: %d docs rows, %d ownership rows; want 5 and 4 (a public upload records no owner)", f.docsBefore, f.ownershipBeforeCount)
	}
	return f
}

func (f *accountUploadsFixture) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := f.app.DB.QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *accountUploadsFixture) stored(t *testing.T, ref string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(f.app.Dir, filepath.FromSlash(strings.TrimPrefix(ref, "/"))))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func (f *accountUploadsFixture) get(t *testing.T, path string) int {
	t.Helper()
	return crudScopeRequest(t, f.mux, http.MethodGet, path, "", nil).Code
}
