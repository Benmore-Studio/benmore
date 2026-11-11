//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The documented owner-scoped flows: the SQL step returns only the caller's
// own row, and the step serves or deletes the reference stored in it.
const ownerServeFlow = `on:
  request:
    method: GET
    path: /api/docs/:id/file
    auth: required
jobs:
  file:
    steps:
      - id: doc
        run: sql
        with:
          query: SELECT id, file_url FROM docs WHERE id = :id AND user_id = :user_id
      - run: serve_file
        with:
          path: ${{ steps.doc.outputs.file_url }}
`

const ownerDeleteFlow = `on:
  request:
    method: POST
    path: /api/docs/:id/remove
    auth: required
jobs:
  remove:
    steps:
      - id: doc
        run: sql
        with:
          query: SELECT id, file_url FROM docs WHERE id = :id AND user_id = :user_id
      - run: delete_upload
        with:
          path: ${{ steps.doc.outputs.file_url }}
      - run: respond
        with:
          json: { ok: true }
`

// The same flows naming the row that owns the file, which turns on the
// uploader rule (without `record:` it is advisory: logged, not refused).
var (
	ownerServeFlowRecord  = withDocRecord(ownerServeFlow, "serve_file")
	ownerDeleteFlowRecord = withDocRecord(ownerDeleteFlow, "delete_upload")
)

func withDocRecord(flow, run string) string {
	step := "      - run: " + run + "\n        with:\n          path: ${{ steps.doc.outputs.file_url }}\n"
	return strings.Replace(flow, step, step+"          record: { table: docs, id: \"${{ steps.doc.outputs.id }}\" }\n", 1)
}

func runOwnerFlow(t *testing.T, app *App, yaml, method, target, id, token string) *httptest.ResponseRecorder {
	t.Helper()
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "owner.yaml"), []byte(yaml))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v", err)
	}
	f := flows[0]
	req := httptest.NewRequest(method, target, nil)
	req.SetPathValue("id", id)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	executeFlowHTTP(app, &f, rec, req)
	return rec
}

// uploadAs posts one file to /api/_upload and returns the response.
func uploadAs(t *testing.T, mux http.Handler, token, kind, name string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if kind != "" {
		if err := mw.WriteField("kind", kind); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(body)
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/_upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func uploadedPath(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	p, _ := out["path"].(string)
	return p
}

// createDocAs stores a row of the caller's own through auto-CRUD.
func createDocAs(t *testing.T, mux *http.ServeMux, token, fileURL string) string {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/docs", token, map[string]any{"file_url": fileURL})
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("create doc: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	mustDecodeBody(t, rec, &out)
	id, ok := out["id"].(float64)
	if !ok {
		t.Fatalf("create doc returned no id: %s", rec.Body.String())
	}
	return strconv.FormatInt(int64(id), 10)
}

// Finding r1104-media #1: a user who learns another user's private
// reference stores it in a row of their own through auto-CRUD; the
// owner-scoped flow then returns that row, and serve_file served the
// other user's bytes. The file must be vouched for like a signed URL's.
func TestServeFileRefusesAnotherUsersCopiedPrivateReference(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	mustExec(t, app.DB, `DELETE FROM docs`)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")

	bobBytes := []byte("%PDF-1.4 bob's private statement")
	bobPath := uploadedPath(t, uploadAs(t, mux, bob, "private", "statement.pdf", bobBytes))
	if !strings.HasPrefix(bobPath, "/uploads/private/") {
		t.Fatalf("private upload stored at %q", bobPath)
	}
	bobDoc := createDocAs(t, mux, bob, bobPath)
	aliceDoc := createDocAs(t, mux, alice, bobPath) // the copied reference

	rec := runOwnerFlow(t, app, ownerServeFlowRecord, http.MethodGet, "/api/docs/"+aliceDoc+"/file", aliceDoc, alice)
	if rec.Code != http.StatusForbidden || bytes.Contains(rec.Body.Bytes(), bobBytes) {
		t.Fatalf("alice read bob's file through her own row: %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "record") {
		t.Fatalf("refusal does not say why the record does not vouch: %s", rec.Body.String())
	}

	// Without `record:` the rule is advisory for now: the flow's SQL stays
	// the gate, so the copied reference is still served (and logged).
	rec = runOwnerFlow(t, app, ownerServeFlow, http.MethodGet, "/api/docs/"+aliceDoc+"/file", aliceDoc, alice)
	if rec.Code != http.StatusOK {
		t.Fatalf("a flow without record: refused a file the caller did not upload: %d %s", rec.Code, rec.Body.String())
	}

	// The uploader's own row still serves.
	rec = runOwnerFlow(t, app, ownerServeFlowRecord, http.MethodGet, "/api/docs/"+bobDoc+"/file", bobDoc, bob)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), bobBytes) {
		t.Fatalf("bob could not read his own file: %d %q", rec.Code, rec.Body.String())
	}

	// So does alice's own upload.
	aliceBytes := []byte("%PDF-1.4 alice's own")
	alicePath := uploadedPath(t, uploadAs(t, mux, alice, "private", "own.pdf", aliceBytes))
	aliceOwn := createDocAs(t, mux, alice, alicePath)
	rec = runOwnerFlow(t, app, ownerServeFlowRecord, http.MethodGet, "/api/docs/"+aliceOwn+"/file", aliceOwn, alice)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), aliceBytes) {
		t.Fatalf("alice could not read her own upload: %d %q", rec.Code, rec.Body.String())
	}

	// A file uploaded before ownership was recorded keeps the reference rule.
	mustExec(t, app.DB, `DELETE FROM _benmore_upload_owners WHERE path = '`+uploadRelPath(bobPath)+`'`)
	rec = runOwnerFlow(t, app, ownerServeFlowRecord, http.MethodGet, "/api/docs/"+aliceDoc+"/file", aliceDoc, alice)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy private file (no ownership row) lost serve_file: %d %s", rec.Code, rec.Body.String())
	}
}

// The same copied reference must not let alice delete bob's file.
func TestDeleteUploadRefusesAnotherUsersCopiedPrivateReference(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	mustExec(t, app.DB, `DELETE FROM docs`)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")

	bobPath := uploadedPath(t, uploadAs(t, mux, bob, "private", "statement.pdf", []byte("%PDF-1.4 bob")))
	bobFile := filepath.Join(app.Dir, filepath.FromSlash(strings.TrimPrefix(bobPath, "/")))
	bobDoc := createDocAs(t, mux, bob, bobPath)
	aliceDoc := createDocAs(t, mux, alice, bobPath)

	rec := runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+aliceDoc+"/remove", aliceDoc, alice)
	if rec.Code < 400 {
		t.Fatalf("alice's delete of bob's file reported success: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(bobFile); err != nil {
		t.Fatalf("alice deleted bob's file through her own row: %v", err)
	}

	rec = runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+bobDoc+"/remove", bobDoc, bob)
	if rec.Code != http.StatusOK {
		t.Fatalf("bob could not delete his own file: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(bobFile); !os.IsNotExist(err) {
		t.Fatalf("bob's own delete left the file: %v", err)
	}
}

// tenantUploadApp is a tenant-keyed app: files rows carry org_id.
func tenantUploadApp(t *testing.T) (*App, *http.ServeMux, func()) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE _benmore_permissions (resource_type TEXT, resource_id INTEGER, grant_type TEXT, grantee_id TEXT, permission TEXT, expires_at TEXT)`)
	mustExec(t, db, `CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, org_id TEXT, file_url TEXT)`)
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group:           &GroupConfig{Key: "org_id"},
		Access:          &AccessConfig{rules: map[string]map[AccessOp]string{}},
		Tables: []Table{
			{Name: "files", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "org_id"}, {Name: "file_url"}}},
		},
	}
	return app, buildAppMux(app, true, "http://localhost"), app.Shutdown
}

// A tenant's shared file: a teammate (not the uploader) reaches it through
// the tenant's row named as `record:`; a user of another tenant who copies
// the reference into a row of their own tenant does not, for reading or
// deleting, and without `record:` only the uploader passes.
func TestPrivateUploadFlowRecordVouchesWithinTenant(t *testing.T) {
	app, mux, cleanup := tenantUploadApp(t)
	defer cleanup()
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "org-a", "")
	carol := createCrudScopeSession(t, app, "carol@example.com", "user", "org-a", "")
	mallory := createCrudScopeSession(t, app, "mallory@example.com", "user", "org-b", "")

	body := []byte("%PDF-1.4 org-a board minutes")
	ref := uploadedPath(t, uploadAs(t, mux, bob, "private", "minutes.pdf", body))
	onDisk := filepath.Join(app.Dir, filepath.FromSlash(strings.TrimPrefix(ref, "/")))
	mustExec(t, app.DB, `INSERT INTO files (id, user_id, org_id, file_url) VALUES (1, 1, 'org-a', '`+ref+`')`)
	mustExec(t, app.DB, `INSERT INTO files (id, user_id, org_id, file_url) VALUES (2, 3, 'org-b', '`+ref+`')`)

	const tenantRead = `on:
  request:
    method: GET
    path: /api/files/:id
    auth: required
jobs:
  file:
    steps:
      - id: f
        run: sql
        with:
          query: SELECT id, file_url FROM files WHERE id = :id AND org_id = :user_group_id
      - run: serve_file
        with:
          path: ${{ steps.f.outputs.file_url }}
          record: { table: files, id: "${{ steps.f.outputs.id }}" }
`
	rec := runOwnerFlow(t, app, tenantRead, http.MethodGet, "/api/files/1", "1", carol)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatalf("teammate could not read the tenant's file through its row: %d %q", rec.Code, rec.Body.String())
	}
	rec = runOwnerFlow(t, app, tenantRead, http.MethodGet, "/api/files/2", "2", mallory)
	if rec.Code != http.StatusForbidden || bytes.Contains(rec.Body.Bytes(), body) {
		t.Fatalf("another tenant read the file through a copied reference: %d %q", rec.Code, rec.Body.String())
	}

	// Without record: the uploader rule is advisory (logged), so the
	// teammate is still served through the flow's own tenant-scoped SQL.
	noRecord := strings.Replace(tenantRead, "          record: { table: files, id: \"${{ steps.f.outputs.id }}\" }\n", "", 1)
	if rec = runOwnerFlow(t, app, noRecord, http.MethodGet, "/api/files/1", "1", carol); rec.Code != http.StatusOK {
		t.Fatalf("teammate refused without naming the record: %d %q", rec.Code, rec.Body.String())
	}
	if rec = runOwnerFlow(t, app, noRecord, http.MethodGet, "/api/files/1", "1", bob); rec.Code != http.StatusOK {
		t.Fatalf("uploader could not read without a record: %d %q", rec.Code, rec.Body.String())
	}

	// A record that does not reference the file vouches for nothing.
	mustExec(t, app.DB, `INSERT INTO files (id, user_id, org_id, file_url) VALUES (3, 1, 'org-a', '/uploads/private/other.pdf')`)
	wrongRecord := strings.Replace(tenantRead, `id: "${{ steps.f.outputs.id }}"`, `id: "3"`, 1)
	if rec = runOwnerFlow(t, app, wrongRecord, http.MethodGet, "/api/files/1", "1", carol); rec.Code != http.StatusForbidden {
		t.Fatalf("a record not referencing the file vouched for it: %d %q", rec.Code, rec.Body.String())
	}

	tenantDelete := strings.NewReplacer(
		"method: GET", "method: POST",
		"      - run: serve_file\n        with:\n          path:", "      - run: delete_upload\n        with:\n          path:",
	).Replace(tenantRead) + "      - run: respond\n        with:\n          json: { ok: true }\n"
	rec = runOwnerFlow(t, app, tenantDelete, http.MethodPost, "/api/files/2", "2", mallory)
	if rec.Code < 400 {
		t.Fatalf("another tenant's delete reported success: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); err != nil {
		t.Fatalf("another tenant deleted the file through a copied reference: %v", err)
	}
	if rec = runOwnerFlow(t, app, tenantDelete, http.MethodPost, "/api/files/1", "1", carol); rec.Code != http.StatusOK {
		t.Fatalf("teammate could not delete through the tenant's row: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); !os.IsNotExist(err) {
		t.Fatalf("the tenant's delete left the file: %v", err)
	}
}

// On the media CDN the copied reference is the CDN URL, and serve_file
// answered with a signed redirect to it.
func TestServeFileCDNRefusesAnotherUsersCopiedPrivateReference(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	app, _, cleanup := signedURLApp(t)
	defer cleanup()
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	cdnURL := "https://" + cfg.CDNDomain + "/private/" + appMediaPrefix(app) + "/uploads/private/bob.pdf"
	EnsureUploadOwnersTable(app.DB)
	mustExec(t, app.DB, `INSERT INTO _benmore_upload_owners (path, user_id) VALUES ('private/bob.pdf', 2)`)
	mustExec(t, app.DB, `DELETE FROM docs`)
	mustExec(t, app.DB, `INSERT INTO docs (id, user_id, file_url) VALUES (10, 2, '`+cdnURL+`'), (11, 1, '`+cdnURL+`')`)

	rec := runOwnerFlow(t, app, ownerServeFlowRecord, http.MethodGet, "/api/docs/11/file", "11", alice)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Location") != "" {
		t.Fatalf("alice got a signed link to bob's CDN file: %d Location=%q", rec.Code, rec.Header().Get("Location"))
	}
	rec = runOwnerFlow(t, app, ownerServeFlowRecord, http.MethodGet, "/api/docs/10/file", "10", bob)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), cdnURL+"?") {
		t.Fatalf("bob's own CDN file = %d %q, want a signed redirect", rec.Code, rec.Header().Get("Location"))
	}
}

// Finding r1104-media #9: serve_file accepted private references in
// spellings delete_upload refuses (#824); a fragment even carried the
// signature into the fragment, so the CDN answered 403.
func TestServeFileRefusesNonCanonicalPrivateReference(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads", "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "uploads", "private", "x.pdf"), []byte("%PDF-1.4 x"), 0o600); err != nil {
		t.Fatal(err)
	}
	serve := func(path string) *httptest.ResponseRecorder {
		step := FlowStep{Type: "serve_file", ServeFile: &FlowServeFile{Path: path}}
		rec := httptest.NewRecorder()
		ctx := &FlowContext{App: app, Request: httptest.NewRequest(http.MethodGet, "/f", nil), Writer: rec, Data: map[string]any{}, Params: map[string]string{}}
		if err := executeStep(ctx, &step); err != nil {
			t.Fatalf("serve %q: %v", path, err)
		}
		return rec
	}
	for _, bad := range []string{
		"/uploads/private/x.pdf?x=1",
		" /uploads/private/x.pdf",
		"/uploads/private/x.pdf#f",
		"/uploads/PRIVATE/x.pdf",
		"/uploads/private//x.pdf",
	} {
		if rec := serve(bad); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "%PDF") {
			t.Errorf("serve_file %q = %d %q, want 404", bad, rec.Code, rec.Body.String())
		}
	}
	if rec := serve("/uploads/private/x.pdf"); rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.4 x" {
		t.Fatalf("canonical reference = %d %q", rec.Code, rec.Body.String())
	}
	// A public path that resolves into private/ through an alias is not the
	// private reference (the ownership check would never see it).
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads", "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "private", "x.pdf"), filepath.Join(app.Dir, "uploads", "files", "alias.pdf")); err != nil {
		t.Fatal(err)
	}
	if rec := serve("/uploads/files/alias.pdf"); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "%PDF") {
		t.Fatalf("alias into private/ = %d %q, want 404", rec.Code, rec.Body.String())
	}

	// On the CDN: no redirect for a spelling the stored URL never has.
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	base := "https://" + cfg.CDNDomain + "/private/" + appMediaPrefix(app) + "/uploads/private/cdn.pdf"
	for _, bad := range []string{base + "?x=1", base + "#f", " " + base} {
		if rec := serve(bad); rec.Code != http.StatusNotFound || rec.Header().Get("Location") != "" {
			t.Errorf("serve_file %q = %d Location=%q, want 404", bad, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := serve(base); rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), base+"?") {
		t.Fatalf("canonical CDN reference = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// Finding r1104-media #7: `filename:` went out Go-quoted with any
// extension. It now follows run: proxy's rule: a safe name whose extension
// is the served file's own.
func TestServeFileDownloadNameFollowsServedType(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads", "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "uploads", "files", "rows.csv"), []byte("a,b\n1,2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ disposition, filename, want string }{
		{"attachment", `export.html`, "export.csv"},
		{"attachment", `a"; filename*=UTF-8''evil.html`, "a__ filename__UTF-8__evil.csv"},
		{"attachment", `../../etc/passwd`, "passwd.csv"},
		{"attachment", `Q4 report.csv`, "Q4 report.csv"},
		{"attachment", ``, "rows.csv"},
		{"inline", `view.html`, "view.csv"},
	} {
		step := FlowStep{Type: "serve_file", ServeFile: &FlowServeFile{Path: "/uploads/files/rows.csv", Disposition: tc.disposition, Filename: tc.filename}}
		rec := httptest.NewRecorder()
		ctx := &FlowContext{App: app, Request: httptest.NewRequest(http.MethodGet, "/f", nil), Writer: rec, Data: map[string]any{}, Params: map[string]string{}}
		if err := executeStep(ctx, &step); err != nil {
			t.Fatal(err)
		}
		cd := rec.Header().Get("Content-Disposition")
		kind, params, err := mime.ParseMediaType(cd)
		if err != nil || kind != tc.disposition || params["filename"] != tc.want || strings.Contains(cd, "filename*") {
			t.Errorf("filename %q: Content-Disposition = %q (parsed %q %v), want %s with filename %q", tc.filename, cd, kind, params, tc.disposition, tc.want)
		}
	}
}

// The streamed CDN download follows the same rule.
func TestServeFileCDNDownloadNameFollowsServedType(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	app, cleanup := newTestApp(t)
	defer cleanup()
	key := "private/" + appMediaPrefix(app) + "/uploads/private/report.pdf"
	cdn := startFakeMediaCDN(t, key, []byte("%PDF-1.4"))
	cfg := testMediaConfig(t)
	cfg.CDNDomain = strings.TrimPrefix(cdn.srv.URL, "https://")
	withPlatformMedia(t, cfg)
	step := FlowStep{Type: "serve_file", ServeFile: &FlowServeFile{Path: "/uploads/private/report.pdf", Disposition: "attachment", Filename: `invoice.html"; x=y`}}
	rec := httptest.NewRecorder()
	ctx := &FlowContext{App: app, Request: httptest.NewRequest(http.MethodGet, "/f", nil), Writer: rec, Data: map[string]any{}, Params: map[string]string{}}
	if err := executeStep(ctx, &step); err != nil {
		t.Fatal(err)
	}
	kind, params, err := mime.ParseMediaType(rec.Header().Get("Content-Disposition"))
	if rec.Code != http.StatusOK || err != nil || kind != "attachment" || params["filename"] != "invoice.html__ x_y.pdf" || len(params) != 1 {
		t.Fatalf("download = %d, Content-Disposition %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}
}

// Finding r1104-media #8: kind=Private stored the file PUBLIC (a folder
// named Private). The tier names are case-insensitive now, and a kind that
// reads as private but is not is refused instead of stored public.
func TestUploadKindPrivateIsCaseInsensitive(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	tok := createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "")
	for _, kind := range []string{"Private", "PRIVATE", "private"} {
		p := uploadedPath(t, uploadAs(t, mux, tok, kind, "a.pdf", []byte("%PDF-1.4 a")))
		if !strings.HasPrefix(p, "/uploads/private/") {
			t.Errorf("kind=%s stored at %q, want the private tier", kind, p)
			continue
		}
		var n int
		app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_upload_owners WHERE path = ?`, uploadRelPath(p)).Scan(&n)
		if n != 1 {
			t.Errorf("kind=%s recorded no uploader", kind)
		}
	}
	if p := uploadedPath(t, uploadAs(t, mux, tok, "Public", "a.png", []byte("\x89PNG\r\n\x1a\n"))); !strings.HasPrefix(p, "/uploads/public/") {
		t.Errorf("kind=Public stored at %q", p)
	}
	if p := uploadedPath(t, uploadAs(t, mux, tok, "avatars", "a.png", []byte("\x89PNG\r\n\x1a\n"))); !strings.HasPrefix(p, "/uploads/avatars/") {
		t.Errorf("kind=avatars stored at %q", p)
	}
	for _, kind := range []string{"private-docs", "my_private", "Privates"} {
		rec := uploadAs(t, mux, tok, kind, "a.pdf", []byte("%PDF-1.4 a"))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "kind=private") {
			t.Errorf("kind=%s = %d %s, want 400 naming kind=private", kind, rec.Code, rec.Body.String())
		}
	}
	entries, _ := os.ReadDir(filepath.Join(app.Dir, "uploads"))
	for _, e := range entries {
		if e.Name() != "private" && strings.Contains(strings.ToLower(e.Name()), "private") {
			t.Errorf("an upload landed in public folder %q", e.Name())
		}
	}
}

// `record:` is checked when the file is written, and a public flow that
// serves or deletes without one is flagged.
func TestUploadRecordWriteGateAndCheckWarning(t *testing.T) {
	base := `on:
  request:
    method: GET
    path: /api/f/:id
    auth: %s
jobs:
  f:
    steps:
      - id: f
        run: sql
        with:
          query: SELECT id, file_url FROM files WHERE id = :id
      - run: %s
        with:
          path: ${{ steps.f.outputs.file_url }}
%s`
	render := func(auth, run, record string) string {
		out := strings.Replace(base, "%s", auth, 1)
		out = strings.Replace(out, "%s", run, 1)
		return strings.Replace(out, "%s", record, 1)
	}
	good := "          record: { table: files, id: \"${{ steps.f.outputs.id }}\" }\n"
	for _, run := range []string{"serve_file", "delete_upload"} {
		if msg := validateFlowsYAML(render("required", run, good)); msg != "" {
			t.Errorf("%s with a record refused: %s", run, msg)
		}
		for _, bad := range []string{
			"          record: files\n",
			"          record: { table: files }\n",
			"          record: { id: \"1\" }\n",
			"          record: { table: \"${{ params.t }}\", id: \"1\" }\n",
			"          record: { table: files, id: \"1\", column: file_url }\n",
		} {
			if msg := validateFlowsYAML(render("required", run, bad)); !strings.Contains(msg, "record") {
				t.Errorf("%s %q passed the write gate: %q", run, strings.TrimSpace(bad), msg)
			}
		}
		if w := ghaPrivateUploadRecordWarnings(render("none", run, "")); len(w) != 1 || !strings.Contains(w[0], "record:") {
			t.Errorf("%s in a public flow without record: warnings = %q", run, w)
		}
		for _, quiet := range []string{render("none", run, good), render("required", run, "")} {
			if w := ghaPrivateUploadRecordWarnings(quiet); len(w) != 0 {
				t.Errorf("%s: unexpected warnings %q", run, w)
			}
		}
	}
}
