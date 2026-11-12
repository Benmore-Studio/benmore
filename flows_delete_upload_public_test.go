//go:build !cli

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// publicUploadFile is where a local public reference (/uploads/<kind>/<name>)
// lives on disk.
func publicUploadFile(app *App, ref string) string {
	return filepath.Join(app.Dir, filepath.FromSlash(strings.TrimPrefix(ref, "/")))
}

// A public upload (every file of a multipart create, /api/_upload without
// kind=private) can be deleted by the app: `run: delete_upload` with `record:`
// naming the row that owns it. Without the proof, and through a row that only
// copied the reference, nothing is deleted.
func TestDeleteUploadDeletesOwnPublicFileWithRecord(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	mustExec(t, app.DB, `DELETE FROM docs`)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")

	ref := uploadedPath(t, uploadAs(t, mux, bob, "avatars", "me.png", []byte("\x89PNG\r\n\x1a\n bob")))
	if !strings.HasPrefix(ref, "/uploads/avatars/") {
		t.Fatalf("public upload stored at %q", ref)
	}
	onDisk := publicUploadFile(app, ref)
	bobDoc := createDocAs(t, mux, bob, ref)
	aliceDoc := createDocAs(t, mux, alice, ref) // the copied reference

	// Refused without proof: the flow's own SQL is not enough for a public file.
	rec := runOwnerFlow(t, app, ownerDeleteFlow, http.MethodPost, "/api/docs/"+bobDoc+"/remove", bobDoc, bob)
	if rec.Code < 400 {
		t.Fatalf("a public file was deleted without `record:`: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); err != nil {
		t.Fatalf("delete without `record:` removed the file: %v", err)
	}

	// Refused through a row that only copied the reference.
	rec = runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+aliceDoc+"/remove", aliceDoc, alice)
	if rec.Code < 400 {
		t.Fatalf("alice's delete of bob's public file reported success: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); err != nil {
		t.Fatalf("alice deleted bob's public file through her own row: %v", err)
	}

	// Deleted with proof: the uploader's own row.
	rec = runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+bobDoc+"/remove", bobDoc, bob)
	if rec.Code != http.StatusOK {
		t.Fatalf("bob could not delete his own public file: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); !os.IsNotExist(err) {
		t.Fatalf("bob's delete left the public file: %v", err)
	}
	// A second run finds nothing to delete and still succeeds (safe retries).
	rec = runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+bobDoc+"/remove", bobDoc, bob)
	if rec.Code != http.StatusOK {
		t.Fatalf("repeated delete of a missing public file: %d %s", rec.Code, rec.Body.String())
	}
}

// The uploader of a public file is recorded apart from the private records
// (app SQL reads _benmore_upload_owners as "private files this user
// uploaded"), and the record rule is the private one: a row that does not
// reference the file vouches for nothing, a tenant's row vouches for a
// teammate's upload, and a file with no uploader record passes on the
// reference alone.
func TestPublicUploadRecordRuleMatchesPrivate(t *testing.T) {
	app, mux, cleanup := tenantUploadApp(t)
	defer cleanup()
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "org-a", "")
	carol := createCrudScopeSession(t, app, "carol@example.com", "user", "org-a", "")
	mallory := createCrudScopeSession(t, app, "mallory@example.com", "user", "org-b", "")

	ref := uploadedPath(t, uploadAs(t, mux, bob, "logos", "logo.png", []byte("\x89PNG\r\n\x1a\n org-a")))
	onDisk := publicUploadFile(app, ref)
	var private, public int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_upload_owners`).Scan(&private)
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_public_upload_owners WHERE path = ? AND user_id = 1 AND group_id = 'org-a'`, uploadRelPath(ref)).Scan(&public)
	if private != 0 || public != 1 {
		t.Fatalf("public upload recorded private=%d public=%d uploader rows, want 0 and 1", private, public)
	}
	mustExec(t, app.DB, `INSERT INTO files (id, user_id, org_id, file_url) VALUES (1, 1, 'org-a', '`+ref+`')`)
	mustExec(t, app.DB, `INSERT INTO files (id, user_id, org_id, file_url) VALUES (2, 3, 'org-b', '`+ref+`')`)
	mustExec(t, app.DB, `INSERT INTO files (id, user_id, org_id, file_url) VALUES (3, 1, 'org-a', '/uploads/logos/other.png')`)

	const tenantDelete = `on:
  request:
    method: POST
    path: /api/files/:id
    auth: required
jobs:
  file:
    steps:
      - id: f
        run: sql
        with:
          query: SELECT id, file_url FROM files WHERE id = :id AND org_id = :user_group_id
      - run: delete_upload
        with:
          path: ${{ steps.f.outputs.file_url }}
          record: { table: files, id: "${{ steps.f.outputs.id }}" }
      - run: respond
        with:
          json: { ok: true }
`
	rec := runOwnerFlow(t, app, tenantDelete, http.MethodPost, "/api/files/2", "2", mallory)
	if rec.Code < 400 {
		t.Fatalf("another tenant's delete reported success: %d %s", rec.Code, rec.Body.String())
	}
	wrongRecord := strings.Replace(tenantDelete, `id: "${{ steps.f.outputs.id }}"`, `id: "3"`, 1)
	if rec = runOwnerFlow(t, app, wrongRecord, http.MethodPost, "/api/files/1", "1", carol); rec.Code < 400 {
		t.Fatalf("a record not referencing the file vouched for it: %d %s", rec.Code, rec.Body.String())
	}
	noTable := strings.Replace(tenantDelete, "table: files", "table: nosuchtable", 1)
	if rec = runOwnerFlow(t, app, noTable, http.MethodPost, "/api/files/1", "1", carol); rec.Code < 400 {
		t.Fatalf("a record naming no table of the app vouched: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); err != nil {
		t.Fatalf("a refused delete removed the tenant's public file: %v", err)
	}
	if rec = runOwnerFlow(t, app, tenantDelete, http.MethodPost, "/api/files/1", "1", carol); rec.Code != http.StatusOK {
		t.Fatalf("teammate could not delete through the tenant's row: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); !os.IsNotExist(err) {
		t.Fatalf("the tenant's delete left the file: %v", err)
	}

	// A public file with no uploader record (stored before uploaders were
	// recorded, or written by a server-side step): the row reference vouches.
	legacy := filepath.Join(app.Dir, "uploads", "logos", "legacy.png")
	if err := os.WriteFile(legacy, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, `INSERT INTO files (id, user_id, org_id, file_url) VALUES (4, 3, 'org-b', '/uploads/logos/legacy.png')`)
	if rec = runOwnerFlow(t, app, tenantDelete, http.MethodPost, "/api/files/4", "4", mallory); rec.Code != http.StatusOK {
		t.Fatalf("a public file with no uploader record was refused: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("the legacy public file was not deleted: %v", err)
	}
}

// A public reference is accepted only in the spelling an upload produced,
// under this app's own prefix on the selected backend.
func TestPublicUploadReferenceMatchesOwnPrefixOnly(t *testing.T) {
	app := &App{Dir: filepath.Join(t.TempDir(), "current-app")}
	cdn := &CDNStorage{Prefix: "current-app", CDNDomain: "cdn.example"}
	s3 := &S3Storage{Endpoint: "https://objects.example", Bucket: "bucket"}
	local := &LocalStorage{Dir: app.Dir}
	cdnBase := "https://cdn.example/public/" + appMediaPrefix(app)
	const want = "uploads/avatars/a.png"

	for _, tt := range []struct {
		name    string
		backend StorageBackend
		raw     string
	}{
		{"cdn stored url", cdn, cdnBase + "/uploads/avatars/a.png"},
		{"s3 stored url", s3, "https://objects.example/bucket/uploads/avatars/a.png"},
		{"local served path", local, "/uploads/avatars/a.png"},
		{"logical path", local, "uploads/avatars/a.png"},
		{"logical path on the cdn", cdn, "uploads/avatars/a.png"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := publicUploadPath(app, tt.backend, tt.raw); err != nil || got != want {
				t.Fatalf("publicUploadPath(%q) = %q, %v; want %q", tt.raw, got, err, want)
			}
		})
	}

	for _, tt := range []struct {
		name    string
		backend StorageBackend
		raw     string
	}{
		{"cdn another app's prefix", cdn, "https://cdn.example/public/other-app/uploads/avatars/a.png"},
		{"cdn prefix that only starts like this app's", cdn, cdnBase + "-dev/uploads/avatars/a.png"},
		{"cdn private tier", cdn, "https://cdn.example/private/" + appMediaPrefix(app) + "/uploads/avatars/a.png"},
		{"cdn public tier, private folder", cdn, cdnBase + "/uploads/private/a.pdf"},
		{"cdn unknown tier", cdn, "https://cdn.example/shared/" + appMediaPrefix(app) + "/uploads/avatars/a.png"},
		{"cdn unknown host", cdn, "https://files.example/public/" + appMediaPrefix(app) + "/uploads/avatars/a.png"},
		{"cdn host suffix", cdn, "https://cdn.example.evil.test/public/" + appMediaPrefix(app) + "/uploads/avatars/a.png"},
		{"cdn userinfo", cdn, "https://cdn.example@files.example/public/" + appMediaPrefix(app) + "/uploads/avatars/a.png"},
		{"cdn explicit port", cdn, "https://cdn.example:443/public/" + appMediaPrefix(app) + "/uploads/avatars/a.png"},
		{"cdn wrong scheme", cdn, "http://cdn.example/public/" + appMediaPrefix(app) + "/uploads/avatars/a.png"},
		{"cdn uppercase scheme", cdn, "HTTPS://cdn.example/public/" + appMediaPrefix(app) + "/uploads/avatars/a.png"},
		{"cdn query", cdn, cdnBase + "/uploads/avatars/a.png?x=1"},
		{"cdn fragment", cdn, cdnBase + "/uploads/avatars/a.png#f"},
		{"cdn encoded slash", cdn, cdnBase + "/uploads/avatars%2fa.png"},
		{"cdn encoded traversal", cdn, cdnBase + "/uploads/%2e%2e/%2e%2e/other-app/uploads/a.png"},
		{"cdn traversal", cdn, cdnBase + "/uploads/../../other-app/uploads/a.png"},
		{"cdn dot segment", cdn, cdnBase + "/uploads/./avatars/a.png"},
		{"cdn backslash", cdn, cdnBase + "/uploads\\avatars\\a.png"},
		{"cdn doubled slash after prefix", cdn, cdnBase + "//uploads/avatars/a.png"},
		{"cdn doubled slash in the key", cdn, cdnBase + "/uploads/avatars//a.png"},
		{"cdn trailing slash", cdn, cdnBase + "/uploads/avatars/a.png/"},
		{"cdn key outside uploads", cdn, cdnBase + "/static/app.js"},
		{"s3 another bucket", s3, "https://objects.example/other/uploads/avatars/a.png"},
		{"s3 unknown host", s3, "https://files.example/bucket/uploads/avatars/a.png"},
		{"s3 query", s3, "https://objects.example/bucket/uploads/avatars/a.png?x=1"},
		{"s3 traversal", s3, "https://objects.example/bucket/uploads/../backups/a.db"},
		{"s3 doubled slash", s3, "https://objects.example/bucket//uploads/avatars/a.png"},
		{"s3 uppercase scheme", s3, "HTTPS://objects.example/bucket/uploads/avatars/a.png"},
		{"s3 key outside uploads", s3, "https://objects.example/bucket/backups/a.db"},
		{"local url", local, "https://cdn.example/public/current-app/uploads/avatars/a.png"},
		{"empty", local, ""},
		{"leading space", local, " uploads/avatars/a.png"},
		{"trailing space", local, "uploads/avatars/a.png "},
		{"outside uploads", local, "static/app.js"},
		{"app database", local, "data.db"},
		{"no uploads prefix", local, "avatars/a.png"},
		{"uploads alone", local, "uploads/"},
		{"doubled leading slash", local, "//uploads/avatars/a.png"},
		{"doubled slash", local, "uploads//avatars/a.png"},
		{"dot segment", local, "uploads/./avatars/a.png"},
		{"traversal", local, "uploads/../data.db"},
		{"traversal back in", local, "uploads/avatars/../../uploads/private/a.pdf"},
		{"encoded traversal", local, "uploads/%2e%2e/data.db"},
		{"backslash", local, "uploads\\avatars\\a.png"},
		{"nul", local, "uploads/avatars/a\x00.png"},
		{"query", local, "uploads/avatars/a.png?download=1"},
		{"fragment", local, "uploads/avatars/a.png#f"},
		{"private folder", local, "uploads/private/a.pdf"},
		{"private folder in another case", local, "uploads/PRIVATE/a.pdf"},
		{"nested private folder", local, "uploads/docs/private/a.pdf"},
		{"nested private folder in another case", local, "uploads/docs/Private/a.pdf"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := publicUploadPath(app, tt.backend, tt.raw); err == nil {
				t.Fatalf("publicUploadPath(%q) accepted it as %q", tt.raw, got)
			}
		})
	}
}

// Every refused form stops before the ownership proof is asked and before
// the storage backend is touched; the canonical reference reaches both.
func TestDeleteUploadRefusesMalformedPublicReferenceBeforeProofAndStorage(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	file := filepath.Join(app.Dir, "uploads", "avatars", "keep.png")
	private := filepath.Join(app.Dir, "uploads", "private", "keep.pdf")
	for _, f := range []string{file, private} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	asked := 0
	allow := func(StorageBackend, string, bool) error { asked++; return nil }

	for _, raw := range []string{
		"uploads/avatars/../avatars/keep.png",
		"uploads/avatars/%6beep.png",
		"uploads\\avatars\\keep.png",
		"uploads/avatars/keep.png?x=1",
		"uploads/avatars/keep.png#f",
		"uploads//avatars/keep.png",
		"//uploads/avatars/keep.png",
		"avatars/keep.png",
		"https://files.example/uploads/avatars/keep.png",
		"https://cdn.example/public/" + appMediaPrefix(app) + "/uploads/avatars/keep.png",
		"uploads/PRIVATE/keep.pdf",
		"uploads/Private/keep.pdf",
		"uploads/avatars/../private/keep.pdf",
	} {
		if err := deleteUploadAuthorized(app, raw, allow); err == nil {
			t.Errorf("deleteUploadAuthorized(%q) unexpectedly succeeded", raw)
		}
	}
	if asked != 0 {
		t.Fatalf("a refused reference reached the ownership proof %d time(s)", asked)
	}
	for _, f := range []string{file, private} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("a refused reference touched %s: %v", f, err)
		}
	}

	// The proof's refusal is final: nothing is deleted.
	refuse := func(_ StorageBackend, logical string, public bool) error {
		if logical != "uploads/avatars/keep.png" || !public {
			t.Errorf("proof asked about %q public=%v", logical, public)
		}
		return os.ErrPermission
	}
	if err := deleteUploadAuthorized(app, "/uploads/avatars/keep.png", refuse); err == nil {
		t.Fatal("a refused proof still deleted")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("a refused proof removed the file: %v", err)
	}
	if err := deleteUploadAuthorized(app, "/uploads/avatars/keep.png", allow); err != nil || asked != 1 {
		t.Fatalf("canonical public reference: err=%v, proof asked %d time(s)", err, asked)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("the public file was not deleted: %v", err)
	}
}

// On a case-insensitive disk another spelling of a stored name opens the same
// file, but the uploader record is keyed by the stored spelling. Such a
// reference must not reach the file past its record (on a case-sensitive
// disk it names no file at all and deletes nothing).
func TestDeleteUploadPublicRefusesAnotherSpellingOfAStoredFile(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	mustExec(t, app.DB, `DELETE FROM docs`)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")

	ref := uploadedPath(t, uploadAs(t, mux, bob, "avatars", "me.png", []byte("\x89PNG\r\n\x1a\n bob")))
	onDisk := publicUploadFile(app, ref)
	for _, respelled := range []string{
		strings.Replace(ref, "/avatars/", "/AVATARS/", 1),
		strings.TrimSuffix(ref, ".png") + ".PNG",
		"/uploads/avatars/" + strings.ToUpper(filepath.Base(ref)),
	} {
		aliceDoc := createDocAs(t, mux, alice, respelled)
		runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+aliceDoc+"/remove", aliceDoc, alice)
		if _, err := os.Stat(onDisk); err != nil {
			t.Fatalf("alice deleted bob's public file through the spelling %q: %v", respelled, err)
		}
	}

	if !localUploadStoredAs(app.Dir, strings.TrimPrefix(ref, "/")) {
		t.Fatalf("the stored spelling %q was not recognized", ref)
	}
	if !localUploadStoredAs(app.Dir, "uploads/avatars/missing.png") || !localUploadStoredAs(app.Dir, "uploads/nofolder/missing.png") {
		t.Fatal("a reference to a missing file must stay a no-op delete, not a refusal")
	}
}

// Hosted tenants delete through the router's broker, which takes the prefix
// from the peer, never from the request: a dev instance's public delete
// stays under <sub>-dev, production's URL is refused before any storage
// call, and a public key outside the peer's own prefix is refused.
func TestDeleteUploadPublicThroughBrokerStaysInOwnPrefix(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	devSecret, prodSecret := strings.Repeat("d", 64), strings.Repeat("p", 64)
	withInstanceSecrets(t, devSecret, map[string]string{scopeTestDev: devSecret, scopeTestApp: prodSecret})
	s3, deleted := fakeMediaBucketServer(t)
	startScopedTestBroker(t, scopeTestApp, cfg, s3)

	dev := &App{Dir: filepath.Join(t.TempDir(), scopeTestDev)}
	cdn := "https://" + cfg.CDNDomain + "/"
	allow := func(_ StorageBackend, _ string, public bool) error {
		if !public {
			t.Error("a public reference resolved as private")
		}
		return nil
	}
	for _, raw := range []string{
		cdn + "public/" + scopeTestApp + "/uploads/avatars/prod.png",
		cdn + "public/other-app/uploads/avatars/a.png",
		cdn + "public/" + scopeTestDev + "/uploads/../../" + scopeTestApp + "/uploads/avatars/prod.png",
	} {
		if err := deleteUploadAuthorized(dev, raw, allow); err == nil {
			t.Errorf("the dev instance deleted %q", raw)
		}
	}
	if got := deleted(); len(got) != 0 {
		t.Fatalf("a refused public reference reached storage: %q", got)
	}
	if err := deleteUploadAuthorized(dev, cdn+"public/"+scopeTestDev+"/uploads/avatars/dev.png", allow); err != nil {
		t.Fatalf("dev could not delete its own public upload: %v", err)
	}
	if err := deleteUploadAuthorized(dev, "/uploads/avatars/logical.png", allow); err != nil {
		t.Fatalf("dev logical public delete: %v", err)
	}
	want := []string{"public/" + scopeTestDev + "/uploads/avatars/dev.png", "public/" + scopeTestDev + "/uploads/avatars/logical.png"}
	if got := deleted(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("deleted keys = %q, want only dev's own %q", got, want)
	}

	// The broker itself: a tenant that names another prefix, or sends a full
	// bucket key of another app, deletes nothing outside its own prefix.
	for _, req := range []presignReq{
		{Operation: "delete", Prefix: "other-app", Path: "public/other-app/uploads/avatars/a.png"},
		{Operation: "delete", Prefix: "other-app", Path: "uploads/../../other-app/uploads/avatars/a.png"},
		{Operation: "delete", Prefix: "other-app", Path: "uploads/avatars/%2e%2e/a.png"},
	} {
		scope, err := presignCallerScope(req, scopeTestApp, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := executePresignBrokerRequest(req, scope, s3); err == nil {
			t.Errorf("broker deleted %q for a peer scoped to %s: %+v", req.Path, scopeTestApp, resp)
		}
	}
	req := presignReq{Operation: "delete", Prefix: "other-app", Path: "uploads/avatars/a.png"}
	scope, err := presignCallerScope(req, scopeTestApp, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := executePresignBrokerRequest(req, scope, s3); err != nil || resp.Key != "public/"+scopeTestApp+"/uploads/avatars/a.png" {
		t.Fatalf("broker public delete = %+v, %v; want the peer's own prefix whatever the request names", resp, err)
	}
	if got := deleted(); len(got) != 3 || got[2] != "public/"+scopeTestApp+"/uploads/avatars/a.png" {
		t.Fatalf("bucket deletes = %q, want exactly the three own-prefix keys", got)
	}
}

// A multipart create records the uploader of the public file it stores, and a
// create that is refused takes that row away with the file
// (discardStoredUpload), as it does a private file's ownership row.
func TestRefusedMultipartCreateRemovesPublicUploaderRow(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, attachment TEXT)")
	if err := EnsureUploadOwnersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	_, sid := gateUser(t, app, "owner@example.com")

	if w := multipartCreate(t, app, "docs", sid); w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("accepted create: %d %s", w.Code, w.Body.String())
	}
	kept := storedUploadFiles(t, app, "docs")
	if len(kept) != 1 {
		t.Fatalf("accepted create stored %d files, want 1", len(kept))
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_public_upload_owners WHERE path = 'docs/"+kept[0]+"' AND user_id > 0"); got != "1" {
		t.Fatalf("accepted create recorded %s public uploader rows for its file, want 1", got)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_upload_owners"); got != "0" {
		t.Fatalf("a public file got %s rows among the private ownership records", got)
	}

	app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{
		"docs": {{SQL: "SELECT 'scans are closed' AS error"}},
	}}
	if w := multipartCreate(t, app, "docs", sid); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("hook did not refuse the create: %d %s", w.Code, w.Body.String())
	}
	if got := storedUploadFiles(t, app, "docs"); len(got) != 1 || got[0] != kept[0] {
		t.Fatalf("refused create left files behind: %v (kept %v)", got, kept)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_public_upload_owners"); got != "1" {
		t.Fatalf("refused create left a public uploader row: %s rows, want 1", got)
	}
}
