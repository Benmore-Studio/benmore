//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// setUploadsFeature sets features.uploads the way app.yaml would carry v,
// keeping the rest of the app's design config.
func setUploadsFeature(app *App, v any) {
	if app.Design == nil {
		app.Design = &DesignConfig{}
	}
	app.Design.Features = parseFeaturesConfig(map[string]any{"uploads": v})
}

// multipartBody builds a multipart/form-data body from text fields and file
// parts (field name -> file name; every file holds the same bytes).
func multipartBody(t *testing.T, fields, files map[string]string) (contentType, body string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for field, name := range files {
		fw, err := mw.CreateFormFile(field, name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte("\x89PNG\r\n\x1a\nnot really an image"))
	}
	mw.Close()
	return mw.FormDataContentType(), buf.String()
}

// everyStoredUpload lists every file under the app's uploads/ directory.
func everyStoredUpload(t *testing.T, app *App) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(filepath.Join(app.Dir, "uploads"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// With features.uploads: false, POST /api/_upload and /api/_files were gone
// but a multipart create still stored its file parts (publicly, in the
// table's folder). The create is refused before anything is stored: no
// object, no ownership row, no table row, no audit row. The same create
// without a file part, or as JSON, is an ordinary create, and with the
// switch on the file is stored as before.
func TestUploadsSwitchOffRefusesCreateWithFilePart(t *testing.T) {
	for _, table := range []string{"docs", "private"} { // "private" is the folder that records an ownership row
		t.Run(table, func(t *testing.T) {
			app := newGateApp(t, "CREATE TABLE "+quoteIdent(table)+" (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, attachment TEXT)")
			if err := EnsureUploadOwnersTable(app.DB); err != nil {
				t.Fatal(err)
			}
			_, sid := gateUser(t, app, "owner@example.com")
			count := func(q string) string { return gateScalar(t, app, q) }

			setUploadsFeature(app, false)
			w := multipartCreate(t, app, table, sid)
			var refusal map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &refusal); err != nil {
				t.Fatalf("refusal is not JSON: %d %q", w.Code, w.Body.String())
			}
			if w.Code != http.StatusForbidden || refusal["error"] != "uploads_disabled" || refusal["field"] != "attachment" {
				t.Fatalf("create with a file part: %d %s, want 403 uploads_disabled naming the part", w.Code, w.Body.String())
			}
			if msg, _ := refusal["message"].(string); !strings.Contains(msg, "features.uploads: false") {
				t.Errorf("message %q does not name the switch", msg)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want JSON", ct)
			}
			if left := everyStoredUpload(t, app); len(left) != 0 {
				t.Errorf("refused create stored %v", left)
			}
			if got := count("SELECT COUNT(*) FROM " + quoteIdent(table)); got != "0" {
				t.Errorf("refused create left %s rows", got)
			}
			if got := count("SELECT COUNT(*) FROM _benmore_upload_owners"); got != "0" {
				t.Errorf("refused create left %s ownership rows", got)
			}
			if got := count("SELECT COUNT(*) FROM _benmore_audit_log"); got != "0" {
				t.Errorf("refused create left %s audit rows", got)
			}

			// A multipart body with fields only is an ordinary create.
			ctype, body := multipartBody(t, map[string]string{"title": "fields only"}, nil)
			if w := gateCall(app, handleCreate, table, "POST", "/api/"+table, ctype, body, sid); w.Code != http.StatusOK {
				t.Fatalf("multipart create without a file: %d %s", w.Code, w.Body.String())
			}
			// So is a JSON create.
			if w := gateCall(app, handleCreate, table, "POST", "/api/"+table, "application/json", `{"title":"from json"}`, sid); w.Code != http.StatusOK {
				t.Fatalf("JSON create: %d %s", w.Code, w.Body.String())
			}
			if got := count("SELECT COUNT(*) FROM " + quoteIdent(table) + " WHERE title IN ('fields only', 'from json') AND COALESCE(attachment, '') = ''"); got != "2" {
				t.Errorf("creates without a file stored %s rows, want 2", got)
			}
			if left := everyStoredUpload(t, app); len(left) != 0 {
				t.Errorf("creates without a file stored %v", left)
			}

			// The same multipart create with the switch on stores its file.
			setUploadsFeature(app, true)
			if w := multipartCreate(t, app, table, sid); w.Code != http.StatusOK {
				t.Fatalf("create with the switch on: %d %s", w.Code, w.Body.String())
			}
			if kept := storedUploadFiles(t, app, table); len(kept) != 1 {
				t.Fatalf("create with the switch on stored %v, want one file", kept)
			}
			if got := count("SELECT COUNT(*) FROM " + quoteIdent(table) + " WHERE attachment LIKE '/uploads/" + table + "/%'"); got != "1" {
				t.Errorf("row with the stored path: %s, want 1", got)
			}
		})
	}
}

// Every spelling app.yaml accepts for "off" closes the create path, and
// every spelling for "on" (and no key at all) leaves it open.
func TestUploadsSwitchSpellings(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, attachment TEXT)")
	_, sid := gateUser(t, app, "owner@example.com")
	for _, off := range []any{false, "false", "no", "off", "0", "No", "OFF"} {
		setUploadsFeature(app, off)
		if w := multipartCreate(t, app, "docs", sid); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "uploads_disabled") {
			t.Errorf("features.uploads: %#v: %d %s, want the refusal", off, w.Code, w.Body.String())
		}
	}
	if left := everyStoredUpload(t, app); len(left) != 0 {
		t.Fatalf("refused creates stored %v", left)
	}
	stored := 0
	for _, on := range []any{true, "true", "yes", "on", "1"} {
		setUploadsFeature(app, on)
		if w := multipartCreate(t, app, "docs", sid); w.Code != http.StatusOK {
			t.Errorf("features.uploads: %#v: %d %s, want the create", on, w.Code, w.Body.String())
		}
		stored++
	}
	app.Design = nil // no features: block
	if w := multipartCreate(t, app, "docs", sid); w.Code != http.StatusOK {
		t.Errorf("no features block: %d %s, want the create", w.Code, w.Body.String())
	}
	if kept := storedUploadFiles(t, app, "docs"); len(kept) != stored+1 {
		t.Errorf("stored %d files, want %d", len(kept), stored+1)
	}
}

// The function every HTTP upload goes through (multipart creates,
// /api/_upload, /api/_files) refuses on its own, so a caller added later
// cannot store a file while the switch is off.
func TestUploadsSwitchOffClosesTheSharedStorePath(t *testing.T) {
	app := newGateApp(t)
	request := func() *http.Request {
		ctype, body := multipartBody(t, nil, map[string]string{"file": "scan.png"})
		r := httptest.NewRequest("POST", "https://app.example.com/api/anything", strings.NewReader(body))
		r.Header.Set("Content-Type", ctype)
		return r
	}
	setUploadsFeature(app, false)
	for _, folder := range []string{"docs", "private", "_files", ""} {
		url, dest, err := handleFileUploadAt(app, request(), "file", folder, 0, nil)
		if err == nil || url != "" || dest != "" || !strings.Contains(err.Error(), "features.uploads: false") {
			t.Errorf("folder %q with the switch off: url=%q dest=%q err=%v, want a refusal that names the switch", folder, url, dest, err)
		}
		if url, err := HandleFileUpload(app, request(), "file", folder, 0, nil); err == nil || url != "" {
			t.Errorf("HandleFileUpload folder %q with the switch off: url=%q err=%v", folder, url, err)
		}
	}
	if left := everyStoredUpload(t, app); len(left) != 0 {
		t.Fatalf("the switch off stored %v", left)
	}
	setUploadsFeature(app, true)
	if url, _, err := handleFileUploadAt(app, request(), "file", "docs", 0, nil); err != nil || !strings.HasPrefix(url, "/uploads/docs/") {
		t.Fatalf("switch on: url=%q err=%v", url, err)
	}
}

// The other write paths cannot carry a file: an update ignores a file part
// (switch on or off), and batch, ingest and /api/_transaction take JSON or
// NDJSON only. None of them stores an object.
func TestOtherWritePathsStoreNoFile(t *testing.T) {
	for _, on := range []bool{true, false} {
		app := newGateApp(t, "CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, attachment TEXT)")
		uid, sid := gateUser(t, app, "owner@example.com")
		mustExec(t, app.DB, fmt.Sprintf("INSERT INTO docs (id, user_id, title, attachment) VALUES (1, %d, 'first', '')", uid))
		setUploadsFeature(app, on)
		ctype, body := multipartBody(t, map[string]string{"title": "renamed"}, map[string]string{"attachment": "scan.png"})

		w := gateCall(app, handleUpdate, "docs", "PATCH", "/api/docs/1", ctype, body, sid)
		if got := gateScalar(t, app, "SELECT COALESCE(attachment, '') FROM docs WHERE id = 1"); got != "" {
			t.Errorf("uploads=%v: update (%d) set the file column to %q", on, w.Code, got)
		}
		for name, call := range map[string]func() *httptest.ResponseRecorder{
			"batch": func() *httptest.ResponseRecorder {
				return gateCall(app, handleBatchCreate, "docs", "POST", "/api/docs/batch", ctype, body, sid)
			},
			"ingest": func() *httptest.ResponseRecorder {
				return gateCall(app, handleStreamingIngest, "docs", "POST", "/api/docs/ingest", ctype, body, sid)
			},
			"transaction": func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "https://app.example.com/api/_transaction", strings.NewReader(body))
				r.Header.Set("Content-Type", ctype)
				r.Header.Set("Authorization", "Bearer "+sid)
				w := httptest.NewRecorder()
				handleTransaction(w, r, app)
				return w
			},
		} {
			if w := call(); w.Code >= 200 && w.Code < 300 {
				t.Errorf("uploads=%v: %s accepted a multipart body: %d %s", on, name, w.Code, w.Body.String())
			}
		}
		if got := gateScalar(t, app, "SELECT COUNT(*) FROM docs"); got != "1" {
			t.Errorf("uploads=%v: %s rows after the bulk calls, want 1", on, got)
		}
		if left := everyStoredUpload(t, app); len(left) != 0 {
			t.Errorf("uploads=%v: update/batch/ingest/transaction stored %v", on, left)
		}
	}
}

// A connector pull stores the upstream file as a private upload. The store
// step refuses while uploads are off: no ownership row, no bytes.
func TestUploadsSwitchOffRefusesPulledFile(t *testing.T) {
	app := newGateApp(t)
	path := "uploads/private/mcp/" + strings.Repeat("d", 64) + ".pdf"
	content := []byte("%PDF-1.7 fixture")
	store := func() error {
		return appMCPStorePulledFile(app, Session{UserID: 42}, path, content, "application/pdf", hashBytesSHA256(content), "fixture_source", "fixture-id", "rev-1")
	}
	setUploadsFeature(app, false)
	if err := store(); err == nil || !strings.Contains(err.Error(), "features.uploads: false") {
		t.Fatalf("pulled file with the switch off: %v, want a refusal that names the switch", err)
	}
	if left := everyStoredUpload(t, app); len(left) != 0 {
		t.Fatalf("refused pull stored %v", left)
	}
	var owners int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = '_benmore_upload_owners'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners == 1 {
		if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_upload_owners"); got != "0" {
			t.Fatalf("refused pull left %s ownership rows", got)
		}
	}
	setUploadsFeature(app, true)
	if err := store(); err != nil {
		t.Fatalf("pulled file with the switch on: %v", err)
	}
	if kept := everyStoredUpload(t, app); len(kept) != 1 {
		t.Fatalf("pull with the switch on stored %v, want one file", kept)
	}
}

// A connector command with a pull transfer is refused at prepare while
// uploads are off, before review, approval or any request to the source.
func TestUploadsSwitchOffRefusesConnectorPullAtPrepare(t *testing.T) {
	app, _, _, pair, generation := newTransferPullFixture(t)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := appMCPConnectorOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	var gets atomic.Int32
	installPipeUpstream(t, func(req *http.Request) (int, string, bool) {
		gets.Add(1)
		return http.StatusOK, `{}`, false
	})
	setUploadsFeature(app, false)
	request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
	input := map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7, "file_id": "upstream-file-99", "record_id": "1"}}
	_, err = appMCPPrepareOperation(context.Background(), request, input)
	var failure *appMCPResultError
	if !errors.As(err, &failure) || failure.Code != "denied" {
		t.Fatalf("prepare with uploads off: %v, want the connector's denied result", err)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM main._benmore_jobs WHERE job_type = ?", appMCPTransferJobType); got != "0" {
		t.Errorf("refused prepare queued %s transfer jobs", got)
	}
	if gets.Load() != 0 || len(everyStoredUpload(t, app)) != 0 {
		t.Errorf("refused prepare reached the source %d times and stored %v", gets.Load(), everyStoredUpload(t, app))
	}
}

// A pull approved while uploads were on does not download or store once the
// switch is turned off before the worker runs: the job is blocked.
func TestUploadsSwitchedOffBlocksQueuedConnectorPull(t *testing.T) {
	app, sessionID, _, pair, generation := newTransferPullFixture(t)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := appMCPConnectorOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
	input := map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7, "file_id": "upstream-file-99", "record_id": "1"}}
	prepared, err := appMCPPrepareOperation(context.Background(), request, input)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	approve := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
	if _, err := appMCPReviewOperation(context.Background(), approve, prepared.ID, "fixture-approved"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := appMCPCommitOperation(context.Background(), request, prepared.ID); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var gets atomic.Int32
	installPipeUpstream(t, func(req *http.Request) (int, string, bool) {
		gets.Add(1)
		content := []byte("%PDF-1.7\nprivate transfer fixture\n")
		response, _ := json.Marshal(map[string]string{"content": "JVBERi0xLjcKcHJpdmF0ZSB0cmFuc2ZlciBmaXh0dXJlCg==", "mime": "application/pdf", "revision": "rev-42", "checksum": hashBytesSHA256(content)})
		return http.StatusOK, string(response), false
	})

	setUploadsFeature(app, false)
	if !processNextJob(app) {
		t.Fatal("worker did not process the pull job")
	}
	var status, lastError string
	if err := app.DB.QueryRow(`SELECT status, COALESCE(error, '') FROM main._benmore_jobs WHERE job_type = ?`, appMCPTransferJobType).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(lastError, "features.uploads: false") {
		t.Errorf("job status %q error %q, want a failed job that names the switch", status, lastError)
	}
	if gets.Load() != 0 {
		t.Errorf("the worker asked the source for the file %d times", gets.Load())
	}
	if left := everyStoredUpload(t, app); len(left) != 0 {
		t.Errorf("blocked pull stored %v", left)
	}
	if got := gateScalar(t, app, "SELECT COALESCE(evidence_file, '') FROM main.tasks WHERE id = 1"); got != "" {
		t.Errorf("blocked pull attached %q", got)
	}
	var ownersTable int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = '_benmore_upload_owners'`).Scan(&ownersTable); err != nil {
		t.Fatal(err)
	}
	if ownersTable == 1 {
		if got := gateScalar(t, app, "SELECT COUNT(*) FROM main._benmore_upload_owners"); got != "0" {
			t.Errorf("blocked pull left %s ownership rows", got)
		}
	}
}

// The two fixture apps (CI runs them through scripts/check-fixture-apps.py)
// pass under `benmore test --app`: uploads-switch-off refuses the multipart
// create and leaves nothing behind while its JSON, form and fields-only
// creates work; uploads-switch-on stores the same create's file and serves
// it back.
func TestUploadsSwitchFixturesPass(t *testing.T) {
	for fixture, want := range map[string]int{"uploads-switch-off": 4, "uploads-switch-on": 2} {
		results, err := runServerTestsOnCopy(filepath.Join("testdata", fixture), "app")
		if err != nil {
			t.Fatalf("%s: %v", fixture, err)
		}
		passed := 0
		for _, r := range results {
			switch {
			case r.File == "SUMMARY" || r.Skipped:
			case r.Pass:
				passed++
			default:
				t.Errorf("%s: %s / %s failed: %s %+v", fixture, r.File, r.Test, r.Message, r.Steps)
			}
		}
		if passed != want {
			t.Errorf("%s: %d tests passed, want %d", fixture, passed, want)
		}
	}
}
