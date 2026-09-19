//go:build !cli

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockingImportReader struct {
	entered chan struct{}
	release <-chan struct{}
	data    []byte
	sent    bool
}

func (r *blockingImportReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	close(r.entered)
	<-r.release
	return copy(p, r.data), nil
}

func TestImportTableAllowedExcludesFrameworkTables(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	if !importTableAllowed(app, "products") {
		t.Fatal("products should be importable")
	}
	// Framework tables are excluded structurally by GetTableNames
	// (db.go:508), not by a hand-maintained deny-list.
	for _, forbidden := range []string{"_benmore_users", "_benmore_imports", "_benmore_audit_log", "sqlite_master", "nonexistent"} {
		if importTableAllowed(app, forbidden) {
			t.Errorf("%s must not be importable", forbidden)
		}
	}
}

func TestImportCreateRejectsUnknownTable(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	// Authenticated as admin: the 404 must be about the table, not about
	// auth. An anonymous caller gets 401 here instead (see the next test),
	// which is what stops 404-vs-403 from being a table-existence probe.
	sessCookie := seedAdminSession(t, app)
	body := `{"table":"_benmore_users","format":"csv","bytes":10,"sha256":"x"}`
	req := authedRequest("POST", "/api/_import", body, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a framework table", rec.Code)
	}
}

func TestImportCreateDoesNotLeakTableExistence(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	// CSRF satisfied (unbound token, no session cookie) for both a real and
	// a nonexistent table, so the request actually reaches
	// importCallerAuthorized's session==nil branch instead of being
	// trivially satisfied by the earlier "missing CSRF token" 403 for both
	// cases equally - a version of this test that never gets past the CSRF
	// gate would pass even if the auth-before-table-resolution ordering it
	// claims to prove were dead code (review Important 4).
	for _, table := range []string{"products", "definitely_not_a_table"} {
		body := `{"table":"` + table + `","format":"csv","bytes":10,"sha256":"x"}`
		req := csrfOnlyRequest("POST", "/api/_import", body)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("table %q: status = %d, want 401 for a session-less (but CSRF-valid) caller", table, rec.Code)
		}
	}
}

func TestImportCreateRequiresAuth(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	// CSRF satisfied (unbound token, no cookie) so this exercises the real
	// session==nil 401 branch in importCallerAuthorized rather than being
	// turned away earlier by the CSRF check - see the comment on
	// csrfOnlyRequest (review Important 4).
	body := `{"table":"products","format":"csv","bytes":10,"sha256":"x"}`
	req := csrfOnlyRequest("POST", "/api/_import", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a CSRF-valid but session-less caller", rec.Code)
	}
}

// TestImportRequiresAdminEvenWithTableWriteAccess is the spec's central
// Mode A assertion: a member who genuinely holds write access to the
// target table (via access:) must still be refused, because
// importCallerAuthorized's admin-or-owner gate runs BEFORE the per-table
// access check and is not satisfiable by table access alone. Without this
// test the rule was asserted nowhere (review Important 4).
func TestImportRequiresAdminEvenWithTableWriteAccess(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	// Grant ANY authenticated session write access to products - the most
	// generous access: an app could declare short of "off" entirely. If
	// this alone were enough to import, this test would fail; it exists to
	// prove it is NOT enough.
	app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{
		"products": {OpWrite: "everyone"},
	}}
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	adminSess := seedAdminSession(t, app)
	memberSess := seedMemberSession(t, app)

	body := `{"table":"products","format":"csv","bytes":10,"sha256":"` + strings.Repeat("a", 64) + `"}`

	// The member cannot even create an import session, despite having
	// table write access.
	req := authedRequest("POST", "/api/_import", body, memberSess)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member create: status = %d, want 403", rec.Code)
	}

	// Nor can the member chunk or commit an import the admin already
	// created on the same table.
	req = authedRequest("POST", "/api/_import", body, adminSess)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ImportID == "" {
		t.Fatalf("admin create failed, cannot continue: %s", rec.Body.String())
	}

	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", strings.Repeat("x", 10), memberSess)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member chunk: status = %d, want 403", rec.Code)
	}

	req = authedRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", memberSess)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member commit: status = %d, want 403", rec.Code)
	}
}

func TestImportCreateRejectsOversize(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	t.Setenv("BENMORE_MAX_IMPORT_BYTES", "100")
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	sess := seedAdminSession(t, app)
	body := `{"table":"products","format":"csv","bytes":100000,"sha256":"x"}`
	req := authedRequest("POST", "/api/_import", body, sess)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// TestImportCreateRejectsDeclaredProtectedColumnBeforeAnyUpload is the I4
// fix: the concrete cost this catches is a CSV exported from the source
// table that still carries its own `id` primary key - previously that
// only surfaced from the header check INSIDE the runner, after the
// caller had already paid for uploading (and committing) the whole file.
// Declaring `columns` on create now fails the session immediately -
// asserted here by never staging a single chunk before the 400.
func TestImportCreateRejectsDeclaredProtectedColumnBeforeAnyUpload(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	sess := seedAdminSession(t, app)
	body := `{"table":"products","format":"csv","bytes":100,"sha256":"` + strings.Repeat("a", 64) +
		`","columns":["sku","user_id"]}`
	req := authedRequest("POST", "/api/_import", body, sess)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Error string `json:"error"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if !strings.Contains(out.Error, "user_id") {
		t.Fatalf("error must name the offending column, got: %q", out.Error)
	}

	// No session should have been created for this rejected request - a
	// caller retrying after fixing their columns list must not find a
	// dangling 'staging' row (and, more importantly, no import_id was ever
	// returned to stage a chunk against in the first place).
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_imports").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a column-validation rejection must not create a session, found %d", n)
	}
}

// TestImportCreateAcceptsValidDeclaredColumns is the positive case
// alongside the rejection test above: a columns list naming only
// legitimately importable columns must not be rejected.
func TestImportCreateAcceptsValidDeclaredColumns(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	sess := seedAdminSession(t, app)
	body := `{"table":"products","format":"csv","bytes":100,"sha256":"` + strings.Repeat("a", 64) +
		`","columns":["sku","qty"]}`
	req := authedRequest("POST", "/api/_import", body, sess)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestImportEndToEnd(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "sku,qty\nA,1\nB,2\n"
	sum := sha256.Sum256([]byte(content))
	hexSum := hex.EncodeToString(sum[:])

	// 1. create
	createBody := `{"table":"products","format":"csv","bytes":` +
		itoa(len(content)) + `,"sha256":"` + hexSum + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ImportID  string `json:"import_id"`
		ChunkSize int64  `json:"chunk_size"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ImportID == "" {
		t.Fatal("create returned no import_id")
	}

	// 2. chunk
	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", content, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk status = %d body = %s", rec.Code, rec.Body.String())
	}

	// 3. commit
	req = authedRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("commit status = %d body = %s", rec.Code, rec.Body.String())
	}

	// 4. poll to completion
	var state string
	for i := 0; i < 100; i++ {
		req = authedRequest("GET", "/api/_import/"+created.ImportID, "", sessCookie)
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var st struct {
			State      string `json:"state"`
			RowsLoaded int64  `json:"rows_loaded"`
		}
		json.Unmarshal(rec.Body.Bytes(), &st)
		state = st.State
		if state == "completed" {
			if st.RowsLoaded != 2 {
				t.Fatalf("rows_loaded = %d, want 2", st.RowsLoaded)
			}
			break
		}
		if state == "failed" {
			t.Fatalf("import failed: %s", rec.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if state != "completed" {
		t.Fatalf("import did not complete, last state = %q", state)
	}

	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 2 {
		t.Fatalf("products has %d rows, want 2", n)
	}
}

func TestImportChunkRejectsOverDeclaredTotal(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	// Declare 10 bytes, then try to stage 50. Preflight only ever sees the
	// declared size, so without a write-time cap this fills the disk and
	// only fails at commit.
	content := strings.Repeat("x", 10)
	sum := sha256.Sum256([]byte(content))
	createBody := `{"table":"products","format":"csv","bytes":10,"sha256":"` +
		hex.EncodeToString(sum[:]) + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", strings.Repeat("x", 50), sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for a chunk past the declared total", rec.Code)
	}
	// The rejected chunk must not survive on disk.
	if n, _ := stagedBytes(app, created.ImportID); n != 0 {
		t.Fatalf("rejected chunk left %d bytes staged, want 0", n)
	}
}

func TestImportChunkRejectsOversizeChunk(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	// A real, in-staging import - the brief's original version PUT to a
	// fabricated id ("abcdefgh") that was never created, so
	// importSessionFor's 404 ("unknown import") fired before the body was
	// ever read and the test's own "or 404" escape hatch always took that
	// path. maxImportChunkBytes had zero HTTP-level coverage as a result
	// (review Important 5). With a real session the 404 escape hatch is
	// gone and 413 is asserted strictly.
	declared := int64(maxImportChunkBytes) + 1024
	createBody := fmt.Sprintf(`{"table":"products","format":"csv","bytes":%d,"sha256":"%s"}`,
		declared, strings.Repeat("a", 64))
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	big := strings.Repeat("x", maxImportChunkBytes+1024)
	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", big, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// TestImportChunkWriteFailureIsServerErrorNotLeaked covers a chunk-write
// failure that is NOT the size cap (import.go's writeImportChunk also
// returns errors for MkdirAll/CreateTemp/Copy/Close/Rename). Before the
// fix every such failure surfaced as 413 with the raw wrapped error text,
// which for a filesystem fault includes the absolute staging path (review
// Important 3).
func TestImportChunkWriteFailureIsServerErrorNotLeaked(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	createBody := `{"table":"products","format":"csv","bytes":10,"sha256":"` + strings.Repeat("a", 64) + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ImportID == "" {
		t.Fatalf("create failed: %s", rec.Body.String())
	}

	// Force writeImportChunk's os.MkdirAll to fail with something other
	// than the size cap: put a plain FILE where the staging directory
	// needs to be created, so MkdirAll errors with ENOTDIR.
	dir := importStagingDir(app, created.ImportID)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("blocking file"), 0o644); err != nil {
		t.Fatal(err)
	}

	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", "hello", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a non-size write failure", rec.Code)
	}
	if strings.Contains(rec.Body.String(), app.Dir) {
		t.Fatalf("response leaked the staging path: %s", rec.Body.String())
	}
}

// TestImportChunkFullSizeSurvivesGlobalBodyLimitMiddleware is a regression
// test for a bug found via a real `benmore serve` smoke test while
// verifying the Task 6 resume fix: the server's global request-body-size
// middleware (serverBodyLimitMiddleware, server.go) defaults to a 10MB cap
// on every non-multipart request - including the bulk-import chunk PUT,
// whose OWN cap (handleImportChunk's http.MaxBytesReader) is
// maxImportChunkBytes (32MB). Every OTHER test in this file registers
// RegisterImportRoutes on a BARE mux, which never runs wrapMiddleware at
// all, so none of them could have caught a full-size chunk being
// truncated by the OUTER 10MB cap before it ever reached the import
// handler's own (correct) 32MB one - `benmore import` would 500 on every
// single chunk at the feature's own designed chunk size, making chunked
// upload (the entire point of the feature) non-functional for any real
// file. This test wires the REAL middleware chain (wrapMiddleware) so a
// full 32MB chunk is actually exercised end-to-end, the way it is in
// production.
func TestImportChunkFullSizeSurvivesGlobalBodyLimitMiddleware(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	handler := wrapMiddleware(mux, app, true) // dev=true: skip gzip, higher rate limit - neither matters for this test
	srv := httptest.NewServer(handler)
	defer srv.Close()

	prev := serverSecret
	serverSecret = "chunk-size-regression-secret-00000000"
	defer func() { serverSecret = prev }()
	tok := mintImportOwnerToken(app, time.Now().Add(5*time.Minute), "owner@example.com")

	content := bytes.Repeat([]byte("x"), maxImportChunkBytes)
	sum := sha256.Sum256(content)
	createBody, _ := json.Marshal(map[string]any{
		"table": "products", "format": "csv", "gzip": false,
		"bytes": maxImportChunkBytes, "sha256": hex.EncodeToString(sum[:]),
	})
	createReq, _ := http.NewRequest("POST", srv.URL+"/api/_import", bytes.NewReader(createBody))
	createReq.Header.Set("X-Benmore-Import-Token", tok)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatal(err)
	}
	createRespBody, _ := io.ReadAll(createResp.Body)
	createResp.Body.Close()
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(createRespBody, &created)
	if created.ImportID == "" {
		t.Fatalf("create failed: %s", createRespBody)
	}

	putReq, _ := http.NewRequest("PUT", srv.URL+"/api/_import/"+created.ImportID+"/chunk/0", bytes.NewReader(content))
	putReq.Header.Set("X-Benmore-Import-Token", tok)
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	putRespBody, _ := io.ReadAll(putResp.Body)
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("a full %d-byte chunk (the feature's own designed chunk size) must succeed through the real middleware chain: status=%d body=%s",
			maxImportChunkBytes, putResp.StatusCode, putRespBody)
	}
}

// TestImportCreateResumesMatchingStagingSession is the CRITICAL fix from
// the Task 6 review: before the fix, POST /api/_import called newImportID()
// unconditionally, so a CLI re-run after a dropped connection always got a
// SECOND id whose received_chunks was necessarily empty - the "skip chunks
// already uploaded" resume logic was unreachable dead code, and every
// retry of a large upload restarted from byte zero. An identical create
// request (same table/format/gzip/bytes/sha256, same caller) against a
// still-staging session must now return the SAME import_id, and a chunk
// staged before the "retry" must be visible via GET status afterward.
func TestImportCreateResumesMatchingStagingSession(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "sku,qty\nA,1\nB,2\n"
	sum := sha256.Sum256([]byte(content))
	hexSum := hex.EncodeToString(sum[:])
	createBody := `{"table":"products","format":"csv","bytes":` +
		itoa(len(content)) + `,"sha256":"` + hexSum + `"}`

	// First "attempt": create, then stage chunk 0 (simulating an upload
	// that then dies before commit - e.g. the connection drops).
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first create status = %d body = %s", rec.Code, rec.Body.String())
	}
	var first struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &first)
	if first.ImportID == "" {
		t.Fatal("first create returned no import_id")
	}

	req = authedRequest("PUT", "/api/_import/"+first.ImportID+"/chunk/0", content, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk status = %d body = %s", rec.Code, rec.Body.String())
	}

	// Second "attempt": the CLI re-runs the exact same command, which
	// posts the IDENTICAL create body. This must resume, not orphan the
	// first session's staged chunk.
	req = authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second create status = %d body = %s", rec.Code, rec.Body.String())
	}
	var second struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &second)
	if second.ImportID != first.ImportID {
		t.Fatalf("resume must return the SAME import_id: first=%q second=%q", first.ImportID, second.ImportID)
	}

	// The chunk staged before the "retry" must still be visible - this is
	// exactly what the CLI's received_chunks skip-logic depends on.
	req = authedRequest("GET", "/api/_import/"+second.ImportID, "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var status struct {
		ReceivedChunks []int `json:"received_chunks"`
	}
	json.Unmarshal(rec.Body.Bytes(), &status)
	if len(status.ReceivedChunks) != 1 || status.ReceivedChunks[0] != 0 {
		t.Fatalf("resumed session lost its staged chunk: received_chunks = %v", status.ReceivedChunks)
	}

	// And the resumed session must still complete normally end-to-end.
	req = authedRequest("POST", "/api/_import/"+second.ImportID+"/commit", "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("commit status = %d body = %s", rec.Code, rec.Body.String())
	}
	var state string
	for i := 0; i < 100; i++ {
		req := authedRequest("GET", "/api/_import/"+second.ImportID, "", sessCookie)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var st struct {
			State      string `json:"state"`
			RowsLoaded int64  `json:"rows_loaded"`
		}
		json.Unmarshal(rec.Body.Bytes(), &st)
		state = st.State
		if state == "completed" {
			if st.RowsLoaded != 2 {
				t.Fatalf("rows_loaded = %d, want 2", st.RowsLoaded)
			}
			break
		}
		if state == "failed" {
			t.Fatalf("resumed import failed: %s", rec.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if state != "completed" {
		t.Fatalf("resumed import did not complete, last state = %q", state)
	}
}

// TestImportCreateDoesNotResumeDifferentFile proves the resume match is
// keyed on sha256 (not just table/format/bytes, which a coincidentally
// same-sized different file could share): a different file must always
// get its own session, never silently attach to someone else's in-progress
// upload.
func TestImportCreateDoesNotResumeDifferentFile(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	bodyFor := func(content string) string {
		sum := sha256.Sum256([]byte(content))
		return `{"table":"products","format":"csv","bytes":` +
			itoa(len(content)) + `,"sha256":"` + hex.EncodeToString(sum[:]) + `"}`
	}
	// Same byte LENGTH, different content/hash.
	bodyA := bodyFor("sku,qty\nA,111\n")
	bodyB := bodyFor("sku,qty\nB,222\n")

	req := authedRequest("POST", "/api/_import", bodyA, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var a struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &a)

	req = authedRequest("POST", "/api/_import", bodyB, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var b struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &b)

	if a.ImportID == "" || b.ImportID == "" {
		t.Fatalf("expected two successful creates, got a=%q b=%q", a.ImportID, b.ImportID)
	}
	if a.ImportID == b.ImportID {
		t.Fatal("two different files must never resume onto the same session")
	}
}

func TestImportCreateResumeIdentityIncludesSemanticsAndActor(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	prev := serverSecret
	serverSecret = "resume-identity-secret-000000000000"
	defer func() { serverSecret = prev }()
	request := func(body, subject string) string {
		tok := mintImportOwnerToken(app, time.Now().Add(time.Minute), subject)
		req := ownerTokenRequest("POST", "/api/_import", body, tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("create: status=%d body=%s", rec.Code, rec.Body.String())
		}
		var out struct {
			ImportID string `json:"import_id"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out.ImportID
	}

	base := `{"table":"products","format":"csv","gzip":true,"bytes":100,"uncompressed_bytes":200,"null_as":"\\N","sha256":"` + strings.Repeat("a", 64) + `"}`
	first := request(base, "one@example.com")
	for _, tc := range []struct {
		body    string
		subject string
	}{
		{strings.Replace(base, `"null_as":"\\N"`, `"null_as":"NULL"`, 1), "one@example.com"},
		{strings.Replace(base, `"uncompressed_bytes":200`, `"uncompressed_bytes":201`, 1), "one@example.com"},
		{base, "two@example.com"},
	} {
		if got := request(tc.body, tc.subject); got == first {
			t.Fatal("a different import semantic or owner must not resume another staging session")
		}
	}
}

func TestImportChunkDiscardsPartWhenCommitWinsDuringWrite(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	cookie := seedAdminSession(t, app)

	sum := sha256.Sum256([]byte("x"))
	create := authedRequest("POST", "/api/_import", `{"table":"products","format":"csv","bytes":1,"sha256":"`+hex.EncodeToString(sum[:])+`"}`, cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, create)
	var out struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)

	release := make(chan struct{})
	reader := &blockingImportReader{entered: make(chan struct{}), release: release, data: []byte("x")}
	req := httptest.NewRequest("PUT", "/api/_import/"+out.ImportID+"/chunk/0", reader)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	req.Header.Set("X-CSRF-Token", authMintCSRFToken(cookie))
	rec = httptest.NewRecorder()
	done := make(chan struct{})
	go func() { mux.ServeHTTP(rec, req); close(done) }()
	<-reader.entered
	if _, err := app.DB.Exec(`UPDATE _benmore_imports SET state='running' WHERE id=?`, out.ImportID); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	if rec.Code != http.StatusConflict {
		t.Fatalf("chunk racing a commit: status=%d, want 409", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(importStagingDir(app, out.ImportID), "part-0")); !os.IsNotExist(err) {
		t.Fatalf("a chunk written after commit wins must be discarded, stat err=%v", err)
	}
}

func TestImportCommitRecoveryInterleaveKeepsLiveStaging(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	cookie := seedAdminSession(t, app)
	mustExec(t, app.DB, "CREATE TABLE strict (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)")

	content := "n\n1\n\"\"\n"
	sum := sha256.Sum256([]byte(content))
	create := authedRequest("POST", "/api/_import", `{"table":"strict","format":"csv","bytes":`+itoa(len(content))+`,"sha256":"`+hex.EncodeToString(sum[:])+`"}`, cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, create)
	var out struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	chunk := authedRequest("PUT", "/api/_import/"+out.ImportID+"/chunk/0", content, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, chunk)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk: status=%d body=%s", rec.Code, rec.Body.String())
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var releaseOnce sync.Once
	prevFree := freeDiskBytes
	freeDiskBytes = func(string) (int64, error) {
		close(entered)
		<-release
		return 1 << 60, nil
	}
	defer func() {
		freeDiskBytes = prevFree
		releaseOnce.Do(func() { close(release) })
		<-done
	}()

	commit := authedRequest("POST", "/api/_import/"+out.ImportID+"/commit", "", cookie)
	commitRec := httptest.NewRecorder()
	go func() { mux.ServeHTTP(commitRec, commit); close(done) }()
	<-entered // commit owns the row as running, but has not launched a runner yet.

	recoverInterruptedImports(app)
	state, err := loadImportSession(app.DB, out.ImportID)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != "running" {
		t.Fatalf("recovery changed a live commit to %q", state.State)
	}
	if _, err := os.Stat(importStagingDir(app, out.ImportID)); err != nil {
		t.Fatalf("recovery purged live staging: %v", err)
	}

	releaseOnce.Do(func() { close(release) })
	<-done
	if commitRec.Code != http.StatusAccepted {
		t.Fatalf("commit: status=%d body=%s", commitRec.Code, commitRec.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	// The runner persists failure before purging staging. Wait for its
	// in-flight flag to clear so the assertions observe completed cleanup.
	for importRunning(app) {
		if time.Now().After(deadline) {
			t.Fatal("import runner did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	state, err = loadImportSession(app.DB, out.ImportID)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != "failed" || state.RowsLoaded != 0 || !strings.Contains(state.Error, "NOT NULL") {
		t.Fatalf("terminal state = %q rows=%d error=%q, want truthful failed zero-row result", state.State, state.RowsLoaded, state.Error)
	}
	var rows int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM strict").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("strict rows = %d, want 0 after failed atomic import", rows)
	}
	if _, err := os.Stat(importStagingDir(app, out.ImportID)); !os.IsNotExist(err) {
		t.Fatalf("runner-owned failure must purge staging, stat err=%v", err)
	}
}

// TestImportCreateDoesNotResumeNonStagingSession proves a session that has
// already moved past 'staging' (e.g. committed and running/completed) is
// never handed back by a matching create request - only an in-progress
// upload is resumable. Without this, a retry racing a load already in
// flight could return an id whose chunk/commit endpoints now reject with
// "not staging", confusing the CLI instead of transparently starting a
// fresh session.
func TestImportCreateDoesNotResumeNonStagingSession(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "sku,qty\nA,1\n"
	sum := sha256.Sum256([]byte(content))
	createBody := `{"table":"products","format":"csv","bytes":` +
		itoa(len(content)) + `,"sha256":"` + hex.EncodeToString(sum[:]) + `"}`

	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var first struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &first)
	if first.ImportID == "" {
		t.Fatalf("create failed: %s", rec.Body.String())
	}

	// Force the session out of 'staging' without going through a real
	// commit, so this test is deterministic (no race against the async
	// loader finishing before the second create fires).
	if _, err := app.DB.Exec(`UPDATE _benmore_imports SET state='running' WHERE id=?`, first.ImportID); err != nil {
		t.Fatal(err)
	}

	req = authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var second struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &second)
	if second.ImportID == "" {
		t.Fatalf("second create failed: %s", rec.Body.String())
	}
	if second.ImportID == first.ImportID {
		t.Fatal("a non-staging session must never be resumed")
	}
}

// TestImportCreateRateLimitIsPerApp guards against the same bug class an
// earlier review already caught in importRunning: _benmore_users ids are
// per-app autoincrement, so "user 1" of app A and "user 1" of app B are
// different people. Before the fix importCreateLimiter was keyed only by
// user id, so they shared one 10/minute bucket - app A could exhaust app
// B's ability to create imports (review Important 1).
func TestImportCreateRateLimitIsPerApp(t *testing.T) {
	appA, cleanupA := newImportTestApp(t)
	defer cleanupA()
	appB, cleanupB := newImportTestApp(t)
	defer cleanupB()

	muxA := http.NewServeMux()
	RegisterImportRoutes(muxA, appA)
	muxB := http.NewServeMux()
	RegisterImportRoutes(muxB, appB)

	// Both apps' first-ever user gets id=1 (fresh autoincrement) - the
	// exact collision the fix needs to survive.
	sessA := seedAdminSession(t, appA)
	sessB := seedAdminSession(t, appB)

	// A DISTINCT sha256 per request: identical create bodies now resume the
	// same staging session (review CRITICAL) rather than minting a new one,
	// which would never touch the rate limiter at all and defeat this
	// test's premise. Distinct hashes force 10 genuinely new sessions.
	bodyN := func(n int) string {
		return fmt.Sprintf(`{"table":"products","format":"csv","bytes":10,"sha256":"%02d%s"}`, n, strings.Repeat("a", 62))
	}

	// Exhaust A's 10/minute bucket.
	for i := 0; i < 10; i++ {
		req := authedRequest("POST", "/api/_import", bodyN(i), sessA)
		rec := httptest.NewRecorder()
		muxA.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("A got rate limited early, on request %d", i)
		}
	}
	req := authedRequest("POST", "/api/_import", bodyN(10), sessA)
	rec := httptest.NewRecorder()
	muxA.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("A: expected 429 after exhausting its bucket, got %d", rec.Code)
	}

	// B's identically-numbered user must be unaffected.
	req = authedRequest("POST", "/api/_import", bodyN(0), sessB)
	rec = httptest.NewRecorder()
	muxB.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("B was rate limited by A's bucket - the limiter key is not app-scoped")
	}
}

// TestImportCommitConcurrentDoubleCommitLeavesNoWindowStaging fires two
// concurrent commits at the same import id. Before the fix, both could
// pass the staging-state check, both call startImport, and the loser's
// failure handler unconditionally wrote the row BACK to "staging" while
// the winner's goroutine was actively reading the staging directory -
// reopening the chunk-PUT-append and cancel/purge windows on a load in
// flight (review Important 2). Exactly one commit must win, the row must
// never be observed back in "staging" once a commit has won, and exactly
// one copy of the row must land.
// TestImportCancelStillWorksForStagingSession pins that the review round 2
// terminal-state refusal did NOT change behavior for the normal case: an
// in-progress (never-committed) upload must still be cancellable.
func TestImportCancelStillWorksForStagingSession(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "sku,qty\nA,1\n"
	sum := sha256.Sum256([]byte(content))
	createBody := `{"table":"products","format":"csv","bytes":` + itoa(len(content)) + `,"sha256":"` + hex.EncodeToString(sum[:]) + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ImportID == "" {
		t.Fatalf("create failed: %s", rec.Body.String())
	}

	req = authedRequest("DELETE", "/api/_import/"+created.ImportID, "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel of a staging session: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// TestImportCancelRefusesCompletedSession is the review round 2 minor fix
// AND closes the concurrent-create race the reviewer found: two identical
// creates can now resume onto the SAME session (round 1's resume fix);
// the LOSING caller's commit gets a 409 and (pre-fix) called DELETE. If
// the WINNER's load had already reached "completed" by then, an
// unconditional cancel rewrote the row to "cancelled"/rows_loaded=0 out
// from under the winner - so the winner's own poll would report "Import
// was cancelled" and exit 1 despite a fully successful load. This test
// drives a real import to "completed", then proves a DELETE against it is
// refused (409) and the row is left completely unchanged.
func TestImportCancelRefusesCompletedSession(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "sku,qty\nA,1\n"
	sum := sha256.Sum256([]byte(content))
	createBody := `{"table":"products","format":"csv","bytes":` + itoa(len(content)) + `,"sha256":"` + hex.EncodeToString(sum[:]) + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", content, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = authedRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("commit status = %d body = %s", rec.Code, rec.Body.String())
	}

	var state string
	for i := 0; i < 100; i++ {
		req := authedRequest("GET", "/api/_import/"+created.ImportID, "", sessCookie)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var st struct {
			State string `json:"state"`
		}
		json.Unmarshal(rec.Body.Bytes(), &st)
		state = st.State
		if state == "completed" || state == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if state != "completed" {
		t.Fatalf("setup failed: import did not complete, last state = %q", state)
	}

	// The "loser" of a concurrent-create race would call this DELETE.
	req = authedRequest("DELETE", "/api/_import/"+created.ImportID, "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("cancel of a completed session: status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}

	// The row must be UNCHANGED - still completed, still 1 row loaded. This
	// is the actual regression the race produced: a completed import
	// silently turning into a reported cancellation.
	req = authedRequest("GET", "/api/_import/"+created.ImportID, "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var final struct {
		State      string `json:"state"`
		RowsLoaded int64  `json:"rows_loaded"`
	}
	json.Unmarshal(rec.Body.Bytes(), &final)
	if final.State != "completed" || final.RowsLoaded != 1 {
		t.Fatalf("a refused cancel must not alter the session: got state=%q rows=%d, want completed/1", final.State, final.RowsLoaded)
	}
}

// TestImportCancelRefusesFailedSessionPreservingError is the other half of
// the review round 2 minor fix: cancelling a "failed" session used to
// overwrite state/error to "cancelled"/"cancelled by caller", destroying
// the ONLY record of why a load failed - which matters most for a load
// that failed well into a long run. The error must survive a cancel
// attempt.
func TestImportCancelRefusesFailedSessionPreservingError(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE strict3 (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)")
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "n\n1\n\"\"\n"
	sum := sha256.Sum256([]byte(content))
	createBody := `{"table":"strict3","format":"csv","bytes":` + itoa(len(content)) + `,"sha256":"` + hex.EncodeToString(sum[:]) + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", content, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	req = authedRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var state, errMsg string
	for i := 0; i < 100; i++ {
		req := authedRequest("GET", "/api/_import/"+created.ImportID, "", sessCookie)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var st struct {
			State string `json:"state"`
			Error string `json:"error"`
		}
		json.Unmarshal(rec.Body.Bytes(), &st)
		state, errMsg = st.State, st.Error
		if state == "completed" || state == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if state != "failed" || errMsg == "" {
		t.Fatalf("setup failed: expected a failed import with a non-empty error, got state=%q error=%q", state, errMsg)
	}

	req = authedRequest("DELETE", "/api/_import/"+created.ImportID, "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("cancel of a failed session: status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}

	req = authedRequest("GET", "/api/_import/"+created.ImportID, "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var final struct {
		State string `json:"state"`
		Error string `json:"error"`
	}
	json.Unmarshal(rec.Body.Bytes(), &final)
	if final.State != "failed" || final.Error != errMsg {
		t.Fatalf("a refused cancel must not overwrite the failure reason: got state=%q error=%q, want state=failed error=%q",
			final.State, final.Error, errMsg)
	}
}

func TestImportCommitConcurrentDoubleCommitLeavesNoWindowStaging(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "sku,qty\nA,1\n"
	sum := sha256.Sum256([]byte(content))
	hexSum := hex.EncodeToString(sum[:])
	createBody := `{"table":"products","format":"csv","bytes":` + itoa(len(content)) + `,"sha256":"` + hexSum + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ImportID == "" {
		t.Fatalf("create failed: %s", rec.Body.String())
	}

	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", content, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk status = %d body = %s", rec.Code, rec.Body.String())
	}

	var wg sync.WaitGroup
	codes := make([]int, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			req := authedRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", sessCookie)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}(i)
	}
	close(start)
	wg.Wait()

	accepted, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusAccepted:
			accepted++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected commit status %d (codes=%v)", c, codes)
		}
	}
	if accepted != 1 || conflict != 1 {
		t.Fatalf("want exactly one 202 and one 409, got accepted=%d conflict=%d (codes=%v)", accepted, conflict, codes)
	}

	var state string
	for i := 0; i < 200; i++ {
		req := authedRequest("GET", "/api/_import/"+created.ImportID, "", sessCookie)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var st struct {
			State string `json:"state"`
		}
		json.Unmarshal(rec.Body.Bytes(), &st)
		state = st.State
		if state == "completed" || state == "failed" {
			break
		}
		// The row must never be observed back in "staging" once a commit
		// has won - that is exactly the corrupted-state window this fix
		// closes.
		if state == "staging" {
			t.Fatal("import state reverted to staging while a commit had already won")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if state != "completed" {
		t.Fatalf("import did not complete, last state = %q", state)
	}

	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 1 {
		t.Fatalf("products has %d rows, want 1 (double-run would produce 2)", n)
	}
}

// TestImportCommitReRunsDiskCheckAgainstGroundTruth is the C1 Part 3 fix:
// handleImportCommit re-runs the disk check against the ACTUALLY staged
// byte count and CURRENT free disk, right before starting the load -
// create-time preflight only ever saw a declared size and whatever free
// disk existed possibly hours earlier. This forces that re-check to fail
// by mutating the session AFTER create (simulating "disk conditions
// changed" - nothing about the staged-bytes check, which still matches
// bytes_total, would catch this) to claim a decompressed footprint no
// real test machine has free disk for.
func TestImportCommitReRunsDiskCheckAgainstGroundTruth(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "sku,qty\nA,1\n"
	sum := sha256.Sum256([]byte(content))
	hexSum := hex.EncodeToString(sum[:])
	createBody := `{"table":"products","format":"csv","bytes":` + itoa(len(content)) + `,"sha256":"` + hexSum + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ImportID == "" {
		t.Fatalf("create failed: %s", rec.Body.String())
	}

	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", content, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk status = %d body = %s", rec.Code, rec.Body.String())
	}

	if _, err := app.DB.Exec(`UPDATE _benmore_imports SET gzip=1, uncompressed_bytes=? WHERE id=?`,
		int64(1)<<60, created.ImportID); err != nil {
		t.Fatal(err)
	}

	req = authedRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("commit status = %d, want 413: %s", rec.Code, rec.Body.String())
	}

	// Must revert to 'staging' like every other commit-time rejection, not
	// wedge in 'running'.
	sess, err := loadImportSession(app.DB, created.ImportID)
	if err != nil {
		t.Fatal(err)
	}
	if sess.State != "staging" {
		t.Fatalf("state after a rejected commit = %q, want staging", sess.State)
	}
}

// csrfOnlyRequest builds a request with a valid but session-UNBOUND CSRF
// token and NO session cookie. It clears the CSRF gate without
// authenticating, so a request built this way actually reaches
// importCallerAuthorized's session==nil 401 branch instead of being
// satisfied earlier by the "missing CSRF token" 403 - the two are easy to
// conflate (both non-2xx) but only one proves the auth branch is live
// (review Important 4).
func csrfOnlyRequest(method, path, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Header.Set("X-CSRF-Token", authMintCSRFToken(""))
	return req
}

// authedRequest builds a request carrying the session cookie plus a
// session-bound CSRF token. importCallerAuthorized requires CSRF on every
// cookie-authenticated MUTATING call (GET is exempt - see
// importCallerAuthorized) - see auth_csrf.go validateCSRFReason and
// auth_csrf.go authCSRFSign for the pairing this reproduces. Sending the
// header on a GET too is harmless (simply ignored), so this helper stays
// one shape for every method.
func authedRequest(method, path, body, sess string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.Header.Set("X-CSRF-Token", authMintCSRFToken(sess))
	return req
}

// seedAdminSession creates an admin user plus a live session row and
// returns the session cookie value.
//
// The brief's original version called a nonexistent EnsureAuthTables and
// hand-inserted a _benmore_sessions row omitting the NOT NULL `email`
// column, and _benmore_users omitting the NOT NULL UNIQUE `username`
// column (db.go EnsureUsersTable, auth_sessions.go EnsureSessionsTable) -
// both would fail their INSERT outright. This version calls the real
// table-ensure functions and CreateSession (auth_sessions.go), the same helper
// production code uses, so the row shape can't drift from what
// getSession/GetSessionFromDB (auth_sessions.go) actually read.
func seedAdminSession(t *testing.T, app *App) string {
	t.Helper()
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}
	EnsureSessionsTable(app.DB)
	res, err := app.DB.Exec(
		`INSERT INTO _benmore_users (username, email, password_hash, role) VALUES (?,?,?,?)`,
		"admin", "admin@test.local", "x", "admin")
	if err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(app.DB, uid, "admin@test.local", "", time.Hour)
	if sid == "" {
		t.Fatal("CreateSession returned empty id")
	}
	return sid
}

// seedMemberSession is seedAdminSession's non-admin counterpart: role
// "user", no admin grant of any kind. Used to prove Mode A refuses a
// caller who is authenticated and may even hold table write access, but
// is not admin-or-owner (review Important 4).
func seedMemberSession(t *testing.T, app *App) string {
	t.Helper()
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}
	EnsureSessionsTable(app.DB)
	res, err := app.DB.Exec(
		`INSERT INTO _benmore_users (username, email, password_hash, role) VALUES (?,?,?,?)`,
		"member", "member@test.local", "x", "user")
	if err != nil {
		t.Fatalf("seed member user: %v", err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(app.DB, uid, "member@test.local", "", time.Hour)
	if sid == "" {
		t.Fatal("CreateSession returned empty id")
	}
	return sid
}

func itoa(n int) string { return strconv.Itoa(n) }

// ownerTokenRequest builds a request carrying only the owner-token header -
// no session cookie, no CSRF token. This is the CLI's actual shape:
// `benmore import` authenticates as a PLATFORM user, which has no identity
// in THIS app's _benmore_users, so it can never hold a session cookie or a
// session-bound CSRF token for this app (Step 3b's whole reason for being).
func ownerTokenRequest(method, path, body, token string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Header.Set("X-Benmore-Import-Token", token)
	return req
}

// TestImportOwnerTokenCreatesModeAImportWithoutSession is the Step 3b
// assertion: an owner token, with NO session cookie and NO CSRF token,
// must be able to create a Mode A (csv/ndjson) import. Without the CSRF
// exemption for a verified owner token, this request 403s on the CSRF
// gate before the owner-token check in importCallerAuthorized ever runs -
// which would silently defeat the whole point of Step 3b (the CLI
// authenticates as a platform user and can never hold this app's
// session cookie or CSRF token).
func TestImportOwnerTokenCreatesModeAImportWithoutSession(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	prev := serverSecret
	serverSecret = "test-secret-for-import-http-owner-0000"
	defer func() { serverSecret = prev }()
	token := mintImportOwnerToken(app, time.Now().Add(5*time.Minute), "owner@example.com")

	body := `{"table":"products","format":"csv","bytes":10,"sha256":"` + strings.Repeat("a", 64) + `"}`
	req := ownerTokenRequest("POST", "/api/_import", body, token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a valid owner token with no session: %s", rec.Code, rec.Body.String())
	}
}

// TestImportOwnerTokenDoesNotTripCSRFRejectLog is the M1 fix:
// importCallerAuthorized's gate used to read
// `!validateCSRF(r) && !isBearerAuth(r) && !viaOwnerToken` - Go evaluates
// && left to right, so validateCSRF (which logs a REJECT line,
// auth_csrf.go validateCSRFReason) ran and logged BEFORE either short-circuit had a chance to
// apply, on EVERY legitimate token-authenticated request: one spurious
// security-log line per 32 MiB chunk PUT on a real `benmore import` run.
// Reordering to check viaOwnerToken/isBearerAuth FIRST means a valid
// owner-token request never reaches validateCSRF at all.
func TestImportOwnerTokenDoesNotTripCSRFRejectLog(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	prev := serverSecret
	serverSecret = "test-secret-for-import-http-owner-csrf0"
	defer func() { serverSecret = prev }()
	token := mintImportOwnerToken(app, time.Now().Add(5*time.Minute), "owner@example.com")

	buf := &syncBuffer{}
	prevOut := log.Writer()
	log.SetOutput(buf)
	defer log.SetOutput(prevOut)

	body := `{"table":"products","format":"csv","bytes":10,"sha256":"` + strings.Repeat("a", 64) + `"}`
	req := ownerTokenRequest("POST", "/api/_import", body, token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(buf.String(), "validateCSRF: REJECT") {
		t.Fatalf("a valid owner-token request must not trip the CSRF reject log; got: %s", buf.String())
	}
}

// TestImportOwnerTokenExpiredOrTamperedRejected covers both failure shapes
// of the token: signature tampering and expiry. Neither may create an
// import - both fall through to the ordinary CSRF/auth gate, which a
// session-less, CSRF-token-less request always fails.
func TestImportOwnerTokenExpiredOrTamperedRejected(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	prev := serverSecret
	serverSecret = "test-secret-for-import-http-owner-0001"
	defer func() { serverSecret = prev }()

	body := `{"table":"products","format":"csv","bytes":10,"sha256":"` + strings.Repeat("a", 64) + `"}`

	expired := mintImportOwnerToken(app, time.Now().Add(-1*time.Minute), "owner@example.com")
	req := ownerTokenRequest("POST", "/api/_import", body, expired)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("an expired owner token must not create an import")
	}

	good := mintImportOwnerToken(app, time.Now().Add(5*time.Minute), "owner@example.com")
	req = ownerTokenRequest("POST", "/api/_import", body, good+"x")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("a tampered owner token must not create an import")
	}
}

// TestImportOwnerTokenCannotTargetUsersTable proves the owner token's
// blanket authority still routes through importTableAllowed: _benmore_*
// stays unreachable regardless of who is asking, admin session or owner
// token alike (review note in the brief: 403/404, never 200).
func TestImportOwnerTokenCannotTargetUsersTable(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	prev := serverSecret
	serverSecret = "test-secret-for-import-http-owner-0002"
	defer func() { serverSecret = prev }()
	token := mintImportOwnerToken(app, time.Now().Add(5*time.Minute), "owner@example.com")

	body := `{"table":"_benmore_users","format":"csv","bytes":10,"sha256":"` + strings.Repeat("a", 64) + `"}`
	req := ownerTokenRequest("POST", "/api/_import", body, token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (importTableAllowed excludes _benmore_* structurally): %s", rec.Code, rec.Body.String())
	}
}

// TestImportOwnerTokenSQLRestoreEndToEnd exercises the full Mode B path
// through HTTP: create with format "sql" (owner token required), stage the
// script, commit, and poll to completion - proving the create-time gate,
// importSessionFor's sql-format branch, and startImport's format dispatch
// all agree on the same session.
func TestImportOwnerTokenSQLRestoreEndToEnd(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)

	prev := serverSecret
	serverSecret = "test-secret-for-import-http-owner-0003"
	defer func() { serverSecret = prev }()
	token := mintImportOwnerToken(app, time.Now().Add(5*time.Minute), "owner@example.com")

	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\nINSERT INTO products (sku, qty) VALUES ('B', 2);\n"
	sum := sha256.Sum256([]byte(script))
	hexSum := hex.EncodeToString(sum[:])

	createBody := `{"format":"sql","bytes":` + itoa(len(script)) + `,"sha256":"` + hexSum + `"}`
	req := ownerTokenRequest("POST", "/api/_import", createBody, token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ImportID == "" {
		t.Fatal("create returned no import_id")
	}

	req = ownerTokenRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", script, token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = ownerTokenRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("commit status = %d body = %s", rec.Code, rec.Body.String())
	}

	var state string
	for i := 0; i < 100; i++ {
		req = ownerTokenRequest("GET", "/api/_import/"+created.ImportID, "", token)
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var st struct {
			State      string `json:"state"`
			RowsLoaded int64  `json:"rows_loaded"`
		}
		json.Unmarshal(rec.Body.Bytes(), &st)
		state = st.State
		if state == "completed" {
			if st.RowsLoaded != 2 {
				t.Fatalf("rows_loaded = %d, want 2", st.RowsLoaded)
			}
			break
		}
		if state == "failed" {
			t.Fatalf("restore failed: %s", rec.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if state != "completed" {
		t.Fatalf("restore did not complete, last state = %q", state)
	}

	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 2 {
		t.Fatalf("products has %d rows, want 2", n)
	}
}
