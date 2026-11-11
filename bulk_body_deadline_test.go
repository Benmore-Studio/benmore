//go:build !cli

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ingestTestServer serves streaming ingest for ingest_rows through the full
// production middleware chain (gzip included: Go's client asks for it) with
// the given listener timeouts.
func ingestTestServer(t *testing.T, app *App, read, write time.Duration) *httptest.Server {
	t.Helper()
	SetAppEnv(app.Dir, "RATE_LIMIT_PER_MIN", "0")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ingest_rows/ingest", func(w http.ResponseWriter, r *http.Request) {
		handleStreamingIngest(w, r, app, "ingest_rows")
	})
	srv := httptest.NewUnstartedServer(wrapMiddleware(mux, app, false))
	srv.Config.ReadTimeout = read
	srv.Config.WriteTimeout = write
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// slowNDJSON streams rows rows, one every gap.
func slowNDJSON(rows int, gap time.Duration) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < rows; i++ {
			if _, err := fmt.Fprintf(pw, "{\"note\":\"row %d\"}\n", i); err != nil {
				return
			}
			time.Sleep(gap)
		}
		pw.Close()
	}()
	return pr
}

// Observed 2026-10-29: a 60,000-row ingest was cut by the server's 15 s
// ReadTimeout after 42,489 rows, and its answer could not be written past the
// 30 s WriteTimeout either. Ingest now takes its own deadlines once the caller
// is authenticated. Scaled down: 200 ms / 300 ms listener timeouts and a body
// that takes about a second.
func TestStreamingIngestSlowBodyOutlivesServerTimeouts(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE ingest_rows (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, note TEXT)")
	_, sid := gateUser(t, app, "loader@example.com")
	srv := ingestTestServer(t, app, 200*time.Millisecond, 300*time.Millisecond)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/ingest_rows/ingest", slowNDJSON(8, 130*time.Millisecond))
	req.Header.Set("Authorization", "Bearer "+sid)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("slow ingest lost its answer: %v (committed %s rows)", err, gateScalar(t, app, "SELECT COUNT(*) FROM ingest_rows"))
	}
	defer resp.Body.Close()
	var out ingestCompletionResponse
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if resp.StatusCode != http.StatusOK || out.Status != "completed" || out.Ingested != 8 {
		t.Fatalf("slow ingest: %d %s", resp.StatusCode, body)
	}
}

// A body that stops arriving is cut at the bulk read deadline. The valid
// prefix commits (documented partial semantics) and the JSON answer says how
// many rows committed, so the caller can reconcile instead of replaying.
func TestStreamingIngestTruncatedBodyNamesCommittedRows(t *testing.T) {
	oldRead := bulkBodyReadTimeout
	bulkBodyReadTimeout = 400 * time.Millisecond
	defer func() { bulkBodyReadTimeout = oldRead }()

	app := newGateApp(t, "CREATE TABLE ingest_rows (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, note TEXT)")
	_, sid := gateUser(t, app, "loader@example.com")
	srv := ingestTestServer(t, app, 100*time.Millisecond, 200*time.Millisecond)

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Two complete rows, then the client stalls without ending the body.
	rows := "{\"note\":\"a\"}\n{\"note\":\"b\"}\n"
	fmt.Fprintf(conn, "POST /api/ingest_rows/ingest HTTP/1.1\r\nHost: app.example.com\r\nAuthorization: Bearer %s\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", sid, len(rows), rows)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer for a stalled body: %v (committed %s rows)", err, gateScalar(t, app, "SELECT COUNT(*) FROM ingest_rows"))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out ingestCompletionResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if resp.StatusCode != http.StatusBadRequest || out.Status != "partial" || out.Ingested != 2 || !strings.HasPrefix(out.Error, "read error:") {
		t.Fatalf("stalled body: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(out.Error, "2 rows") || !strings.Contains(out.Error, "committed") {
		t.Fatalf("partial answer does not say what committed: %q", out.Error)
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM ingest_rows"); n != "2" {
		t.Fatalf("committed rows = %s, want 2", n)
	}
}

// Ingest documents a 100 MB body, but the global request-body cap
// (MAX_REQUEST_BODY_BYTES, 10 MB by default) wrapped it first, so any larger
// body ended in a 413 partial at the global cap. Scaled down with a 64 KiB
// global cap.
func TestStreamingIngestNotCutByGlobalBodyCap(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE ingest_rows (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, note TEXT)")
	_, sid := gateUser(t, app, "loader@example.com")
	SetAppEnv(app.Dir, "MAX_REQUEST_BODY_BYTES", "65536")
	srv := ingestTestServer(t, app, 5*time.Second, 5*time.Second)

	var b strings.Builder
	row := "{\"note\":\"" + strings.Repeat("x", 200) + "\"}\n"
	rows := 0
	for b.Len() < 256<<10 {
		b.WriteString(row)
		rows++
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/ingest_rows/ingest", strings.NewReader(b.String()))
	req.Header.Set("Authorization", "Bearer "+sid)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out ingestCompletionResponse
	json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.Ingested != rows {
		t.Fatalf("256 KiB ingest under a 64 KiB global cap: %d %s (want %d rows)", resp.StatusCode, body, rows)
	}

	// The global cap still holds for the ordinary JSON surface and for an
	// ingest-shaped path some other handler (a flow) serves.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/{name}/ingest", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		if _, tooLarge := requestBodyTooLarge(err); tooLarge {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		}
	})
	mux.HandleFunc("POST /api/ingest_rows", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		if _, tooLarge := requestBodyTooLarge(err); tooLarge {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		}
	})
	h := wrapMiddleware(mux, app, true)
	for _, path := range []string{"/api/ingest_rows", "/api/not_a_table/ingest"} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(b.String()))
		r.Header.Set("Authorization", "Bearer "+sid)
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s escaped the global body cap: %d", path, rec.Code)
		}
	}
}

// File uploads take the bulk deadlines too, after their auth and slot checks.
func TestUploadSlowBodyOutlivesServerReadTimeout(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "RATE_LIMIT_PER_MIN", "0")
	mux := http.NewServeMux()
	RegisterUploadRoute(mux, app)
	srv := httptest.NewUnstartedServer(wrapMiddleware(mux, app, false))
	srv.Config.ReadTimeout = 200 * time.Millisecond
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	const boundary = "benmore-slow-upload"
	pr, pw := io.Pipe()
	go func() {
		io.WriteString(pw, "--"+boundary+"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"slow.txt\"\r\nContent-Type: text/plain\r\n\r\n")
		for i := 0; i < 8; i++ {
			if _, err := io.WriteString(pw, strings.Repeat("a", 1024)); err != nil {
				return
			}
			time.Sleep(130 * time.Millisecond)
		}
		io.WriteString(pw, "\r\n--"+boundary+"--\r\n")
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/_upload", pr)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.Header.Set("Authorization", "Bearer slow-upload-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("slow upload lost its answer: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"size":8192`) {
		t.Fatalf("slow upload: %d %s", resp.StatusCode, body)
	}
}
