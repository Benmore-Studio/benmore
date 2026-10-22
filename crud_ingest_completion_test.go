//go:build !cli

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type ingestReadFailure struct{ err error }

func (r ingestReadFailure) Read([]byte) (int, error) { return 0, r.err }

func TestStreamingIngestReportsReadFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		body func() io.Reader
		code int
	}{
		{
			name: "line too large",
			body: func() io.Reader {
				return strings.NewReader(`{"note":"` + strings.Repeat("x", 1024*1024) + "\"}\n{\"note\":\"unread\"}\n")
			},
			code: http.StatusRequestEntityTooLarge,
		},
		{
			name: "reader interrupted",
			body: func() io.Reader { return ingestReadFailure{io.ErrUnexpectedEOF} },
			code: http.StatusBadRequest,
		},
		{
			name: "body too large",
			body: func() io.Reader { return ingestReadFailure{&http.MaxBytesError{Limit: 100 * 1024 * 1024}} },
			code: http.StatusRequestEntityTooLarge,
		},
	} {
		for _, prefix := range []bool{false, true} {
			name := tc.name + "/without prefix"
			if prefix {
				name = tc.name + "/with prefix"
			}
			t.Run(name, func(t *testing.T) {
				app := newGateApp(t, "CREATE TABLE ingest_rows (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, note TEXT)")
				_, sid := gateUser(t, app, "loader@example.com")
				body := tc.body()
				wantIngested, wantStatus, wantLine := 0, "failed", 1
				if prefix {
					body = io.MultiReader(strings.NewReader("{\"note\":\"accepted\"}\n"), body)
					wantIngested, wantStatus, wantLine = 1, "partial", 2
				}
				w, out := callIngestCompletion(t, app, sid, body)
				if w.Code != tc.code || out.Status != wantStatus || out.Ingested != wantIngested || out.Errors != 1 || out.Line != wantLine || !strings.HasPrefix(out.Error, "read error:") {
					t.Fatalf("unexpected interrupted response: %d %s", w.Code, w.Body.String())
				}
				var count int
				if err := app.DB.QueryRow("SELECT COUNT(*) FROM ingest_rows").Scan(&count); err != nil || count != wantIngested {
					t.Fatalf("committed rows = %d, want %d: %v", count, wantIngested, err)
				}
				var audits int
				if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE action='ingest'").Scan(&audits); err != nil || audits != wantIngested {
					t.Fatalf("ingest audits = %d, want %d: %v", audits, wantIngested, err)
				}
			})
		}
	}
}

func TestStreamingIngestCompletedRowCounts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		ingested   int
		errorCount int
	}{
		{"valid rows", "{\"note\":\"first\"}\n\n{\"note\":\"last\"}", 2, 0},
		{"skipped malformed row", "{\"note\":\"first\"}\n{not json}\n{\"note\":\"last\"}\n", 2, 1},
		{"exact row limit", "{\"note\":\"accepted\"}\n" + strings.Repeat("{not json}\n", 99999), 1, 99999},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newGateApp(t, "CREATE TABLE ingest_rows (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, note TEXT)")
			_, sid := gateUser(t, app, "loader@example.com")
			w, out := callIngestCompletion(t, app, sid, strings.NewReader(tc.body))
			if w.Code != http.StatusOK || out.Status != "completed" || out.Ingested != tc.ingested || out.Errors != tc.errorCount || out.Error != "" {
				t.Fatalf("unexpected completion response: %d %s", w.Code, w.Body.String())
			}
			var count int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM ingest_rows").Scan(&count); err != nil || count != tc.ingested {
				t.Fatalf("committed rows = %d, want %d: %v", count, tc.ingested, err)
			}
		})
	}
}

func TestStreamingIngestRowLimitReportsRollback(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE ingest_rows (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, note TEXT)")
	_, sid := gateUser(t, app, "loader@example.com")
	body := "{\"note\":\"rolled-back\"}\n" + strings.Repeat("{not json}\n", 99999) + "{\"note\":\"over-limit\"}\n"
	w, out := callIngestCompletion(t, app, sid, strings.NewReader(body))
	if w.Code != http.StatusRequestEntityTooLarge || out.Status != "failed" || out.Ingested != 0 || out.Errors != 100000 || out.Line != 100001 || !strings.Contains(out.Error, "maximum of 100000 rows") {
		t.Fatalf("unexpected row-limit response: %d %s", w.Code, w.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM ingest_rows"); n != "0" {
		t.Fatalf("over-limit request must roll back, persisted %s rows", n)
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_audit_log WHERE action='ingest'"); n != "0" {
		t.Fatalf("over-limit request must not commit an audit, persisted %s", n)
	}
}

type ingestCompletionResponse struct {
	Ingested int    `json:"ingested"`
	Errors   int    `json:"errors"`
	Status   string `json:"status"`
	Error    string `json:"error"`
	Line     int    `json:"line"`
}

func callIngestCompletion(t *testing.T, app *App, sid string, body io.Reader) (*httptest.ResponseRecorder, ingestCompletionResponse) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/ingest_rows/ingest", body)
	r.Header.Set("Authorization", "Bearer "+sid)
	r.Header.Set("Content-Type", "application/x-ndjson")
	w := httptest.NewRecorder()
	handleStreamingIngest(w, r, app, "ingest_rows")
	var out ingestCompletionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode ingest response: %v: %s", err, w.Body.String())
	}
	return w, out
}
