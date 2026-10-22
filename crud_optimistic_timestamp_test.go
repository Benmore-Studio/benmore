//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func optimisticTimestampFixture(t *testing.T, columnType, initial string) (*App, string) {
	t.Helper()
	app, sid, uid := canonicalUpdateFixture(t)
	mustExec(t, app.DB, fmt.Sprintf(`CREATE TABLE booking_notes (id INTEGER PRIMARY KEY, user_id INTEGER, body TEXT, updated_at %s)`, columnType))
	if _, err := app.DB.Exec(`INSERT INTO booking_notes VALUES (1,?,'before',?),(2,?,'second',?)`, uid, initial, uid, initial); err != nil {
		t.Fatal(err)
	}
	refreshTableColumns(t, app, "booking_notes")
	app.Access.rules["booking_notes"] = map[AccessOp]string{"all": "self"}
	return app, sid
}

func optimisticTimestampRead(t *testing.T, app *App, sid, id string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/api/booking_notes/"+id, nil)
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	handleRead(w, r, app, "booking_notes")
	var row map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &row) != nil {
		t.Fatalf("read: status=%d body=%s", w.Code, w.Body.String())
	}
	return row
}

func TestOptimisticTimestampFreshReadAndRapidStaleUpdate(t *testing.T) {
	for _, tc := range []struct{ name, columnType, initial string }{
		{"sqlite datetime", "DATETIME", "2026-10-14 11:30:28"},
		{"fractional offset datetime", "DATETIME", "2026-10-14T13:30:28.123456789+02:00"},
		{"legacy text", "TEXT", "2026-10-14 11:30:28"},
		{"date only text", "TEXT", "2026-10-14"},
		{"date only datetime", "DATETIME", "2026-10-14"},
		{"sqlite UTC marker", "DATETIME", "2026-10-14 11:30:28.123456789Z"},
		// The existing version can be ahead of this server's clock. It must
		// still advance, without sleeping or weakening the stale-write guard.
		{"future datetime", "DATETIME", "2099-01-01T00:00:00.123456789Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, sid := optimisticTimestampFixture(t, tc.columnType, tc.initial)
			for i := range 3 {
				before := optimisticTimestampRead(t, app, sid, "1")
				body := fmt.Sprintf(`{"body":"winner %d","_expected_updated_at":%q}`, i, before["updated_at"])
				w := canonicalPatch(app, sid, "booking_notes", "1", "application/json", body)
				if w.Code != http.StatusOK {
					t.Fatalf("fresh GET version was rejected: %d %s; read=%v", w.Code, w.Body.String(), before)
				}
				after := optimisticTimestampRead(t, app, sid, "1")
				if after["body"] != fmt.Sprintf("winner %d", i) || after["updated_at"] == before["updated_at"] {
					t.Fatalf("write did not advance visible version: before=%v after=%v", before, after)
				}
				if tc.columnType == "DATETIME" {
					oldTime, err1 := time.Parse(time.RFC3339Nano, before["updated_at"].(string))
					newTime, err2 := time.Parse(time.RFC3339Nano, after["updated_at"].(string))
					if err1 != nil || err2 != nil || !newTime.After(oldTime) {
						t.Fatalf("version did not advance monotonically: before=%v after=%v", before, after)
					}
				}
				w = canonicalPatch(app, sid, "booking_notes", "1", "application/json", fmt.Sprintf(`{"body":"stale","_expected_updated_at":%q}`, before["updated_at"]))
				if w.Code != http.StatusConflict || optimisticTimestampRead(t, app, sid, "1")["body"] != after["body"] {
					t.Fatalf("stale version overwrote winner: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestOptimisticTimestampTransactionRollback(t *testing.T) {
	app, sid := optimisticTimestampFixture(t, "DATETIME", "2026-10-14 11:30:28")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	before := optimisticTimestampRead(t, app, sid, "1")
	// The first update is permitted and reaches SQLite, then the stale second
	// update must roll it back, including the version and its audit entry.
	body := fmt.Sprintf(`{"operations":[{"table":"booking_notes","action":"update","id":1,"data":{"body":"rolled back","_expected_updated_at":%q}},{"table":"booking_notes","action":"update","id":2,"data":{"body":"stale","_expected_updated_at":"2020-01-01T00:00:00Z"}}]}`, before["updated_at"])
	w := auditPost(mux, sid, "/api/_transaction", "", body, false)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale second operation: %d %s", w.Code, w.Body.String())
	}
	after := optimisticTimestampRead(t, app, sid, "1")
	if after["body"] != before["body"] || after["updated_at"] != before["updated_at"] {
		t.Fatalf("transaction leaked first update: before=%v after=%v", before, after)
	}
	var audits int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name='booking_notes'`).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("rolled back audit count=%d err=%v", audits, err)
	}
	body = fmt.Sprintf(`{"operations":[{"table":"booking_notes","action":"update","id":1,"data":{"body":"committed","_expected_updated_at":%q}}]}`, before["updated_at"])
	w = auditPost(mux, sid, "/api/_transaction", "", body, false)
	if w.Code != http.StatusOK || optimisticTimestampRead(t, app, sid, "1")["body"] != "committed" {
		t.Fatalf("fresh transaction version rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestOptimisticTimestampRejectsRoundedTokenAndSupportsNull(t *testing.T) {
	app, sid := optimisticTimestampFixture(t, "DATETIME", "2099-01-01T00:00:00.123456789Z")
	w := canonicalPatch(app, sid, "booking_notes", "1", "application/json", `{"body":"rounded overwrite","_expected_updated_at":"2099-01-01T00:00:00.123Z"}`)
	if w.Code != http.StatusConflict || optimisticTimestampRead(t, app, sid, "1")["body"] != "before" {
		t.Fatalf("rounded token was accepted: %d %s", w.Code, w.Body.String())
	}
	mustExec(t, app.DB, `UPDATE booking_notes SET updated_at=NULL WHERE id=1`)
	if optimisticTimestampRead(t, app, sid, "1")["updated_at"] != nil {
		t.Fatal("null version did not stay null on read")
	}
	w = canonicalPatch(app, sid, "booking_notes", "1", "application/json", `{"body":"stale null overwrite","_expected_updated_at":"2099-01-01T00:00:00Z"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("non-null token matched null version: %d %s", w.Code, w.Body.String())
	}
	w = canonicalPatch(app, sid, "booking_notes", "1", "application/json", `{"body":"first version"}`)
	if w.Code != http.StatusOK || optimisticTimestampRead(t, app, sid, "1")["updated_at"] == nil {
		t.Fatalf("unconditional update did not initialize null version: %d %s", w.Code, w.Body.String())
	}
}

func TestOptimisticTimestampConcurrentWriters(t *testing.T) {
	for _, endpoint := range []string{"patch", "transaction"} {
		t.Run(endpoint, func(t *testing.T) {
			app, sid := optimisticTimestampFixture(t, "DATETIME", "2099-01-01T00:00:00.123456789Z")
			mux := http.NewServeMux()
			RegisterCRUD(mux, app)
			before := optimisticTimestampRead(t, app, sid, "1")
			type outcome struct {
				status int
				body   string
				writer string
			}
			start := make(chan struct{})
			results := make(chan outcome, 2)
			for _, writer := range []string{"Alice", "Bob"} {
				go func() {
					<-start
					data := fmt.Sprintf(`{"body":%q,"_expected_updated_at":%q}`, writer, before["updated_at"])
					var w *httptest.ResponseRecorder
					if endpoint == "transaction" {
						w = auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"booking_notes","action":"update","id":1,"data":`+data+`}]}`, false)
					} else {
						w = canonicalPatch(app, sid, "booking_notes", "1", "application/json", data)
					}
					results <- outcome{w.Code, w.Body.String(), writer}
				}()
			}
			close(start)
			a, b := <-results, <-results
			if a.status != http.StatusOK {
				a, b = b, a
			}
			if a.status != http.StatusOK || b.status != http.StatusConflict {
				t.Fatalf("same-base writers must have one winner: %+v %+v", a, b)
			}
			after := optimisticTimestampRead(t, app, sid, "1")
			if after["body"] != a.writer || after["updated_at"] == before["updated_at"] {
				t.Fatalf("winner/version not persisted: winner=%+v row=%v", a, after)
			}
		})
	}
}
