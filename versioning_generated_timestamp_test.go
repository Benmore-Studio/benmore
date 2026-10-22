//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generatedTimestampFixture(t *testing.T, prismaTouch, encrypted bool) (*App, *http.ServeMux, string, string) {
	t.Helper()
	app, mux := newCrudScopeTestApp(t)
	attribute := ""
	if prismaTouch {
		attribute = " @updatedAt"
	}
	models, err := ParsePrismaSchema(`model TimelineRecord {
  id Int @id @default(autoincrement())
  userId Int @map("user_id")
  title String
  body String @default("")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @default(now())` + attribute + ` @map("updated_at")
}`)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, EmitSQL(models))
	if encrypted {
		path := filepath.Join(app.Dir, "data.db")
		RegisterDBEncryptionKey(path, []byte(strings.Repeat("k", 32)))
		t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(path)) })
		app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
			"timeline_records": {{Column: "body", Roles: []string{"user"}, BlindIndex: true}},
		}}
		for _, install := range []func() error{
			func() error { return EnsureBlindColumns(app.DB, app.Encrypted) },
			func() error { return InstallEncryptionTriggers(app.DB, app.Encrypted) },
			func() error { return InstallBlindIndexTriggers(app.DB, app.Encrypted) },
		} {
			if err := install(); err != nil {
				t.Fatal(err)
			}
		}
	}
	refreshTableColumns(t, app, "timeline_records")
	app.Access.rules["timeline_records"] = map[AccessOp]string{"all": "self"}
	if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"timeline_records"}}, app.Encrypted); err != nil {
		t.Fatal(err)
	}
	mux = http.NewServeMux()
	RegisterCRUD(mux, app)
	sid := createCrudScopeSession(t, app, "timeline@example.com", "user", "", "")
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/timeline_records", sid, map[string]any{"title": "created", "body": "private created"})
	var row map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &row) != nil {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	return app, mux, sid, fmt.Sprint(row["id"])
}

func generatedTimestampRead(t *testing.T, mux *http.ServeMux, sid, id, query string) map[string]any {
	t.Helper()
	w := crudScopeRequest(t, mux, http.MethodGet, "/api/timeline_records/"+id+query, sid, nil)
	var row map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &row) != nil {
		t.Fatalf("read: %d %s", w.Code, w.Body.String())
	}
	return row
}

func TestGeneratedHistoryRetainsPreciseCanonicalIntervals(t *testing.T) {
	for _, tc := range []struct {
		name             string
		touch, encrypted bool
	}{{"plain", false, false}, {"Prisma", true, false}, {"Prisma encrypted blind index", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			app, mux, sid, id := generatedTimestampFixture(t, tc.touch, tc.encrypted)
			var beforeToken, afterToken string
			for _, title := range []string{"before", "after"} {
				w := canonicalPatch(app, sid, "timeline_records", id, "application/json", fmt.Sprintf(`{"title":%q,"body":%q}`, title, "private "+title))
				if w.Code != 200 {
					t.Fatalf("patch: %d %s", w.Code, w.Body.String())
				}
				if title == "before" {
					row := generatedTimestampRead(t, mux, sid, id, "")
					// Save the exact ordinary GET token outside any clock guess.
					beforeToken = row["updated_at"].(string)
				} else {
					afterToken = generatedTimestampRead(t, mux, sid, id, "")["updated_at"].(string)
				}
			}
			// The prior state must have a nonempty generated interval, even
			// when canonical timestamps and trigger writes share one second.
			var start, end string
			if err := app.DB.QueryRow(`SELECT CAST(_valid_from AS TEXT),CAST(_valid_to AS TEXT) FROM timeline_records_history WHERE id=? AND title='before' ORDER BY _version DESC LIMIT 1`, id).Scan(&start, &end); err != nil {
				t.Fatal(err)
			}
			from, okFrom := parseUpdateTimestamp(start)
			to, okTo := parseUpdateTimestamp(end)
			if !okFrom || !okTo || !from.Before(to) {
				t.Fatalf("generated interval is empty/inverted: %q -> %q", start, end)
			}
			for _, instant := range []string{beforeToken, from.Format(time.RFC3339Nano), from.In(time.FixedZone("offset", -5*3600)).Format(time.RFC3339Nano), to.Add(-time.Nanosecond).Format(time.RFC3339Nano)} {
				got := generatedTimestampRead(t, mux, sid, id, "?as_of="+url.QueryEscape(instant))
				if got["title"] != "before" || got["body"] != "private before" {
					t.Fatalf("as_of returned newer state: %v", got)
				}
			}
			for _, instant := range []string{to.Format(time.RFC3339Nano), to.In(time.FixedZone("offset", 5*3600+1800)).Format(time.RFC3339Nano), afterToken} {
				got := generatedTimestampRead(t, mux, sid, id, "?as_of="+url.QueryEscape(instant))
				if got["title"] != "after" || got["body"] != "private after" {
					t.Fatalf("exclusive end/current boundary returned old state at %s: %v", instant, got)
				}
			}
		})
	}
}

func TestGeneratedPrismaTimestampPreservesCanonicalCAS(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
			app, mux, sid, id := generatedTimestampFixture(t, true, encrypted)
			// An accepted future token makes regression deterministic without
			// sleeping or weakening the ordinary request/CAS path.
			seedGeneratedFutureTimestamp(t, app, id)
			before := generatedTimestampRead(t, mux, sid, id, "")
			if before["updated_at"] != "2099-01-01T00:00:00.123456789Z" {
				t.Fatalf("fixture did not retain exact future seed: %v", before["updated_at"])
			}
			w := canonicalPatch(app, sid, "timeline_records", id, "application/json", fmt.Sprintf(`{"title":"winner","body":"private winner","_expected_updated_at":%q}`, before["updated_at"]))
			if w.Code != 200 {
				t.Fatalf("patch: %d %s", w.Code, w.Body.String())
			}
			after := generatedTimestampRead(t, mux, sid, id, "")
			prior, priorOK := parseUpdateTimestamp(before["updated_at"].(string))
			next, nextOK := parseUpdateTimestamp(after["updated_at"].(string))
			if !priorOK || !nextOK || !next.After(prior) {
				t.Fatalf("generated maintenance regressed canonical token: %v -> %v", before["updated_at"], after["updated_at"])
			}
			var historyBefore, auditBefore, historyAfter, auditAfter int
			generatedTimestampCount(t, app, `SELECT count(*) FROM timeline_records_history`, &historyBefore)
			generatedTimestampCount(t, app, `SELECT count(*) FROM _benmore_audit_log`, &auditBefore)
			w = canonicalPatch(app, sid, "timeline_records", id, "application/json", fmt.Sprintf(`{"title":"stale","_expected_updated_at":%q}`, before["updated_at"]))
			if w.Code != http.StatusConflict {
				t.Fatalf("stale replay: %d %s", w.Code, w.Body.String())
			}
			generatedTimestampCount(t, app, `SELECT count(*) FROM timeline_records_history`, &historyAfter)
			generatedTimestampCount(t, app, `SELECT count(*) FROM _benmore_audit_log`, &auditAfter)
			persisted := generatedTimestampRead(t, mux, sid, id, "")
			if persisted["title"] != "winner" || persisted["body"] != "private winner" || persisted["updated_at"] != after["updated_at"] || historyAfter != historyBefore || auditAfter != auditBefore {
				t.Fatal("stale update changed row/history/audit")
			}
		})
	}
}

// Seed an exact pre-existing token without letting the legacy trigger erase
// the fixture's input. Restore the captured trigger before any ordinary PATCH:
// the test must exercise the real generated maintenance behavior under review.
func seedGeneratedFutureTimestamp(t *testing.T, app *App, id string) {
	t.Helper()
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var ddl string
	if err := tx.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='trg_timeline_records_updated_at_updated'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DROP TRIGGER trg_timeline_records_updated_at_updated`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE timeline_records SET updated_at=? WHERE id=?`, "2099-01-01 00:00:00.123456789", id); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ddl); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func generatedTimestampCount(t *testing.T, app *App, query string, count *int) {
	t.Helper()
	if err := app.DB.QueryRow(query).Scan(count); err != nil {
		t.Fatal(err)
	}
}

func TestPointInTimeCurrentFallbackRejectsUnprovenHistoryGaps(t *testing.T) {
	for _, kind := range []string{"no history table", "pruned history", "retained gap", "inverted legacy boundary"} {
		t.Run(kind, func(t *testing.T) {
			app, mux := newCrudScopeTestApp(t)
			sid := createCrudScopeSession(t, app, "gap@example.com", "user", "", "")
			mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN created_at DATETIME`)
			mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN updated_at DATETIME`)
			mustExec(t, app.DB, `UPDATE notes SET created_at='2026-01-01 08:00:00',updated_at='2026-01-01 14:00:00.75',title='current' WHERE id=1`)
			refreshTableColumns(t, app, "notes")
			if kind != "no history table" {
				if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"notes"}}); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "retained gap" {
				mustExec(t, app.DB, `INSERT INTO notes_history(id,user_id,title,created_at,updated_at,_version,_valid_from,_valid_to,_change_type) VALUES(1,1,'early','2026-01-01 08:00:00','2026-01-01 08:00:00',1,'2026-01-01 08:00:00','2026-01-01 10:00:00','update')`)
			}
			if kind == "inverted legacy boundary" {
				// A legacy Prisma touch can regress the row clock below a
				// retained fractional start. It cannot prove the current state
				// existed before that later recorded boundary.
				mustExec(t, app.DB, `DROP TRIGGER _benmore_ver_notes_update`)
				mustExec(t, app.DB, `UPDATE notes SET updated_at='2026-01-01 14:00:00' WHERE id=1`)
				mustExec(t, app.DB, `INSERT INTO notes_history(id,user_id,title,created_at,updated_at,_version,_valid_from,_valid_to,_change_type) VALUES(1,1,'legacy','2026-01-01 08:00:00','2026-01-01 14:00:00.75',1,'2026-01-01 14:00:00.75','2026-01-01 14:00:00','update')`)
			}
			for _, instant := range []string{"2026-01-01T12:00:00Z", "2026-01-01T14:00:00.5Z", "2026-01-01T09:00:00.5-05:00"} {
				w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1?as_of="+url.QueryEscape(instant), sid, nil)
				if w.Code != http.StatusNotFound {
					t.Fatalf("unproven current state served at %s: %d %s", instant, w.Code, w.Body.String())
				}
			}
			if kind != "inverted legacy boundary" {
				w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1?as_of=2026-01-01T14:00:00.75Z", sid, nil)
				var row map[string]any
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &row) != nil || row["title"] != "current" {
					t.Fatalf("proven current boundary was lost: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestPointInTimeCurrentFallbackRejectsMalformedBoundary(t *testing.T) {
	for _, kind := range []string{"current timestamp", "current DATETIME timestamp", "retained start", "retained end"} {
		t.Run(kind, func(t *testing.T) {
			app, mux := newCrudScopeTestApp(t)
			sid := createCrudScopeSession(t, app, "malformed@example.com", "user", "", "")
			mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN created_at DATETIME`)
			if kind == "current DATETIME timestamp" {
				mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN updated_at DATETIME`)
			} else {
				mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN updated_at TEXT`)
			}
			mustExec(t, app.DB, `UPDATE notes SET created_at='2026-01-01 08:00:00',updated_at='2026-01-01 10:00:00',title='current' WHERE id=1`)
			if strings.HasPrefix(kind, "current ") {
				mustExec(t, app.DB, `UPDATE notes SET updated_at='unknown-time' WHERE id=1`)
			}
			refreshTableColumns(t, app, "notes")
			if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"notes"}}); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(kind, "current ") {
				from, to := "2026-01-01 10:00:00", "2026-01-01 11:00:00"
				if kind == "retained start" {
					from = "unknown-time"
				} else {
					// Sort before the query so it cannot be selected as a valid
					// historical interval by the legacy lexical predicate.
					to = "!unknown-time"
				}
				if _, err := app.DB.Exec(`INSERT INTO notes_history(id,user_id,title,created_at,updated_at,_version,_valid_from,_valid_to,_change_type) VALUES(1,1,'legacy','2026-01-01 08:00:00','2026-01-01 10:00:00',1,?,?,'update')`, from, to); err != nil {
					t.Fatal(err)
				}
			}
			w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1?as_of=2026-01-01T12:00:00Z", sid, nil)
			if w.Code != http.StatusNotFound {
				t.Fatalf("malformed boundary was discarded to serve current row: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
