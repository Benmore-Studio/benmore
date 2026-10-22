//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func canonicalUpdateFixture(t *testing.T) (*App, string, int64) {
	t.Helper()
	app, _ := auditApp(t)
	EnsureLocksTable(app.DB)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	for _, statement := range []string{
		`ALTER TABLE notes ADD COLUMN org_id TEXT`,
		`ALTER TABLE notes ADD COLUMN updated_at TEXT`,
		`ALTER TABLE notes ADD COLUMN deleted_at TEXT`,
		`ALTER TABLE notes ADD COLUMN stage TEXT`,
		`ALTER TABLE notes ADD COLUMN room_id INTEGER`,
		`CREATE TABLE activities (id INTEGER PRIMARY KEY AUTOINCREMENT, note_id INTEGER, status TEXT)`,
	} {
		mustExec(t, app.DB, statement)
	}
	refreshTableColumns(t, app, "notes", "activities")
	sid := createCrudScopeSession(t, app, "canonical@example.com", "user", "tenant-a", "")
	session := GetSessionFromDB(app.DB, sid)
	if session == nil {
		t.Fatal("missing update session")
	}
	if _, err := app.DB.Exec(`INSERT INTO notes (id,user_id,org_id,title,stage,updated_at) VALUES (1,?,'tenant-a','before','open','2026-10-03 12:00:00')`, session.UserID); err != nil {
		t.Fatal(err)
	}
	return app, sid, session.UserID
}

func refreshTableColumns(t *testing.T, app *App, names ...string) {
	t.Helper()
	for _, name := range names {
		cols, err := GetTableColumns(app.DB, name)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for i := range app.Tables {
			if app.Tables[i].Name == name {
				app.Tables[i].Columns = cols
				found = true
				break
			}
		}
		if !found {
			app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
		}
	}
}

func canonicalPatch(app *App, sid, table, id, contentType, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPatch, "https://app.example.com/api/"+table+"/"+id, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	if sid != "" {
		r.Header.Set("Authorization", "Bearer "+sid)
	} else {
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(""))
	}
	w := httptest.NewRecorder()
	handleUpdate(w, r, app, table)
	return w
}

func canonicalTitle(t *testing.T, app *App) string {
	t.Helper()
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM notes WHERE id=1`).Scan(&title); err != nil {
		t.Fatal(err)
	}
	return title
}

func TestCanonicalUpdateNativeHandlerGatesAndCas(t *testing.T) {
	app, sid, uid := canonicalUpdateFixture(t)

	// Owner and tenant columns are both immutable even when submitted with a valid title.
	w := canonicalPatch(app, sid, "notes", "1", "application/json", fmt.Sprintf(`{"title":"changed","user_id":%d,"org_id":"tenant-b"}`, uid+100))
	if w.Code != http.StatusOK || canonicalTitle(t, app) != "changed" {
		t.Fatalf("valid patch: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}
	var owner int64
	var group string
	if err := app.DB.QueryRow(`SELECT user_id,org_id FROM notes WHERE id=1`).Scan(&owner, &group); err != nil {
		t.Fatal(err)
	}
	if owner != uid || group != "tenant-a" {
		t.Fatalf("protected owner/group fields changed: user=%d group=%q", owner, group)
	}

	var updated string
	if err := app.DB.QueryRow(`SELECT updated_at FROM notes WHERE id=1`).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	w = canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"stale","_expected_updated_at":"2020-01-01"}`)
	if w.Code != http.StatusConflict || canonicalTitle(t, app) != "changed" {
		t.Fatalf("stale JSON CAS: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}

	form := url.Values{"title": {"form changed"}, "_expected_updated_at": {updated}}
	w = canonicalPatch(app, sid, "notes", "1", "application/x-www-form-urlencoded", form.Encode())
	if w.Code != http.StatusOK || canonicalTitle(t, app) != "form changed" {
		t.Fatalf("form CAS: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}
}

func TestCanonicalUpdateNativeHandlerForeignViewerAndMemberRepoint(t *testing.T) {
	t.Run("foreign tenant row", func(t *testing.T) {
		app, _, _ := canonicalUpdateFixture(t)
		sid := createCrudScopeSession(t, app, "foreign@example.com", "user", "tenant-a", "")
		w := canonicalPatch(app, sid, "orgdocs", "2", "application/json", `{"title":"crossed"}`)
		if w.Code != http.StatusNotFound {
			t.Fatalf("foreign tenant patch: %d %s", w.Code, w.Body.String())
		}
		var title string
		if err := app.DB.QueryRow(`SELECT title FROM orgdocs WHERE id=2`).Scan(&title); err != nil || title != "private-b" {
			t.Fatalf("foreign row changed: title=%q err=%v", title, err)
		}
	})

	t.Run("viewer update denied", func(t *testing.T) {
		app, sid, _ := canonicalUpdateFixture(t)
		app.Access.rules["notes"] = map[AccessOp]string{"read": "self", "update": "admin"}
		w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"viewer-write"}`)
		if w.Code != http.StatusNotFound || canonicalTitle(t, app) != "before" {
			t.Fatalf("viewer updated row: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
		}
	})

	t.Run("member cannot repoint", func(t *testing.T) {
		app, sid, uid := canonicalUpdateFixture(t)
		mustExec(t, app.DB, `CREATE TABLE messages (id INTEGER PRIMARY KEY, room_id INTEGER, user_id INTEGER, body TEXT)`)
		refreshTableColumns(t, app, "messages")
		app.Access.rules["messages"] = map[AccessOp]string{"all": "member-of:room_members(room_id, member_id)"}
		mustExec(t, app.DB, `INSERT INTO rooms (id,title) VALUES (2,'other')`)
		if _, err := app.DB.Exec(`INSERT INTO room_members (id,room_id,member_id) VALUES (1,1,?)`, uid); err != nil {
			t.Fatal(err)
		}
		mustExec(t, app.DB, `INSERT INTO messages VALUES (1,1,1,'hello')`)
		w := canonicalPatch(app, sid, "messages", "1", "application/json", `{"room_id":2}`)
		if w.Code != http.StatusNotFound {
			t.Fatalf("member repoint: %d %s", w.Code, w.Body.String())
		}
		var roomID int
		if err := app.DB.QueryRow(`SELECT room_id FROM messages WHERE id=1`).Scan(&roomID); err != nil || roomID != 1 {
			t.Fatalf("message was repointed: room=%d err=%v", roomID, err)
		}
	})
}

func TestCanonicalUpdateNativeHandlerPreservesAnonymousAndEveryoneModes(t *testing.T) {
	t.Run("anonymous anon access", func(t *testing.T) {
		app, _, _ := canonicalUpdateFixture(t)
		app.Access.rules["notes"] = map[AccessOp]string{"all": "anon"}
		w := canonicalPatch(app, "", "notes", "1", "application/json", `{"title":"anonymous edit"}`)
		if w.Code != http.StatusOK || canonicalTitle(t, app) != "anonymous edit" {
			t.Fatalf("anonymous update: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
		}
	})
	t.Run("authenticated everyone access", func(t *testing.T) {
		app, sid, _ := canonicalUpdateFixture(t)
		app.Access.rules["notes"] = map[AccessOp]string{"all": "everyone"}
		w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"everyone edit"}`)
		if w.Code != http.StatusOK || canonicalTitle(t, app) != "everyone edit" {
			t.Fatalf("everyone update: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
		}
	})
}

func TestCanonicalUpdateNativeHandlerValidatorBeforeHookAndSoftDelete(t *testing.T) {
	app, sid, _ := canonicalUpdateFixture(t)
	app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"notes": {{Rule: "title != 'blocked'", Error: "custom validator denial"}}}}
	for _, title := range []string{"blocked", "hook denied"} {
		if title == "hook denied" {
			app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {{When: "title = 'hook denied'", SQL: `SELECT 'custom approval denial' AS error`}}}}
		}
		w := canonicalPatch(app, sid, "notes", "1", "application/json", fmt.Sprintf(`{"title":%q}`, title))
		if w.Code != http.StatusUnprocessableEntity || canonicalTitle(t, app) != "before" {
			t.Fatalf("%s denial: status=%d body=%s title=%q", title, w.Code, w.Body.String(), canonicalTitle(t, app))
		}
	}

	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {{SQL: `UPDATE notes SET deleted_at=datetime('now') WHERE id={{id}}`}}}}
	w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"must roll back"}`)
	if w.Code != http.StatusNotFound || canonicalTitle(t, app) != "before" {
		t.Fatalf("before-hook soft-delete race was accepted: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}
	var deleted sql.NullString
	if err := app.DB.QueryRow(`SELECT deleted_at FROM notes WHERE id=1`).Scan(&deleted); err != nil || deleted.Valid {
		t.Fatalf("soft-delete hook escaped rollback: value=%v err=%v", deleted, err)
	}
}

func TestCanonicalUpdateTxReadbackAuditAndSQLActivity(t *testing.T) {
	app, sid, _ := canonicalUpdateFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{
		"notes": {
			{SQL: `UPDATE notes SET title='changed by SQL hook' WHERE id={{id}}`},
			{SQL: `INSERT INTO activities(note_id,status) VALUES({{id}},'{{old_stage}}')`},
		},
	}}
	actor := GetSessionFromDB(app.DB, sid)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	before, after, _, err := applyCanonicalUpdateTx(tx, app, actor, "notes", "1", map[string]any{"title": "submitted"}, "")
	if err != nil {
		t.Fatalf("canonical tx update: %v", err)
	}
	if before["title"] != "before" || after["title"] != "changed by SQL hook" {
		t.Fatalf("before/authoritative after = %v / %v", before["title"], after["title"])
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var activityCount int
	var activityStatus string
	if err := app.DB.QueryRow(`SELECT COUNT(*),MIN(status) FROM activities WHERE note_id=1`).Scan(&activityCount, &activityStatus); err != nil {
		t.Fatal(err)
	}
	if activityCount != 1 || activityStatus != "open" {
		t.Fatalf("SQL completion activity count/status=%d/%q", activityCount, activityStatus)
	}
	var oldJSON, newJSON string
	if err := app.DB.QueryRow(`SELECT old_values,new_values FROM _benmore_audit_log WHERE table_name='notes' AND action='update' AND row_id='1'`).Scan(&oldJSON, &newJSON); err != nil {
		t.Fatal(err)
	}
	var oldRow, newRow map[string]any
	if err := json.Unmarshal([]byte(oldJSON), &oldRow); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(newJSON), &newRow); err != nil {
		t.Fatal(err)
	}
	if oldRow["title"] != "before" || newRow["title"] != "changed by SQL hook" {
		t.Fatalf("audit old/new snapshots = %v / %v", oldRow["title"], newRow["title"])
	}
}

func TestCanonicalUpdateTransactionEndpointUsesSharedPipeline(t *testing.T) {
	app, sid, _ := canonicalUpdateFixture(t)
	app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"notes": {{SQL: `UPDATE notes SET title='transaction hook readback' WHERE id={{id}}`}}}}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	w := auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"update","id":1,"data":{"title":"stale","_expected_updated_at":"2020-01-01"}}]}`, false)
	if w.Code != http.StatusConflict || canonicalTitle(t, app) != "before" {
		t.Fatalf("transaction CAS: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}
	w = auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"update","id":1,"data":{"title":"submitted"}}]}`, false)
	if w.Code != http.StatusOK || canonicalTitle(t, app) != "transaction hook readback" {
		t.Fatalf("transaction update: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}
	var oldJSON, newJSON string
	if err := app.DB.QueryRow(`SELECT old_values,new_values FROM _benmore_audit_log WHERE table_name='notes' AND action='update' AND row_id='1'`).Scan(&oldJSON, &newJSON); err != nil {
		t.Fatal(err)
	}
	var oldRow, newRow map[string]any
	if err := json.Unmarshal([]byte(oldJSON), &oldRow); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(newJSON), &newRow); err != nil {
		t.Fatal(err)
	}
	if oldRow["title"] != "before" || newRow["title"] != "transaction hook readback" {
		t.Fatalf("transaction audit old/new = %v / %v", oldRow["title"], newRow["title"])
	}
}

func TestCanonicalUpdateTransactionEndpointAuditFailureRollsBack(t *testing.T) {
	app, sid, _ := canonicalUpdateFixture(t)
	mustExec(t, app.DB, `CREATE TRIGGER reject_transaction_audit BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT,'reject audit'); END`)
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	w := auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"update","id":1,"data":{"title":"must roll back"}}]}`, false)
	if w.Code != http.StatusInternalServerError || canonicalTitle(t, app) != "before" {
		t.Fatalf("transaction audit failure: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}
	var auditCount int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name='notes' AND action='update'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 0 {
		t.Fatalf("transaction audit failure left %d update audit rows", auditCount)
	}
}

func TestCanonicalUpdateTxAuditsAndDurableNetworkIntentRollback(t *testing.T) {
	app, sid, _ := canonicalUpdateFixture(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"notes": {{Webhook: server.URL}}}}
	app.DB.SetMaxOpenConns(1)
	actor := GetSessionFromDB(app.DB, sid)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, _, err := applyCanonicalUpdateTx(tx, app, actor, "notes", "1", map[string]any{"title": "submitted"}, ""); err != nil {
		t.Fatalf("canonical tx update: %v", err)
	}
	var jobs int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM _benmore_jobs WHERE job_type='hook'`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("transactional hook intent count=%d err=%v", jobs, err)
	}
	if requests.Load() != 0 {
		t.Fatal("observed network traffic before the caller committed")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if canonicalTitle(t, app) != "before" {
		t.Fatal("rolled-back tx kept its business update")
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_jobs`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("rolled-back hook intent count=%d err=%v", jobs, err)
	}
	if requests.Load() != 0 {
		t.Fatal("observed network traffic after the caller rolled back")
	}
}

func TestCanonicalUpdateTxPropagatesWebhookOwnerLookupFailure(t *testing.T) {
	app, sid, _ := canonicalUpdateFixture(t)
	EnsureUserRolesTable(app.DB)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_webhooks(user_id,url,secret,tables,events) SELECT id,'https://hooks.example.test/update','secret','notes','update' FROM _benmore_users WHERE email='canonical@example.com'`); err != nil {
		t.Fatal(err)
	}
	actor := GetSessionFromDB(app.DB, sid)
	if actor == nil {
		t.Fatal("missing actor session")
	}
	mustExec(t, app.DB, `DROP TABLE _benmore_user_roles`)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, _, _, err = applyCanonicalUpdateTx(tx, app, actor, "notes", "1", map[string]any{"title": "must roll back"}, "")
	if err == nil || !strings.Contains(err.Error(), "update side effect failed") {
		_ = tx.Rollback()
		t.Fatalf("webhook owner query failure was hidden: %v", err)
	}
	if rollbackErr := tx.Rollback(); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	if canonicalTitle(t, app) != "before" {
		t.Fatal("webhook owner lookup failure kept the business update")
	}
}

func TestCanonicalUpdateHandlerFaultsRollbackAndAnnouncesOnlyCommit(t *testing.T) {
	for _, failure := range []string{"audit", "hook job", "webhook job"} {
		t.Run(failure, func(t *testing.T) {
			app, sid, uid := canonicalUpdateFixture(t)
			sub := subscribeFlowRealtime(t, app, sid)
			switch failure {
			case "audit":
				mustExec(t, app.DB, `CREATE TRIGGER reject_update_audit BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT,'reject audit'); END`)
			case "hook job":
				app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"notes": {{Webhook: "https://hooks.example.test/update"}}}}
				mustExec(t, app.DB, `CREATE TRIGGER reject_update_job BEFORE INSERT ON _benmore_jobs BEGIN SELECT RAISE(ABORT,'reject job'); END`)
			case "webhook job":
				adminSID := createCrudScopeSession(t, app, "subscriber@example.com", "admin", "tenant-a", "")
				admin := GetSessionFromDB(app.DB, adminSID)
				if admin == nil || admin.UserID == uid {
					t.Fatal("test admin missing")
				}
				if _, err := app.DB.Exec(`INSERT INTO _benmore_webhooks(user_id,url,secret,tables,events) VALUES(?, 'https://hooks.example.test/update', 'secret', 'notes', 'update')`, admin.UserID); err != nil {
					t.Fatal(err)
				}
				mustExec(t, app.DB, `CREATE TRIGGER reject_update_job BEFORE INSERT ON _benmore_jobs BEGIN SELECT RAISE(ABORT,'reject job'); END`)
			}
			sub.drain()
			w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"must roll back"}`)
			if w.Code != http.StatusInternalServerError || canonicalTitle(t, app) != "before" {
				t.Fatalf("%s failure did not roll back: status=%d body=%s title=%q", failure, w.Code, w.Body.String(), canonicalTitle(t, app))
			}
			var auditCount, jobCount int
			if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log WHERE action='update'`).Scan(&auditCount); err != nil {
				t.Fatal(err)
			}
			if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_jobs`).Scan(&jobCount); err != nil {
				t.Fatal(err)
			}
			if auditCount != 0 || jobCount != 0 {
				t.Fatalf("%s failure leaked audit/jobs: %d/%d", failure, auditCount, jobCount)
			}
			sse, ws := sub.drain()
			if len(sse) != 0 || len(ws) != 0 {
				t.Fatalf("%s rollback broadcast: SSE=%v WS=%v", failure, sse, ws)
			}
		})
	}

	t.Run("one committed announcement", func(t *testing.T) {
		app, sid, _ := canonicalUpdateFixture(t)
		sub := subscribeFlowRealtime(t, app, sid)
		sub.drain()
		w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"committed"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("committed update: %d %s", w.Code, w.Body.String())
		}
		sse, ws := sub.drain()
		if len(sse) != 1 || len(ws) != 1 || !strings.Contains(sse[0], `"table":"notes"`) || !strings.Contains(sse[0], `"action":"update"`) {
			t.Fatalf("commit announcements SSE=%v WS=%v", sse, ws)
		}
	})
}
