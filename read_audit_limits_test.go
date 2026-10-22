//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestReadAuditPageLimitsPreserveActorIsolation(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureReadAuditTable(app.DB)
	owner := createCrudScopeSession(t, app, "reader@example.com", "user", "", "")
	peer := createCrudScopeSession(t, app, "peer@example.com", "user", "", "")
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	ownerID := GetSessionFromDB(app.DB, owner).UserID
	peerID := GetSessionFromDB(app.DB, peer).UserID
	// A bounded local fixture proves negative LIMIT really removes the bound;
	// no large hosted response or resource-exhaustion experiment is needed.
	if _, err := app.DB.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1002)
		INSERT INTO _benmore_read_audit(table_name,row_id,query_type,user_id,user_email)
		SELECT 'notes',CAST(x AS TEXT),'single',?,'reader@example.com' FROM n`, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_read_audit(table_name,row_id,query_type,user_id,user_email) VALUES('notes','peer-only','single',?,'peer@example.com')`, peerID); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterReadAuditAPI(mux, app)
	// Keep this fixture's flush explicit and deterministic, without a timer.
	app.readAudit = &readAuditBuffer{db: app.DB}
	LogReadAccess(app, "notes", "pending", "read", GetSessionFromDB(app.DB, owner))
	for _, value := range []string{"-1", "0", "1001", "100000", "banana", "1.5", "9999999999999999999999999"} {
		t.Run("invalid_"+value, func(t *testing.T) {
			w := crudScopeRequest(t, mux, "GET", "/api/_audit/reads?limit="+url.QueryEscape(value), owner, nil)
			if w.Code != http.StatusBadRequest {
				var rows []map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &rows)
				t.Errorf("limit %q returned %d with %d rows; want 400", value, w.Code, len(rows))
			}
		})
	}
	var pendingRows int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_read_audit WHERE row_id='pending'").Scan(&pendingRows); err != nil || pendingRows != 0 {
		t.Fatalf("invalid limit flushed pending audit entries: rows=%d error=%v", pendingRows, err)
	}
	for _, tc := range []struct {
		name, query, token string
		count              int
		actor              int64
	}{
		{"default", "", owner, 100, ownerID},
		{"one", "?limit=1", owner, 1, ownerID},
		{"maximum", "?limit=1000", owner, 1000, ownerID},
		{"foreign_filter", fmt.Sprintf("?limit=2&user_id=%d", peerID), owner, 2, ownerID},
		{"peer_own", fmt.Sprintf("?limit=20&user_id=%d", ownerID), peer, 1, peerID},
		{"admin_actor_filter", fmt.Sprintf("?limit=20&user_id=%d", peerID), admin, 1, peerID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := crudScopeRequest(t, mux, "GET", "/api/_audit/reads"+tc.query, tc.token, nil)
			var rows []map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || w.Code != 200 || len(rows) != tc.count {
				t.Fatalf("status=%d rows=%d error=%v; want %d rows", w.Code, len(rows), err, tc.count)
			}
			for _, row := range rows {
				if row["user_id"] != float64(tc.actor) {
					t.Fatalf("unexpected actor in %s", tc.name)
				}
			}
		})
	}
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_read_audit WHERE row_id='pending'").Scan(&pendingRows); err != nil || pendingRows != 1 {
		t.Fatalf("valid request did not flush pending audit entry: rows=%d error=%v", pendingRows, err)
	}
	if w := crudScopeRequest(t, mux, "GET", "/api/_audit/reads?limit=-1", "", nil); w.Code != 401 {
		t.Errorf("authentication must precede limit validation: %d", w.Code)
	}
}
