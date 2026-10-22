//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The built review inbox emits notifications after committed transitions. Once
// its retained inbox is full, multiple writes in one timestamp second must keep
// the newest IDs so a live cursor can still retrieve a just-created notice.
func TestNotificationRetentionPreservesNewestTiedTimestamp(t *testing.T) {
	for _, mixedRead := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed_read_%t", mixedRead), func(t *testing.T) {
			app, _ := auditApp(t)
			sid := createCrudScopeSession(t, app, "retention@example.invalid", "user", "", "")
			uid := GetSessionFromDB(app.DB, sid).UserID
			// Freeze timestamp precision without a wall-clock race. This trigger
			// only gives the local fixture the same-second values real writes use.
			mustExec(t, app.DB, `CREATE TRIGGER fixture_notification_clock AFTER INSERT ON _benmore_notifications BEGIN UPDATE _benmore_notifications SET created_at='2026-10-21 12:00:00' WHERE id=NEW.id; END`)
			readExpr := "0"
			if mixedRead {
				readExpr = "n % 2"
			}
			auditExec(t, app.DB, `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<1000) INSERT INTO _benmore_notifications(user_id,title,read) SELECT ?, 'retained', `+readExpr+` FROM seq`, uid)
			var baseline int64
			if err := app.DB.QueryRow("SELECT MAX(id) FROM _benmore_notifications WHERE user_id=?", uid).Scan(&baseline); err != nil {
				t.Fatal(err)
			}
			auditExec(t, app.DB, "INSERT INTO _benmore_notifications(user_id,title) VALUES (999999,'other inbox')")
			id, err := CreateNotification(app.DB, uid, "Review submitted", "synthetic case", "info", "")
			if err != nil {
				t.Fatal(err)
			}
			var count, newest, oldest, foreign int
			for _, q := range []struct {
				sql string
				arg any
				out *int
			}{
				{"SELECT COUNT(*) FROM _benmore_notifications WHERE user_id=?", uid, &count},
				{"SELECT COUNT(*) FROM _benmore_notifications WHERE id=?", id, &newest},
				{"SELECT COUNT(*) FROM _benmore_notifications WHERE id=?", int64(1), &oldest},
				{"SELECT COUNT(*) FROM _benmore_notifications WHERE user_id=?", int64(999999), &foreign},
			} {
				if err := app.DB.QueryRow(q.sql, q.arg).Scan(q.out); err != nil {
					t.Fatal(err)
				}
			}
			if count != maxNotificationsPerUser || newest != 1 || oldest != 0 || foreign != 1 {
				t.Errorf("retention count=%d newest=%d oldest=%d other inbox=%d; want1000/1/0/1", count, newest, oldest, foreign)
			}
			mux := http.NewServeMux()
			RegisterNotificationRoutes(mux, app)
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/_notifications?after_id=%d&limit=1", baseline), nil)
			req.Header.Set("Authorization", "Bearer "+sid)
			res := httptest.NewRecorder()
			mux.ServeHTTP(res, req)
			var body struct {
				Notifications []struct{ ID int64 } `json:"notifications"`
			}
			if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &body) != nil || len(body.Notifications) != 1 || body.Notifications[0].ID != id {
				t.Errorf("new notification cannot be drained by live cursor: HTTP%d %s", res.Code, res.Body.String())
			}
		})
	}
}
