//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNotificationsCursorDrainsBurstAcrossReadChanges(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "cursor@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	mux := http.NewServeMux()
	RegisterNotificationRoutes(mux, app)
	for i := 0; i < 205; i++ {
		auditExec(t, app.DB, "INSERT INTO _benmore_notifications(user_id,title,read) VALUES (?, 'task', ?)", uid, i%2)
	}
	// Another user's later ID must affect neither the baseline nor the drain.
	mustExec(t, app.DB, "INSERT INTO _benmore_notifications(user_id,title) VALUES (999999, 'other inbox')")
	read := func(query string) struct {
		Rows   []struct{ ID int64 } `json:"notifications"`
		Latest int64                `json:"latest_id"`
		Total  int                  `json:"total"`
	} {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/_notifications"+query, nil)
		req.Header.Set("Authorization", "Bearer "+sid)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		var result struct {
			Rows   []struct{ ID int64 } `json:"notifications"`
			Latest int64                `json:"latest_id"`
			Total  int                  `json:"total"`
		}
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &result) != nil {
			t.Fatalf("cursor response %d: %s", rr.Code, rr.Body.String())
		}
		return result
	}
	initial := read("?limit=1")
	if initial.Latest != 205 || initial.Total != 205 {
		t.Fatalf("baseline includes another inbox or omits read rows: %+v", initial)
	}
	var cursor int64
	for page, expected := range []int{100, 100, 5} {
		r := read(fmt.Sprintf("?after_id=%d&limit=100", cursor))
		if len(r.Rows) != expected || r.Total != 205-int(cursor) {
			t.Fatalf("page %d: rows=%d total=%d cursor=%d", page, len(r.Rows), r.Total, cursor)
		}
		for _, row := range r.Rows {
			if row.ID != cursor+1 {
				t.Fatalf("cursor skipped/repeated id %d after %d", row.ID, cursor)
			}
			cursor = row.ID
		}
		auditExec(t, app.DB, "UPDATE _benmore_notifications SET read = 1 WHERE user_id = ?", uid)
	}
	if rows := read("?after_id=205&limit=100").Rows; len(rows) != 0 {
		t.Fatalf("drain repeated old rows: %v", rows)
	}
	for _, value := range []string{"", "-1", "oops", "1.5", "9223372036854775808"} {
		req := httptest.NewRequest("GET", "/api/_notifications?after_id="+value, nil)
		req.Header.Set("Authorization", "Bearer "+sid)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != 400 {
			t.Errorf("after_id=%q status=%d", value, rr.Code)
		}
	}
}
