//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// Notification center for the Benmore framework.
// Table: _benmore_notifications
// API: GET /api/_notifications, PATCH /api/_notifications/{id}/read,
//      DELETE /api/_notifications/{id}, POST /api/_notifications/read-all
// Hook integration: notify: field in hooks.yaml
// SSE: broadcasts to target user on new notification
// Template: {{notification_count}} available in all pages

const notificationsTable = "_benmore_notifications"
const maxNotificationsPerUser = 1000

// EnsureNotificationsTable creates the notifications table if it doesn't exist.
func EnsureNotificationsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		title TEXT NOT NULL,
		body TEXT DEFAULT '',
		type TEXT DEFAULT 'info',
		read INTEGER DEFAULT 0,
		link TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_notifications_user ON _benmore_notifications(user_id, read, created_at DESC)")
}

// CreateNotification inserts a notification for a user and broadcasts via SSE.
// notifType: "info", "success", "warning", "error"
func CreateNotification(db *sql.DB, userID int64, title, body, notifType, link string) (int64, error) {
	if notifType == "" {
		notifType = "info"
	}
	// Validate type
	switch notifType {
	case "info", "success", "warning", "error":
		// valid
	default:
		notifType = "info"
	}

	result, err := db.Exec(
		`INSERT INTO _benmore_notifications (user_id, title, body, type, link)
		 VALUES (?, ?, ?, ?, ?)`,
		userID, title, body, notifType, link,
	)
	if err != nil {
		return 0, fmt.Errorf("create notification: %w", err)
	}

	id, _ := result.LastInsertId()

	// Auto-cleanup: keep only the most recent maxNotificationsPerUser per user
	db.Exec(
		`DELETE FROM _benmore_notifications WHERE user_id = ? AND id NOT IN (
			SELECT id FROM _benmore_notifications WHERE user_id = ?
			ORDER BY created_at DESC LIMIT ?
		)`,
		userID, userID, maxNotificationsPerUser,
	)

	// Broadcast via SSE to the target user only
	BroadcastChangeScoped(notificationsTable, "insert", "", userID)

	log.Printf("NOTIFICATION [%s] user=%d title=%q", notifType, userID, truncateNotif(title, 60))

	return id, nil
}

// GetUnreadNotificationCount returns the number of unread notifications for a user.
func GetUnreadNotificationCount(db *sql.DB, userID int64) int64 {
	var count int64
	db.QueryRow("SELECT COUNT(*) FROM _benmore_notifications WHERE user_id = ? AND read = 0", userID).Scan(&count)
	return count
}

// RegisterNotificationRoutes sets up notification API endpoints.
// All endpoints require authentication. Mutations require CSRF (Bearer bypass).
func RegisterNotificationRoutes(mux *http.ServeMux, app *App) {
	EnsureNotificationsTable(app.DB)

	// Rate limiter for read-all (prevent abuse)
	readAllLimiter := NewRateLimiter(10, time.Minute)

	// GET /api/_notifications — list own notifications, paginated, unread first
	mux.HandleFunc("GET /api/_notifications", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		page := 1
		perPage := 20
		if p := r.URL.Query().Get("page"); p != "" {
			if n, err := strconv.Atoi(p); err == nil && n > 0 {
				page = n
			}
		}
		if pp := r.URL.Query().Get("per_page"); pp != "" {
			if n, err := strconv.Atoi(pp); err == nil && n > 0 && n <= 100 {
				perPage = n
			}
		}
		offset := (page - 1) * perPage

		rows, err := QueryRows(app.DB,
			`SELECT id, user_id, title, body, type, read, link, created_at
			 FROM _benmore_notifications
			 WHERE user_id = ?
			 ORDER BY read ASC, created_at DESC
			 LIMIT ? OFFSET ?`,
			session.UserID, perPage, offset,
		)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}

		var total int64
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_notifications WHERE user_id = ?", session.UserID).Scan(&total)

		unread := GetUnreadNotificationCount(app.DB, session.UserID)

		httpJSON(w, http.StatusOK, map[string]any{
			"notifications": rows,
			"total":         total,
			"unread":        unread,
			"page":          page,
			"per_page":      perPage,
		})
	})

	// GET /api/_notifications/count — quick unread count (for polling/badges)
	mux.HandleFunc("GET /api/_notifications/count", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		unread := GetUnreadNotificationCount(app.DB, session.UserID)
		httpJSON(w, http.StatusOK, map[string]any{"unread": unread})
	})

	// PATCH /api/_notifications/{id}/read — mark as read (own only)
	mux.HandleFunc("PATCH /api/_notifications/{id}/read", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		// CSRF check (skip for Bearer)
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		id := r.PathValue("id")
		result, err := app.DB.Exec(
			"UPDATE _benmore_notifications SET read = 1 WHERE id = ? AND user_id = ?",
			id, session.UserID,
		)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "update failed"})
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "notification not found"})
			return
		}

		httpJSON(w, http.StatusOK, map[string]any{"status": "read"})
	})

	// DELETE /api/_notifications/{id} — dismiss (own only, admin can delete any)
	mux.HandleFunc("DELETE /api/_notifications/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		// CSRF check (skip for Bearer)
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		id := r.PathValue("id")
		var query string
		var args []any
		if session.IsAdmin() {
			// Admin can delete any notification
			query = "DELETE FROM _benmore_notifications WHERE id = ?"
			args = []any{id}
		} else {
			// Regular users can only delete own
			query = "DELETE FROM _benmore_notifications WHERE id = ? AND user_id = ?"
			args = []any{id, session.UserID}
		}

		result, err := app.DB.Exec(query, args...)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "delete failed"})
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "notification not found"})
			return
		}

		httpJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
	})

	// POST /api/_notifications/read-all — mark all as read
	mux.HandleFunc("POST /api/_notifications/read-all", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		// CSRF check (skip for Bearer)
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		// Rate limit read-all to prevent abuse
		key := fmt.Sprintf("user:%d", session.UserID)
		if !readAllLimiter.Allow(key) {
			httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
			return
		}

		result, err := app.DB.Exec(
			"UPDATE _benmore_notifications SET read = 1 WHERE user_id = ? AND read = 0",
			session.UserID,
		)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "update failed"})
			return
		}
		affected, _ := result.RowsAffected()

		httpJSON(w, http.StatusOK, map[string]any{"status": "done", "updated": affected})
	})

	log.Printf("  notifications: /api/_notifications (auth required)")
}

// InjectNotificationCount adds notification_count to the render context.
// Called from servePage for authenticated users.
func InjectNotificationCount(ctx *RenderContext) {
	if ctx.User == nil || ctx.App == nil || ctx.App.DB == nil {
		return
	}
	count := GetUnreadNotificationCount(ctx.App.DB, ctx.User.UserID)
	ctx.Data["notification_count"] = count
}

// NotifyHook holds configuration for a notification hook action.
type NotifyHook struct {
	UserID string // template: "{{user_id}}" or "{{assigned_to}}"
	Title  string // template: "New deal: {{name}}"
	Body   string // template: "Deal {{name}} was created"
	Type   string // info, success, warning, error
	Link   string // template: "/deals/{{id}}"
}

// executeNotifyHook creates a notification from a hook definition + row data.
func executeNotifyHook(db *sql.DB, notify *NotifyHook, row map[string]any, appDir string) {
	if notify == nil {
		return
	}

	// Resolve target user ID from row data
	userIDStr := interpolateRow(notify.UserID, row, appDir)
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil || userID <= 0 {
		log.Printf("HOOK ERROR [notify] invalid user_id: %q (resolved from %q)", userIDStr, notify.UserID)
		return
	}

	title := interpolateRow(notify.Title, row, appDir)
	body := interpolateRow(notify.Body, row, appDir)
	notifType := notify.Type
	if notifType == "" {
		notifType = "info"
	}
	link := interpolateRow(notify.Link, row, appDir)

	if _, err := CreateNotification(db, userID, title, body, notifType, link); err != nil {
		log.Printf("HOOK ERROR [notify] user=%d title=%q: %s", userID, title, err)
	}
}

// marshalNotifyHook serializes a NotifyHook for job payload.
func marshalNotifyHook(notify *NotifyHook) map[string]any {
	if notify == nil {
		return nil
	}
	return map[string]any{
		"user_id": notify.UserID,
		"title":   notify.Title,
		"body":    notify.Body,
		"type":    notify.Type,
		"link":    notify.Link,
	}
}

// unmarshalNotifyHook deserializes a NotifyHook from job payload.
func unmarshalNotifyHook(data map[string]any) *NotifyHook {
	if data == nil {
		return nil
	}
	return &NotifyHook{
		UserID: fmt.Sprintf("%v", data["user_id"]),
		Title:  fmt.Sprintf("%v", data["title"]),
		Body:   fmt.Sprintf("%v", data["body"]),
		Type:   fmt.Sprintf("%v", data["type"]),
		Link:   fmt.Sprintf("%v", data["link"]),
	}
}

func truncateNotif(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// CreateNotificationJSON is a convenience for creating notifications from JSON request body.
// Used internally; not exposed as an API endpoint.
func CreateNotificationJSON(db *sql.DB, body []byte) (int64, error) {
	var req struct {
		UserID int64  `json:"user_id"`
		Title  string `json:"title"`
		Body   string `json:"body"`
		Type   string `json:"type"`
		Link   string `json:"link"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, fmt.Errorf("invalid JSON: %w", err)
	}
	if req.UserID <= 0 {
		return 0, fmt.Errorf("user_id is required")
	}
	if req.Title == "" {
		return 0, fmt.Errorf("title is required")
	}
	return CreateNotification(db, req.UserID, req.Title, req.Body, req.Type, req.Link)
}
