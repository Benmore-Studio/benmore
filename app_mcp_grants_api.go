//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"strings"
	"time"
)

// Self-service management of the signed-in account's connected AI clients
// (connector grants), the counterpart of /api/_auth/api-tokens. Mounted with
// the connector transport, so an app without mcp.yaml has neither route.
//
//	GET    /api/_mcp/grants       the caller's own live grants
//	DELETE /api/_mcp/grants/{id}  revoke one of them
func registerAppMCPGrantRoutes(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET "+appMCPGrantsRoute, func(w http.ResponseWriter, r *http.Request) { serveAppMCPGrantList(w, r, app) })
	mux.HandleFunc("DELETE "+appMCPGrantsRoute+"/{id}", func(w http.ResponseWriter, r *http.Request) { serveAppMCPGrantRevoke(w, r, app) })
}

const appMCPGrantsRoute = "/api/_mcp/grants"

// appMCPGrantsSession admits only the account holder's own interactive browser
// session: no Authorization header at all (so no API token, Bearer session or
// connector token), no scoped, edge, act-as or support/delegated session.
func appMCPGrantsSession(w http.ResponseWriter, r *http.Request, app *App) *Session {
	w.Header().Set("Cache-Control", "no-store")
	if cookie, err := requestSessionCookie(r); err != nil || cookie.Value == "" || len(r.Header.Values("Authorization")) > 0 {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "connected AI clients can be managed only from a signed-in browser session"})
		return nil
	}
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return nil
	}
	if !requireOwnAccountManagement(w, app, session) {
		return nil
	}
	if !directLoginSession(app, session) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "connected AI clients can be managed only from a direct sign-in"})
		return nil
	}
	return session
}

func serveAppMCPGrantList(w http.ResponseWriter, r *http.Request, app *App) {
	session := appMCPGrantsSession(w, r, app)
	if session == nil {
		return
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		serverErrorJSON(w, r, app, "_mcp grants", err, "connector grants unavailable")
		return
	}
	grants := []map[string]any{}
	if state.Exposed {
		var clients int
		_ = app.DB.QueryRow("SELECT COUNT(*) FROM main.sqlite_master WHERE type='table' AND name='_benmore_oauth_clients'").Scan(&clients)
		name, join := "''", ""
		if clients > 0 {
			name, join = "COALESCE(c.name,'')", " LEFT JOIN main._benmore_oauth_clients c ON c.client_id=g.client"
		}
		rows, err := app.DB.Query("SELECT g.id, g.client, "+name+", g.scopes, g.tenant, g.expires_at FROM main._benmore_mcp_grants g"+join+
			" WHERE g.user_id=? AND g.app=? AND g.epoch=? AND g.revoked=0 AND g.expires_at>? ORDER BY g.expires_at DESC, g.id",
			session.UserID, state.App, state.Epoch, time.Now().Unix())
		if err != nil {
			serverErrorJSON(w, r, app, "_mcp grants", err, "connector grants unavailable")
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id, client, clientName, scopes, tenant string
			var expires int64
			if err := rows.Scan(&id, &client, &clientName, &scopes, &tenant, &expires); err != nil {
				serverErrorJSON(w, r, app, "_mcp grants", err, "connector grants unavailable")
				return
			}
			if clientName == "" {
				clientName = client
			}
			// _benmore_mcp_grants stores no creation time. expires_at is written
			// once, at insert, as issue time + appMCPGrantLifetime, and no
			// UPDATE moves it (refresh rotates credentials, not the grant), so
			// created_at is expires_at - appMCPGrantLifetime. It is an
			// approximation only if that constant ever changes: grants issued
			// under an older lifetime would then report a shifted created_at,
			// and a stored column would be needed. last_used_at is not tracked.
			grants = append(grants, map[string]any{
				"id": id, "client_id": client, "client_name": clientName, "scopes": scopes, "workspace": tenant,
				"created_at": time.Unix(expires, 0).Add(-appMCPGrantLifetime).UTC().Format(time.RFC3339),
				"expires_at": time.Unix(expires, 0).UTC().Format(time.RFC3339),
			})
		}
		if err := rows.Err(); err != nil {
			serverErrorJSON(w, r, app, "_mcp grants", err, "connector grants unavailable")
			return
		}
	}
	httpJSON(w, http.StatusOK, map[string]any{"grants": grants})
}

func serveAppMCPGrantRevoke(w http.ResponseWriter, r *http.Request, app *App) {
	session := appMCPGrantsSession(w, r, app)
	if session == nil {
		return
	}
	if !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}
	id := r.PathValue("id")
	root, key, err := appMCPAuthorityRoot(app.Dir)
	if err != nil {
		serverErrorJSON(w, r, app, "_mcp grants", err, "connector grants unavailable")
		return
	}
	root.Close()
	revoked, err := revokeAppMCPOwnGrant(app.DB, key, id, session.UserID)
	if err != nil {
		serverErrorJSON(w, r, app, "_mcp grants", err, "revoke failed")
		return
	}
	if !revoked { // unknown, already ended, or another account's: one answer
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "grant not found"})
		return
	}
	LogAudit(app, "mcp_grant_revoke", "_benmore_mcp_grants", id, session, nil, nil)
	httpJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}

// revokeAppMCPOwnGrant ends one live grant of userID and deletes its access and
// refresh credentials in one transaction; the grant row stays as history.
func revokeAppMCPOwnGrant(db *sql.DB, appKey, id string, userID int64) (bool, error) {
	if id == "" || strings.ContainsAny(id, "/%") {
		return false, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec("UPDATE main._benmore_mcp_grants SET revoked=1 WHERE id=? AND app=? AND user_id=? AND revoked=0", id, appKey, userID)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.Exec("DELETE FROM main._benmore_mcp_credentials WHERE grant_id=?", id); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
