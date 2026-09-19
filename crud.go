//go:build !cli

package main

// CRUD route registration, shared authentication, and limiter initialization.

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RegisterCRUD sets up automatic CRUD API routes for all tables.
// requireAPIAuth checks if the app requires authentication and rejects unauthenticated API requests.
// Tables listed in auth.public_api OR with access:<table>:<op>: anon in app.yaml are exempt.
// Returns true if the request should be blocked (caller should return immediately).
//
// v2.7.29 fix: previously this gate ran BEFORE the declarative
// `access:` system (v2.7.12) - so a table marked `read: anon` would
// still be rejected with 401 on any app with `auth:` configured. That
// silently broke the canonical "logged-out viewers can read public
// data" pattern that `read: anon` exists to enable. Now requireAPIAuth
// peeks at the access mode for the (table, op) tuple and bails out of
// the auth gate when the developer explicitly opted into anon for
// this op. The legacy `auth.public_api` whitelist still works as a
// shorthand for tables that are anon for every op.
func requireAPIAuth(w http.ResponseWriter, r *http.Request, app *App, table string) bool {
	// Auth is opt-in: only enforce when the developer wrote an `auth:`
	// block in app.yaml. Check `len(...)`, not nil - the map is always
	// initialized non-nil during config load, so a nil-check would
	// silently make every app require auth even with no `auth:` block.
	if app.Design == nil || len(app.Design.Auth) == 0 {
		return false // no auth configured - all APIs public
	}
	// Check if this table is in the public_api whitelist (legacy escape hatch).
	if publicTables, ok := app.Design.Auth["public_api"]; ok {
		for _, t := range strings.Split(fmt.Sprintf("%v", publicTables), ",") {
			if strings.TrimSpace(t) == table {
				return false // whitelisted as public
			}
		}
	}
	// New v2.7.29: declarative `access:` config can opt this op into
	// anon access. We resolve the op for the current method and check
	// if the mode is "anon" - if so, skip the auth gate entirely.
	// EnforceCRUDAccess still runs downstream and enforces the per-op
	// rules; this just stops requireAPIAuth from masking them.
	if app.Access != nil {
		op := accessOpForMethod(r.Method)
		hasUID := hasColumn(app, table, "user_id")
		hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
		if app.Access.AllowsAnon(app.Access.ModeFor(table, op, hasUID, hasGroupKey)) {
			return false // declarative access: anon - let the request through
		}
	}
	session := getSession(app, r)
	if session == nil {
		// N19 hint: when reading an owner-scoped table without an
		// explicit access: rule, point the agent at access.read: anon.
		// An earlier app build built a custom /api/feed flow before
		// discovering this was the right lever.
		body := `{"error":"authentication required"}`
		op := accessOpForMethod(r.Method)
		hasUID := hasColumn(app, table, "user_id")
		if op == OpRead && hasUID && !app.Access.HasExplicitRule(table, op) {
			body = `{"error":"authentication required","hint":"This table is owner-scoped (visitors see 401). For a public feed, declare ` + "`access:\\n  " + table + ":\\n    read: anon`" + ` in app.yaml. Run benmore docs for the full access-mode catalogue."}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(body))
		return true
	}
	// Meter API request (session already resolved, no extra DB call)
	Increment(meterScope(session), "api_requests")
	if r.Method != "GET" && r.Method != "HEAD" {
		Increment(meterScope(session), "api_mutations")
	}
	return false
}

// accessOpForMethod maps the HTTP method to the declarative-access op
// name used by access.yaml. /api/<table>/batch and other non-canonical
// shapes still pass through this map; sub-route gates downstream
// (handleBatchCreate, etc.) re-check ops they may interpret differently.
func accessOpForMethod(method string) AccessOp {
	switch method {
	case "GET", "HEAD":
		return "read"
	case "POST":
		return "write"
	case "PATCH", "PUT":
		return "update"
	case "DELETE":
		return "delete"
	}
	return "read"
}

func RegisterCRUD(mux *http.ServeMux, app *App) {
	tables, err := GetTableNames(app.DB)
	if err != nil {
		return
	}

	for _, table := range tables {
		t := table // capture for closure
		// POST /api/{table} - create
		mux.HandleFunc(fmt.Sprintf("POST /api/%s", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleCreate(w, r, app, t)
		})

		// GET /api/{table} - list
		mux.HandleFunc(fmt.Sprintf("GET /api/%s", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleList(w, r, app, t)
		})

		// GET /api/{table}/{id} - read
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleRead(w, r, app, t)
		})

		// PATCH /api/{table}/{id} - update
		mux.HandleFunc(fmt.Sprintf("PATCH /api/%s/", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleUpdate(w, r, app, t)
		})

		// PATCH /api/{table} - singleton-row upsert for tables with UNIQUE(user_id).
		// Closes the profile/settings save loop: one row per user, no ID needed.
		mux.HandleFunc(fmt.Sprintf("PATCH /api/%s", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleSingletonUpdate(w, r, app, t)
		})

		// DELETE /api/{table}/{id} - delete
		mux.HandleFunc(fmt.Sprintf("DELETE /api/%s/", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleDelete(w, r, app, t)
		})

		// POST /api/{table}/batch - batch create (JSON array)
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/batch", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleBatchCreate(w, r, app, t)
		})

		// PATCH /api/{table}/batch - bulk update (JSON: {ids: [...], fields: {...}})
		mux.HandleFunc(fmt.Sprintf("PATCH /api/%s/batch", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleBatchUpdate(w, r, app, t)
		})

		// DELETE /api/{table}/batch - bulk delete (JSON: {ids: [...]})
		mux.HandleFunc(fmt.Sprintf("DELETE /api/%s/batch", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleBatchDelete(w, r, app, t)
		})

		// POST /api/{table}/ingest - streaming NDJSON ingestion
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/ingest", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleStreamingIngest(w, r, app, t)
		})
	}

	// POST /api/_transaction - atomic cross-table operations
	mux.HandleFunc("POST /api/_transaction", func(w http.ResponseWriter, r *http.Request) {
		if requireAPIAuth(w, r, app, "_transaction") {
			return
		}
		handleTransaction(w, r, app)
	})
}

// ingestLimiter limits streaming ingestion to 5 requests per minute per user (expensive operation).
var ingestLimiter = NewRateLimiter(5, time.Minute)
