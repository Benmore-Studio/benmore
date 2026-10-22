//go:build !cli

package main

// Batch review page (first-party fallback): one page lists every pending,
// unexpired operation one connection (grant) prepared for the signed-in
// person, so several first_party writes need one browser visit, not one each.
//   - GET  /api/_mcp/operations/batch?grant=<id>
//   - POST /api/_mcp/operations/batch/approve   (grant, op..., _csrf)
// The gates are the single-operation page's: browser cookie session only
// (never a bearer), a direct unscoped login, the same rate limits and CSP.
// One CSRF token is bound to this session and grant:<id>. Approving runs the
// unchanged appMCPReviewOperation once per selected operation, each in its own
// transaction, so every approval stays a human approval sealed on its own.

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"time"
)

const appMCPBatchRoute = appMCPOperationRoute + "batch"

// appMCPBatchBinding ties the batch token to one session AND one grant.
func appMCPBatchBinding(sessionCookie, grantID string) string {
	return sessionCookie + "|grant:" + grantID
}

// appMCPBatchReviewURL is where a prepared result sends the person to approve
// everything that connection has pending.
func appMCPBatchReviewURL(resource, grantID string) string {
	return appMCPOAuthOrigin(resource) + appMCPBatchRoute + "?grant=" + url.QueryEscape(grantID)
}

type appMCPPendingOperation struct {
	ID, Command string
	ExpiresAt   int64
}

// appMCPPendingOperations lists the actor's own unfinished, unexpired
// connector operations prepared by grantID, oldest first. Like
// appMCPOperationCommandOwner it confers nothing: each one is re-read and fully
// bound to the session inside the coordinator before it is shown or approved.
// ponytail: decrypts every unfinished operation, bounded like the prepare scan
// by the per-actor cap and the expiry sweep.
func appMCPPendingOperations(ctx context.Context, app *App, actorID int64, grantID string, now time.Time) ([]appMCPPendingOperation, error) {
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT operation_id FROM main._benmore_mcp_operations WHERE receipt_digest IS NULL")
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	var pending []appMCPPendingOperation
	created := map[string]int64{}
	for _, id := range ids {
		stored, err := readAppMCPStoredOperation(ctx, tx, app, id)
		if err != nil {
			continue // unreadable rows are skipped, as by the prepare scan
		}
		p := stored.Prepared
		if stored.Receipt != nil || p.Origin.Kind != "connector" || p.Origin.ActorID != actorID || !SecureCompare(p.Origin.GrantID, grantID) || now.Unix() >= p.ExpiresAt {
			continue
		}
		pending = append(pending, appMCPPendingOperation{ID: id, Command: p.Command, ExpiresAt: p.ExpiresAt})
		created[id] = p.CreatedAt
	}
	sort.SliceStable(pending, func(i, j int) bool {
		if created[pending[i].ID] != created[pending[j].ID] {
			return created[pending[i].ID] < created[pending[j].ID]
		}
		return pending[i].ID < pending[j].ID
	})
	return pending, nil
}

func registerAppMCPBatchRoutes(mux appRouteRegistrar, app *App, resource string, limits func() *appMCPOperationLimits) {
	mux.HandleFunc("GET "+appMCPBatchRoute, func(w http.ResponseWriter, r *http.Request) {
		serveAppMCPOperationBatch(w, r, app, resource, limits(), false)
	})
	mux.HandleFunc("POST "+appMCPBatchRoute+"/approve", func(w http.ResponseWriter, r *http.Request) {
		serveAppMCPOperationBatch(w, r, app, resource, limits(), true)
	})
}

func serveAppMCPOperationBatch(w http.ResponseWriter, r *http.Request, app *App, resource string, limits *appMCPOperationLimits, approve bool) {
	w.Header().Set("Cache-Control", "no-store")
	if approve {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if r.ParseForm() != nil || r.URL.RawQuery != "" {
			writeAppMCPCannotApprove(w, app)
			return
		}
	}
	grantID := r.URL.Query().Get("grant")
	if approve {
		grantID = r.PostForm.Get("grant")
	}
	generation := snapshotAppMCPGeneration(app)
	// Same order as the single page (serveAppMCPOperation): a malformed grant
	// is judged only after the viewer is signed in, so a signed-out request
	// such as ?grant=x is sent to /login instead of a bare 404 that reads as
	// "route not mounted" (#770).
	if generation == nil || generation.manifest == nil || !appMCPOAuthHost(r, app, resource) || (approve && !appMCPIsHex(grantID, 32)) {
		writeAppMCPCannotShow(w, app)
		return
	}
	_, writesLive := appMCPWritesLive(app)
	if limits.ip.refuse(w, app, "mcp-operation-ip:"+clientIP(r)) {
		return
	}
	hasAuthorization := len(r.Header.Values("Authorization")) > 0
	cookie, cookieErr := requestSessionCookie(r)
	var session *Session
	if cookieErr == nil && !hasAuthorization {
		session = GetSessionFromDB(app.DB, cookie.Value)
	}
	if session == nil && !approve && !hasAuthorization {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	if session == nil || session.ImpersonatorUserID != 0 || session.ActingAsGroup != "" || !directLoginSession(app, session) {
		if approve {
			writeAppMCPCannotApprove(w, app)
		} else {
			writeAppMCPCannotShow(w, app)
		}
		return
	}
	// Writes off is said only to a signed-in direct session: signed out, every
	// connector app answers the same redirect, so a stranger cannot map which
	// apps have approved writes switched on.
	if !writesLive {
		writeAppMCPApprovalsOff(w, app)
		return
	}
	if !appMCPIsHex(grantID, 32) {
		writeAppMCPCannotShow(w, app)
		return
	}
	serverSide := func(class string) {
		w.Header().Set(requestIDHeader, recordRequestError(r, "[mcp batch review] "+class))
		writeAppMCPUnavailable(w, app)
	}
	pending, err := appMCPPendingOperations(r.Context(), app, session.UserID, grantID, appMCPClock())
	if err != nil {
		appMCPLogCommandError("batch", "", err)
		serverSide("unavailable_provider")
		return
	}
	uid := strconv.FormatInt(session.UserID, 10)
	request := func(command string) appMCPCommandRequest {
		return appMCPCommandRequest{app: app, generation: generation, toolName: command,
			origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: session.ID}}
	}
	if approve {
		selected := r.PostForm["op"]
		if len(selected) > appMCPOperationActorLimit || !appMCPBoundCSRF(r, appMCPBatchBinding(cookie.Value, grantID)) {
			writeAppMCPCannotApprove(w, app)
			return
		}
		if len(selected) == 0 { // a valid submit with nothing ticked: say so, approve nothing
			http.Redirect(w, r, appMCPBatchRoute+"?grant="+url.QueryEscape(grantID)+"&notice=none", http.StatusSeeOther)
			return
		}
		byID := map[string]appMCPPendingOperation{}
		for _, op := range pending {
			byID[op.ID] = op
		}
		var chosen []appMCPPendingOperation
		for _, id := range selected {
			op, ok := byID[id]
			if !ok || slices.ContainsFunc(chosen, func(c appMCPPendingOperation) bool { return c.ID == id }) {
				writeAppMCPCannotApprove(w, app)
				return
			}
			chosen = append(chosen, op)
		}
		challenge := r.PostForm.Get(csrfTokenName)
		approved := 0
		for _, op := range chosen {
			// Each approval spends the same per-user budget as on its own
			// page, charged just before it runs: a 429 midway spends nothing
			// for the changes left pending.
			if limits.approve.refuse(w, app, "mcp-operation:"+uid) {
				return
			}
			if _, err := appMCPReviewOperation(r.Context(), request(op.Command), op.ID, challenge); err != nil {
				// Each is its own transaction: one refusal (already approved,
				// expired, source changed) leaves the others to go ahead.
				appMCPLogCommandError("batch", op.ID, err)
				continue
			}
			approved++
		}
		http.Redirect(w, r, appMCPBatchRoute+"?grant="+url.QueryEscape(grantID)+"&approved="+strconv.Itoa(approved), http.StatusSeeOther)
		return
	}
	if len(pending) > 0 && r.Header.Get("Sec-Fetch-Site") != "cross-site" && limits.review.refuse(w, app, "mcp-operation-review:"+uid) {
		return
	}
	var items []appMCPBatchItem
	now := appMCPClock()
	for _, op := range pending {
		review, err := appMCPReviewOperation(r.Context(), request(op.Command), op.ID, "")
		if err != nil {
			if class := appMCPLogCommandError("batch", op.ID, err); class == "unavailable_provider" || class == "incomplete_result" {
				serverSide(class)
				return
			}
			continue // foreign tenant, stale source and refusals are not shown
		}
		if review.State != "prepared" {
			continue
		}
		items = append(items, newAppMCPReviewView(review, op.ID, now))
	}
	// The notices only echo this page's own post-approval redirect: a link from
	// another site cannot make the page claim changes were approved.
	ownRedirect := r.Header.Get("Sec-Fetch-Site") != "cross-site" && r.Header.Get("Sec-Fetch-Site") != "same-site"
	approvedNotice := -1
	if ownRedirect {
		approvedNotice = appMCPBatchApprovedCount(r.URL.Query().Get("approved"))
	}
	csrf := ""
	if len(items) > 0 {
		csrf = authMintCSRFToken(appMCPBatchBinding(cookie.Value, grantID)) // this session and this grant only
	}
	writeAppMCPPage(w, app, http.StatusOK, appMCPBatchReviewPage, appMCPPageOpts{Title: "Review requested changes", Wide: true, Referrer: "same-origin"},
		map[string]any{"Items": items, "CSRF": csrf, "Grant": grantID, "Action": appMCPBatchRoute + "/approve",
			"NoneTicked": ownRedirect && r.URL.Query().Get("notice") == "none", "Approved": approvedNotice})
}

// appMCPBatchApprovedCount reads the post-approval count from the redirect. It
// is display-only (the page re-reads what is still pending), bounded, and a
// value that isn't a plain small number shows nothing.
func appMCPBatchApprovedCount(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > appMCPOperationActorLimit || raw != strconv.Itoa(n) {
		return -1
	}
	return n
}
