//go:build !cli

package main

// Sign-in trail (opt-in: `auth.sign_in_audit: true` in app.yaml).
//
// The audit log records what changed an account's credentials and, by
// default, nothing of who signed in. With the switch on, every session a
// sign-in issues writes a `sign_in` row through the transaction that inserts
// the session, so no session exists without its row, and every refused
// password, code or passkey check and every lockout refusal writes a
// `sign_in_refused` row. Off (the default, and what every app had before the
// switch existed) nothing here writes or changes anything.
//
// A row holds the method and, for a refusal, a reason: never a password, a
// code, a token or a session id. The account is named by id and address as
// every other row names it. A refused attempt for no account keeps what was
// typed only when it is shaped like an address: people type passwords into
// the wrong field, and that must not land in a log admins read.

import (
	"log"
	"strconv"
	"strings"
)

const (
	accountAuditSignIn        = "sign_in"
	accountAuditSignInRefused = "sign_in_refused"

	signInAuditKey = "sign_in_audit" // under auth: in app.yaml
)

// signInAudited reports whether the app keeps the sign-in trail.
func signInAudited(app *App) bool {
	return app != nil && app.Design != nil && app.Design.Auth[signInAuditKey] == "true"
}

// auditSignIn writes the sign_in row of a session being issued, through the
// transaction that inserts it. A row that cannot be written fails the
// transaction: the caller issues no session.
func auditSignIn(tx sqlExecutor, app *App, method string, userID int64, email string) error {
	if !signInAudited(app) {
		return nil
	}
	return auditAccountEvent(tx, app, accountAuditSignIn, strconv.FormatInt(userID, 10),
		&Session{UserID: userID, Email: email}, nil, map[string]any{"method": method})
}

// auditSignInRefused writes the sign_in_refused row of an attempt that was
// turned away. userID is 0 when no account matched; identifier is then what
// was presented. Nothing depends on the row (the attempt is refused either
// way), so a failed write is logged.
func auditSignInRefused(app *App, method, reason string, userID int64, identifier string) {
	if !signInAudited(app) || app.DB == nil {
		return
	}
	rowID := ""
	if userID > 0 {
		rowID = strconv.FormatInt(userID, 10)
		if identifier == "" { // a passkey names the account, not an address
			if self, err := accountAuditSelf(app.DB, userID); err == nil {
				identifier = self.Email
			}
		}
	} else if !addressShaped(identifier) {
		identifier = ""
	}
	if err := auditAccountEvent(app.DB, app, accountAuditSignInRefused, rowID,
		&Session{UserID: userID, Email: identifier}, nil, map[string]any{"method": method, "reason": reason}); err != nil {
		log.Printf("audit: a refused sign-in could not be recorded: %v", err)
	}
}

// addressShaped is a loose test that text is an email address and not
// something else typed into the field.
func addressShaped(s string) bool {
	at := strings.IndexByte(s, '@')
	return len(s) <= 254 && at > 0 && at == strings.LastIndexByte(s, '@') && at < len(s)-1 && !strings.ContainsAny(s, " \t\r\n")
}

// auditSignInLockedOut is auditSignInRefused for a lockout refusal, which is
// decided before the account is read. It looks the account up itself, and
// only when the trail is on: an app without it runs no extra query.
func auditSignInLockedOut(app *App, method, reason, identifier string) {
	if !signInAudited(app) || app.DB == nil {
		return
	}
	field, collate := authIdentifier(app), ""
	if field == "email" {
		collate = " COLLATE NOCASE"
	}
	var id int64
	_ = app.DB.QueryRow("SELECT id FROM _benmore_users WHERE "+quoteIdent(field)+" = ?"+collate, identifier).Scan(&id)
	if id > 0 {
		identifier = "" // the row names the account by its stored address
	}
	auditSignInRefused(app, method, reason, id, identifier)
}

// createAuditedSignInSession is createSignInSession for the sign-ins that
// issue their session in a statement of its own (sign-up, social sign-in).
// With the trail on, the session and its sign_in row commit together and ""
// is returned when either cannot be written.
func createAuditedSignInSession(app *App, method string, userID int64, email, groupID string) string {
	if !signInAudited(app) {
		return createSignInSession(app.DB, userID, email, groupID, app.SessionDuration)
	}
	tx, err := app.DB.Begin()
	if err != nil {
		log.Printf("ERROR creating session: %s", err)
		return ""
	}
	defer tx.Rollback()
	token, err := createSignInSessionTx(tx, userID, email, groupID, app.SessionDuration)
	if err == nil {
		err = auditSignIn(tx, app, method, userID, email)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		log.Printf("ERROR creating session: %s", err)
		return ""
	}
	return token
}
