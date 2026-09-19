//go:build !cli

package main

import (
	"net/http"
	"path/filepath"
)

// App directories, rather than basenames, distinguish deployed environments.
func realtimeAppID(dir string) string {
	if dir == "" {
		return ""
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	return filepath.Clean(abs)
}

func realtimeSameApp(a, b *App) bool {
	if a == nil || b == nil {
		return false
	}
	if a.DB != nil && a.DB == b.DB {
		return true
	}
	return a.Dir != "" && b.Dir != "" && realtimeAppID(a.Dir) == realtimeAppID(b.Dir)
}

// Keep the request credential, not just a connect-time admin flag. Revocation,
// expiry, role changes and tenant switches apply to established streams too.
type realtimePrincipal struct {
	app     *App
	request *http.Request
	session *Session
}

func (p realtimePrincipal) current() (*Session, bool) {
	if p.request == nil {
		return p.session, true
	} // in-process synthetic clients
	var current *Session
	if p.app != nil && p.app.DB != nil {
		current = getSession(p.app, p.request)
	}
	if p.session == nil {
		return nil, current == nil
	}
	if current == nil || current.UserID != p.session.UserID ||
		current.EffectiveGroupID() != p.session.EffectiveGroupID() ||
		current.IsAdminBypass() != p.session.IsAdminBypass() {
		return nil, false
	}
	return current, true
}

func (p realtimePrincipal) canRead(table string, userID int64) bool {
	session, valid := p.current()
	if !valid || p.app == nil {
		return false
	}
	if table == notificationsTable {
		return session != nil && session.UserID == userID
	}
	return SessionCanAccessTable(p.app, table, OpRead, session) &&
		(session == nil || checkScope(session, table, "read") == nil)
}
