//go:build !cli

package main

// Private-file ownership. Signing a private file requires naming a record
// the caller can read that references the file - but references are just
// column values, so a caller who learned another user's private path could
// write it into a record of their own and sign it. Each private upload now
// records who uploaded it, and a signature is issued only when the
// referencing record vouches for that uploader:
//
//   - the caller is the uploader;
//   - the record's owner (user_id) is the uploader;
//   - on a tenant-keyed table, the record's tenant is the uploader's tenant
//     at upload time; or
//   - an app admin uploaded it (admins attach files to other users' rows).
//
// Files uploaded before ownership was recorded have no row and keep the
// previous rule (a readable record that references them).

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
)

// EnsureUploadOwnersTable creates the private-upload ownership table.
func EnsureUploadOwnersTable(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("upload ownership database unavailable")
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_upload_owners (
		path TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL DEFAULT 0,
		group_id TEXT NOT NULL DEFAULT '',
		uploader_admin INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	return err
}

// privateUploadKey is the canonical ownership key for an upload reference in
// any spelling (CDN URL, /uploads/private/x, uploads/private/x, private/x):
// the logical path under uploads/, e.g. "private/x.pdf".
func privateUploadKey(app *App, raw string) string {
	if cfg := getPlatformMedia(); cfg != nil {
		if url, _, ok := cdnURLForServe(app, raw, cfg); ok {
			key := strings.TrimPrefix(url, "https://"+cfg.CDNDomain+"/")
			if parts := strings.SplitN(key, "/", 3); len(parts) == 3 {
				return uploadRelPath(parts[2])
			}
		}
	}
	return uploadRelPath(raw)
}

// recordPrivateUploadOwner reserves a new private file's ownership before
// any file bytes are stored. Missing ownership rows are reserved for legacy
// files, so a failed write must never create new bytes without this record.
func recordPrivateUploadOwner(app *App, r *http.Request, destPath string) error {
	if !isPrivateUploadPath(destPath) {
		return nil
	}
	if app == nil || app.DB == nil {
		return fmt.Errorf("upload ownership database unavailable")
	}
	session := getSession(app, r)
	var uid int64
	group, admin := "", 0
	if session != nil {
		uid = session.UserID
		group = session.EffectiveGroupID()
		if session.IsAdmin() {
			admin = 1
		}
	}
	if err := EnsureUploadOwnersTable(app.DB); err != nil {
		return fmt.Errorf("prepare upload ownership: %w", err)
	}
	_, err := app.DB.Exec(`INSERT INTO _benmore_upload_owners (path, user_id, group_id, uploader_admin) VALUES (?, ?, ?, ?)`,
		uploadRelPath(destPath), uid, group, admin)
	return err
}

// privateUploadVouched reports whether the already-authorized record
// table/id vouches for the uploader of the private file at key.
func privateUploadVouched(app *App, session *Session, table, id, key string) bool {
	var uploader int64
	var group string
	var admin int
	err := app.DB.QueryRow(`SELECT user_id, group_id, uploader_admin FROM _benmore_upload_owners WHERE path = ?`, key).Scan(&uploader, &group, &admin)
	if err != nil {
		// No ownership row: a file from before ownership was recorded (or
		// written by a server-side step), so the reference rule alone applies.
		return err == sql.ErrNoRows || strings.Contains(err.Error(), "no such table")
	}
	if admin == 1 || (session != nil && uploader != 0 && session.UserID == uploader) {
		return true
	}
	if uploader != 0 && hasColumn(app, table, "user_id") {
		var owner sql.NullInt64
		app.DB.QueryRow("SELECT user_id FROM "+quoteIdent(table)+" WHERE id = ?", id).Scan(&owner)
		if owner.Valid && owner.Int64 == uploader {
			return true
		}
	}
	if group != "" && app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key) {
		var rowGroup sql.NullString
		app.DB.QueryRow("SELECT "+quoteColumn(table, app.Group.Key)+" FROM "+quoteIdent(table)+" WHERE id = ?", id).Scan(&rowGroup)
		if rowGroup.Valid && rowGroup.String == group {
			return true
		}
	}
	return false
}
