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
//
// Public uploads record their uploader too, in a table of their own
// (publicUploadOwnersTable), for the one step that needs it: `run:
// delete_upload` of a public file, which applies the same rule
// (flows_upload_owner.go). A public URL is known to everyone who can see the
// file, so without it any user could store another user's URL in a row of
// their own and have the flow that deletes "their" file delete it. The rows
// are kept apart from _benmore_upload_owners because app SQL reads that table
// as "the private files this user uploaded".

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// The uploader records: one table per tier, same columns. The names are
// constants, never request input.
const (
	privateUploadOwnersTable = "_benmore_upload_owners"
	publicUploadOwnersTable  = "_benmore_public_upload_owners"
)

// EnsureUploadOwnersTable creates the upload ownership tables.
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
	if err != nil {
		return err
	}
	// Best effort here, like the rows it holds (recordUploadOwner): a database
	// that cannot take a new table must not start refusing private uploads.
	_ = ensurePublicUploadOwnersTable(db)
	return nil
}

func ensurePublicUploadOwnersTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_public_upload_owners (
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

// recordUploadOwner records who uploads the file about to be stored at
// destPath, before any of its bytes are.
//
// A private file's row is required: missing ownership rows are reserved for
// legacy files, so a failed write must never create new private bytes without
// this record. A public file's row is best effort: uploading a public file
// never depended on this write, and a file left without a row only falls back
// to the reference rule when the app later deletes it.
func recordUploadOwner(app *App, r *http.Request, destPath string) error {
	private := isPrivateUploadPath(destPath)
	err := insertUploadOwner(app, r, destPath, private)
	if err != nil && !private {
		log.Printf("upload %s: uploader not recorded: %v", destPath, err)
		return nil
	}
	return err
}

func insertUploadOwner(app *App, r *http.Request, destPath string, private bool) error {
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
	table, ensure := publicUploadOwnersTable, ensurePublicUploadOwnersTable
	if private {
		table, ensure = privateUploadOwnersTable, EnsureUploadOwnersTable
	}
	if err := ensure(app.DB); err != nil {
		return fmt.Errorf("prepare upload ownership: %w", err)
	}
	_, err := app.DB.Exec(`INSERT INTO `+table+` (path, user_id, group_id, uploader_admin) VALUES (?, ?, ?, ?)`,
		uploadRelPath(destPath), uid, group, admin)
	return err
}

// privateUploadVouched reports whether the already-authorized record
// table/id vouches for the uploader of the private file at key.
func privateUploadVouched(app *App, session *Session, table, id, key string) bool {
	return uploadVouchedIn(app, session, privateUploadOwnersTable, table, id, key)
}

// uploadVouchedIn is the uploader rule against one tier's records (owners is
// privateUploadOwnersTable or publicUploadOwnersTable).
func uploadVouchedIn(app *App, session *Session, owners, table, id, key string) bool {
	var uploader int64
	var group string
	var admin int
	err := app.DB.QueryRow(`SELECT user_id, group_id, uploader_admin FROM `+owners+` WHERE path = ?`, key).Scan(&uploader, &group, &admin)
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
