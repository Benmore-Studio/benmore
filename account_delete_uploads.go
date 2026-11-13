//go:build !cli

package main

// The private files of an erased account.
//
// An erasure used to leave every file the person had uploaded stored and
// servable: a signed URL issued earlier kept working until it expired. Once
// the erasure commits, the deletions that run no app flow remove the private
// files whose recorded uploader (_benmore_upload_owners.user_id) is the
// account and that it did not upload as an admin: the operator delete
// (delete_app_user, `benmore users <app> delete`), and /settings/delete-account
// and the dashboard's Delete account in an app that declares no erasure flow
// of its own (appDeclaresOwnErasure). Each file goes through the app's own
// storage backend and the reference rule `run: delete_upload` uses
// (deletePrivateUpload), so a hosted app still deletes only under its own
// prefix through the peer-authenticated broker.
//
// A file the account uploaded as an admin (uploader_admin = 1) stays. The
// change erases a person's own files; a file a staff account attached to a
// client's record is the app's record, and deleting it when the staff member
// leaves would be data loss nobody can undo. Those files are counted and
// reported, and an app flow can remove one with `run: delete_upload`.
//
// Best effort, as for connector artifacts (deleteAppMCPArtifactBytes): the
// account is already gone, so a file that cannot be removed is logged and
// counted, never a reason to fail or undo the delete. Not touched:
//   - app rows (they keep their reference and the tombstone's id);
//   - public files, which the cleanup leaves to the app (`run:
//     delete_upload` with `record:`);
//   - private files with no uploader record (stored before uploaders were
//     recorded, or by a server-side step);
//   - the uploader records themselves: a private file with no record falls
//     under the looser reference-only rule (upload_owners.go), and a dev
//     instance can still read production's copy of a file it cannot delete.
//
// What was done is recorded in one audit row holding the three counts and
// nothing else (recordAccountUploadCleanup).
//
// `run: purge_current_user` does not call this: the step runs inside an app
// flow, and that flow decides what happens to the person's files. Flows in
// use keep some on purpose (a photo the person shared stays with the group
// it was shared with), so the step leaves every file where it is and
// `benmore check` says so when a purge flow removes none
// (ghaPurgeKeepsUploadsWarnings).

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// appUserDeleteTimeout is the data channel budget of user_delete: the purge
// transaction plus one storage delete per private file of the account.
const appUserDeleteTimeout = 2 * time.Minute

// accountUploadCleanupReserve is left of the operation's budget for the
// answer: a cleanup still running this close to the deadline stops, so the
// operator is told what happened instead of getting a timeout for a delete
// that already committed.
const accountUploadCleanupReserve = 10 * time.Second

// selfDeleteUploadCleanupTimeout bounds the cleanup of a self-service
// deletion. The app server ends a response 30 s after the request was read,
// and the answer says how many files went, so the cleanup stops
// accountUploadCleanupReserve before this and counts what it left.
const selfDeleteUploadCleanupTimeout = 25 * time.Second

// accountUploadCleanup counts what an account deletion did with the private
// files the account uploaded.
type accountUploadCleanup struct {
	Removed int `json:"removed"`
	Failed  int `json:"failed"`
	// KeptAdmin counts the files the account uploaded as an admin: they are
	// never removed.
	KeptAdmin int `json:"kept_admin"`
}

// addTo puts the counts in an answer under the names every deletion uses.
func (c accountUploadCleanup) addTo(answer map[string]any) {
	answer["private_files_removed"], answer["private_files_failed"] = c.Removed, c.Failed
	answer["private_files_kept_admin"] = c.KeptAdmin
}

// summary is the sentence the tool answers with.
func (c accountUploadCleanup) summary() string {
	out := fmt.Sprintf("%d private %s removed, %d failed.", c.Removed, pluralWord(c.Removed, "file"), c.Failed)
	if c.KeptAdmin > 0 {
		verb := "remain"
		if c.KeptAdmin == 1 {
			verb = "remains"
		}
		out += fmt.Sprintf(" %d private %s the account uploaded as an admin %s stored: an app flow with `run: delete_upload` removes one.", c.KeptAdmin, pluralWord(c.KeptAdmin, "file"), verb)
	}
	return out + " Public files and the app's own rows are unchanged."
}

// ownErasureFlowLeavesFiles is what a self-service deletion answers in
// `private_files` when it removed no file because the app has its own
// erasure flow.
const ownErasureFlowLeavesFiles = "left to the app's erasure flow"

// appDeclaresOwnErasure reports whether one of the app's loaded flows runs
// `purge_current_user`. Such an app has stated what happens to a person's
// files when their account goes (some keep what the person shared), so the
// built-in deletion must not decide otherwise through a door the app does
// not offer. Read from the app's current flows, published under app.mu with
// the rest of the runtime generation: a reload that adds or removes the flow
// changes the answer with it.
func appDeclaresOwnErasure(app *App) bool {
	if app == nil {
		return false
	}
	app.mu.RLock()
	flows := app.Flows
	app.mu.RUnlock()
	for i := range flows {
		if flowHasPurgeCurrentUser(flows[i].Steps) {
			return true
		}
	}
	return false
}

// ownAccountUploads is what a self-service deletion did with the account's
// private uploads: the cleanup's counts, or nothing because the app's own
// erasure flow decides (leftToFlow).
type ownAccountUploads struct {
	accountUploadCleanup
	leftToFlow bool
}

// addTo puts the outcome in the deletion's JSON answer: the three counts,
// or `private_files` saying the files were left and why.
func (o ownAccountUploads) addTo(answer map[string]any) {
	if o.leftToFlow {
		answer["private_files"] = ownErasureFlowLeavesFiles
		return
	}
	o.accountUploadCleanup.addTo(answer)
}

// removeOwnAccountUploads is the upload cleanup of a self-service deletion
// (/settings/delete-account, the dashboard's Delete account), run once the
// erasure committed. It removes nothing in an app that declares its own
// erasure flow (appDeclaresOwnErasure). It finishes within the request's
// answer time even when the client has gone: the account is already erased.
func removeOwnAccountUploads(ctx context.Context, app *App, uid int64) ownAccountUploads {
	if appDeclaresOwnErasure(app) {
		return ownAccountUploads{leftToFlow: true}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), selfDeleteUploadCleanupTimeout)
	defer cancel()
	return ownAccountUploads{accountUploadCleanup: deleteAccountPrivateUploads(ctx, app, uid, uid, "")}
}

// recordAccountUploadCleanup writes the audit row of a cleanup that found
// files: the counts and nothing else, so the row names no file and no
// address. Its actor is who asked for the erasure, as on the account_purge
// marker (the account itself, or the operator by address). table_name is
// _benmore_users so a restore carries the row forward with the other account
// events. Best effort like the cleanup; never creates the audit table.
func recordAccountUploadCleanup(app *App, uid, actorID int64, actorEmail string, out accountUploadCleanup) {
	if out == (accountUploadCleanup{}) {
		return
	}
	values, err := json.Marshal(out)
	if err == nil {
		_, err = app.DB.Exec(`INSERT INTO main._benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values)
			VALUES ('account_upload_cleanup', '_benmore_users', ?, ?, ?, NULL, ?)`, strconv.FormatInt(uid, 10), actorID, actorEmail, string(values))
	}
	if err != nil && !strings.Contains(err.Error(), "no such table") {
		log.Printf("account delete [%s]: the upload cleanup of deleted account %d could not be recorded in the audit log: %v", filepath.Base(app.Dir), uid, err)
	}
}

// deleteAccountPrivateUploads removes the stored private files whose
// recorded uploader is uid, except the ones uid uploaded as an admin, which
// it counts and leaves, and records the counts (recordAccountUploadCleanup)
// for the actor who asked for the erasure. Call it only after the
// transaction that erased the account committed.
func deleteAccountPrivateUploads(ctx context.Context, app *App, uid, actorID int64, actorEmail string) (out accountUploadCleanup) {
	if app == nil || app.DB == nil || uid <= 0 {
		return out
	}
	name := filepath.Base(app.Dir)
	rows, err := app.DB.Query(`SELECT path, uploader_admin FROM _benmore_upload_owners WHERE user_id = ? ORDER BY path`, uid)
	if err != nil {
		if !strings.Contains(err.Error(), "no such table") {
			log.Printf("account delete [%s]: could not list the private files of deleted account %d: %v", name, uid, err)
		}
		return out
	}
	var keys []string
	for rows.Next() {
		var key string
		var asAdmin int
		if err := rows.Scan(&key, &asAdmin); err != nil {
			rows.Close()
			log.Printf("account delete [%s]: could not list the private files of deleted account %d: %v", name, uid, err)
			return accountUploadCleanup{}
		}
		// Connector artifacts are removed with their manifests
		// (deleteAppMCPArtifactBytes), never as an upload.
		if appMCPArtifactStorageReference("uploads/" + key) {
			continue
		}
		if asAdmin != 0 {
			out.KeptAdmin++
			continue
		}
		keys = append(keys, key)
	}
	if err := rows.Close(); err != nil {
		log.Printf("account delete [%s]: could not list the private files of deleted account %d: %v", name, uid, err)
	}
	deadline, bounded := time.Time{}, false
	if ctx != nil {
		deadline, bounded = ctx.Deadline()
	}
	for i, key := range keys {
		logical := "uploads/" + key
		if ctx != nil && ctx.Err() != nil || bounded && time.Until(deadline) < accountUploadCleanupReserve {
			left := len(keys) - i
			out.Failed += left
			log.Printf("account delete [%s]: stopped at the time limit with %d private file(s) of deleted account %d still stored, the first %s", name, left, uid, logical)
			break
		}
		if err := deletePrivateUpload(app, logical); err != nil {
			out.Failed++
			log.Printf("account delete [%s]: could not remove private file %s of deleted account %d: %v", name, logical, uid, err)
			continue
		}
		out.Removed++
	}
	if out != (accountUploadCleanup{}) {
		log.Printf("account delete [%s]: %d private file(s) of deleted account %d removed, %d failed, %d uploaded as an admin kept", name, out.Removed, uid, out.Failed, out.KeptAdmin)
	}
	recordAccountUploadCleanup(app, uid, actorID, actorEmail, out)
	return out
}

// ghaPurgeKeepsUploadsWarnings flags a flow that erases the caller with
// `run: purge_current_user` and has no step that could remove the person's
// files: no `run: delete_upload`, and no `run: enqueue` handing the work to
// another flow. The purge step removes no file (see the file comment), so
// in such a flow every file the person uploaded stays stored and a signed
// URL already issued for one keeps working. Advisory: an app with no user
// uploads, or one that keeps them on purpose, has nothing to change.
func ghaPurgeKeepsUploadsWarnings(content string) []string {
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(content), &file); err != nil || file.Jobs == nil {
		return nil
	}
	purgeJob, purgeStep, removes := "", "", false
	var walk func(job string, steps []FlowStepGHA)
	walk = func(job string, steps []FlowStepGHA) {
		for _, s := range steps {
			switch ghaStepRunType(s) {
			case "purge_current_user":
				if purgeJob == "" {
					purgeJob, purgeStep = job, s.ID
				}
			case "delete_upload", "enqueue":
				removes = true
			}
			walk(job, s.Steps)
			walk(job, s.Else)
			walk(job, s.OnError)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(file.Jobs)) {
		walk(name, file.Jobs[name].Steps)
	}
	if purgeJob == "" || removes {
		return nil
	}
	if purgeStep == "" {
		purgeStep = "purge_current_user"
	}
	return []string{fmt.Sprintf(
		"job %q step %q (`run: purge_current_user`) erases the account and leaves every file it uploaded: the files stay stored, the rows that reference them stay, and a signed URL already issued for one keeps working. This flow has no `run: delete_upload` step and enqueues no flow that could remove them. Before the purge step, select the person's own file references and `run: delete_upload` each one, or `run: enqueue` a flow that does (api(at:\"auth\") -> account_erasure). Ignore this if the app stores no user uploads or keeps them on purpose.",
		purgeJob, purgeStep)}
}
