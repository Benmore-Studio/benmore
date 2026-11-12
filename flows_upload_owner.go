//go:build !cli

package main

// Private-upload ownership for `run: serve_file` and `run: delete_upload`.
//
// Both steps act on a reference the flow read from a row, and the flow's SQL
// decides which row a caller reaches. A reference is only a column value,
// though: a user who learned another user's private reference could store it
// in a row of their own through auto-CRUD, and the documented owner-scoped
// lookup (`SELECT file_url FROM documents WHERE id = :id AND user_id =
// :user_id`) then handed it to serve_file (the other user's bytes) or
// delete_upload (their file deleted). /api/_signed_url already refuses this
// with the uploader records (upload_owners.go); these steps now apply the
// same rule, privateUploadVouched, when the step names the row:
//
//   - with `record: {table, id}`, that row must reference the file and its
//     owner (user_id) or tenant must be the uploader's: a teammate's file in
//     a shared tenant, an anonymous share link, a cron or event flow.
//     Anything else is refused before any byte is read, redirected or
//     deleted.
//   - a PUBLIC file (delete_upload only) is deleted on the same proof and
//     never without it: `record:` is required (flowPublicUploadOwnerRefusal).
//   - without `record:`, a private file's step still acts as before (the flow's SQL is
//     the gate) and only logs a file the caller did not upload. Enforcing
//     the uploader rule there would refuse the common cross-user flows
//     (staff opening a member's document, a driver viewing a customer's
//     photo, cron cleanup), which 14 hosted apps had without `record:` when
//     this shipped. A later release refuses once apps name their records.

import (
	"fmt"
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// ghaUploadRecord reads a serve_file or delete_upload step's `with.record`.
// Any value makes the step name a record, so one without a table and an id
// refuses the file at run time instead of falling back to the caller check.
func ghaUploadRecord(v any) *FlowUploadRecord {
	rec := &FlowUploadRecord{}
	m, ok := v.(map[string]any)
	if !ok {
		return rec
	}
	if t, ok := m["table"].(string); ok {
		rec.Table = strings.TrimSpace(t)
	}
	switch id := m["id"].(type) {
	case string:
		rec.ID = normalizeGHARefs(id)
	case int, int64, uint64, float64:
		rec.ID = fmt.Sprint(id)
	}
	return rec
}

// flowPrivateUploadOwnerRefusal applies the signed-URL ownership rule to the
// private upload at logical (uploads/private/...), which the step resolved
// through backend. recordID is the step's interpolated `record.id`. It
// returns "" when the file may be served or deleted, else why not.
func flowPrivateUploadOwnerRefusal(ctx *FlowContext, record *FlowUploadRecord, recordID string, backend StorageBackend, logical string) string {
	app := ctx.App
	if app == nil || app.DB == nil {
		if record == nil {
			return "" // advisory without a record: nothing to look up
		}
		return "upload ownership records are unavailable"
	}
	key := uploadRelPath(logical)
	if record == nil {
		// No row: privateUploadVouched checks the uploader alone (an empty
		// table has neither a user_id nor a tenant column). Advisory for now
		// (see the file comment): the flow's own SQL stays the gate.
		if !privateUploadVouched(app, ctx.Session, "", "", key) {
			logUnvouchedPrivateUpload(app, logical)
		}
		return ""
	}
	return uploadRecordRefusal(ctx, record, recordID, backend, logical, privateUploadOwnersTable)
}

// flowPublicUploadOwnerRefusal is the proof `run: delete_upload` needs before
// it deletes the public upload at logical (uploads/...): the same `record:`
// rule a private file gets, and never advisory. A public URL is no secret,
// so the flow's own SQL cannot be the only gate: the step must name the row,
// the row must reference the file, and it must belong to the uploader or the
// uploader's tenant (an admin upload or a file with no uploader record still
// passes). It returns "" when the file may be deleted, else why not.
func flowPublicUploadOwnerRefusal(ctx *FlowContext, record *FlowUploadRecord, recordID string, backend StorageBackend, logical string) string {
	if record == nil {
		return "a public upload is deleted only with `record:` naming the row that owns it: add `with: { record: { table: <table>, id: <row id> } }` (api(at:\"uploads\") public_deletion)"
	}
	if ctx.App == nil || ctx.App.DB == nil {
		return "upload ownership records are unavailable"
	}
	return uploadRecordRefusal(ctx, record, recordID, backend, logical, publicUploadOwnersTable)
}

// uploadRecordRefusal checks a step's `record:` against the upload at
// logical: a table of this app and a row, the row references the file, and
// the row vouches for the uploader recorded in owners.
func uploadRecordRefusal(ctx *FlowContext, record *FlowUploadRecord, recordID string, backend StorageBackend, logical, owners string) string {
	app := ctx.App
	if !safeIdent(record.Table) || !appHasTable(app, record.Table) || recordID == "" {
		return "`record:` must name a table of this app (`table:`) and a row (`id:`)"
	}
	if !recordReferencesPrivateUpload(app, backend, record.Table, recordID, logical) {
		return "the `record:` row does not reference this file"
	}
	if !uploadVouchedIn(app, ctx.Session, owners, record.Table, recordID, uploadRelPath(logical)) {
		return "this record does not own the file: it was uploaded by someone the record doesn't belong to"
	}
	return ""
}

// flowCallerCanReadRecord reports whether the run's signed-in caller could
// read the `record:` row through auto-CRUD, by the three checks the
// connector's file tools make (appMCPAuthorizeFileRecord): the table's read
// mode, the credential's `<table>:read` scope, and the per-row scope. The row
// scope alone is not the rule: it is empty on a table with no owner or tenant
// column, where the mode (`admin`, `role:`, `perm:`, `off`) decides
// everything, and it never looks at a credential's scopes. A run with no
// caller is refused.
//
// extract_text asks this when a request chose its reference. serve_file and
// delete_upload do not ask it: their flow's own gates and SQL authorize the
// caller (an anonymous share link, staff opening a member's file, cron
// cleanup), and `record:` there only vouches for the uploader.
func flowCallerCanReadRecord(ctx *FlowContext, table, id string) bool {
	session := ctx.Session
	if session == nil {
		return false
	}
	return SessionCanAccessTable(ctx.App, table, OpRead, session) &&
		checkScope(session, table, "read") == nil &&
		canAccessRowScoped(ctx.App, table, id, session, "view")
}

// unvouchedUploadLogged throttles logUnvouchedPrivateUpload per app.
var unvouchedUploadLogged sync.Map // app dir -> time.Time

// logUnvouchedPrivateUpload notes a serve_file or delete_upload without
// `record:` that acted on a private file the caller did not upload, at most
// once per app every ten minutes, so the owner can add `record:` before the
// rule is enforced.
func logUnvouchedPrivateUpload(app *App, logical string) {
	now := time.Now()
	if last, ok := unvouchedUploadLogged.Load(app.Dir); ok && now.Sub(last.(time.Time)) < 10*time.Minute {
		return
	}
	unvouchedUploadLogged.Store(app.Dir, now)
	log.Printf("serve_file/delete_upload [%s]: acted on %s, a private file the caller did not upload, with no `record:` naming the row that owns it. A later release will refuse this: add `with: { record: { table: <table>, id: <row id> } }` (api(at:\"uploads\") private_ownership)", filepath.Base(app.Dir), logical)
}

// recordReferencesPrivateUpload reports whether table/id stores the upload at
// logical (private, or public for delete_upload) in some column, in any
// spelling the signed-URL checks accept (recordReferencesLocalFile,
// recordReferencesFile) or as the object URL of the app's own bucket.
func recordReferencesPrivateUpload(app *App, backend StorageBackend, table, id, logical string) bool {
	if recordReferencesLocalFile(app, table, id, logical) {
		return true
	}
	if cfg := getPlatformMedia(); cfg != nil && recordReferencesFile(app, table, id, logical, cfg) {
		return true
	}
	// A configured bucket stores its object URL, which neither form above
	// normalizes; recordReferencesLocalFile leaves a URL as is, so this is
	// an exact comparison.
	if s3, ok := backend.(*S3Storage); ok {
		return recordReferencesLocalFile(app, table, id, s3.objectURL(logical))
	}
	return false
}

// serveFileNamesPrivateUpload reports a serve_file path that names a private
// upload in any spelling: a media-CDN URL in the private tier, or an uploads
// path through a folder named private in any letter case (a case-insensitive
// disk opens uploads/PRIVATE/x as uploads/private/x). Such a path must be
// the stored reference itself (privateUploadPath, the delete_upload rule).
func serveFileNamesPrivateUpload(app *App, raw string, cfg *PlatformMediaConfig) bool {
	if cfg != nil && strings.HasPrefix(raw, "https://"+cfg.CDNDomain+"/") {
		_, isPrivate, ok := cdnURLForServe(app, raw, cfg)
		return ok && isPrivate
	}
	return isPrivateUploadPath(strings.ToLower(raw))
}

// serveFileStorage is the backend serve_file reads from: the platform media
// CDN when configured, else the app's uploads/ directory.
func serveFileStorage(app *App, cfg *PlatformMediaConfig) StorageBackend {
	if cfg != nil {
		if c := newCDNStorage(app); c != nil {
			return c
		}
	}
	return &LocalStorage{Dir: app.Dir}
}

// uploadRecordValueProblems checks a serve_file or delete_upload step's
// `with.record`. The table is literal: request input must not pick which
// table vouches for a file.
func uploadRecordValueProblems(with map[string]any) []string {
	v, ok := with["record"]
	if !ok {
		return nil
	}
	shape := "`with.record` names the row that owns the private file, as `record: { table: documents, id: \"${{ steps.doc.outputs.id }}\" }`"
	m, ok := v.(map[string]any)
	if !ok {
		return []string{shape + "; the file is refused at run time until it does."}
	}
	var problems []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if k != "table" && k != "id" {
			problems = append(problems, fmt.Sprintf("`with.record.%s` is not read: %s.", k, shape))
		}
	}
	switch table, _ := m["table"].(string); {
	case strings.TrimSpace(table) == "":
		problems = append(problems, "`with.record` has no `table:`: "+shape+".")
	case strings.Contains(table, "{{") || !safeIdent(strings.TrimSpace(table)):
		problems = append(problems, fmt.Sprintf("`with.record.table` %q must be a literal table name (letters, digits, underscore), not a template: request input must not choose which table vouches for a file.", table))
	}
	switch id := m["id"].(type) {
	case string:
		if strings.TrimSpace(id) == "" {
			problems = append(problems, "`with.record.id` is empty: "+shape+".")
		}
	case int, int64, uint64, float64:
	default:
		problems = append(problems, "`with.record` has no `id:` (text or a number): "+shape+".")
	}
	return problems
}

// ghaPrivateUploadRecordWarnings flags serve_file and delete_upload steps
// with no `record:` in a flow that has no signed-in caller (a public
// request, a schedule or a data event). Once the uploader rule is enforced
// without a record, such a step refuses every file a user uploaded; only
// admin uploads and files from before ownership was recorded pass.
// Advisory: the step may serve public files only.
func ghaPrivateUploadRecordWarnings(content string) []string {
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(content), &file); err != nil || file.Jobs == nil {
		return nil
	}
	if flowRequestSignedIn(file.On.Request) {
		return nil
	}
	var out []string
	var walk func(job string, steps []FlowStepGHA)
	walk = func(job string, steps []FlowStepGHA) {
		for _, s := range steps {
			run := ghaStepRunType(s)
			if run == "serve_file" || run == "delete_upload" {
				if _, named := s.With["record"]; !named {
					label := s.ID
					if label == "" {
						label = run
					}
					out = append(out, fmt.Sprintf(
						"job %q step %q (`run: %s`) has no `record:` and the flow has no signed-in caller. A later release serves or deletes a private upload only for the user who uploaded it unless the step names the row that owns it, so this step will then refuse every private file a user uploaded (admin uploads and files from before ownership was recorded will still pass). Add `record: { table: <table>, id: \"${{ steps.<lookup>.outputs.id }}\" }` naming the row the file belongs to; ignore this if the step only serves public files.",
						job, label, run))
				}
			}
			walk(job, s.Steps)
			walk(job, s.Else)
			walk(job, s.OnError)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(file.Jobs)) {
		walk(name, file.Jobs[name].Steps)
	}
	return out
}
