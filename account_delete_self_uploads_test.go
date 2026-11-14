//go:build !cli && !windows

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// deleteOwnAccountRequest posts /settings/delete-account as the session.
func (f *accountUploadsFixture) deleteOwnAccountRequest(t *testing.T, token, confirm string, asJSON bool) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"confirm": {confirm}, "_csrf": {authMintCSRFToken(token)}}
	r := httptest.NewRequest(http.MethodPost, "/settings/delete-account", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if asJSON {
		r.Header.Set("Accept", "application/json")
	}
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

// uploadCleanupAudit returns the new_values of the account's upload-cleanup
// audit rows and who they name as the actor.
func (f *accountUploadsFixture) uploadCleanupAudit(t *testing.T, uid int64) (values []string, actorID int64, actorEmail string) {
	t.Helper()
	rows, err := f.app.DB.Query(`SELECT COALESCE(new_values, ''), COALESCE(user_id, 0), COALESCE(user_email, ''), COALESCE(old_values, '') FROM _benmore_audit_log
		WHERE action = 'account_upload_cleanup' AND table_name = '_benmore_users' AND row_id = ?`, strconv.FormatInt(uid, 10))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var v, old string
		if err := rows.Scan(&v, &actorID, &actorEmail, &old); err != nil {
			t.Fatal(err)
		}
		if old != "" {
			t.Errorf("upload-cleanup audit row has old_values %q, want none", old)
		}
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return values, actorID, actorEmail
}

func newSelfDeleteUploadsFixture(t *testing.T) *accountUploadsFixture {
	t.Helper()
	f := newAccountUploadsFixture(t)
	f.app.Paths = DiscoverAuthPaths(nil)
	RegisterSettingsRoutes(f.mux, f.app)
	return f
}

// /settings/delete-account erased the sign-in and left every private file
// the person had uploaded stored, with an already issued signed URL still
// serving it. Like the operator delete, it removes them once the erasure
// commits, says how many in its JSON answer and writes one audit row holding
// the counts only. Other accounts' files, public files, the app's rows and
// the files the account uploaded as an admin stay.
func TestSelfServiceDeleteRemovesTheAccountsPrivateUploads(t *testing.T) {
	f := newSelfDeleteUploadsFixture(t)

	// A refused deletion removes nothing.
	if w := f.deleteOwnAccountRequest(t, f.goneToken, "delete", true); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong confirmation answered %d %s", w.Code, w.Body.String())
	}
	if !f.stored(t, f.gonePrivate) || !f.stored(t, f.gonePrivate2) {
		t.Fatal("a refused deletion removed files")
	}

	w := f.deleteOwnAccountRequest(t, f.goneToken, "DELETE", true)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	var answer map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatalf("answer is not JSON: %v: %s", err, w.Body.String())
	}
	for key, want := range map[string]any{
		"ok": true, "deleted": true, "redirect": f.app.Paths.Login,
		"private_files_removed": float64(2), "private_files_failed": float64(0), "private_files_kept_admin": float64(1),
	} {
		if answer[key] != want {
			t.Errorf("answer %s = %v, want %v (%s)", key, answer[key], want, w.Body.String())
		}
	}
	var email sql.NullString
	if err := f.app.DB.QueryRow(`SELECT email FROM _benmore_users WHERE id=?`, f.goneID).Scan(&email); err != nil || email.Valid {
		t.Fatalf("account not erased: email=%v err=%v", email, err)
	}
	for _, ref := range []string{f.gonePrivate, f.gonePrivate2} {
		if f.stored(t, ref) {
			t.Errorf("the deleted account's private file %s is still stored", ref)
		}
	}
	if code := f.get(t, f.goneSigned); code != http.StatusNotFound {
		t.Errorf("signed URL of the deleted account's private file answered %d, want 404", code)
	}
	if !f.stored(t, f.goneAdminUpload) {
		t.Error("a file the deleted account uploaded as an admin was removed")
	}
	if code := f.get(t, f.adminUploadSigned); code != http.StatusOK {
		t.Errorf("signed URL of the admin upload on another account's record answered %d, want 200", code)
	}
	if !f.stored(t, f.keptPrivate) || f.get(t, f.keptSigned) != http.StatusOK {
		t.Error("another account's private file was removed or stopped serving")
	}
	if !f.stored(t, f.gonePublic) || f.get(t, f.gonePublic) != http.StatusOK {
		t.Error("the deleted account's public file was removed")
	}
	if got := f.count(t, `SELECT COUNT(*) FROM docs WHERE id BETWEEN 101 AND 105 AND file_url LIKE '/uploads/%'`); got != f.docsBefore {
		t.Errorf("docs rows after the delete = %d, want %d unchanged", got, f.docsBefore)
	}
	if got := f.count(t, `SELECT COUNT(*) FROM _benmore_upload_owners`); got != f.ownershipBeforeCount {
		t.Errorf("uploader records after the delete = %d, want %d unchanged", got, f.ownershipBeforeCount)
	}

	// One audit row: the counts, the account as its own actor, no file name
	// and no address.
	values, actorID, actorEmail := f.uploadCleanupAudit(t, f.goneID)
	if len(values) != 1 {
		t.Fatalf("%d upload-cleanup audit rows, want 1: %v", len(values), values)
	}
	var counts map[string]any
	if err := json.Unmarshal([]byte(values[0]), &counts); err != nil {
		t.Fatalf("audit values are not JSON: %v: %s", err, values[0])
	}
	if len(counts) != 3 || counts["removed"] != float64(2) || counts["failed"] != float64(0) || counts["kept_admin"] != float64(1) {
		t.Errorf("audit values = %s, want the three counts only", values[0])
	}
	if actorID != f.goneID || actorEmail != "" {
		t.Errorf("audit actor = %d %q, want the erased account's id and no address", actorID, actorEmail)
	}
	if strings.Contains(values[0], "uploads") || strings.Contains(values[0], "@") {
		t.Errorf("audit values name a file or an address: %s", values[0])
	}
}

// A form post still lands on the sign-in page, and the files go all the
// same. An account that uploaded nothing writes no upload-cleanup row.
func TestSelfServiceDeleteFormPostRemovesUploads(t *testing.T) {
	f := newSelfDeleteUploadsFixture(t)
	w := f.deleteOwnAccountRequest(t, f.goneToken, "DELETE", false)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || loc != f.app.Paths.Login {
		t.Fatalf("form delete: %d to %q, want 303 to %q", w.Code, loc, f.app.Paths.Login)
	}
	if f.stored(t, f.gonePrivate) || f.stored(t, f.gonePrivate2) {
		t.Error("the deleted account's private files are still stored")
	}
	if !f.stored(t, f.goneAdminUpload) || !f.stored(t, f.keptPrivate) || !f.stored(t, f.gonePublic) {
		t.Error("a file that must stay was removed")
	}

	token := createCrudScopeSession(t, f.app, "no-files@example.com", "user", "", "")
	var id int64
	if err := f.app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email='no-files@example.com'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	w = f.deleteOwnAccountRequest(t, token, "DELETE", true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"private_files_removed":0`) {
		t.Fatalf("delete of an account with no files: %d %s", w.Code, w.Body.String())
	}
	if values, _, _ := f.uploadCleanupAudit(t, id); len(values) != 0 {
		t.Errorf("an account with no files wrote upload-cleanup rows: %v", values)
	}
	if !f.stored(t, f.keptPrivate) {
		t.Error("deleting an account with no files removed someone else's file")
	}
}

const ownErasureFlowYAML = `on:
  request:
    method: POST
    path: /api/account-delete
    auth: required
    transaction: true
jobs:
  delete:
    steps:
      - id: purge
        run: purge_current_user
        with:
          confirm: "${{ params.confirm }}"
      - run: respond
        with: { status: 200, json: { deleted: true } }
`

// An app with a flow that runs purge_current_user has stated what happens to
// a person's files when their account goes (some keep what the person
// shared). The built-in deletion is still reachable there by a direct POST;
// it erases the account, removes no file and says why. The rule follows the
// app's loaded flows: a reload that removes the flow brings the cleanup
// back, and one that adds it again takes it away.
func TestSelfServiceDeleteLeavesUploadsToTheAppsErasureFlow(t *testing.T) {
	f := newSelfDeleteUploadsFixture(t)
	reload := func(withFlow bool) {
		t.Helper()
		path := filepath.Join(f.app.Dir, "flows", "account-delete.yaml")
		if withFlow {
			writeTestFile(t, f.app.Dir, "flows/account-delete.yaml", ownErasureFlowYAML)
		} else if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := reloadAppConfig(f.app); err != nil {
			t.Fatalf("reload (flow present: %v): %v", withFlow, err)
		}
		if got := appDeclaresOwnErasure(f.app); got != withFlow {
			t.Fatalf("after reload appDeclaresOwnErasure = %v, want %v", got, withFlow)
		}
	}
	// account makes a user with one private file and returns its session,
	// id and file.
	account := func(name string) (token string, id int64, ref string) {
		t.Helper()
		email := name + "@example.com"
		token = createCrudScopeSession(t, f.app, email, "user", "", "")
		if err := f.app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email=?`, email).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return token, id, uploadAsFixtureUser(t, f.mux, token, "private", "file of "+name)
	}
	erased := func(id int64) bool {
		return f.count(t, `SELECT COUNT(*) FROM _benmore_users WHERE email IS NULL AND deactivated_at IS NOT NULL AND id=`+strconv.FormatInt(id, 10)) == 1
	}
	answerOf := func(w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var answer map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || w.Code != http.StatusOK {
			t.Fatalf("delete answered %d %s (%v)", w.Code, w.Body.String(), err)
		}
		return answer
	}

	// With the app's own erasure flow loaded: account gone, files left.
	reload(true)
	answer := answerOf(f.deleteOwnAccountRequest(t, f.goneToken, "DELETE", true))
	if answer["ok"] != true || answer["deleted"] != true || answer["private_files"] != "left to the app's erasure flow" {
		t.Errorf("answer = %v, want deleted with private_files left to the app's erasure flow", answer)
	}
	for _, key := range []string{"private_files_removed", "private_files_failed", "private_files_kept_admin"} {
		if _, has := answer[key]; has {
			t.Errorf("answer carries %s though no cleanup ran: %v", key, answer)
		}
	}
	if !erased(f.goneID) {
		t.Fatal("the account was not erased")
	}
	for _, ref := range []string{f.gonePrivate, f.gonePrivate2, f.goneAdminUpload, f.gonePublic} {
		if !f.stored(t, ref) {
			t.Errorf("the built-in deletion removed %s in an app with its own erasure flow", ref)
		}
	}
	if code := f.get(t, f.goneSigned); code != http.StatusOK {
		t.Errorf("signed URL of a kept file answered %d, want 200", code)
	}
	if values, _, _ := f.uploadCleanupAudit(t, f.goneID); len(values) != 0 {
		t.Errorf("upload-cleanup audit rows written though nothing was cleaned: %v", values)
	}
	// A form post leaves them too.
	formToken, formID, formRef := account("form-post")
	if w := f.deleteOwnAccountRequest(t, formToken, "DELETE", false); w.Code != http.StatusSeeOther || !erased(formID) || !f.stored(t, formRef) {
		t.Errorf("form delete with the flow loaded: %d, erased=%v, file stored=%v; want 303, erased, stored", w.Code, erased(formID), f.stored(t, formRef))
	}

	// The flow removed: the built-in deletion cleans up again.
	token, id, ref := account("after-removal")
	reload(false)
	answer = answerOf(f.deleteOwnAccountRequest(t, token, "DELETE", true))
	if _, has := answer["private_files"]; has || answer["private_files_removed"] != float64(1) || !erased(id) || f.stored(t, ref) {
		t.Errorf("after the flow was removed: answer = %v, erased=%v, file stored=%v; want one file removed", answer, erased(id), f.stored(t, ref))
	}

	// And added back: files are left again.
	token, id, ref = account("after-return")
	reload(true)
	answer = answerOf(f.deleteOwnAccountRequest(t, token, "DELETE", true))
	if answer["private_files"] != "left to the app's erasure flow" || !erased(id) || !f.stored(t, ref) {
		t.Errorf("after the flow came back: answer = %v, erased=%v, file stored=%v; want the file left", answer, erased(id), f.stored(t, ref))
	}
	if !f.stored(t, f.keptPrivate) {
		t.Fatal("another account's file was removed")
	}
}
