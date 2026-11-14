//go:build !cli && !windows

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func erasureWarningFlow(auth, steps string) string {
	return "on:\n  request:\n    method: POST\n    path: /api/x\n    auth: " + auth + "\n    transaction: true\njobs:\n  main:\n    steps:\n" + steps
}

// `run: delete_upload` deletes a public upload only with `record:` and fails
// the flow otherwise. Nothing said so before the flow ran; the check now
// does, certainly for a path that names a public folder and conditionally
// for a template in a signed-in flow.
func TestCheckWarnsAboutPublicDeleteUploadWithoutRecord(t *testing.T) {
	step := func(path, record string) string {
		return "      - id: rm\n        run: delete_upload\n        with:\n          path: \"" + path + "\"\n" + record
	}
	const record = "          record: { table: files, id: \"1\" }\n"
	const tmpl = "${{ steps.f.outputs.file_url }}"

	for _, auth := range []string{"required", "none"} {
		for _, path := range []string{"uploads/avatars/a.png", "/uploads/avatars/${{ steps.f.outputs.name }}", "/Uploads/logos/x.png"} {
			w := ghaPublicDeleteRecordWarnings(erasureWarningFlow(auth, step(path, "")))
			if len(w) != 1 || !strings.Contains(w[0], "names a public upload") || !strings.Contains(w[0], "refused when it runs") || !strings.Contains(w[0], `step "rm"`) {
				t.Errorf("auth %s, public path %q without record: warnings = %q", auth, path, w)
			}
			if w := ghaPublicDeleteRecordWarnings(erasureWarningFlow(auth, step(path, record))); len(w) != 0 {
				t.Errorf("auth %s, public path %q with record: warnings = %q", auth, path, w)
			}
		}
		for _, path := range []string{"uploads/private/a.pdf", "/uploads/private/${{ steps.f.outputs.name }}"} {
			if w := ghaPublicDeleteRecordWarnings(erasureWarningFlow(auth, step(path, ""))); len(w) != 0 {
				t.Errorf("auth %s, private path %q: warnings = %q", auth, path, w)
			}
		}
	}
	// A template may resolve to either tier.
	w := ghaPublicDeleteRecordWarnings(erasureWarningFlow("required", step(tmpl, "")))
	if len(w) != 1 || !strings.Contains(w[0], "If the reference it resolves is a public upload") || !strings.Contains(w[0], "record:") {
		t.Errorf("template in a signed-in flow without record: warnings = %q", w)
	}
	if w := ghaPublicDeleteRecordWarnings(erasureWarningFlow("required", step(tmpl, record))); len(w) != 0 {
		t.Errorf("template with record: warnings = %q", w)
	}
	// No signed-in caller: the uploader-rule warning already covers the step.
	if w := ghaPublicDeleteRecordWarnings(erasureWarningFlow("none", step(tmpl, ""))); len(w) != 0 {
		t.Errorf("template in a public flow: warnings = %q, want none beside the uploader-rule warning", w)
	}
	if w := ghaPrivateUploadRecordWarnings(erasureWarningFlow("none", step(tmpl, ""))); len(w) != 1 {
		t.Errorf("the uploader-rule warning for the same step: %q", w)
	}
	// Nested steps are read too.
	nested := "      - if: ${{ params.a }} == 1\n        steps:\n          - run: delete_upload\n            with: { path: \"uploads/avatars/a.png\" }\n"
	if w := ghaPublicDeleteRecordWarnings(erasureWarningFlow("required", nested)); len(w) != 1 {
		t.Errorf("nested step: warnings = %q", w)
	}
}

// `run: purge_current_user` removes no file. A purge flow with no step that
// could remove the person's files is told so; one that deletes them, or
// hands the work to another flow, is not.
func TestCheckWarnsAboutPurgeFlowThatKeepsUploads(t *testing.T) {
	const purge = "      - id: purge\n        run: purge_current_user\n        with:\n          confirm: \"${{ params.confirm }}\"\n"
	const respond = "      - run: respond\n        with: { status: 200, json: { deleted: true } }\n"
	w := ghaPurgeKeepsUploadsWarnings(erasureWarningFlow("required", "      - query: \"DELETE FROM notes WHERE user_id = :user_id\"\n"+purge+respond))
	if len(w) != 1 || !strings.Contains(w[0], `step "purge"`) || !strings.Contains(w[0], "leaves every file it uploaded") || !strings.Contains(w[0], "delete_upload") {
		t.Fatalf("purge flow with no file step: warnings = %q", w)
	}
	for name, before := range map[string]string{
		"delete_upload": "      - run: delete_upload\n        with:\n          path: \"${{ steps.f.outputs.file_url }}\"\n          record: { table: files, id: \"1\" }\n",
		"enqueue":       "      - run: enqueue\n        with:\n          flow: purge-files\n",
		"nested":        "      - for_each: ${{ steps.files.outputs.rows }}\n        as: f\n        steps:\n          - run: enqueue\n            with: { flow: purge-files }\n",
	} {
		if w := ghaPurgeKeepsUploadsWarnings(erasureWarningFlow("required", before+purge+respond)); len(w) != 0 {
			t.Errorf("purge flow with %s: warnings = %q", name, w)
		}
	}
	if w := ghaPurgeKeepsUploadsWarnings(erasureWarningFlow("required", respond)); len(w) != 0 {
		t.Errorf("a flow with no purge step: warnings = %q", w)
	}

	// `benmore check` and the write gate's check report both warnings.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows", "account-delete.yaml"), []byte(erasureWarningFlow("required", purge+respond)), 0o644); err != nil {
		t.Fatal(err)
	}
	rm := "      - run: delete_upload\n        with: { path: \"uploads/avatars/a.png\" }\n"
	if err := os.WriteFile(filepath.Join(dir, "flows", "avatar-remove.yaml"), []byte(erasureWarningFlow("required", rm)), 0o644); err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, f := range redirectWarnings(dir) {
		if f.Severity != "warning" {
			t.Errorf("finding %q has severity %q, want warning", f.Message, f.Severity)
		}
		found[filepath.ToSlash(f.File)] += f.Message
	}
	if !strings.Contains(found["flows/account-delete.yaml"], "leaves every file it uploaded") {
		t.Errorf("check findings for the purge flow: %q", found["flows/account-delete.yaml"])
	}
	if !strings.Contains(found["flows/avatar-remove.yaml"], "names a public upload") {
		t.Errorf("check findings for the public delete: %q", found["flows/avatar-remove.yaml"])
	}
}

// `run: purge_current_user` runs inside an app flow that decides what
// happens to the person's files, and flows in use keep shared ones on
// purpose: the step erases the account and removes no file.
func TestPurgeCurrentUserLeavesUploadsToTheFlow(t *testing.T) {
	f := newAccountUploadsFixture(t)
	flow := &Flow{
		Name:        "account-delete",
		Trigger:     FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/account-delete"},
		Auth:        "required",
		Transaction: true,
		Steps: []FlowStep{
			{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"deleted": true}}},
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.goneToken)
	w := httptest.NewRecorder()
	executeFlowHTTP(f.app, flow, w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("purge flow: %d %s", w.Code, w.Body.String())
	}
	if n := f.count(t, `SELECT COUNT(*) FROM _benmore_users WHERE email='gone-uploader@example.com'`); n != 0 {
		t.Fatal("the account was not erased")
	}
	for _, ref := range []string{f.gonePrivate, f.gonePrivate2, f.goneAdminUpload, f.gonePublic} {
		if !f.stored(t, ref) {
			t.Errorf("the purge step removed %s: the flow decides what happens to the person's files", ref)
		}
	}
	if n := f.count(t, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='account_upload_cleanup'`); n != 0 {
		t.Errorf("%d upload-cleanup audit rows after a purge flow, want none", n)
	}
}
