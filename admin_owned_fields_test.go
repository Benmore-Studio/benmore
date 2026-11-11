//go:build !cli && !windows

package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var (
	adminFormInputRe = regexp.MustCompile(`<input\b[^>]*>`)
	adminFormAttrRe  = regexp.MustCompile(`\b(name|value)="([^"]*)"`)
)

// adminFormFields returns what a browser submits for the admin form that
// posts to action: every named input that is not disabled, with the value the
// page rendered (blank for an input the admin leaves untouched).
func adminFormFields(t *testing.T, page, action string) url.Values {
	t.Helper()
	start := strings.Index(page, `action="`+action+`"`)
	if start < 0 {
		t.Fatalf("no form posts to %s", action)
	}
	form := page[start:]
	if end := strings.Index(form, "</form>"); end >= 0 {
		form = form[:end]
	}
	fields := url.Values{}
	for _, input := range adminFormInputRe.FindAllString(form, -1) {
		if strings.Contains(input, " disabled") {
			continue
		}
		var name, value string
		for _, attr := range adminFormAttrRe.FindAllStringSubmatch(input, -1) {
			if attr[1] == "name" {
				name = attr[2]
			} else {
				value = attr[2]
			}
		}
		if name != "" {
			fields.Set(name, value)
		}
	}
	return fields
}

// The admin panel's forms offered an input for a command-owned column. A
// browser submits every input, blank ones included, and generic CRUD refuses
// any request that names an owned column, so every create from the form was
// refused, and so was saving a row whose owned column is NULL (a blank input
// is not an echo of NULL).
func TestAdminFormsLeaveCommandOwnedColumnsOut(t *testing.T) {
	f := newOwnedFieldFixture(t, "  owns: [tasks.completed_by, Tasks.COMPLETED_AT]\n")
	mustExec(t, f.app.DB, `UPDATE tasks SET completed_at='2026-01-02 03:04:05' WHERE id=1`)

	// Create: the form has no input for an owned column.
	rec := crudScopeRequest(t, f.mux, http.MethodGet, "/_admin/tasks", f.admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin table page: %d %s", rec.Code, rec.Body.String())
	}
	create := adminFormFields(t, rec.Body.String(), "/_admin/api/tasks/create")
	for _, owned := range []string{"completed_by", "completed_at"} {
		if _, offered := create[owned]; offered {
			t.Errorf("create form offers an input for the command-owned column %s", owned)
		}
	}
	for _, plain := range []string{"project_id", "title", "status"} {
		if _, offered := create[plain]; !offered {
			t.Errorf("create form lost the input for %s", plain)
		}
	}
	// What the browser sends once the admin fills the required fields in.
	create.Set("project_id", "7")
	create.Set("org_id", "17")
	create.Set("title", "made in the admin panel")
	create.Set("status", "open")
	rec = rawOwnedRequest(f.mux, http.MethodPost, "/_admin/api/tasks/create", f.admin, "application/x-www-form-urlencoded", create.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("create from the admin form: %d %s", rec.Code, rec.Body.String())
	}
	var status string
	var completedBy, completedAt any
	if err := f.app.DB.QueryRow(`SELECT status, completed_by, completed_at FROM tasks WHERE title='made in the admin panel'`).Scan(&status, &completedBy, &completedAt); err != nil {
		t.Fatalf("the row the form created: %v", err)
	}
	if status != "open" || completedBy != nil || completedAt != nil {
		t.Fatalf("created row: status %q completed_by %v completed_at %v, want open and the owned columns at their default", status, completedBy, completedAt)
	}

	// Edit: owned columns are shown, read-only, and not submitted.
	rec = crudScopeRequest(t, f.mux, http.MethodGet, "/_admin/tasks/1", f.admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin record page: %d %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	if !strings.Contains(page, "2026-01-02 03:04:05") || !strings.Contains(page, "Changed only by the complete_item command") {
		t.Errorf("edit page must show the owned column's value and name the command that sets it")
	}
	edit := adminFormFields(t, page, "/_admin/api/tasks/update/1")
	for _, owned := range []string{"completed_by", "completed_at"} {
		if _, offered := edit[owned]; offered {
			t.Errorf("edit form submits the command-owned column %s", owned)
		}
	}
	edit.Set("title", "saved in the admin panel")
	rec = rawOwnedRequest(f.mux, http.MethodPost, "/_admin/api/tasks/update/1", f.admin, "application/x-www-form-urlencoded", edit.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("save from the admin form: %d %s", rec.Code, rec.Body.String())
	}
	if title, _, by := f.task(t); title != "saved in the admin panel" || by != nil {
		t.Fatalf("after the save: title %q completed_by %v", title, by)
	}

	// The gate itself is unchanged: a request that names an owned column is
	// still refused, blank value or not.
	rec = rawOwnedRequest(f.mux, http.MethodPost, "/_admin/api/tasks/create", f.admin, "application/x-www-form-urlencoded", "project_id=7&org_id=17&title=n&status=open&completed_by=")
	f.ownedBody(t, rec, "tasks.completed_by")
}
