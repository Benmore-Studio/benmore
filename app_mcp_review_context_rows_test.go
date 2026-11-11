//go:build !cli && !windows

package main

import (
	"strings"
	"testing"
	"time"
)

// reviewRowHTML renders the review table for a preview and returns each body
// row's HTML keyed by its label.
func reviewRowHTML(t *testing.T, tool *AppMCPTool, schema *AppMCPSchema, preview map[string]any) (string, map[string]string) {
	t.Helper()
	review := &appMCPReview{Tool: "approve_expense", Preview: "{}", State: "prepared", ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		Changes: appMCPReviewChanges(tool, schema, preview)}
	view := newAppMCPReviewView(review, strings.Repeat("a", 32), time.Now())
	var b strings.Builder
	if err := appMCPReviewPage.ExecuteTemplate(&b, "changes", view); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	body := out[strings.Index(out, "<tbody>")+len("<tbody>") : strings.Index(out, "</tbody>")]
	rows := map[string]string{}
	for _, row := range strings.Split(body, "</tr>") {
		if row == "" {
			continue
		}
		start := strings.Index(row, `<th scope="row">`) + len(`<th scope="row">`)
		end := strings.IndexAny(row[start:], "<")
		rows[row[start:start+end]] = row
	}
	return out, rows
}

// An approval that changes only status shows the expense as context, not as
// "(empty) -> Hotel Boston": no before was read for it, so none is shown.
func TestAppMCPReviewPageShowsContextRowsWithoutBefore(t *testing.T) {
	schema := &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{
		"expense": {Type: "string"}, "amount": {Type: "string"}, "old_status": {Type: "string"}, "new_status": {Type: "string"},
	}}
	tool := &AppMCPTool{ReviewChanges: []AppMCPReviewPair{{Before: "old_status", After: "new_status", Label: "Status"}}}
	out, rows := reviewRowHTML(t, tool, schema, map[string]any{"expense": "Hotel Boston", "amount": "", "old_status": "pending", "new_status": "approved"})
	if !strings.Contains(out, `<th scope="col">Before</th>`) {
		t.Fatalf("a real change lost its Before column: %s", out)
	}
	status := rows["Status"]
	if !strings.Contains(status, `<td data-label="Before">pending</td>`) || !strings.Contains(status, `<td data-label="After">approved</td>`) || !strings.Contains(status, `class="changed"`) {
		t.Errorf("status change row: %s", status)
	}
	expense := rows["Expense"]
	if expense == "" || strings.Contains(expense, "(empty)") || strings.Contains(expense, `data-label="Before"`) || strings.Contains(expense, `data-label="After"`) || strings.Contains(expense, "changed") {
		t.Errorf("context row rendered as a change: %s", expense)
	}
	if !strings.Contains(expense, `<td colspan="2" data-label="Value">Hotel Boston</td>`) {
		t.Errorf("context row does not show its value as plain context: %s", expense)
	}
	// An empty context value is still shown (it may be a field being cleared),
	// but as the value, never as a before.
	amount := rows["Amount"]
	if !strings.Contains(amount, `<td colspan="2" data-label="Value"><span class="none">(empty)</span></td>`) || strings.Contains(amount, `data-label="Before"`) {
		t.Errorf("empty context row: %s", amount)
	}
}

// A change whose before the prepare step read as empty is still a before/after
// row: the Before column appears and says "(empty)".
func TestAppMCPReviewPageShowsEmptyBeforeOfARealChange(t *testing.T) {
	schema := &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{"old_note": {Type: "string"}, "new_note": {Type: "string"}}}
	tool := &AppMCPTool{ReviewChanges: []AppMCPReviewPair{{Before: "old_note", After: "new_note", Label: "Note"}}}
	out, rows := reviewRowHTML(t, tool, schema, map[string]any{"old_note": "", "new_note": "Paid in cash"})
	if !strings.Contains(out, `<th scope="col">Before</th>`) {
		t.Fatalf("an empty before hid the Before column: %s", out)
	}
	if note := rows["Note"]; !strings.Contains(note, `<td data-label="Before"><span class="none">(empty)</span></td>`) || !strings.Contains(note, `<td data-label="After">Paid in cash</td>`) {
		t.Errorf("note change row: %s", note)
	}
	// With no change rows at all, there is one Value column and no colspan.
	out, rows = reviewRowHTML(t, &AppMCPTool{}, &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{"name": {Type: "string"}}}, map[string]any{"name": "Acme"})
	if strings.Contains(out, ">Before<") || !strings.Contains(rows["Name"], `<td data-label="Value">Acme</td>`) {
		t.Errorf("create rows: %s", out)
	}
}
