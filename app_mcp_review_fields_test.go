//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func reviewFieldsTool(edit func(*AppMCPTool)) AppMCPTool {
	tool := commandManifest().Tools[0]
	edit(&tool)
	return tool
}

func TestAppMCPReviewFieldsValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*AppMCPTool)
		want string // empty: accepted
	}{
		"all fields": {func(x *AppMCPTool) {
			x.Title, x.ReviewSummary = "Create a project", "Adds the project to your workspace."
			x.Labels = map[string]string{"id": "Item"}
			x.ReviewChanges = []AppMCPReviewPair{{Before: "old_value", After: "new_value", Field: "field"}, {Before: "a", After: "b", Label: "Role"}}
		}, ""},
		"title too long":       {func(x *AppMCPTool) { x.Title = strings.Repeat("a", 81) }, "title"},
		"title at limit":       {func(x *AppMCPTool) { x.Title = strings.Repeat("a", 80) }, ""},
		"summary too long":     {func(x *AppMCPTool) { x.ReviewSummary = strings.Repeat("a", 501) }, "review_summary"},
		"label too long":       {func(x *AppMCPTool) { x.Labels = map[string]string{"id": strings.Repeat("a", 61)} }, "labels[id]"},
		"zero width in title":  {func(x *AppMCPTool) { x.Title = "Create\u200b a project" }, "invisible"},
		"bidi in summary":      {func(x *AppMCPTool) { x.ReviewSummary = "Pay \u202eelas" }, "invisible"},
		"newline in summary":   {func(x *AppMCPTool) { x.ReviewSummary = "one\ntwo" }, "invisible"},
		"variation selector":   {func(x *AppMCPTool) { x.Labels = map[string]string{"id": "Co\ufe0funtry"} }, "invisible"},
		"padded title":         {func(x *AppMCPTool) { x.Title = " Create" }, "whitespace"},
		"empty label":          {func(x *AppMCPTool) { x.Labels = map[string]string{"id": " "} }, "empty"},
		"label key not a name": {func(x *AppMCPTool) { x.Labels = map[string]string{"a b": "X"} }, "plain name"},
		"pair with both": {func(x *AppMCPTool) {
			x.ReviewChanges = []AppMCPReviewPair{{Before: "a", After: "b", Field: "f", Label: "L"}}
		}, "exactly one"},
		"pair with neither":    {func(x *AppMCPTool) { x.ReviewChanges = []AppMCPReviewPair{{Before: "a", After: "b"}} }, "exactly one"},
		"pair reuses a key":    {func(x *AppMCPTool) { x.ReviewChanges = []AppMCPReviewPair{{Before: "a", After: "a", Label: "L"}} }, "twice"},
		"pair label invisible": {func(x *AppMCPTool) { x.ReviewChanges = []AppMCPReviewPair{{Before: "a", After: "b", Label: "L\u200b"}} }, "invisible"},
		"read tool declares": {func(x *AppMCPTool) {
			x.Handler, x.Effect, x.Approval, x.Idempotency, x.Reconciliation = AppMCPHandler{Kind: "native", Table: "t", Operation: "table.list"}, "read", "none", "none", "none"
			x.Title = "List"
		}, "only to flow command tools"},
	} {
		t.Run(name, func(t *testing.T) {
			tool := reviewFieldsTool(tc.edit)
			err := validateAppMCPReviewFields(tool, tool.Handler.Operation == "command")
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
	// The same check runs where a manifest is parsed (runtime, upload, review).
	m := commandManifest()
	m.Tools[0].Title = strings.Repeat("a", 81)
	if err := validateAppMCPManifestGated(m, true); err == nil || !strings.Contains(err.Error(), "title") {
		t.Fatalf("manifest validation: %v", err)
	}
}

func TestAppMCPReviewFieldsBindings(t *testing.T) {
	preview := &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{
		"status": {Type: "string"}, "field": {Type: "string", Enum: []any{"priority"}}, "old_value": {Type: "string"}, "new_value": {Type: "string"}, "count": {Type: "integer"}}}
	command := &FlowCommand{PreviewSchema: preview}
	check := func(edit func(*AppMCPTool)) error {
		return validateAppMCPReviewBindings(reviewFieldsTool(edit), command)
	}
	if err := check(func(x *AppMCPTool) {
		x.Labels = map[string]string{"id": "Item", "status": "State", "priority": "Priority"} // input property, preview key, enum value of the field key
		x.ReviewChanges = []AppMCPReviewPair{{Before: "old_value", After: "new_value", Field: "field"}}
	}); err != nil {
		t.Fatalf("valid declaration refused: %v", err)
	}
	for name, edit := range map[string]func(*AppMCPTool){
		"unknown label key":      func(x *AppMCPTool) { x.Labels = map[string]string{"country": "Country"} },
		"enum without field key": func(x *AppMCPTool) { x.Labels = map[string]string{"priority": "Priority"} },
		"unknown before": func(x *AppMCPTool) {
			x.ReviewChanges = []AppMCPReviewPair{{Before: "nope", After: "new_value", Label: "L"}}
		},
		"unknown after": func(x *AppMCPTool) {
			x.ReviewChanges = []AppMCPReviewPair{{Before: "old_value", After: "nope", Label: "L"}}
		},
		"field not a string": func(x *AppMCPTool) {
			x.ReviewChanges = []AppMCPReviewPair{{Before: "old_value", After: "new_value", Field: "count"}}
		},
	} {
		if err := check(edit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A manifest that declares no review fields must keep the digest it was
// reviewed under; this value was computed by the code before the fields existed.
func TestAppMCPReviewFieldsKeepOldDigest(t *testing.T) {
	const before = "c73fe72cf81a786bdb2bca6fd9ec3e68a37ca44a355684e88833899dde8c7f17"
	m := commandManifest()
	if got, err := appMCPContractDigest(m); err != nil || got != before {
		t.Fatalf("digest of a manifest without review fields changed: %s %v", got, err)
	}
	raw, _ := json.Marshal(m)
	for _, key := range []string{"Title", "ReviewSummary", "Labels", "ReviewChanges"} {
		if strings.Contains(string(raw), `"`+key+`"`) {
			t.Fatalf("canonical form carries empty %s", key)
		}
	}
	// Declared fields are reviewed content: each one moves the digest.
	for name, edit := range map[string]func(*AppMCPTool){
		"title":   func(x *AppMCPTool) { x.Title = "Complete" },
		"summary": func(x *AppMCPTool) { x.ReviewSummary = "Marks the item done." },
		"label":   func(x *AppMCPTool) { x.Labels = map[string]string{"id": "Item"} },
		"changes": func(x *AppMCPTool) { x.ReviewChanges = []AppMCPReviewPair{{Before: "a", After: "b", Label: "L"}} },
	} {
		changed := commandManifest()
		edit(&changed.Tools[0])
		if got, _ := appMCPContractDigest(changed); got == before {
			t.Errorf("%s is not covered by the contract digest", name)
		}
	}
}

func TestAppMCPReviewFieldsYAMLRoundTrip(t *testing.T) {
	m := commandManifest()
	m.Tools[0].Title, m.Tools[0].ReviewSummary = "Complete an item", "Marks one item done."
	m.Tools[0].Labels = map[string]string{"id": "Item"}
	m.Tools[0].ReviewChanges = []AppMCPReviewPair{{Before: "old_value", After: "new_value", Field: "field"}}
	data, err := yaml.Marshal(m) // what `benmore mcp review` writes back
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeAppMCPManifest(data)
	if err != nil {
		t.Fatalf("decode: %v\n%s", err, data)
	}
	got, want := back.Tools[0], m.Tools[0]
	if got.Title != want.Title || got.ReviewSummary != want.ReviewSummary || !reflect.DeepEqual(got.Labels, want.Labels) || !reflect.DeepEqual(got.ReviewChanges, want.ReviewChanges) {
		t.Fatalf("round trip lost review fields: %#v", got)
	}
}

func TestAppMCPReviewDisplayText(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"plain text", "plain text"},
		{"a\u200bb", `a\u200bb`},             // zero width space
		{"pay \u202eelas", `pay \u202eelas`}, // right-to-left override
		{"two\nlines", `two\u000alines`},
		{"typed \\u200b", `typed \\u200b`}, // literal text can't pass for an escape
		{"C:\\dir", `C:\dir`},
		{"\U0001F600", "\U0001F600"},
		{true, "Yes"}, {false, "No"}, {nil, "\u2014"},
		{json.Number("42"), "42"}, {json.Number("1e3"), "1000"}, {json.Number("12.50"), "12.50"}, {json.Number("0.10000000000000001"), "0.10000000000000001"},
		{map[string]any{"b": "x\u200by", "a": json.Number("1")}, `{"a":1,"b":"x\u200by"}`},
		{[]any{"<a>", nil}, `["<a>",null]`},
	} {
		if got := appMCPReviewValueText(tc.in); got != tc.want {
			t.Errorf("%#v: got %q, want %q", tc.in, got, tc.want)
		}
	}
	for in, want := range map[string]string{"project_status": "Project status", "next-action.date": "Next action date", "name": "Name", "__": "__"} {
		if got := appMCPHumanizeKey(in); got != want {
			t.Errorf("humanize %q: %q, want %q", in, got, want)
		}
	}
}

func TestAppMCPReviewChangesRows(t *testing.T) {
	schema := &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{
		"lead_name": {Type: "string"}, "field": {Type: "string"}, "old_value": {Type: "string"}, "new_value": {Type: "string"},
		"project_status": {Type: "string"}, "paid": {Type: "boolean"},
		"country": {Type: "object", Properties: map[string]*AppMCPSchema{"before": {Type: "string"}, "after": {Type: "string"}}},
		"data":    {Type: "object", Properties: map[string]*AppMCPSchema{"x": {Type: "string"}}},
	}}
	tool := &AppMCPTool{Labels: map[string]string{"country": "Country", "next_action": "Next action"},
		ReviewChanges: []AppMCPReviewPair{{Before: "old_value", After: "new_value", Field: "field"}}}
	preview := map[string]any{
		"lead_name": "Acme\u200b", "field": "next_action", "old_value": "call", "new_value": "email",
		"project_status": "open", "paid": json.Number("0") /* not a bool: shown as a number */, "country": map[string]any{"before": "ZA", "after": "NG"},
		// A model-chosen nested object is not a pair unless the schema declares one.
		"data": map[string]any{"before": "forged", "after": "x"},
	}
	preview["paid"] = false
	rows := appMCPReviewChanges(tool, schema, preview)
	want := []appMCPReviewChange{
		{Label: "Country", Before: "ZA", After: "NG", Changed: true},
		{Label: "Data", After: `{"after":"x","before":"forged"}`},
		{Label: "Lead name", After: `Acme\u200b`},
		{Label: "Paid", After: "No"},
		{Label: "Project status", After: "open"},
		{Label: "Next action", Before: "call", After: "email", Changed: true},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %#v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d: %#v, want %#v", i, rows[i], want[i])
		}
	}
	// A plain value has no before: never "changed"; an empty one is kept (it may be a field being cleared).
	if plain := appMCPReviewChanges(&AppMCPTool{}, schema, map[string]any{"lead_name": "", "project_status": "open"}); len(plain) != 2 || plain[0].Changed || plain[0].Label != "Lead name" || plain[0].After != "" || plain[1].Label != "Project status" {
		t.Fatalf("plain rows: %#v", plain)
	}
	unchanged := appMCPReviewChanges(tool, schema, map[string]any{"field": "priority", "old_value": "low", "new_value": "low"})
	if len(unchanged) != 1 || unchanged[0].Changed || unchanged[0].Label != "Priority" {
		t.Fatalf("unchanged row: %#v", unchanged)
	}
}

// reviewFieldsFlow is the task flow with a nested before/after pair and a flat
// old_value/new_value pair in its preview, both read by the prepare step.
var reviewFieldsFlow = func() string {
	flow := strings.Replace(hookTaskFlow, "      status: {type: string, minLength: 1, maxLength: 32}\n  writes:", `      status: {type: string, minLength: 1, maxLength: 32}
      state:
        type: object
        additionalProperties: false
        required: [before, after]
        properties:
          before: {type: string, maxLength: 32}
          after: {type: string, maxLength: 32}
      old_value: {type: string, maxLength: 32}
      new_value: {type: string, maxLength: 32}
  writes:`, 1)
	flow = strings.Replace(flow, "    required: [status]\n    properties:\n      status:", "    required: [status, state, old_value, new_value]\n    properties:\n      status:", 1)
	return strings.Replace(flow, "preview: {status: '${{ steps.selected_task.outputs.first.status }}'}", `preview:
              status: '${{ steps.selected_task.outputs.first.status }}'
              state: {before: '${{ steps.selected_task.outputs.first.status }}', after: done}
              old_value: '${{ steps.selected_task.outputs.first.status }}'
              new_value: done`, 1)
}()

func reviewFieldsManifest(m *AppMCPManifest) {
	m.Tools[0].Approval = "first_party"
	m.Tools[0].Title = "Complete a task"
	m.Tools[0].ReviewSummary = "Marks the task done and records who did it."
	m.Tools[0].Labels = map[string]string{"state": "Task state", "id": "Task"}
	m.Tools[0].ReviewChanges = []AppMCPReviewPair{{Before: "old_value", After: "new_value", Label: "Progress"}}
}

func (h *exposureHarness) reviewOf(id string) *appMCPReview {
	h.t.Helper()
	req, err := h.connectorRequest()
	if err != nil {
		h.t.Fatal(err)
	}
	req.origin = appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: GetSessionFromDB(h.app.DB, h.cookie).ID}
	review, err := appMCPReviewOperation(context.Background(), req, id, "")
	if err != nil {
		h.t.Fatalf("review: %v", err)
	}
	return review
}

func TestAppMCPReviewFieldsPopulateReview(t *testing.T) {
	h := newGrantExposureHarnessWith(t, reviewFieldsFlow, reviewFieldsManifest, "complete_item")
	out, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if code != "" {
		t.Fatalf("prepare: %s", code)
	}
	if out["approval_reason"] != "This kind of change always needs your approval" {
		t.Fatalf("approval_reason: %#v", out["approval_reason"])
	}
	review := h.reviewOf(out["operation_id"].(string))
	if review.Title != "Complete a task" || review.Summary != "Marks the task done and records who did it." || review.Description == review.Summary {
		t.Fatalf("title/summary: %q %q", review.Title, review.Summary)
	}
	if review.AutoApprove != "This kind of change always needs your approval" {
		t.Fatalf("AutoApprove: %q", review.AutoApprove)
	}
	want := []appMCPReviewChange{
		{Label: "Task state", Before: "open", After: "done", Changed: true},
		{Label: "Status", After: "open"},
		{Label: "Progress", Before: "open", After: "done", Changed: true},
	}
	if len(review.Changes) != len(want) {
		t.Fatalf("changes: %#v", review.Changes)
	}
	for i := range want {
		if review.Changes[i] != want[i] {
			t.Errorf("change %d: %#v, want %#v", i, review.Changes[i], want[i])
		}
	}
}

// Without declarations the review leaves Title and Summary empty (never the
// model-facing description) and labels humanised keys.
func TestAppMCPReviewFieldsUndeclared(t *testing.T) {
	h := newGrantExposureHarness(t, "first_party", "complete_item")
	review := h.reviewOf(h.prepare())
	if review.Title != "" || review.Summary != "" || review.Description == "" {
		t.Fatalf("undeclared fields: %q %q", review.Title, review.Summary)
	}
	if len(review.Changes) != 1 || review.Changes[0] != (appMCPReviewChange{Label: "Status", After: "open"}) {
		t.Fatalf("changes: %#v", review.Changes)
	}
}

func TestAppMCPApprovalReasons(t *testing.T) {
	prepare := func(h *exposureHarness) map[string]any {
		t.Helper()
		out, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if code != "" {
			t.Fatalf("prepare: %s", code)
		}
		return out
	}
	grantOnly := func(m *AppMCPManifest) { m.Tools[0].Approval = "grant"; m.Tools[0].Title = "Complete a task" }
	for name, tc := range map[string]struct {
		setup func(*exposureHarness)
		list  string
		edit  func(*AppMCPManifest)
		want  string
	}{
		"first_party": {nil, "complete_item", func(m *AppMCPManifest) { m.Tools[0].Approval = "first_party" }, "This kind of change always needs your approval"},
		"owner switch off": {func(h *exposureHarness) {
			if err := appMCPConnectorApply(context.Background(), h.app, appMCPConnectorRequest{Action: "disable", AutoApprove: true}); err != nil {
				t.Fatal(err)
			}
		}, "complete_item", grantOnly, "Auto-approve is turned off for this app"},
		"not ticked": {nil, "other_tool", grantOnly, "This connection was not allowed to auto-approve this kind of change"},
		"manifest changed": {func(h *exposureHarness) {
			if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_grants SET auto_approve=? WHERE id=?", appMCPAutoApproveEntry("complete_item", strings.Repeat("e", 64), strings.Repeat("e", 64)), h.pair.GrantID); err != nil {
				t.Fatal(err)
			}
		}, "complete_item", grantOnly, "The app's tools changed since you connected; reconnect the assistant to re-enable auto-approve"},
		"owner epoch changed": {func(h *exposureHarness) {
			for _, on := range []bool{false, true} {
				if _, err := setAppMCPAutoApproveContext(context.Background(), h.app.Dir, on); err != nil {
					t.Fatal(err)
				}
			}
		}, "complete_item", grantOnly, "Auto-approve was switched off and on since you connected; reconnect to re-enable it"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newGrantExposureHarnessWith(t, hookTaskFlow, tc.edit, tc.list)
			if tc.setup != nil {
				tc.setup(h)
			}
			out := prepare(h)
			if out["approval_reason"] != tc.want {
				t.Fatalf("approval_reason %q, want %q", out["approval_reason"], tc.want)
			}
			if review := h.reviewOf(out["operation_id"].(string)); review.AutoApprove != tc.want {
				t.Fatalf("review AutoApprove %q, want %q", review.AutoApprove, tc.want)
			}
		})
	}
	t.Run("applied call has no reason", func(t *testing.T) {
		h := newGrantExposureHarnessWith(t, hookTaskFlow, grantOnly, "complete_item")
		if out := prepare(h); out["outcome"] != "applied" || out["approval_reason"] != nil {
			t.Fatalf("auto-approved call: %#v", out)
		}
	})
}
