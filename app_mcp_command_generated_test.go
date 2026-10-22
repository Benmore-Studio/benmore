//go:build !cli && !windows

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// generatedTaskFlow is the task command with a generated invitation-style
// token written into tasks.title by apply. With showInPreview the author also
// puts it in the preview.
func generatedTaskFlow(t *testing.T, showInPreview bool) string {
	t.Helper()
	replace := func(src, old, repl string) string {
		if strings.Count(src, old) != 1 {
			t.Fatalf("fixture anchor %q found %d times", old, strings.Count(src, old))
		}
		return strings.Replace(src, old, repl, 1)
	}
	flow := replace(commandTaskFlowFixture, "  version: 1\n", "  version: 1\n  generated:\n    - {name: invite_token, kind: token, bytes: 24}\n")
	flow = replace(flow, "completed_at = datetime('now') WHERE", "completed_at = datetime('now'), title = :token WHERE")
	flow = replace(flow, "actor: '${{ user.id }}', tenant: '${{ user.group_id }}'}\n      - id: add_activity",
		"actor: '${{ user.id }}', tenant: '${{ user.group_id }}', token: '${{ params.generated.invite_token }}'}\n      - id: add_activity")
	if showInPreview {
		flow = replace(flow, "    required: [status]\n    properties:\n      status: {type: string, minLength: 1, maxLength: 32}\n",
			"    required: [status, invite]\n    properties:\n      status: {type: string, minLength: 1, maxLength: 32}\n      invite: {type: string, minLength: 32, maxLength: 32}\n")
		flow = replace(flow, "preview: {status: '${{ steps.selected_task.outputs.first.status }}'}",
			"preview: {status: '${{ steps.selected_task.outputs.first.status }}', invite: '${{ params.generated.invite_token }}'}")
	}
	return flow
}

func (h *exposureHarness) prepareOutput() (string, map[string]any) {
	h.t.Helper()
	out, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if code != "" {
		h.t.Fatalf("prepare failed: %s", code)
	}
	id, _ := out["operation_id"].(string)
	return id, out
}

// storedPrepared reads the operation record the way commit does.
func (h *exposureHarness) storedPrepared(id string) (arguments, preview map[string]any) {
	h.t.Helper()
	tx, err := h.app.DB.Begin()
	if err != nil {
		h.t.Fatal(err)
	}
	defer tx.Rollback()
	appID, key, err := appMCPReadyOperationStorage(context.Background(), tx, h.app)
	if err != nil {
		h.t.Fatal(err)
	}
	stored, err := appMCPReadOperationWithKey(context.Background(), tx, appID, key, id)
	if err != nil {
		h.t.Fatal(err)
	}
	if arguments, err = appMCPDecodeObject(stored.Prepared.Arguments); err != nil {
		h.t.Fatal(err)
	}
	if preview, err = appMCPDecodeObject(stored.Prepared.Preview); err != nil {
		h.t.Fatal(err)
	}
	return arguments, preview
}

func (h *exposureHarness) generatedToken(id string) string {
	h.t.Helper()
	arguments, _ := h.storedPrepared(id)
	generated, _ := arguments["generated"].(map[string]any)
	token, _ := generated["invite_token"].(string)
	if len(generated) != 1 || token == "" {
		h.t.Fatalf("sealed arguments carry %#v", arguments)
	}
	return token
}

func (h *exposureHarness) taskTitle() string {
	h.t.Helper()
	var title string
	if err := h.app.DB.QueryRow("SELECT title FROM tasks WHERE id=1").Scan(&title); err != nil {
		h.t.Fatal(err)
	}
	return title
}

// auditDump is every column of every audit row as one string.
func (h *exposureHarness) auditDump() string {
	h.t.Helper()
	rows, err := h.app.DB.Query("SELECT * FROM _benmore_audit_log")
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	columns, _ := rows.Columns()
	var dump strings.Builder
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			h.t.Fatal(err)
		}
		for _, v := range values {
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			fmt.Fprintf(&dump, "%v|", v)
		}
		dump.WriteString("\n")
	}
	if dump.Len() == 0 {
		h.t.Fatal("no audit rows to inspect")
	}
	return dump.String()
}

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAppMCPGeneratedTokenStaysOutOfEverythingTheModelSees(t *testing.T) {
	h := newExposureHarnessWithFlow(t, generatedTaskFlow(t, false), "")
	id1, out1 := h.prepareOutput()
	id2, _ := h.prepareOutput()
	token1, token2 := h.generatedToken(id1), h.generatedToken(id2)
	raw, err := base64.RawURLEncoding.DecodeString(token1)
	if err != nil || len(raw) != 24 || len(token1) != 32 {
		t.Fatalf("token is not 24 base64url bytes: %q %v", token1, err)
	}
	if token1 == token2 {
		t.Fatal("two operations drew the same token")
	}
	if _, preview := h.storedPrepared(id1); strings.Contains(jsonText(t, preview), token1) {
		t.Fatalf("author did not put the token in the preview: %#v", preview)
	}
	_, page, _ := h.review(h.cookie, id1)
	for name, seen := range map[string]string{"prepare": jsonText(t, out1), "status": jsonText(t, h.status(id1)), "review page": page} {
		if strings.Contains(seen, token1) || strings.Contains(seen, token2) {
			t.Fatalf("%s shows a generated token: %s", name, seen)
		}
	}
	if h.taskTitle() != "Source-backed task" {
		t.Fatal("prepare wrote business data")
	}

	h.approveOK(id1)
	first, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id1})
	if code != "" || first["outcome"] != "applied" {
		t.Fatalf("commit: %q %#v", code, first)
	}
	// Apply bound exactly the sealed value, and not the other operation's.
	if got := h.taskTitle(); got != token1 || got == token2 {
		t.Fatalf("apply bound %q, sealed %q", got, token1)
	}
	if h.generatedToken(id1) != token1 {
		t.Fatal("sealed value changed after commit")
	}
	// The author's readback never selected it, so the receipt does not carry it.
	if strings.Contains(jsonText(t, first), token1) || strings.Contains(jsonText(t, h.status(id1)), token1) {
		t.Fatal("receipt or status shows the generated token")
	}
	// A replay applies nothing and draws nothing.
	again, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id1})
	if code != "" || again["outcome"] != "already_applied" || h.taskTitle() != token1 || h.generatedToken(id1) != token1 {
		t.Fatalf("replay: %q %#v", code, again)
	}

	// The audit log holds a digest of each value, never the value.
	dump := h.auditDump()
	if strings.Contains(dump, token1) || strings.Contains(dump, token2) {
		t.Fatal("an audit row holds a generated token")
	}
	arguments, _ := h.storedPrepared(id1)
	for name, digest := range appMCPGeneratedDigests(arguments) {
		if name != "invite_token" || !strings.Contains(dump, digest.(string)) {
			t.Fatalf("prepare audit lacks the digest of %s", name)
		}
	}
}

func TestAppMCPGeneratedTokenIsInThePreviewOnlyWhenTheAuthorPutsItThere(t *testing.T) {
	h := newExposureHarnessWithFlow(t, generatedTaskFlow(t, true), "")
	id, out := h.prepareOutput()
	token := h.generatedToken(id)
	_, storedPreview := h.storedPrepared(id)
	shown, _ := out["preview"].(map[string]any)
	if shown["invite"] != token || storedPreview["invite"] != token {
		t.Fatalf("preview %#v / stored %#v / sealed %q", shown, storedPreview, token)
	}
	_, page, _ := h.review(h.cookie, id)
	if !strings.Contains(page, token) {
		t.Fatal("the reviewer is not shown the token the preview carries")
	}
	h.approveOK(id)
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" {
		t.Fatalf("commit: %q", code)
	}
	// Preview, approval and apply all saw the one value.
	if h.taskTitle() != token {
		t.Fatalf("apply bound %q, preview and seal held %q", h.taskTitle(), token)
	}
	if dump := h.auditDump(); strings.Contains(dump, token) {
		t.Fatal("an audit row holds the previewed token")
	}
}

func TestAppMCPGeneratedValuesHaveTheDeclaredShape(t *testing.T) {
	declared := []FlowCommandGenerated{
		{Name: "a", Kind: "token", Bytes: 16, Encoding: "base64url"},
		{Name: "b", Kind: "token", Bytes: 24, Encoding: "hex"},
		{Name: "c", Kind: "token", Bytes: 64, Encoding: "base64url"},
	}
	drawn, err := appMCPGenerateCommandValues(declared)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := appMCPGenerateCommandValues(declared)
	for _, g := range declared {
		value := drawn[g.Name].(string)
		var raw []byte
		if g.Encoding == "hex" {
			raw, err = hex.DecodeString(value)
		} else {
			raw, err = base64.RawURLEncoding.DecodeString(value)
		}
		if err != nil || len(raw) != g.Bytes || len(value) != g.length() {
			t.Fatalf("%s: %q (%d bytes, %v), want %d bytes / %d chars", g.Name, value, len(raw), err, g.Bytes, g.length())
		}
		if value == again[g.Name] {
			t.Fatalf("%s drew the same value twice", g.Name)
		}
	}
}

const generatedBlock = "  version: 1\n  generated:\n    - {name: invite_token, kind: token, bytes: 24}\n"

func generatedFixture(t *testing.T, edit func(string) string) string {
	t.Helper()
	src := strings.Replace(commandFixture, "  version: 1\n", generatedBlock, 1)
	// Apply binds the token; the fixture's SQL uses it as the stored status.
	src = strings.Replace(src, "UPDATE work_items SET status = 'done' WHERE id = :id\n          params: {id: '${{ params.arguments.id }}'}",
		"UPDATE work_items SET status = :tok WHERE id = :id\n          params: {id: '${{ params.arguments.id }}', tok: '${{ params.generated.invite_token }}'}", 1)
	if !strings.Contains(src, "params.generated.invite_token") {
		t.Fatal("fixture anchor moved")
	}
	if edit != nil {
		src = edit(src)
	}
	return src
}

func TestFlowCommandGeneratedCompile(t *testing.T) {
	tables := map[string]bool{"work_items": true}
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(generatedFixture(t, nil)), tables)
	if err != nil {
		t.Fatal(err)
	}
	command := flow.Command
	if len(command.Generated) != 1 || command.Generated[0] != (FlowCommandGenerated{Name: "invite_token", Kind: "token", Encoding: "base64url", Bytes: 24}) {
		t.Fatalf("generated: %#v", command.Generated)
	}
	property := command.PreparedSchema.Properties["generated"]
	token := property.Properties["invite_token"]
	if property.Type != "object" || property.AdditionalProperties == nil || *property.AdditionalProperties || token == nil ||
		*token.MinLength != 32 || *token.MaxLength != 32 || !sameStrings(property.Required, []string{"invite_token"}) || !sameStrings(command.PreparedSchema.Required, []string{"arguments", "generated"}) {
		t.Fatalf("prepared schema does not declare the generated object: %#v", property)
	}
	if err := validateAppMCPSchemaValue(command.PreparedSchema, map[string]any{"arguments": map[string]any{"id": "1"}, "generated": map[string]any{"invite_token": strings.Repeat("A", 32)}}); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"short": strings.Repeat("A", 31), "extra": strings.Repeat("A", 33)} {
		if validateAppMCPSchemaValue(command.PreparedSchema, map[string]any{"arguments": map[string]any{"id": "1"}, "generated": map[string]any{"invite_token": value}}) == nil {
			t.Fatalf("%s token passed the prepared schema", name)
		}
	}
	if validateAppMCPSchemaValue(command.PreparedSchema, map[string]any{"arguments": map[string]any{"id": "1"}}) == nil {
		t.Fatal("arguments without the generated object passed")
	}

	refused := map[string]func(string) string{
		"undeclared name in apply": func(s string) string {
			return strings.Replace(s, "params.generated.invite_token", "params.generated.other", 1)
		},
		"undeclared name in preview": func(s string) string {
			return strings.Replace(s, "preview: '${{ steps.item.outputs }}'", "preview: '${{ params.generated.other }}'", 1)
		},
		"whole object": func(s string) string {
			return strings.Replace(s, "params.generated.invite_token", "params.generated", 1)
		},
		"path below name": func(s string) string {
			return strings.Replace(s, "params.generated.invite_token", "params.generated.invite_token.x", 1)
		},
		"unknown kind":   func(s string) string { return strings.Replace(s, "kind: token", "kind: uuid", 1) },
		"too few bytes":  func(s string) string { return strings.Replace(s, "bytes: 24", "bytes: 8", 1) },
		"too many bytes": func(s string) string { return strings.Replace(s, "bytes: 24", "bytes: 65", 1) },
		"bad encoding":   func(s string) string { return strings.Replace(s, "bytes: 24}", "bytes: 24, encoding: base64}", 1) },
		"unknown key":    func(s string) string { return strings.Replace(s, "bytes: 24}", "bytes: 24, prefix: x}", 1) },
		"bad name":       func(s string) string { return strings.Replace(s, "name: invite_token", "name: Invite", 1) },
		"duplicate name": func(s string) string {
			return strings.Replace(s, "bytes: 24}\n", "bytes: 24}\n    - {name: invite_token, kind: token, bytes: 16}\n", 1)
		},
		"empty list": func(s string) string {
			return strings.Replace(s, "  generated:\n    - {name: invite_token, kind: token, bytes: 24}\n", "  generated: []\n", 1)
		},
		"author declares generated": func(s string) string {
			return strings.Replace(s, "    properties:\n      arguments:", "    properties:\n      generated: {type: string, maxLength: 4}\n      arguments:", 1)
		},
	}
	for name, edit := range refused {
		src := generatedFixture(t, edit)
		if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(src), tables); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}

func TestAppMCPGeneratedInputSchemaCannotShadowIt(t *testing.T) {
	command := &FlowCommand{Generated: []FlowCommandGenerated{{Name: "invite_token", Kind: "token", Encoding: "base64url", Bytes: 24}}}
	manifest := commandManifest()
	tool := manifest.Tools[0]
	tool.InputSchema.Properties["generated"] = &AppMCPSchema{Type: "string", MaxLength: intPointer(4)}
	err := validateAppMCPCommandDescriptor(tool, command, nil, map[string]bool{"work_items": true}, nil)
	if err == nil || !strings.Contains(err.Error(), "generated") {
		t.Fatalf("input schema shadowing generated: %v", err)
	}
}
