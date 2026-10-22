//go:build !cli && !windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const commandRefusalAnchor = "      - run: respond\n        with:\n          status: 200\n          json:\n            arguments: {id:"

// refusalTaskFlow is the task command with an `if` in prepare that refuses
// when project_id equals the given literal.
func refusalTaskFlow(t *testing.T, projectID, status, message string) string {
	t.Helper()
	step := "      - if: '${{ params.arguments.project_id }} == " + projectID + "'\n        steps:\n          - run: respond\n            with: {status: " + status + ", json: {error: \"" + message + "\"}}\n"
	return replaceCommandTextOnce(t, hookTaskFlow, commandRefusalAnchor, step+commandRefusalAnchor)
}

// callMessage returns the failed tool result's code and text.
func (h *exposureHarness) callMessage(name string, args map[string]any) (code, text string, isError bool) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := h.client.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		h.t.Fatalf("call %s: %v", name, err)
	}
	if len(result.Content) > 0 {
		if content, ok := result.Content[0].(*sdk.TextContent); ok {
			text = content.Text
		}
	}
	code, _ = result.Meta["error_code"].(string)
	return code, text, result.IsError
}

func (h *exposureHarness) operationRows() int {
	h.t.Helper()
	if h.count("SELECT count(*) FROM sqlite_master WHERE name='_benmore_mcp_operations'") == 0 {
		return 0
	}
	return h.count("SELECT count(*) FROM _benmore_mcp_operations")
}

func TestAppMCPCommandPrepareRefusalReturnsCodeAndMessageAndStoresNothing(t *testing.T) {
	cases := []struct{ status, code string }{
		{"400", "invalid_input"}, {"422", "invalid_input"}, {"403", "denied"}, {"404", "denied"}, {"409", "conflict"}, {"418", "denied"},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			message := "Only an organization owner, admin or member can complete tasks."
			h := newExposureHarnessWithFlow(t, refusalTaskFlow(t, "7", tc.status, message), "")
			code, text, isError := h.callMessage("complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if !isError || code != tc.code || text != tc.code+": "+message {
				t.Fatalf("refusal: error=%t code=%q text=%q", isError, code, text)
			}
			if rows := h.operationRows(); rows != 0 {
				t.Fatalf("a refused prepare stored %d operations", rows)
			}
			if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action LIKE 'mcp_command%'") != 0 {
				t.Fatal("a refused prepare wrote an audit row")
			}
			if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 {
				t.Fatal("a refused prepare changed business data")
			}
		})
	}
}

func TestAppMCPCommandPrepareRefusalOnlyFiresWhenItsConditionHolds(t *testing.T) {
	h := newExposureHarnessWithFlow(t, refusalTaskFlow(t, "8", "403", "Not for this project."), "")
	// project_id 7 does not match the condition, so the prepare proceeds as usual.
	id := h.prepare()
	if h.operationRows() != 1 || h.status(id)["state"] != "prepared" {
		t.Fatal("a prepare whose refusal condition is false did not store its operation")
	}
}

func TestAppMCPCommandRuntimeRefusalRespondIsPreparePhaseOnly(t *testing.T) {
	refusal := func(status int, body map[string]any) FlowStep {
		return FlowStep{Type: "respond", Respond: &FlowRespond{Status: status, JSON: body}}
	}
	ok := map[string]any{"error": "Not allowed."}
	branch := func(steps ...FlowStep) FlowStep { return FlowStep{Type: "if", Condition: "x", Steps: steps} }
	set := FlowStep{Type: "set", Set: map[string]string{"a": "b"}}
	success := FlowStep{Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"arguments": nil, "preview": nil}}}
	phaseOf := func(first FlowStep) FlowCommandPhase { return FlowCommandPhase{Steps: []FlowStep{first, success}} }

	if err := validateAppMCPCommandRuntimePhase(phaseOf(branch(refusal(403, ok))), "prepare", nil); err != nil {
		t.Fatalf("prepare refusal rejected: %v", err)
	}
	elseOnly := branch(set)
	elseOnly.ElseSteps = []FlowStep{refusal(409, ok)}
	if err := validateAppMCPCommandRuntimePhase(phaseOf(elseOnly), "prepare", nil); err != nil {
		t.Fatalf("prepare else refusal rejected: %v", err)
	}
	for name, step := range map[string]FlowStep{
		"5xx":                branch(refusal(500, ok)),
		"2xx":                branch(refusal(200, ok)),
		"401":                branch(refusal(401, ok)),
		"templated message":  branch(refusal(403, map[string]any{"error": "${{ params.x }}"})),
		"empty message":      branch(refusal(403, map[string]any{"error": ""})),
		"long message":       branch(refusal(403, map[string]any{"error": strings.Repeat("x", 501)})),
		"extra key":          branch(refusal(403, map[string]any{"error": "no", "more": "x"})),
		"non-string message": branch(refusal(403, map[string]any{"error": 7})),
		"not alone":          branch(set, refusal(403, ok)),
		"bare respond":       refusal(403, ok),
		"templated status":   branch(FlowStep{Type: "respond", Respond: &FlowRespond{StatusTemplate: "${{ x }}", JSON: ok}}),
		"extra body":         branch(FlowStep{Type: "respond", Respond: &FlowRespond{Status: 403, JSON: ok, Body: "x"}}),
		"loop":               {Type: "for_each", ForEach: "params.items", ForAs: "row", Steps: []FlowStep{refusal(403, ok)}},
		"refusal if in loop": {Type: "for_each", ForEach: "params.items", ForAs: "row", Steps: []FlowStep{branch(refusal(403, ok))}},
		"refusal in nested":  {Type: "for_each", ForEach: "params.items", ForAs: "row", Steps: []FlowStep{{Type: "for_each", ForEach: "row.items", ForAs: "inner", Steps: []FlowStep{branch(refusal(403, ok))}}}},
	} {
		if err := validateAppMCPCommandRuntimePhase(phaseOf(step), "prepare", nil); err == nil {
			t.Errorf("prepare accepted %s", name)
		}
	}

	// Apply runs in the write transaction, where a refusal must stay an
	// expect_rows rollback; readback must always produce its result.
	applyPhase := FlowCommandPhase{Steps: []FlowStep{branch(refusal(403, ok)), {Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"ok": true}}}}}
	if err := validateAppMCPCommandRuntimePhase(applyPhase, "apply", nil); err == nil {
		t.Error("apply accepted a mid-phase respond")
	}
	readbackPhase := FlowCommandPhase{Steps: []FlowStep{branch(refusal(403, ok)), {Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"x": nil}}}}}
	if err := validateAppMCPCommandRuntimePhase(readbackPhase, "readback", nil); err == nil {
		t.Error("readback accepted a mid-phase respond")
	}
}
