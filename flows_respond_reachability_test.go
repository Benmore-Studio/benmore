//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestFlowStepAfterUnconditionalRespondIsRefused(t *testing.T) {
	flow := "on:\n  request: { method: POST, path: /api/x }\njobs:\n  main:\n    steps:\n" +
		"      - run: respond\n        with: { status: 200, body: { ok: true } }\n" +
		"      - id: cleanup\n        run: sql\n        with: { query: \"SELECT 1 AS ok\" }\n"
	if msg := ValidateOnWrite("flows/x.yaml", flow); msg == "" {
		t.Fatal("a step after an unconditional respond was accepted; it can never run")
	}
}

// Control: steps after a respond that only runs under `if:` are reachable.
func TestFlowStepAfterConditionalRespondIsAccepted(t *testing.T) {
	flow := "on:\n  request: { method: POST, path: /api/x }\njobs:\n  main:\n    steps:\n" +
		"      - if: \"${{ params.a == 'x' }}\"\n        run: respond\n        with: { status: 403, body: { error: no } }\n" +
		"      - id: cleanup\n        run: sql\n        with: { query: \"SELECT 1 AS ok\" }\n" +
		"      - run: respond\n        with: { status: 200, body: { ok: true } }\n"
	if msg := ValidateOnWrite("flows/x.yaml", flow); msg != "" {
		t.Fatalf("a reachable step was refused: %s", msg)
	}
}

func TestFlowResponseReachabilityNestedAndBackground(t *testing.T) {
	response := FlowStepGHA{Run: "respond", With: map[string]any{"status": 200, "body": map[string]any{"ok": true}}}
	work := FlowStepGHA{Run: "sql", With: map[string]any{"query": "SELECT 1 AS ok"}}
	conditional := response
	conditional.If = "${{ params.a == 'x' }}"
	for _, tt := range []struct {
		name      string
		steps     []FlowStepGHA
		wantError bool
	}{
		{"final response", []FlowStepGHA{work, response}, false},
		{"conditional response", []FlowStepGHA{conditional, work}, false},
		{"if branch", []FlowStepGHA{{If: "${{ params.a == 'x' }}", Steps: []FlowStepGHA{response, work}}}, true},
		{"else branch", []FlowStepGHA{{If: "${{ params.a == 'x' }}", Steps: []FlowStepGHA{work}, Else: []FlowStepGHA{response, work}}}, true},
		{"loop body", []FlowStepGHA{{ForEach: "${{ params.items }}", Steps: []FlowStepGHA{response, work}}}, true},
		{"error handler", []FlowStepGHA{{Run: "sql", With: work.With, OnError: []FlowStepGHA{response, work}}}, true},
		{"handler response followed by parent work", []FlowStepGHA{{Run: "sql", With: work.With, OnError: []FlowStepGHA{response}}, work}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var file FlowFileGHA
			if err := yamlUnmarshal([]byte("on:\n  request: {method: POST, path: /api/x}\njobs:\n  main:\n    steps: []\n"), &file); err != nil {
				t.Fatal(err)
			}
			job := file.Jobs["main"]
			job.Steps = tt.steps
			file.Jobs["main"] = job
			msg := flowUnreachableResponseViolation(file)
			if (msg != "") != tt.wantError {
				t.Fatalf("got %q, want error %v", msg, tt.wantError)
			}
			if tt.wantError && !strings.Contains(msg, "before the response") {
				t.Fatalf("missing remedy: %s", msg)
			}
			file.On.Request.Mode = "async"
			if msg := flowUnreachableResponseViolation(file); msg != "" {
				t.Fatalf("background response does not stop execution: %s", msg)
			}
			file.On.Request = nil
			if msg := flowUnreachableResponseViolation(file); msg != "" {
				t.Fatalf("non-HTTP response does not stop execution: %s", msg)
			}
		})
	}
}

func TestFlowResponseReachabilityKeepsExistingSourceLoadable(t *testing.T) {
	flow := "on:\n  request: { method: POST, path: /api/x }\njobs:\n  main:\n    steps:\n" +
		"      - run: respond\n        with: { status: 200, body: { ok: true } }\n" +
		"      - run: sql\n        with: { query: SELECT 1 AS ok }\n"
	if flows, err := parseGHAFlowFile("flows/x.yaml", []byte(flow)); err != nil || len(flows) != 1 {
		t.Fatalf("lint must not remove an existing route at startup: flows=%d err=%v", len(flows), err)
	}
}
