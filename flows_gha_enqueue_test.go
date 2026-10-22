//go:build !cli

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const ghaEnqueueFixture = `on:
  request: {method: POST, path: /api/queue, auth: required, transaction: true}
jobs:
  queue:
    steps:
      - id: queued
        run: enqueue
        with:
          flow: worker
          unique_key: "worker:${{ params.id }}"
          run_at: ""
          with: {id: "${{ params.id }}", label: "${{ steps.read.outputs.label }}"}
`

func parsedEnqueue(t *testing.T, source string) FlowStep {
	t.Helper()
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(source), &file); err != nil {
		t.Fatal(err)
	}
	return convertGHASteps(file.Jobs["queue"].Steps)[0]
}

func TestGHAEnqueueMapsCanonicalTransactionAndActiveUniqueKey(t *testing.T) {
	if message := ValidateOnWrite("flows/queue.yaml", ghaEnqueueFixture); message != "" {
		t.Fatal(message)
	}
	step := parsedEnqueue(t, ghaEnqueueFixture)
	if step.Type != "enqueue" || step.Enqueue.Flow != "worker" || step.Enqueue.UniqueKey != "worker:{{params.id}}" || step.Enqueue.With["label"] != "{{read.label}}" {
		t.Fatalf("mapping: %#v", step.Enqueue)
	}
	app := newJobsTestApp(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ctx := &FlowContext{App: app, Tx: tx, Data: map[string]any{"id": "7", "read": map[string]any{"label": "owned"}}, Params: map[string]string{"id": "7"}}
	if err := executeStep(ctx, &step); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if countJobs(t, app.DB) != 0 {
		t.Fatal("rollback retained enqueue")
	}
	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ctx.Tx = tx
	if err := executeStep(ctx, &step); err != nil {
		t.Fatal(err)
	}
	if err := executeStep(ctx, &step); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if countJobs(t, app.DB) != 1 {
		t.Fatal("active key did not deduplicate parsed enqueue")
	}
	var payload, unique string
	if err := app.DB.QueryRow("SELECT payload,unique_key FROM _benmore_jobs").Scan(&payload, &unique); err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(payload), &values); err != nil {
		t.Fatal(err)
	}
	if unique != "worker:7" || values["id"] != "7" || values["label"] != "owned" {
		t.Fatalf("payload=%v key=%s", values, unique)
	}
	if _, present := values[flowJobActorPayloadField]; present {
		t.Fatal("explicit enqueue forged actor snapshot")
	}
}

func TestGHAEnqueueRejectsMisshapedBindingsAndRequestChosenFlow(t *testing.T) {
	for _, change := range []struct{ old, new string }{
		{"flow: worker", "flow: ''"}, {"flow: worker", "flow: 42"},
		{`run_at: ""`, `run_at: 42`}, {`unique_key: "worker:${{ params.id }}"`, `unique_key: 42`},
		{`with: {id: "${{ params.id }}", label: "${{ steps.read.outputs.label }}"}`, `with: {id: {hidden: value}}`},
	} {
		bad := strings.Replace(ghaEnqueueFixture, change.old, change.new, 1)
		if ValidateOnWrite("flows/queue.yaml", bad) == "" {
			t.Fatalf("accepted %s", change.new)
		}
		step := parsedEnqueue(t, bad)
		app := newJobsTestApp(t)
		if executeStep(&FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}, &step) == nil {
			t.Fatalf("invalid loaded enqueue ran: %s", change.new)
		}
		if countJobs(t, app.DB) != 0 {
			t.Fatal("invalid loaded enqueue created a job")
		}
	}
	step := parsedEnqueue(t, strings.Replace(ghaEnqueueFixture, "flow: worker", "flow: '${{ params.target }}'", 1))
	app := newJobsTestApp(t)
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{"target": "privileged"}, RequestKeys: map[string]bool{"target": true}}
	if err := executeStep(ctx, &step); err == nil || !strings.Contains(err.Error(), "request-sourced") {
		t.Fatalf("request target allowed: %v", err)
	}
	if countJobs(t, app.DB) != 0 {
		t.Fatal("request-chosen flow enqueued")
	}
}

func TestLegacyEnqueuePreservesActiveUniqueKey(t *testing.T) {
	var source []FlowStepYAML
	if err := yamlUnmarshal([]byte(`- enqueue: {flow: worker, unique_key: 'worker:{{id}}', run_at: '', with: {id: '{{id}}'}}`), &source); err != nil {
		t.Fatal(err)
	}
	step := convertSteps(source)[0]
	if step.Enqueue == nil || step.Enqueue.UniqueKey != "worker:{{id}}" {
		t.Fatalf("legacy key dropped: %#v", step.Enqueue)
	}
	app := newJobsTestApp(t)
	ctx := &FlowContext{App: app, Data: map[string]any{"id": "9"}, Params: map[string]string{"id": "9"}}
	for i := 0; i < 2; i++ {
		if err := executeStep(ctx, &step); err != nil {
			t.Fatal(err)
		}
	}
	if countJobs(t, app.DB) != 1 {
		t.Fatal("legacy parsed key did not deduplicate")
	}
}
