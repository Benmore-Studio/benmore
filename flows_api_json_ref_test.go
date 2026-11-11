//go:build !cli

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// `json: ${{ steps.x.outputs }}` names the value to send. It used to be
// dropped, so the upstream (Slack, in the report) received an empty request.
func TestAPIStepJSONReferenceSendsTheValue(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	var sent []byte
	var contentType string
	client := &http.Client{Transport: freshAuditRuntimeTransport(func(r *http.Request) (*http.Response, error) {
		sent, _ = io.ReadAll(r.Body)
		contentType = r.Header.Get("Content-Type")
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})}
	for _, tc := range []struct {
		name, ref string
		data      any
		want      string
	}{
		{"object", "${{ steps.build.outputs }}", map[string]any{"text": "hi", "blocks": []any{map[string]any{"type": "section"}}}, `{"blocks":[{"type":"section"}],"text":"hi"}`},
		{"list", "${{ steps.build.outputs }}", []any{map[string]any{"id": 1}}, `[{"id":1}]`},
		{"json text", "${{ steps.build.outputs }}", `{"text":"from compute"}`, `{"text":"from compute"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sent, contentType = nil, ""
			api := withToAPI(map[string]any{"method": "POST", "url": "https://8.8.8.8/hook", "json": tc.ref})
			if api.JSONRef == "" {
				t.Fatalf("json reference not loaded: %+v", api)
			}
			ctx := &FlowContext{App: app, Data: map[string]any{"build": tc.data}, Params: map[string]string{}}
			step := &FlowStep{Name: "send", Type: "api", API: api}
			if err := execStepAPIWithClient(ctx, step, client); err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(sent, &got); err != nil {
				t.Fatalf("body %q is not JSON: %v", sent, err)
			}
			_ = json.Unmarshal([]byte(tc.want), &want)
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) || contentType != "application/json" {
				t.Fatalf("sent %s (%s), want %s", sent, contentType, tc.want)
			}
		})
	}
}

// `body:` that is one reference to an object sends it as JSON, not Go's %v.
func TestAPIStepTextBodyReferenceToObjectSendsJSON(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	var sent []byte
	client := &http.Client{Transport: freshAuditRuntimeTransport(func(r *http.Request) (*http.Response, error) {
		sent, _ = io.ReadAll(r.Body)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
	})}
	api := withToAPI(map[string]any{"method": "POST", "url": "https://8.8.8.8/hook", "body": "${{ steps.build.outputs }}"})
	ctx := &FlowContext{App: app, Data: map[string]any{"build": map[string]any{"text": "hi"}}, Params: map[string]string{}}
	if err := execStepAPIWithClient(ctx, &FlowStep{Name: "send", Type: "api", API: api}, client); err != nil {
		t.Fatal(err)
	}
	if string(sent) != `{"text":"hi"}` {
		t.Fatalf("sent %q, want the object as JSON", sent)
	}
}

// An unresolved reference fails the step before anything is sent.
func TestAPIStepJSONReferenceUnresolvedSendsNothing(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	calls := 0
	client := &http.Client{Transport: freshAuditRuntimeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
	})}
	api := withToAPI(map[string]any{"method": "POST", "url": "https://8.8.8.8/hook", "json": "${{ steps.missing.outputs }}"})
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	if err := execStepAPIWithClient(ctx, &FlowStep{Name: "send", Type: "api", API: api}, client); err == nil {
		t.Fatal("unresolved json reference did not fail the step")
	}
	if calls != 0 {
		t.Fatalf("request sent %d times with an unresolved body", calls)
	}
}

func TestAPIStepJSONValueProblems(t *testing.T) {
	for _, tc := range []struct {
		with map[string]any
		want string
	}{
		{map[string]any{"json": "${{ steps.x.outputs }}"}, ""},
		{map[string]any{"json": map[string]any{"a": 1}}, ""},
		{map[string]any{"json": "text ${{ steps.x.outputs }}"}, "one `${{ }}` reference"},
		{map[string]any{"json": 3}, "one `${{ }}` reference"},
		{map[string]any{"json": nil}, "one `${{ }}` reference"},
		{map[string]any{"json": "${{ steps.x.outputs }}", "body": "hello"}, "both set"},
	} {
		problems := strings.Join(apiBodyValueProblems(tc.with), "\n")
		if tc.want == "" && problems != "" || tc.want != "" && !strings.Contains(problems, tc.want) {
			t.Errorf("apiBodyValueProblems(%v) = %q, want %q", tc.with, problems, tc.want)
		}
	}
}
