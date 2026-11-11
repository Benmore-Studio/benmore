//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEdgeReplacedStatusWarnings(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	flow := `on:
  request: { method: POST, path: /api/checkout }
jobs:
  checkout:
    steps:
      - id: session
        run: api
        with: { method: POST, url: "https://api.stripe.com/v1/checkout/sessions" }
        on_error:
          - run: respond
            with: { status: 502, json: { error: stripe } }
      - run: respond
        with: { status: "504", json: { error: slow } }
      - run: respond
        with: { status: 503, json: { ok: true } }
`
	if err := os.WriteFile(filepath.Join(dir, "flows", "checkout.yaml"), []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, written := range []string{"flows/checkout.yaml", ""} {
		got := edgeReplacedStatusWarnings(dir, written)
		if len(got) != 2 || !strings.Contains(got[0].Message, "responds 502") || !strings.Contains(got[1].Message, "responds 504") || got[0].Severity != "warning" {
			t.Fatalf("written %q: %+v", written, got)
		}
	}
	// A push of another file does not repeat the warning.
	if got := edgeReplacedStatusWarnings(dir, "static/app.tsx"); len(got) != 0 {
		t.Fatalf("unrelated write repeated the warning: %+v", got)
	}
}

// Cloudflare also replaced a respond 520 with its own "error code: 520" page,
// and a status expression whose answer can be 502 (an on_error handler's
// `${{ params.code == 418 && 202 || 502 }}`) lost its body the same way;
// neither was warned (round 2026-11-05 logic finding 7).
func TestEdgeReplacedStatusWarnsOn52xAndStatusExpressions(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	flow := `on:
  request: { method: POST, path: /api/status-lab }
jobs:
  lab:
    steps:
      - id: call
        run: api
        with: { method: GET, url: "https://example.com/status" }
        on_error:
          - id: handler
            run: respond
            with: { status: "${{ params.code == 418 && 202 || 502 }}", json: { ok: false } }
      - id: a
        run: respond
        with: { status: 520, json: { ok: false } }
      - id: b
        run: respond
        with: { status: "530", json: { ok: false } }
      - id: c
        run: respond
        with: { status: "${{ params.st || 504 }}", json: { ok: false } }
      - id: d
        run: respond
        with: { status: "${{ params.st == 'x' && 520 || params.st | default:521 }}", json: { ok: false } }
      - id: quiet1
        run: respond
        with: { status: 599, json: { ok: false } }
      - id: quiet2
        run: respond
        with: { status: 519, json: { ok: false } }
      - id: quiet3
        run: respond
        with: { status: "${{ params.code == 502 && 503 || 500 }}", json: { ok: false } }
      - id: quiet4
        run: respond
        with: { status: "${{ params.st }}", json: { ok: false } }
      - id: quiet5
        run: respond
        with: { status: "${{ steps.s502.outputs.code || 503 }}", json: { ok: false } }
`
	if err := os.WriteFile(filepath.Join(dir, "flows", "status-lab.yaml"), []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	got := edgeReplacedStatusWarnings(dir, "flows/status-lab.yaml")
	var messages []string
	for _, f := range got {
		messages = append(messages, f.Message)
	}
	joined := strings.Join(messages, "\n")
	for _, want := range []string{`("handler") can respond 502`, `("a") responds 520`, `("b") responds 530`, `("c") can respond 504`, `("d") can respond 520 or 521`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
	for _, quiet := range []string{"quiet1", "quiet2", "quiet3", "quiet4", "quiet5"} {
		if strings.Contains(joined, `("`+quiet+`")`) {
			t.Errorf("step %s warned:\n%s", quiet, joined)
		}
	}
	if len(got) != 5 {
		t.Fatalf("got %d warnings, want 5:\n%s", len(got), joined)
	}
	for _, f := range got {
		if f.Severity != "warning" || !strings.Contains(f.Message, "520-530") || !strings.Contains(f.Message, "Answer 503") {
			t.Fatalf("finding %+v", f)
		}
	}
	// The warning quotes the status as written.
	if !strings.Contains(joined, "(status: ${{ params.code == 418 && 202 || 502 }})") {
		t.Fatalf("expression not quoted as written:\n%s", joined)
	}
}
