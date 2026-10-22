//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func TestGHAInlineSigningPreservesComputeOrder(t *testing.T) {
	const bindings = `  ts: "1700000000"
  sig: "{{ params.secret | hmac_sha256:'{{ts}}.{{body}}' | hex }}"
`
	const tail = `
            secret: synthetic-signing-key
            headers: {X-Timestamp: "{{ts}}", X-Signature: "{{sig}}"}`
	cases := []struct {
		name, prefix, sign string
		nested             bool
	}{
		{"inline", "", `compute:
              ts: "1700000000"
              sig: "{{ params.secret | hmac_sha256:'{{ts}}.{{body}}' | hex }}"` + tail, false},
		{"anchored", "x-compute: &ordered\n" + bindings, `compute: *ordered` + tail, false},
		{"merged", "x-compute: &ordered\n" + bindings, `compute: {<<: *ordered}` + tail, false},
		{"merged-sequence", "x-time: &time {ts: '1700000000'}\nx-signature: &signature\n  sig: \"{{ params.secret | hmac_sha256:'{{ts}}.{{body}}' | hex }}\"\n", `compute: {<<: [*time, *signature]}` + tail, false},
		{"explicit-override", "x-compute: &ordered\n  ts: wrong\n  sig: \"{{ params.secret | hmac_sha256:'{{ts}}.{{body}}' | hex }}\"\n", `compute:
              ts: "1700000000"
              <<: *ordered` + tail, false},
		{"nested", "x-compute: &ordered\n" + bindings, `compute: *ordered` + tail, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			steps := `      - run: api
        with:
          url: https://receiver.example.test/events
          method: POST
          sign:
            ` + tc.sign + "\n"
			if tc.nested {
				steps = "      - if: 'true'\n        steps:\n" + "    " + strings.ReplaceAll(strings.TrimSuffix(steps, "\n"), "\n", "\n    ") + "\n"
			}
			src := tc.prefix + `on:
  request: {method: POST, path: /api/dispatch}
jobs:
  dispatch:
    steps:
` + steps
			flows, err := parseGHAFlowFile("flows/dispatch.yaml", []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			step := flows[0].Steps[0]
			if tc.nested {
				step = step.Steps[0]
			}
			call := step.API
			body := []byte(`{"value":475}`)
			req, _ := http.NewRequest(http.MethodPost, call.URL, strings.NewReader(string(body)))
			if err := applySigner(req, body, call.Sign, nil); err != nil {
				t.Fatalf("documented sequential signature failed: %v", err)
			}
			h := hmac.New(sha256.New, []byte("synthetic-signing-key"))
			h.Write(append([]byte("1700000000."), body...))
			if req.Header.Get("X-Timestamp") != "1700000000" || req.Header.Get("X-Signature") != hex.EncodeToString(h.Sum(nil)) {
				t.Fatal("signature does not match the original body and declared timestamp")
			}
		})
	}
}
