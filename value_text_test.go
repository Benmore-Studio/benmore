//go:build !cli

package main

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestValueTextWritesNumbersInFull(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{1234567.0, "1234567"},
		{1729600000.0, "1729600000"},
		{-2500000.0, "-2500000"},
		{1234567.5, "1234567.5"},
		{0.5, "0.5"},
		{0.0, "0"},
		{0.00001, "0.00001"},
		{1e-7, "1e-7"},
		{1e21, "1e+21"},
		{float32(2500000), "2500000"},
		{json.Number("1234567"), "1234567"},
		{int64(1234567), "1234567"},
		{true, "true"},
		{"1.5e+06", "1.5e+06"},
		{nil, "<nil>"},
		{math.Inf(1), "+Inf"},
	}
	for _, c := range cases {
		if got := valueText(c.in); got != c.want {
			t.Errorf("valueText(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A JSON request number of a million or more used to reach SQL as
// "1.234567e+06", which CAST(... AS INTEGER) reads as 1: every bind form
// (a `:name` request param, a `with.params` template, a bare `{{ref}}`) must
// bind the whole number.
func TestFlowJSONBodyLargeNumbersBindInFull(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow := `on:
  request:
    method: POST
    path: /api/probe-num
jobs:
  main:
    steps:
      - id: direct
        run: sql
        with:
          query: "SELECT CAST(:n AS INTEGER) AS n, typeof(:n) AS t, CAST(:ts AS INTEGER) AS ts, :f AS f"
      - id: templated
        run: sql
        with:
          query: "SELECT CAST(:v AS INTEGER) AS n, typeof(:v) AS t"
          params:
            v: '${{ params.n }}'
      - id: bare
        run: sql
        with:
          query: "SELECT CAST({{n}} AS INTEGER) AS n, typeof({{n}}) AS t"
      - run: respond
        with:
          status: 200
          json:
            direct: ${{ steps.direct.outputs.rows[0] }}
            templated: ${{ steps.templated.outputs.rows[0] }}
            bare: ${{ steps.bare.outputs.rows[0] }}
`
	rr := runProbeGHAFlow(t, app, flow, `{"n":1234567,"ts":1729600000,"f":1234567.5}`)
	if rr.Code != 200 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var got map[string]map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	for _, step := range []string{"direct", "templated", "bare"} {
		row := got[step]
		if row["n"] != float64(1234567) || row["t"] != "integer" {
			t.Errorf("%s: bound %v (%v), want integer 1234567; body %s", step, row["n"], row["t"], rr.Body.String())
		}
	}
	if got["direct"]["ts"] != float64(1729600000) {
		t.Errorf("timestamp bound as %v, want 1729600000", got["direct"]["ts"])
	}
	if got["direct"]["f"] != 1234567.5 {
		t.Errorf("fraction bound as %v, want 1234567.5", got["direct"]["f"])
	}
}

// Hook templates read job payload rows, whose numbers are JSON-decoded.
func TestHookRowTemplateWritesLargeNumbersInFull(t *testing.T) {
	row := map[string]any{}
	if err := json.Unmarshal([]byte(`{"duration_ms":1234567,"size":2500000.5}`), &row); err != nil {
		t.Fatal(err)
	}
	got := interpolateRow("d={{duration_ms}} s={{size}}", row, "")
	if want := "d=1234567 s=2500000.5"; got != want {
		t.Fatalf("interpolateRow = %q, want %q", got, want)
	}
	if strings.Contains(ApplyPipe(row["duration_ms"], "default:0"), "e+") {
		t.Fatalf("pipe output kept exponent notation")
	}
}

func TestUnmarshalJSONExactKeepsLargeIntegers(t *testing.T) {
	var got map[string]any
	if err := unmarshalJSONExact([]byte(`{"snowflake":1234567890123456789,"edge":9007199254740993,"small":1234567,"neg":-9007199254740993,"f":0.5,"nested":[{"id":1234567890123456789}],"huge":1e300}`), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"snowflake": int64(1234567890123456789), "edge": int64(9007199254740993), "small": float64(1234567), "neg": int64(-9007199254740993), "f": 0.5, "huge": 1e300}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	if id := got["nested"].([]any)[0].(map[string]any)["id"]; id != int64(1234567890123456789) {
		t.Errorf("nested id = %#v", id)
	}
	for _, bad := range []string{`{"a":1} trailing`, `{"a":1e400}`, `[1]`} {
		var m map[string]any
		if err := unmarshalJSONExact([]byte(bad), &m); err == nil {
			t.Errorf("%s decoded without error", bad)
		}
	}
}

// A 64-bit id in a request body reaches SQL with every digit.
func TestFlowJSONBodyKeepsSnowflakeIDs(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow := `on:
  request:
    method: POST
    path: /api/probe-id
jobs:
  main:
    steps:
      - id: q
        run: sql
        with:
          query: "SELECT CAST(:id AS TEXT) AS id, typeof(:id) AS t"
      - run: respond
        with:
          status: 200
          body: 'id=${{ steps.q.outputs.id }} t=${{ steps.q.outputs.t }} echo=${{ params.id }}'
`
	rr := runProbeGHAFlow(t, app, flow, `{"id":1234567890123456789}`)
	if got, want := rr.Body.String(), "id=1234567890123456789 t=integer echo=1234567890123456789"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
