//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStrictJSONComputePreservesNativeNumberBehavior(t *testing.T) {
	app, _ := auditApp(t)
	if err := os.MkdirAll(filepath.Join(app.Dir, "static"), 0755); err != nil {
		t.Fatal(err)
	}
	module := `export function order(x) {
 if (!Number.isSafeInteger(x.id) || !x.lines.every(l => Number.isSafeInteger(l.qty))) throw Error("whole quantities required");
 const result = {idType:typeof x.id, nestedType:typeof x.lines[0].qty, total:x.lines.reduce((n,l)=>n+l.qty*l.price,0),
  flag:x.flag === false, absent:x.absent === null, text:x.text === "3", zero:x.zero === 0,
  safe:Number.isSafeInteger(x.safe), unsafe:Number.isSafeInteger(x.unsafe), rounded:x.unsafe === 9007199254740992,
  decimal:x.decimal === 0.1, exponent:x.exponent === 125, negativeZero:Object.is(x.negativeZero,-0)};
 x.lines[0].qty=99; return result;
}`
	if err := os.WriteFile(filepath.Join(app.Dir, "static", "warehouse.ts"), []byte(module), 0644); err != nil {
		t.Fatal(err)
	}
	source := `on:
  request: {method: POST, path: /api/order-%s, strict_json: %t}
jobs:
  order:
    steps:
      - id: calculated
        run: compute
        with:
          module: warehouse
          function: order
          args: {id: '${{ params.id }}', lines: '${{ params.lines }}', flag: '${{ params.flag }}', absent: '${{ params.absent }}', text: '${{ params.text }}', zero: '${{ params.zero }}', safe: '${{ params.safe }}', unsafe: '${{ params.unsafe }}', decimal: '${{ params.decimal }}', exponent: '${{ params.exponent }}', negativeZero: '${{ params.negativeZero }}'}
      - run: respond
        with:
          status: 200
          body: {result: '${{ steps.calculated.outputs }}', original: '${{ params.lines }}', exact: '${{ params.unsafe }}'}
`
	mux := http.NewServeMux()
	for _, strict := range []bool{false, true} {
		label := fmt.Sprint(strict)
		flows, err := parseGHAFlowFile("flows/order-"+label+".yaml", []byte(fmt.Sprintf(source, label, strict)))
		if err != nil {
			t.Fatal(err)
		}
		RegisterFlows(mux, app, flows)
	}
	body := `{"id":7,"lines":[{"qty":2,"price":125},{"qty":3,"price":45}],"flag":false,"absent":null,"text":"3","zero":0,"safe":9007199254740991,"unsafe":9007199254740993,"decimal":0.1,"exponent":1.25e2,"negativeZero":-0}`
	var ordinary map[string]any
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/order-"+fmt.Sprint(strict), strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, request)
			if w.Code != 200 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var response map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			got := response["result"].(map[string]any)
			want := map[string]any{"idType": "number", "nestedType": "number", "total": float64(385), "flag": true, "absent": true, "text": true, "zero": true, "safe": true, "unsafe": false, "rounded": true, "decimal": true, "exponent": true, "negativeZero": true}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("compute result=%#v, want %#v", got, want)
			}
			if response["original"].([]any)[0].(map[string]any)["qty"] != float64(2) {
				t.Fatal("compute mutated request")
			}
			if strict && !strings.Contains(w.Body.String(), `"exact":9007199254740993`) {
				t.Fatalf("source number lost precision outside compute: %s", w.Body.String())
			}
			if strict && !reflect.DeepEqual(got, ordinary) {
				t.Fatal("strict and ordinary compute disagree")
			}
			ordinary = got
		})
	}
	// Ambiguous JSON is still refused before the compute module executes.
	request := httptest.NewRequest(http.MethodPost, "/api/order-true", strings.NewReader(`{"id":7,"id":8}`))
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, request)
	if w.Code != 400 {
		t.Fatalf("duplicate key status=%d", w.Code)
	}
}

func TestComputeJSONNumbersNestedContainersAndBounds(t *testing.T) {
	app := writeComputeFixture(t, "numbers.ts", `export function inspect(x){ return {kind:typeof x.value, value:x.value, finite:Number.isFinite(x.value), safe:Number.isSafeInteger(x.value)}; }`)
	for _, tc := range []struct {
		raw   string
		value float64
		safe  bool
	}{
		{"0", 0, true}, {"-7", -7, true}, {"1.25e2", 125, true}, {"0.1", 0.1, false}, {"9007199254740991", 9007199254740991, true}, {"9007199254740993", 9007199254740992, false}, {"1e-400", 0, true},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			input := map[string]any{"value": json.Number(tc.raw)}
			result, err := RunCompute(app, "numbers", "inspect", input, 0)
			if err != nil {
				t.Fatal(err)
			}
			wire, _ := json.Marshal(result)
			var got map[string]any
			json.Unmarshal(wire, &got)
			if got["kind"] != "number" || got["value"] != tc.value || got["finite"] != true || got["safe"] != tc.safe {
				t.Fatalf("got %s", wire)
			}
			if input["value"] != json.Number(tc.raw) {
				t.Fatal("source input changed")
			}
		})
	}
	for _, raw := range []string{"1e400", "-1e400", "invalid", "NaN", "Inf"} {
		if _, err := RunCompute(app, "numbers", "inspect", map[string]any{"value": json.Number(raw)}, 0); err == nil || !strings.Contains(err.Error(), "finite JavaScript number range") {
			t.Fatalf("invalid number %s: %v", raw, err)
		}
	}
	input := []map[string]any{{"values": []any{json.Number("2"), nil, false, "2"}, "empty": []any{}}, nil}
	out, err := computeJSONNumbers(input)
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{{"values": []any{float64(2), nil, false, "2"}, "empty": []any{}}, nil}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("container conversion=%#v", out)
	}
	if _, ok := input[0]["values"].([]any)[0].(json.Number); !ok {
		t.Fatal("source container changed")
	}
	// Reviewed connector calls retain their exact-number admission rule.
	if _, err := appMCPComputeArgs(map[string]any{"value": json.Number("9007199254740993")}); err == nil {
		t.Fatal("connector precision guard widened")
	}
}
