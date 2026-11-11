//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// `{fn:'count', field:'status'}` used to decode as `{fn:'count'}`, so it
// answered COUNT(*) rather than the count of non-NULL statuses: the unknown
// key was dropped and the caller got a confident wrong number. Spelling the
// operand `field` or `column`, or the alias `alias`, is the mistake an agent
// or a developer actually makes.
func TestQueryAggregateUnknownKeyRefused(t *testing.T) {
	mux := newQuerySemanticsFixture(t)
	for _, tc := range []struct {
		name, aggregates, key string
	}{
		{"count with field", `[{"fn":"count","field":"status"}]`, "field"},
		{"sum with column", `[{"fn":"sum","column":"amount"}]`, "column"},
		{"alias instead of as", `[{"fn":"count","alias":"n"}]`, "alias"},
		{"second aggregate", `[{"fn":"count"},{"fn":"sum","col":"amount","field":"status"}]`, "field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(
				`{"table":"entries","aggregates":`+tc.aggregates+`}`,
			)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"` + tc.key + `"`, "fn", "col", "as"} {
				if !strings.Contains(body.Error, want) {
					t.Errorf("error %q does not name %s", body.Error, want)
				}
			}
		})
	}
}

// Several unknown keys are all named, in a stable order, so one correction
// fixes the request.
func TestQueryAggregateUnknownKeysAllNamed(t *testing.T) {
	mux := newQuerySemanticsFixture(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(
		`{"table":"entries","aggregates":[{"fn":"count","zeta":1,"alpha":2}]}`,
	)))
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || strings.Index(body, "alpha") < 0 || strings.Index(body, "alpha") > strings.Index(body, "zeta") {
		t.Fatalf("status = %d, body = %s, want 400 naming alpha then zeta", rec.Code, body)
	}
}

// Valid specs are untouched, including the case-insensitive key match
// encoding/json has always applied to these fields.
func TestQueryAggregateKnownKeysStillWork(t *testing.T) {
	mux := newQuerySemanticsFixture(t)
	rows := callQuerySemantics(t, mux, `{"table":"entries","aggregates":[{"fn":"count"},{"fn":"sum","col":"amount","as":"total"},{"FN":"max","Col":"amount","AS":"top"}]}`)
	if len(rows) != 1 || rows[0]["count"] != float64(4) || rows[0]["total"] != float64(60) || rows[0]["top"] != float64(100) {
		t.Fatalf("rows = %#v, want count 4, total 60, top 100", rows)
	}
}

// Malformed bodies keep their generic answer; only an unknown key is named.
func TestQueryAggregateMalformedBodyStaysGeneric(t *testing.T) {
	mux := newQuerySemanticsFixture(t)
	for _, body := range []string{
		`{"table":"entries","aggregates":["count"]}`,
		`{"table":"entries","aggregates":[{"fn":1}]}`,
		`{"table":"entries"`,
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid JSON body") {
			t.Fatalf("%s: status = %d, body = %s, want the generic 400", body, rec.Code, rec.Body.String())
		}
	}
}
