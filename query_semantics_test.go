//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func newQuerySemanticsFixture(t *testing.T) *http.ServeMux {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	mustExec(t, db, `CREATE TABLE entries (id INTEGER PRIMARY KEY, category TEXT, status TEXT, amount INTEGER)`)
	mustExec(t, db, `INSERT INTO entries VALUES (1, 'A', NULL, 100), (2, 'A', 'open', -90), (3, 'B', 'closed', 20), (4, 'B', NULL, 30)`)
	app := &App{
		DB: db,
		Tables: []Table{{Name: "entries", Columns: []Column{
			{Name: "id"}, {Name: "category"}, {Name: "status"}, {Name: "amount"},
		}}},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"entries": {OpRead: "anon"},
		}},
	}
	mux := http.NewServeMux()
	RegisterQueryAPI(mux, app)
	return mux
}

func callQuerySemantics(t *testing.T, mux *http.ServeMux, spec string) []map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(spec)))
	if rec.Code != http.StatusOK {
		t.Fatalf("query status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Rows
}

func TestQueryNullEqualityFilters(t *testing.T) {
	mux := newQuerySemanticsFixture(t)
	for _, tc := range []struct {
		name, where string
		want        []float64
	}{
		{"scalar null", `null`, []float64{1, 4}},
		{"explicit eq null", `{"eq":null}`, []float64{1, 4}},
		{"explicit ne null", `{"ne":null}`, []float64{2, 3}},
		{"scalar value", `"open"`, []float64{2}},
		{"explicit eq value", `{"eq":"open"}`, []float64{2}},
		{"explicit ne value", `{"ne":"open"}`, []float64{3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := callQuerySemantics(t, mux, `{"table":"entries","select":["id"],"where":{"status":`+tc.where+`},"order_by":[{"col":"id"}]}`)
			got := make([]float64, 0, len(rows))
			for _, row := range rows {
				got = append(got, row["id"].(float64))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("matching ids = %v, want %v", got, tc.want)
			}
		})
	}
	// NULL predicates consume no placeholder; ordinary filters still bind
	// their values correctly regardless of map iteration order.
	rows := callQuerySemantics(t, mux, `{"table":"entries","select":["id"],"where":{"status":null,"category":"A","amount":{"gte":90}}}`)
	if len(rows) != 1 || rows[0]["id"] != float64(1) {
		t.Fatalf("combined null/value filters = %#v, want id=1", rows)
	}
}

func TestQueryAggregateAliases(t *testing.T) {
	mux := newQuerySemanticsFixture(t)
	for _, alias := range []string{"total", "amount", "order"} {
		t.Run(alias, func(t *testing.T) {
			rows := callQuerySemantics(t, mux, `{"table":"entries","group_by":["category"],"aggregates":[{"fn":"sum","col":"amount","as":"`+alias+`"}],"order_by":[{"col":"`+alias+`","dir":"desc"}]}`)
			if len(rows) != 2 || rows[0]["category"] != "B" || rows[0][alias] != float64(50) || rows[1]["category"] != "A" || rows[1][alias] != float64(10) {
				t.Fatalf("aggregate order = %#v, want B=50 then A=10", rows)
			}
		})
	}
}

func TestQueryAggregateAliasCollisionsRefused(t *testing.T) {
	mux := newQuerySemanticsFixture(t)
	for _, tc := range []struct {
		name, aggregates string
	}{
		{"same aliases", `[{"fn":"sum","col":"amount","as":"total"},{"fn":"count","as":"total"}]`},
		{"case aliases", `[{"fn":"sum","col":"amount","as":"total"},{"fn":"count","as":"TOTAL"}]`},
		{"default aliases", `[{"fn":"count"},{"fn":"count","as":"count"}]`},
		{"group column", `[{"fn":"count","as":"category"}]`},
		{"group column case", `[{"fn":"count","as":"CATEGORY"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(
				`{"table":"entries","group_by":["category"],"aggregates":`+tc.aggregates+`}`,
			)))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "duplicate query output column") {
				t.Fatalf("alias collision status = %d, body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestQueryAggregateAliasValidationRetained(t *testing.T) {
	mux := newQuerySemanticsFixture(t)
	for _, alias := range []string{"not an identifier", "1amount", "amount;DROP", strings.Repeat("a", 41)} {
		t.Run(alias, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(
				`{"table":"entries","aggregates":[{"fn":"sum","col":"amount","as":"`+alias+`"}]}`,
			)))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid aggregate alias") {
				t.Fatalf("invalid alias status = %d, body = %s", rec.Code, rec.Body.String())
			}
		})
	}
	rows := callQuerySemantics(t, mux, `{"table":"entries","aggregates":[{"fn":"count"},{"fn":"sum","col":"amount"}]}`)
	if len(rows) != 1 || rows[0]["count"] != float64(4) || rows[0]["sum_amount"] != float64(60) {
		t.Fatalf("default aliases = %#v, want count=4 sum_amount=60", rows)
	}
}
