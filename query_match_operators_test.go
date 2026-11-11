//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// newQueryMatchFixture serves /api/_query over a table of names chosen to
// tell substring, prefix, suffix and wildcard matches apart.
func newQueryMatchFixture(t *testing.T) *http.ServeMux {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	mustExec(t, db, `CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT)`)
	mustExec(t, db, `INSERT INTO files VALUES
		(1, 'report_2026.pdf'),
		(2, 'reportX2026.pdf'),
		(3, 'Annual REPORT.txt'),
		(4, '100% done'),
		(5, '1000 done'),
		(6, 'back\slash'),
		(7, 'pdf.report'),
		(8, NULL),
		(9, 'Éclair')`)
	app := &App{
		DB:     db,
		Tables: []Table{{Name: "files", Columns: []Column{{Name: "id"}, {Name: "name"}}}},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{"files": {OpRead: "anon"}}},
	}
	mux := http.NewServeMux()
	RegisterQueryAPI(mux, app)
	return mux
}

func queryMatchIDs(t *testing.T, mux *http.ServeMux, where string) []float64 {
	t.Helper()
	rows := callQuerySemantics(t, mux, `{"table":"files","select":["id"],"where":{"name":`+where+`},"order_by":[{"col":"id"}]}`)
	ids := make([]float64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row["id"].(float64))
	}
	return ids
}

// `like` keeps its historical meaning, which apps rely on: the value is
// wrapped in %...%, so it is a substring match, case-insensitive for ASCII,
// and % and _ inside the value are still wildcards.
func TestQueryLikeKeepsSubstringWildcardSemantics(t *testing.T) {
	mux := newQueryMatchFixture(t)
	for _, tc := range []struct {
		name, where string
		want        []float64
	}{
		{"substring anywhere, ASCII case-insensitive", `{"like":"report"}`, []float64{1, 2, 3, 7}},
		{"underscore is a one-character wildcard", `{"like":"report_"}`, []float64{1, 2, 3}},
		{"percent is a wildcard", `{"like":"10%done"}`, []float64{4, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := queryMatchIDs(t, mux, tc.where); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("like %s matched ids %v, want %v", tc.where, got, tc.want)
			}
		})
	}
}

// contains, starts_with and ends_with match the value as literal text:
// %, _ and the escape character \ in it match only themselves.
func TestQueryLiteralMatchOperators(t *testing.T) {
	mux := newQueryMatchFixture(t)
	for _, tc := range []struct {
		name, where string
		want        []float64
	}{
		{"starts_with is a prefix match", `{"starts_with":"report"}`, []float64{1, 2}},
		{"starts_with is ASCII case-insensitive like like", `{"starts_with":"ANNUAL"}`, []float64{3}},
		{"starts_with escapes underscore", `{"starts_with":"report_"}`, []float64{1}},
		{"ends_with is a suffix match", `{"ends_with":".pdf"}`, []float64{1, 2}},
		{"ends_with does not match a prefix", `{"ends_with":"report"}`, []float64{7}},
		{"contains escapes percent", `{"contains":"0% d"}`, []float64{4}},
		{"contains escapes underscore", `{"contains":"t_2"}`, []float64{1}},
		{"contains escapes the escape character", `{"contains":"k\\s"}`, []float64{6}},
		{"non-ASCII letters compare exactly", `{"starts_with":"é"}`, []float64{}},
		{"non-ASCII prefix in its own case", `{"starts_with":"É"}`, []float64{9}},
		{"empty prefix matches every non-null value", `{"starts_with":""}`, []float64{1, 2, 3, 4, 5, 6, 7, 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := queryMatchIDs(t, mux, tc.where); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s matched ids %v, want %v", tc.where, got, tc.want)
			}
		})
	}
}

func TestQueryLiteralMatchOperatorsNeedText(t *testing.T) {
	mux := newQueryMatchFixture(t)
	for _, where := range []string{`{"starts_with":5}`, `{"ends_with":null}`, `{"contains":["a"]}`, `{"contains":{"x":1}}`} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(
			`{"table":"files","select":["id"],"where":{"name":`+where+`}}`,
		)))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "needs a string") {
			t.Fatalf("%s: status %d body %s; want 400 naming the string requirement", where, rec.Code, rec.Body.String())
		}
	}
}
