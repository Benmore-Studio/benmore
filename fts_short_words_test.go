//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// shortWordSearchApp is an owner-scoped, soft-deleting table whose @@fulltext
// lists a hidden column, so one fixture shows that a search with short words
// keeps every filter the list applies.
func shortWordSearchApp(t *testing.T) (mux *http.ServeMux, alice string) {
	t.Helper()
	dir := t.TempDir()
	db := openTestAppDB(t, dir)
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, note TEXT, share_token TEXT, deleted_at DATETIME)`)
	tables := []Table{{
		Name: "tasks",
		Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title", Type: "TEXT"},
			{Name: "note", Type: "TEXT"}, {Name: "share_token", Type: "TEXT"}, {Name: "deleted_at"}},
		FullText: [][]string{{"title", "note", "share_token"}},
	}}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}), Access: &AccessConfig{}, Tables: tables}
	t.Cleanup(app.Shutdown)
	mux = buildAppMux(app, true, "http://localhost")
	alice = createCrudScopeSession(t, app, "alice@example.com", "user", "", "") // user id 1
	createCrudScopeSession(t, app, "bob@example.com", "user", "", "")           // user id 2
	for _, row := range []string{
		`(1, 1, 'Revenue grew in the third quarter', NULL, NULL, NULL)`,
		`(2, 1, 'third quarter only', NULL, NULL, NULL)`,
		// The words sit in different columns.
		`(3, 1, 'Quarter notes', 'the third draft is in review', NULL, NULL)`,
		`(4, 1, 'In the third quarter, deleted', NULL, NULL, '2026-01-01 00:00:00')`,
		`(5, 2, 'Bob wrote in the third quarter', NULL, NULL, NULL)`,
		`(6, 1, 'C# and Go', NULL, NULL, NULL)`,
		// Only the hidden column holds the words.
		`(7, 1, 'budget plan', NULL, 'zq in third quarter', NULL)`,
		`(8, 1, '50% off', NULL, NULL, NULL)`,
		`(9, 1, 'weekly report', NULL, NULL, NULL)`,
	} {
		crudScopeMustExec(t, db, `INSERT INTO tasks (id, user_id, title, note, share_token, deleted_at) VALUES `+row)
	}
	return mux, alice
}

// searchPath lists tasks matching q in id order (the default is newest first).
func searchPath(q string, extra ...string) string {
	return rawSearchPath(url.QueryEscape(q), extra...)
}

func rawSearchPath(escapedQ string, extra ...string) string {
	return strings.Join(append([]string{"/api/tasks?sort=id&order=asc&q=" + escapedQ}, extra...), "&")
}

// A query holding a 1-2 character word was matched as one literal phrase, so
// "third in quarter" found nothing in a row holding all three words. Every
// word must match, whatever its length.
func TestSearchANDsShortAndLongWords(t *testing.T) {
	mux, alice := shortWordSearchApp(t)
	for _, c := range []struct {
		q    string
		want []float64
	}{
		{"third quarter", []float64{1, 2, 3}},
		{"third in quarter", []float64{1, 3}},
		{"quarter in third", []float64{1, 3}},
		{"IN Third", []float64{1, 3}},
		{"in the", []float64{1, 3}},
		{"in", []float64{1, 3}},
		{"C# and", []float64{6}},
		{"c# go", []float64{6}},
		{"go c#", []float64{6}},
		{"in zz", []float64{}},
		{"third in absent", []float64{}},
		// Tab and newline separate words like a space does.
		{"third\tin\nquarter", []float64{1, 3}},
		// A long query repeats its words: still one test per distinct word.
		{strings.Repeat("third in quarter ", 300), []float64{1, 3}},
	} {
		t.Run(c.q[:min(len(c.q), 24)], func(t *testing.T) {
			assertListIDs(t, mux, alice, searchPath(c.q), c.want)
		})
	}
}

// The short words go through LIKE: wildcards stay literal, and a hidden
// @@fulltext column is searched by neither path.
func TestSearchShortWordsKeepEscapingAndHiddenColumns(t *testing.T) {
	mux, alice := shortWordSearchApp(t)
	assertListIDs(t, mux, alice, searchPath("% off"), []float64{8})
	assertListIDs(t, mux, alice, searchPath("_ off"), []float64{})
	assertListIDs(t, mux, alice, searchPath(`\ off`), []float64{})
	assertListIDs(t, mux, alice, searchPath("bu plan"), []float64{7})
	// "zq" is only in share_token, which no response returns.
	assertListIDs(t, mux, alice, searchPath("zq budget"), []float64{})
	assertListIDs(t, mux, alice, searchPath("zq"), []float64{})
}

// The search clause is part of the statement the list, its count, the page
// total and the cursor pages are all built from.
func TestSearchShortWordsAgreeAcrossCountPageAndCursor(t *testing.T) {
	mux, alice := shortWordSearchApp(t)
	q := "third in quarter"
	if rec := crudScopeRequest(t, mux, http.MethodGet, searchPath(q, "count=true"), alice, nil); rec.Body.String() != "{\"count\":2}\n" {
		t.Errorf("count = %d %s, want 2", rec.Code, rec.Body.String())
	}
	var page struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	mustDecodeBody(t, crudScopeRequest(t, mux, http.MethodGet, searchPath(q, "page=2", "per_page=1"), alice, nil), &page)
	if page.Total != 2 || len(page.Data) != 1 || page.Data[0]["id"] != float64(3) {
		t.Errorf("page 2 = %+v, want total 2 and row 3", page)
	}
	var got []any
	cursor := "0"
	for range 5 {
		var body struct {
			Data       []map[string]any `json:"data"`
			NextCursor any              `json:"next_cursor"`
		}
		mustDecodeBody(t, crudScopeRequest(t, mux, http.MethodGet, searchPath(q, "limit=1", "cursor="+cursor), alice, nil), &body)
		for _, row := range body.Data {
			got = append(got, row["id"])
		}
		if body.NextCursor == nil {
			break
		}
		cursor = fmt.Sprint(body.NextCursor)
	}
	if !reflect.DeepEqual(got, []any{float64(1), float64(3)}) {
		t.Errorf("cursor walk = %v, want [1 3]", got)
	}
}

// A NUL byte ended the FTS5 MATCH string early (500 "unterminated string")
// and cut a LIKE pattern short ("%y\x00%" was read as "%y": ends with y). A
// control character now separates words, as tab and newline already did.
func TestSearchControlCharactersSeparateWords(t *testing.T) {
	mux, alice := shortWordSearchApp(t)
	assertListIDs(t, mux, alice, rawSearchPath("rep%00"), []float64{9})
	assertListIDs(t, mux, alice, rawSearchPath("report%00x"), []float64{})
	assertListIDs(t, mux, alice, rawSearchPath("report%00we"), []float64{9})
	assertListIDs(t, mux, alice, rawSearchPath("third%01quarter%7Fin"), []float64{1, 3})
	assertListIDs(t, mux, alice, rawSearchPath("zz%00"), []float64{})
	// Rows 2 and 9 hold a "y"; only row 2 ends with one.
	assertListIDs(t, mux, alice, rawSearchPath("y%00"), []float64{2, 9})
	// Bytes that are not UTF-8 are searched as given and match nothing here.
	assertListIDs(t, mux, alice, rawSearchPath("%ff%fe%fd"), []float64{})
	assertListIDs(t, mux, alice, rawSearchPath("%ff%20third"), []float64{})
	// Nothing but control characters is an empty query: q is ignored.
	assertListIDs(t, mux, alice, rawSearchPath("%00%1F"), []float64{1, 2, 3, 6, 7, 8, 9})
	if rec := crudScopeRequest(t, mux, http.MethodGet, rawSearchPath("rep%00", "count=true"), alice, nil); rec.Body.String() != "{\"count\":1}\n" {
		t.Errorf("count = %d %s, want 1", rec.Code, rec.Body.String())
	}
}

// Each distinct short word adds one LIKE group to the statement, so their
// number is bounded; a request past the bound is refused, not answered with
// some of its words dropped.
func TestSearchRefusesTooManyShortWords(t *testing.T) {
	mux, alice := shortWordSearchApp(t)
	words := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprint(10 + i)
		}
		return strings.Join(parts, " ")
	}
	assertListIDs(t, mux, alice, searchPath(words(ftsMaxShortWords)), []float64{})
	rec := crudScopeRequest(t, mux, http.MethodGet, searchPath(words(ftsMaxShortWords+1)), alice, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), fmt.Sprintf("at most %d", ftsMaxShortWords)) {
		t.Fatalf("%d short words: %d %s", ftsMaxShortWords+1, rec.Code, rec.Body.String())
	}
	if rec := crudScopeRequest(t, mux, http.MethodGet, searchPath(words(ftsMaxShortWords+1), "count=true"), alice, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("count past the bound: %d %s", rec.Code, rec.Body.String())
	}
	// Repeats (in any ASCII case) are one word; words of 3+ characters are
	// one index lookup together and are not counted.
	repeated := strings.Repeat("in IN In ", 200) + words(ftsMaxShortWords-1) + " " + strings.Repeat("third quarter ", 200)
	assertListIDs(t, mux, alice, searchPath(repeated), []float64{})
}

func TestPlanFTSQuery(t *testing.T) {
	for _, c := range []struct {
		q           string
		long, short []string
	}{
		{"third in quarter", []string{"third", "quarter"}, []string{"in"}},
		{"ab", nil, []string{"ab"}},
		{"abc", []string{"abc"}, nil},
		{"john smith", []string{"john", "smith"}, nil},
		{"ab cdef", []string{"cdef"}, []string{"ab"}},
		{"abcd ef gh", []string{"abcd"}, []string{"ef", "gh"}},
		{"  x  y  ", nil, []string{"x", "y"}},
		{"In in IN the THE", []string{"the"}, []string{"In"}},
		{"É é", nil, []string{"É", "é"}}, // LIKE folds ASCII case only
		{"日本 日本語", []string{"日本語"}, []string{"日本"}},
		{"rep\x00", []string{"rep"}, nil},
		{"a\x00b\x1fcde\x7f", []string{"cde"}, []string{"a", "b"}},
		{"\x00 \t\n", nil, nil},
		{"", nil, nil},
	} {
		plan := planFTSQuery(c.q)
		if !reflect.DeepEqual(plan.long, c.long) || !reflect.DeepEqual(plan.short, c.short) {
			t.Errorf("planFTSQuery(%q) = long %q short %q, want long %q short %q", c.q, plan.long, plan.short, c.long, c.short)
		}
	}
}

// The connector's list tool refuses a blank search so it never lists a table
// unfiltered by accident; a search of only control characters has no words
// either.
func TestAppMCPNativeListRefusesWordlessSearch(t *testing.T) {
	columns := []Column{{Name: "id", PK: true}, {Name: "title", Type: "TEXT"}}
	app := &App{Tables: []Table{{Name: "tasks", Columns: columns, FullText: [][]string{{"title"}}}}}
	tool := &AppMCPTool{Handler: AppMCPHandler{Operation: "table.list", Table: "tasks"}}
	for _, q := range []string{"", "  ", "\x00", "\x00 \x1f\t"} {
		if _, _, err := appMCPNativeReadInput(app, tool, map[string]any{"q": q}, columns); err == nil {
			t.Errorf("q=%q accepted, want refused", q)
		}
	}
	_, query, err := appMCPNativeReadInput(app, tool, map[string]any{"q": "rep\x00 in"}, columns)
	if err != nil || query.Get("q") != "rep\x00 in" {
		t.Errorf("search with words refused or altered: %q %v", query.Get("q"), err)
	}
}
