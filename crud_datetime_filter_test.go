//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// datetimeFilterRows are one user's events around 2026-01-15 UTC, in the
// spellings a DATETIME column really holds, plus values that are no date.
// The comment is the instant each one is.
var datetimeFilterRows = []struct {
	name     string
	startsAt any
}{
	{"prev", "2026-01-14 23:59:59"},         // 14th 23:59:59Z
	{"dateonly", "2026-01-15"},              // 15th 00:00Z
	{"minus", "2026-01-14T20:00:00-08:00"},  // 15th 04:00Z
	{"iso", "2026-01-15T09:00:00.000Z"},     // 15th 09:00Z
	{"space", "2026-01-15 10:00:00"},        // 15th 10:00Z (CURRENT_TIMESTAMP form)
	{"offset", "2026-01-16T01:00:00+05:00"}, // 15th 20:00Z
	{"next", "2026-01-16 00:00:00"},         // 16th 00:00Z
	{"null", nil},
	{"junk", "not a date"},
	{"epoch", 1768471200}, // a number: never a date to SQLite's text functions
}

func datetimeFilterFixture(t *testing.T) (*App, *http.ServeMux, string) {
	t.Helper()
	app := newGateApp(t,
		`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT,
			starts_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE INDEX idx_events_starts ON events(starts_at)`,
		`CREATE INDEX idx_events_created ON events(created_at)`,
		`CREATE INDEX idx_events_updated ON events(updated_at)`)
	uid, sid := gateUser(t, app, "events@datetime.invalid")
	for _, row := range datetimeFilterRows {
		mustExecArgs(t, app.DB, "INSERT INTO events (user_id, name, starts_at) VALUES (?, ?, ?)", uid, row.name, row.startsAt)
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	RegisterQueryAPI(mux, app)
	return app, mux, sid
}

func datetimeFilterGet(t *testing.T, mux *http.ServeMux, sid, query string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/api/events?"+query, nil)
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", query, w.Code, w.Body.String())
	}
	return w
}

// datetimeFilterNames lists row names in response order.
func datetimeFilterNames(rows []map[string]any) string {
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		name, _ := row["name"].(string)
		names = append(names, name)
	}
	return strings.Join(names, ",")
}

func datetimeFilterSorted(csv string) string {
	names := strings.Split(csv, ",")
	slices.Sort(names)
	return strings.Join(names, ",")
}

// A filter value in the form the API returns (RFC 3339) must select rows by
// instant whatever spelling each row was stored in. Stored text was compared
// as text: "since midnight" missed the CURRENT_TIMESTAMP row made that day
// (' ' sorts before 'T') and equality on a returned value matched nothing
// (data finding F1, round 2026-11-09). Values that are no date keep the text
// comparison they always had.
func TestListDateTimeFilterComparesInstants(t *testing.T) {
	_, mux, sid := datetimeFilterFixture(t)
	cases := []struct{ query, want string }{
		// Since midnight UTC on the 15th: every spelling of that day and later.
		{"starts_at__gte=2026-01-15T00:00:00Z", "dateonly,minus,iso,space,offset,next,junk"},
		{"where[starts_at__gte]=2026-01-15T00:00:00Z", "dateonly,minus,iso,space,offset,next,junk"},
		// The same instant written with an offset, with a space and as a date.
		{"starts_at__gte=" + url.QueryEscape("2026-01-15T05:00:00+05:00"), "dateonly,minus,iso,space,offset,next,junk"},
		{"starts_at__gte=" + url.QueryEscape("2026-01-15 00:00:00"), "dateonly,minus,iso,space,offset,next,junk"},
		{"starts_at__gte=2026-01-15", "dateonly,minus,iso,space,offset,next,junk"},
		{"starts_at__gt=2026-01-15T00:00:00Z", "minus,iso,space,offset,next,junk"},
		// Before midnight: the row at 23:59:59 the day before, not the rows of the day.
		{"starts_at__lt=2026-01-15T00:00:00Z", "prev,epoch"},
		{"starts_at__lte=2026-01-15T00:00:00Z", "prev,dateonly,epoch"},
		{"starts_at__gt=2026-01-15T10:00:00Z", "offset,next,junk"},
		{"starts_at__lte=2026-01-15T10:00:00Z", "prev,dateonly,minus,iso,space,epoch"},
		// A range inside the day, each bound with its own window.
		{"starts_at__gte=2026-01-15T04:00:00Z&starts_at__lt=2026-01-15T10:00:00Z", "minus,iso"},
		// Equality on the value a read returns for each spelling.
		{"starts_at=2026-01-15T10:00:00Z", "space"},
		{"where[starts_at]=2026-01-15T10:00:00Z", "space"},
		{"starts_at=2026-01-15T20:00:00Z", "offset"},
		{"starts_at=2026-01-15T04:00:00Z", "minus"},
		{"starts_at=2026-01-15T09:00:00Z", "iso"},
		{"starts_at=2026-01-15T00:00:00Z", "dateonly"},
		{"starts_at=2026-01-15", "dateonly"},
		{"starts_at=2026-01-16T00:00:00Z", "next"},
		{"starts_at__ne=2026-01-15T10:00:00Z", "prev,dateonly,minus,iso,offset,next,junk,epoch"},
		{"starts_at__in=2026-01-15T10:00:00Z,2026-01-15T04:00:00Z", "minus,space"},
		{"starts_at__in=2026-01-15T20:00:00Z", "offset"},
		// Operands that are no instant compare as text, as before.
		{"starts_at=" + url.QueryEscape("not a date"), "junk"},
		{"starts_at__in=2026-01-15T10:00:00Z," + url.QueryEscape("not a date"), "junk"},
		{"starts_at__like=2026-01-15%25", "dateonly,iso,space"},
	}
	for _, tc := range cases {
		w := datetimeFilterGet(t, mux, sid, tc.query)
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s: %v %s", tc.query, err, w.Body.String())
		}
		if got := datetimeFilterSorted(datetimeFilterNames(rows)); got != datetimeFilterSorted(tc.want) {
			t.Errorf("%s matched %q, want %q", tc.query, got, datetimeFilterSorted(tc.want))
		}
	}
}

// An operand that parses as no instant must give exactly the rows the plain
// text comparison gives (today's behaviour), for every operator.
func TestListDateTimeFilterNonInstantOperandUnchanged(t *testing.T) {
	app, mux, sid := datetimeFilterFixture(t)
	for suffix, op := range map[string]string{"": "=", "__gt": ">", "__gte": ">=", "__lt": "<", "__lte": "<=", "__ne": "!="} {
		for _, value := range []string{"2026", "2026-01", "10:00", "tomorrow", "2026-01-15T25:00:00Z", "1768471200"} {
			var want []string
			rows, err := app.DB.Query("SELECT name FROM events WHERE starts_at "+op+" ?", value)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var name string
				rows.Scan(&name)
				want = append(want, name)
			}
			rows.Close()
			slices.Sort(want)
			w := datetimeFilterGet(t, mux, sid, "starts_at"+suffix+"="+url.QueryEscape(value))
			var got []map[string]any
			json.Unmarshal(w.Body.Bytes(), &got)
			if names := datetimeFilterSorted(datetimeFilterNames(got)); names != strings.Join(want, ",") {
				t.Errorf("starts_at%s=%s matched %q, want the text comparison's %q", suffix, value, names, strings.Join(want, ","))
			}
		}
	}
}

// count, the paged total and a cursor page go through the same filter, and a
// sort on the column orders by instant: values that are no date first when
// ascending (as NULL always was), then earliest to latest.
func TestListDateTimeCountPageCursorAndSort(t *testing.T) {
	_, mux, sid := datetimeFilterFixture(t)
	const since = "starts_at__gte=2026-01-15T00:00:00Z"

	var count struct{ Count int }
	w := datetimeFilterGet(t, mux, sid, "count=true&"+since)
	if err := json.Unmarshal(w.Body.Bytes(), &count); err != nil || count.Count != 7 {
		t.Errorf("count since midnight: %s, want 7", w.Body.String())
	}
	w = datetimeFilterGet(t, mux, sid, "count=true&starts_at=2026-01-15T10:00:00Z")
	if err := json.Unmarshal(w.Body.Bytes(), &count); err != nil || count.Count != 1 {
		t.Errorf("count of the returned value: %s, want 1", w.Body.String())
	}

	var page struct {
		Data  []map[string]any
		Total int
	}
	w = datetimeFilterGet(t, mux, sid, "page=1&per_page=3&sort=starts_at&order=asc&"+since)
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.Total != 7 || datetimeFilterNames(page.Data) != "junk,dateonly,minus" {
		t.Errorf("first page since midnight: total %d rows %q (%s), want 7 and junk,dateonly,minus", page.Total, datetimeFilterNames(page.Data), w.Body.String())
	}
	w = datetimeFilterGet(t, mux, sid, "page=2&per_page=3&sort=starts_at&order=asc&"+since)
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || datetimeFilterNames(page.Data) != "iso,space,offset" {
		t.Errorf("second page since midnight: %q (%s), want iso,space,offset", datetimeFilterNames(page.Data), w.Body.String())
	}
	w = datetimeFilterGet(t, mux, sid, "cursor=0&"+since)
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || datetimeFilterSorted(datetimeFilterNames(page.Data)) != datetimeFilterSorted("dateonly,minus,iso,space,offset,next,junk") {
		t.Errorf("cursor page since midnight: %q (%s)", datetimeFilterNames(page.Data), w.Body.String())
	}

	const asc = "null,epoch,junk,prev,dateonly,minus,iso,space,offset,next"
	desc := strings.Split(asc, ",")
	slices.Reverse(desc)
	for query, want := range map[string]string{
		"sort=starts_at&order=asc":  asc,
		"sort=starts_at":            asc,
		"sort=starts_at&order=desc": strings.Join(desc, ","),
		"orderBy=starts_at:desc":    strings.Join(desc, ","),
		"orderBy=starts_at":         asc,
	} {
		var rows []map[string]any
		w := datetimeFilterGet(t, mux, sid, query)
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || datetimeFilterNames(rows) != want {
			t.Errorf("%s ordered %q, want %q", query, datetimeFilterNames(rows), want)
		}
	}
}

// The case from the finding: a row made now (created_at from
// CURRENT_TIMESTAMP, protected from client writes) must be found by "since
// midnight" built the way a browser does, and by the value a read returns.
func TestListDateTimeFilterFindsRowCreatedToday(t *testing.T) {
	_, mux, sid := datetimeFilterFixture(t)
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/events", sid, map[string]any{"name": "made-now"})
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	returned, _ := created["created_at"].(string)
	at, err := time.Parse(time.RFC3339, returned)
	if err != nil {
		t.Fatalf("created_at %q is not RFC 3339: %v", returned, err)
	}
	midnight := at.UTC().Truncate(24 * time.Hour).Format("2006-01-02T15:04:05.000Z") // Date.toISOString()
	for query, want := range map[string]string{
		"created_at__gte=" + midnight:                                                       "made-now",
		"created_at__lt=" + midnight:                                                        "",
		"created_at=" + url.QueryEscape(returned):                                           "made-now",
		"created_at__lte=" + url.QueryEscape(returned) + "&name=made-now":                   "made-now",
		"created_at__gt=" + url.QueryEscape(at.Add(time.Second).UTC().Format(time.RFC3339)): "",
	} {
		var rows []map[string]any
		w := datetimeFilterGet(t, mux, sid, "fields=name&name=made-now&"+query)
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || datetimeFilterNames(rows) != want {
			t.Errorf("%s matched %q, want %q", query, datetimeFilterNames(rows), want)
		}
	}
}

func TestQueryAPIDateTimeComparesInstants(t *testing.T) {
	_, mux, sid := datetimeFilterFixture(t)
	query := func(spec map[string]any) string {
		t.Helper()
		spec["table"], spec["select"] = "events", []string{"name"}
		w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, spec)
		var body struct{ Rows []map[string]any }
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
			t.Fatalf("%v: %d %s", spec, w.Code, w.Body.String())
		}
		return datetimeFilterNames(body.Rows)
	}
	cases := []struct {
		where map[string]any
		want  string
	}{
		{map[string]any{"starts_at": map[string]any{"gte": "2026-01-15T00:00:00Z"}}, "dateonly,minus,iso,space,offset,next,junk"},
		{map[string]any{"starts_at": map[string]any{"lt": "2026-01-15T00:00:00Z"}}, "prev,epoch"},
		{map[string]any{"starts_at": map[string]any{"gt": "2026-01-15T10:00:00Z"}}, "offset,next,junk"},
		{map[string]any{"starts_at": map[string]any{"lte": "2026-01-15T10:00:00Z"}}, "prev,dateonly,minus,iso,space,epoch"},
		{map[string]any{"starts_at": "2026-01-15T10:00:00Z"}, "space"},
		{map[string]any{"starts_at": map[string]any{"eq": "2026-01-15T20:00:00Z"}}, "offset"},
		{map[string]any{"starts_at": map[string]any{"ne": "2026-01-15T10:00:00Z"}}, "prev,dateonly,minus,iso,offset,next,junk,epoch"},
		{map[string]any{"starts_at": map[string]any{"in": []any{"2026-01-15T10:00:00Z", "2026-01-15T04:00:00Z"}}}, "minus,space"},
		{map[string]any{"starts_at": map[string]any{"gte": "2026-01-15T04:00:00Z", "lt": "2026-01-15T10:00:00Z"}}, "minus,iso"},
		// No instant: text, as before.
		{map[string]any{"starts_at": "not a date"}, "junk"},
		{map[string]any{"starts_at": map[string]any{"in": []any{"2026-01-15T10:00:00Z", "not a date"}}}, "junk"},
		{map[string]any{"starts_at": map[string]any{"like": "2026-01-15"}}, "dateonly,iso,space"},
		{map[string]any{"starts_at": nil}, "null"},
	}
	for _, tc := range cases {
		if got := datetimeFilterSorted(query(map[string]any{"where": tc.where})); got != datetimeFilterSorted(tc.want) {
			t.Errorf("%v matched %q, want %q", tc.where, got, datetimeFilterSorted(tc.want))
		}
	}
	since := map[string]any{"starts_at": map[string]any{"gte": "2026-01-15T00:00:00Z"}}
	if got := query(map[string]any{"where": since, "order_by": []map[string]any{{"col": "starts_at", "dir": "asc"}}}); got != "junk,dateonly,minus,iso,space,offset,next" {
		t.Errorf("order_by starts_at asc gave %q, want junk,dateonly,minus,iso,space,offset,next", got)
	}
	if got := query(map[string]any{"where": since, "order_by": []map[string]any{{"col": "starts_at", "dir": "desc"}}}); got != "next,offset,space,iso,minus,dateonly,junk" {
		t.Errorf("order_by starts_at desc gave %q, want next,offset,space,iso,minus,dateonly,junk", got)
	}
}

// A report source's YAML where value arrives as a time.Time and is compared
// as the instant it is.
func TestQueryDateTimeFilterAcceptsTimeValue(t *testing.T) {
	app, _, _ := datetimeFilterFixture(t)
	spec := &querySpec{Table: "events", Select: []string{"name"}, Where: map[string]interface{}{
		"starts_at": map[string]interface{}{"gte": time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)},
	}}
	admin := &Session{UserID: 1, Role: "admin"}
	sqlText, args, err := buildQuery(app, spec, columnSet(app, "events"), admin)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := queryNativeRowsWith(app.DB, app, "events", sqlText, args...)
	if err != nil {
		t.Fatalf("%s: %v", sqlText, err)
	}
	if got := datetimeFilterSorted(datetimeFilterNames(rows)); got != datetimeFilterSorted("space,offset,next,junk") {
		t.Errorf("gte time.Time matched %q, want junk,next,offset,space", got)
	}
}

// The text window must never decide a row differently from the comparison it
// stands in front of. Every spelling SQLite reads as a date, at offsets out to
// the ±14:59 it accepts and around day, month and year boundaries, must match
// the unwindowed instant comparison for every operator; a value it cannot read
// must match the text comparison; and the few non-dates its date functions
// would still give a meaning to (a bare time, 'now', a number) keep the text
// comparison too, because none of them sorts inside a window.
func TestInstantComparisonWindowAgreesWithInstants(t *testing.T) {
	app := newGateApp(t, `CREATE TABLE stamps (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, at DATETIME)`)
	offsets := []string{"", "Z", "+00:00", "+05:30", "-08:00", "+14:00", "-12:00", "+14:59", "-14:59"}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	insert := func(kind string, values ...any) {
		for _, v := range values {
			if _, err := tx.Exec("INSERT INTO stamps (kind, at) VALUES (?, ?)", kind, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, day := range []string{"2025-12-30", "2025-12-31", "2026-01-01", "2026-01-02", "2026-02-28", "2026-03-01", "2026-03-02"} {
		insert("date", day)
		for _, clock := range []string{"00:00:00", "00:00", "09:15:00.250", "12:00:00", "23:59:59", "23:59:59.999", "24:00:00", "24:59:59"} {
			for _, sep := range []string{" ", "T"} {
				for _, offset := range offsets {
					insert("date", day+sep+clock+offset)
				}
			}
		}
	}
	insert("unreadable", nil, "", "not a date", "2026-01-01 junk", "2026-13-45", 1768471200, "2026-01-01T10:00:00+15:00")
	insert("odd", "12:00", "23:30", "now", 0, 2460000.5)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var dates, unread int
	app.DB.QueryRow("SELECT COUNT(*) FROM stamps WHERE kind = 'date' AND julianday(at) IS NOT NULL").Scan(&dates)
	app.DB.QueryRow("SELECT COUNT(*) FROM stamps WHERE kind = 'unreadable' AND julianday(at) IS NULL").Scan(&unread)
	if dates != 7*(1+8*2*len(offsets)) || unread != 7 {
		t.Fatalf("fixture: SQLite reads %d date rows and rejects %d unreadable ones", dates, unread)
	}
	ids := func(where string, args ...any) string {
		t.Helper()
		rows, err := app.DB.Query("SELECT id FROM stamps WHERE "+where+" ORDER BY id", args...)
		if err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id int
			rows.Scan(&id)
			out = append(out, fmt.Sprint(id))
		}
		return strings.Join(out, ",")
	}
	operands := []string{
		"2025-12-31T00:00:00Z", "2025-12-31T23:59:59Z", "2026-01-01T00:00:00Z", "2026-01-01", "2026-01-01 09:15:00",
		"2026-01-01T09:15:00.250Z", "2026-01-01T12:00:00+14:00", "2026-01-01T12:00:00-12:00", "2026-01-02T00:00:00+14:59",
		"2025-12-31T00:00:00-14:59", "2026-03-01T00:00:00Z", "2026-02-28T23:59:59.999Z", "2026-03-01T10:00",
	}
	for _, raw := range operands {
		o := mustInstantOperand(t, raw)
		for _, op := range []string{"=", "!=", ">", ">=", "<", "<="} {
			cond, args, ok := instantComparisonSQL("at", op, o)
			if !ok {
				t.Fatalf("no comparison for %s", op)
			}
			windowed := func(kinds string) string {
				return ids("kind IN ("+kinds+") AND "+cond, args...)
			}
			// Instants where SQLite reads a date, text where it reads none.
			want := ids("kind IN ('date','unreadable') AND COALESCE(julianday(at) "+op+" julianday(?), at "+op+" ?)", o.utc, raw)
			if got := windowed("'date','unreadable'"); got != want {
				t.Errorf("at %s %s: windowed predicate matched ids %s, the instant comparison %s", op, raw, got, want)
			}
			want = ids("kind = 'odd' AND at "+op+" ?", raw)
			if got := windowed("'odd'"); got != want {
				t.Errorf("at %s %s: non-date rows matched ids %q, the text comparison %q", op, raw, got, want)
			}
		}
	}
	// IN over two operands far apart: each operand keeps its own window.
	in, args := instantInSQL("at", []instantOperand{mustInstantOperand(t, "2025-12-31T00:00:00Z"), mustInstantOperand(t, "2026-03-01T10:00")})
	want := ids("kind != 'odd' AND (julianday(at) IN (julianday(?), julianday(?)) OR at IN (?, ?))", "2025-12-31T00:00:00Z", "2026-03-01T10:00:00Z", "2025-12-31T00:00:00Z", "2026-03-01T10:00")
	if got := ids(in, args...); got != want || got == "" {
		t.Errorf("IN: windowed predicate matched ids %q, the instant comparison %q", got, want)
	}
}

func mustInstantOperand(t *testing.T, raw string) instantOperand {
	t.Helper()
	o, ok := parseInstantOperand(raw)
	if !ok {
		t.Fatalf("%q is not read as an instant", raw)
	}
	return o
}

// The predicate has to keep an index on the column usable: julianday(col) on
// its own scans every row. The plan for each operator must search the index.
func TestListDateTimeFilterKeepsColumnIndex(t *testing.T) {
	app, _, _ := datetimeFilterFixture(t)
	cols, err := GetTableColumns(app.DB, "events")
	if err != nil {
		t.Fatal(err)
	}
	allow := listColumnAllowlist(app, "events", cols)
	for _, query := range []string{
		"starts_at__gte=2026-01-15T00:00:00Z",
		"starts_at__gt=2026-01-15T00:00:00Z",
		"starts_at__lt=2026-01-15T00:00:00Z",
		"starts_at__lte=2026-01-15T00:00:00Z",
		"starts_at=2026-01-15T10:00:00Z",
		"starts_at__in=2026-01-15T10:00:00Z,2026-01-15T04:00:00Z",
	} {
		r := httptest.NewRequest(http.MethodGet, "https://app.example.com/api/events?"+query, nil)
		sqlText, args := applyAPIWhereWithApp("SELECT * FROM events", r, "events", app, nil, allow)
		if !strings.Contains(sqlText, `julianday("events"."starts_at")`) {
			t.Errorf("%s is not compared as an instant: %s", query, sqlText)
			continue
		}
		rows, err := app.DB.Query("EXPLAIN QUERY PLAN "+sqlText, args...)
		if err != nil {
			t.Fatalf("%s: %v", sqlText, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			rows.Scan(&id, &parent, &unused, &detail)
			plan = append(plan, detail)
		}
		rows.Close()
		if got := strings.Join(plan, "; "); !strings.Contains(got, "SEARCH events USING INDEX idx_events_starts") {
			t.Errorf("%s does not search the column's index: %s\n%s", query, got, sqlText)
		}
	}
}

// Only columns the driver reads as a time are compared as instants, and an
// encrypted one never is (SQL sees ciphertext; its range filters stay dropped).
func TestInstantFilterColumns(t *testing.T) {
	cols := []Column{
		{Name: "a", Type: "DATETIME"}, {Name: "b", Type: "date"}, {Name: "c", Type: "Timestamp"},
		{Name: "d", Type: "TEXT"}, {Name: "e", Type: "INTEGER"}, {Name: "f", Type: "TIME"}, {Name: "sealed", Type: "DATETIME"},
	}
	app := &App{Encrypted: &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"t": {{Column: "sealed"}}}}}
	got := instantFilterColumns(app, "t", cols)
	if len(got) != 3 || !got["a"] || !got["b"] || !got["c"] {
		t.Errorf("instant columns = %v, want a, b and c", got)
	}
	for _, value := range []any{"2026", "10:00", "", "2026-01-15T10:00:00+15:00", "0000-01-01", "9999-12-31T23:00:00-05:00", 17, nil} {
		if o, ok := parseInstantOperand(value); ok {
			t.Errorf("%v was read as the instant %s", value, o.utc)
		}
	}
	o := mustInstantOperand(t, "2026-01-15T05:00:00+05:00")
	if o.utc != "2026-01-15T00:00:00Z" || o.lo != "2026-01-14" || o.hi != "2026-01-16" {
		t.Errorf("operand = %+v, want 2026-01-15T00:00:00Z in [2026-01-14, 2026-01-16)", o)
	}
}

// managedTimestampSchema declares the three timestamp columns the framework
// manages the way an app does: created_at and updated_at from their defaults
// (and the @updatedAt trigger), deleted_at for soft delete.
const managedTimestampSchema = `model Note {
 id Int @id @default(autoincrement())
 userId Int @map("user_id")
 title String
 createdAt DateTime @default(now()) @map("created_at")
 updatedAt DateTime @default(now()) @updatedAt @map("updated_at")
 deletedAt DateTime? @map("deleted_at")

 @@map("notes")
}`

var (
	// CURRENT_TIMESTAMP and datetime('now'): one fixed-width UTC spelling.
	frameworkSecondSpelling = regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$`)
	// prepareUpdateTimestamp: the same, with the fraction a distinct version needs.
	frameworkFractionSpelling = regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,9}$`)
)

func managedTimestampFixture(t *testing.T) (*App, *http.ServeMux, string) {
	t.Helper()
	app := newGateApp(t)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(managedTimestampSchema), 0600); err != nil {
		t.Fatal(err)
	}
	tables, deferred, err := LoadSchema(app.DB, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = ApplyDeferredDDL(app.DB, deferred); err != nil {
		t.Fatal(err)
	}
	app.Tables = tables
	_, sid := gateUser(t, app, "notes@datetime.invalid")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux, sid
}

// What each framework write path stores in created_at, updated_at and
// deleted_at, while every request tries to set them to an RFC 3339 value.
// The plain `ORDER BY` kept for created_at and updated_at (instantSortsAsText)
// rests on it: no request reaches either column, created_at only ever holds
// its default's spelling, and updated_at holds that spelling or the same one
// with fractional seconds (TestFrameworkTimestampSpellingsOrderAsInstants
// shows the two order as their instants).
func TestManagedTimestampWritePathsStoreFrameworkSpellings(t *testing.T) {
	app, mux, sid := managedTimestampFixture(t)
	const iso = "2020-02-02T02:02:02.020Z" // what a client would send
	send := func(method, path, contentType, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	stored := func(title string) (created, updated string, deleted any) {
		t.Helper()
		if err := app.DB.QueryRow("SELECT CAST(created_at AS TEXT), CAST(updated_at AS TEXT), CAST(deleted_at AS TEXT) FROM notes WHERE title = ?", title).Scan(&created, &updated, &deleted); err != nil {
			t.Fatalf("row %q: %v", title, err)
		}
		return created, updated, deleted
	}
	id := func(title string) string {
		t.Helper()
		var n int64
		if err := app.DB.QueryRow("SELECT id FROM notes WHERE title = ?", title).Scan(&n); err != nil {
			t.Fatalf("row %q: %v", title, err)
		}
		return fmt.Sprint(n)
	}
	row := func(title string) string {
		return fmt.Sprintf(`{"title":%q,"created_at":%q,"updated_at":%q}`, title, iso, iso)
	}

	// Creates: the request's created_at and updated_at never arrive; both
	// columns hold the CURRENT_TIMESTAMP default.
	send("POST", "/api/notes", "application/json", row("single-json"))
	send("POST", "/api/notes", "application/x-www-form-urlencoded", url.Values{"title": {"single-form"}, "created_at": {iso}, "updated_at": {iso}}.Encode())
	send("POST", "/api/notes/batch", "application/json", "["+row("batch")+"]")
	send("POST", "/api/notes/ingest", "application/x-ndjson", row("ingest")+"\n")
	send("POST", "/api/_transaction", "application/json", `{"operations":[{"table":"notes","action":"insert","data":`+row("transaction")+`}]}`)
	for _, title := range []string{"single-json", "single-form", "batch", "ingest", "transaction"} {
		created, updated, deleted := stored(title)
		if !frameworkSecondSpelling.MatchString(created) || !frameworkSecondSpelling.MatchString(updated) || deleted != nil {
			t.Errorf("create %s stored created_at %q, updated_at %q, deleted_at %v; want the CURRENT_TIMESTAMP spelling twice and NULL", title, created, updated, deleted)
		}
	}

	// Updates: created_at is untouched and updated_at is stamped by
	// prepareUpdateTimestamp, in the second spelling.
	patch := func(title string) string {
		return fmt.Sprintf(`{"title":%q,"created_at":%q,"updated_at":%q}`, title, iso, iso)
	}
	before := map[string]string{}
	for _, title := range []string{"single-json", "batch", "transaction"} {
		before[title], _, _ = stored(title)
	}
	send("PATCH", "/api/notes/"+id("single-json"), "application/json", patch("single-json"))
	send("PATCH", "/api/notes/batch", "application/json", `{"ids":[`+id("batch")+`],"fields":`+patch("batch")+`}`)
	send("POST", "/api/_transaction", "application/json", `{"operations":[{"table":"notes","action":"update","id":`+id("transaction")+`,"data":`+patch("transaction")+`}]}`)
	for _, title := range []string{"single-json", "batch", "transaction"} {
		created, updated, _ := stored(title)
		if created != before[title] {
			t.Errorf("update %s changed created_at from %q to %q", title, before[title], created)
		}
		if !frameworkFractionSpelling.MatchString(updated) && !frameworkSecondSpelling.MatchString(updated) {
			t.Errorf("update %s stored updated_at %q, want a framework spelling", title, updated)
		}
	}
	if _, updated, _ := stored("single-json"); !frameworkFractionSpelling.MatchString(updated) {
		t.Errorf("a canonical update stored updated_at %q; it is expected to carry fractional seconds, the second framework spelling", updated)
	}

	// SQL that leaves updated_at alone (a flow's `run: sql`): the @updatedAt
	// trigger writes CURRENT_TIMESTAMP, the first spelling again.
	mustExec(t, app.DB, "UPDATE notes SET updated_at = '2020-01-01 00:00:00' WHERE title = 'ingest'")
	mustExec(t, app.DB, "UPDATE notes SET title = 'ingest' WHERE title = 'ingest'")
	if _, updated, _ := stored("ingest"); !frameworkSecondSpelling.MatchString(updated) || strings.HasPrefix(updated, "2020") {
		t.Errorf("the @updatedAt trigger stored %q, want CURRENT_TIMESTAMP's spelling", updated)
	}

	// Soft delete writes deleted_at with datetime('now'); restore clears it
	// and stamps updated_at like any update. created_at stays put.
	created, _, _ := stored("single-form")
	send("DELETE", "/api/notes/"+id("single-form"), "application/json", "")
	if after, _, deleted := stored("single-form"); after != created || !frameworkSecondSpelling.MatchString(fmt.Sprint(deleted)) {
		t.Errorf("soft delete stored deleted_at %v (created_at %q -> %q), want datetime('now')'s spelling", deleted, created, after)
	}
	send("POST", "/api/notes/"+id("single-form")+"/restore", "application/json", "")
	if after, updated, deleted := stored("single-form"); after != created || deleted != nil || !frameworkFractionSpelling.MatchString(updated) {
		t.Errorf("restore left created_at %q -> %q, deleted_at %v, updated_at %q", created, after, deleted, updated)
	}

	// deleted_at on create is not asserted here: a create accepts it from the
	// request and stores it as sent (reported with this change, not altered by
	// it). It does not matter to sorting, since a list returns only rows
	// whose deleted_at is NULL.

	// Bulk import (Mode A) cannot carry any of the three columns.
	importable, err := importableColumns(app.DB, "notes", app)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range importable {
		if identIs(c.Name, "created_at") || identIs(c.Name, "updated_at") || identIs(c.Name, "deleted_at") {
			t.Errorf("bulk import may write %s", c.Name)
		}
	}

	// So on every row created_at holds the one default spelling and
	// updated_at holds it with or without the fraction: the two columns the
	// plain sort is kept for.
	rows, err := app.DB.Query("SELECT title, CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM notes")
	if err != nil {
		t.Fatal(err)
	}
	seen, fractional := 0, 0
	for rows.Next() {
		var title, created, updated string
		if err := rows.Scan(&title, &created, &updated); err != nil {
			t.Fatal(err)
		}
		if !frameworkSecondSpelling.MatchString(created) {
			t.Errorf("%s holds created_at %q, not the default's spelling", title, created)
		}
		if frameworkFractionSpelling.MatchString(updated) {
			fractional++
		} else if !frameworkSecondSpelling.MatchString(updated) {
			t.Errorf("%s holds updated_at %q, not a framework spelling", title, updated)
		}
		seen++
	}
	rows.Close()
	if seen != 5 || fractional == 0 || fractional == seen {
		t.Errorf("%d rows, %d with a fractional updated_at: want both updated_at spellings among the 5 rows", seen, fractional)
	}
	cols, err := GetTableColumns(app.DB, "notes")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cols {
		if want := c.Name == "created_at" || c.Name == "updated_at"; instantSortsAsText(c) != want {
			t.Errorf("instantSortsAsText(%s, default %q) = %v, want %v", c.Name, c.Default, !want, want)
		}
	}
}

// A workflow transition and a workflow timeout stamp updated_at through
// prepareUpdateTimestamp too: the fractional spelling.
func TestWorkflowWritesStoreFrameworkTimestampSpelling(t *testing.T) {
	app, wf, sid := workflowTimestampFixture(t, "2026-01-15 10:00:00")
	if w := transitionAs(app, wf, sid, "1", "approved"); w.Code != http.StatusOK {
		t.Fatalf("transition: %d %s", w.Code, w.Body.String())
	}
	if got := workflowStoredTimestamp(t, app); !frameworkFractionSpelling.MatchString(got) {
		t.Errorf("transition stored updated_at %q", got)
	}
	mustExec(t, app.DB, "UPDATE orders SET updated_at = '2026-01-15 10:00:00' WHERE id = 1")
	if applied, err := applyWorkflowTimeout(app, wf, "1", "approved", "pending"); err != nil || !applied {
		t.Fatalf("timeout: applied %v, %v", applied, err)
	}
	if got := workflowStoredTimestamp(t, app); !frameworkFractionSpelling.MatchString(got) {
		t.Errorf("timeout stored updated_at %q", got)
	}
}

// The framework's two timestamp spellings, `YYYY-MM-DD HH:MM:SS` and that
// form with fractional seconds, order as text exactly as they order as
// instants, mixed in one column and down to the nanosecond. created_at holds
// only the first and updated_at holds both, which is what lets a sort on
// either stay the plain ORDER BY.
func TestFrameworkTimestampSpellingsOrderAsInstants(t *testing.T) {
	app := newGateApp(t, `CREATE TABLE ticks (id INTEGER PRIMARY KEY AUTOINCREMENT, at DATETIME)`, `CREATE INDEX idx_ticks_at ON ticks(at)`)
	rng := rand.New(rand.NewSource(20261109))
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	var instants []time.Time
	for i := 0; i < 400; i++ {
		// Many values share a second, so the fraction decides the order.
		at := base.Add(time.Duration(rng.Intn(40)) * time.Second)
		switch rng.Intn(4) {
		case 0: // whole second, as CURRENT_TIMESTAMP writes it
		case 1:
			at = at.Add(time.Duration(rng.Intn(1000)) * time.Millisecond)
		case 2:
			at = at.Add(time.Duration(rng.Intn(1_000_000_000)))
		case 3:
			at = at.Add(time.Duration(1+rng.Intn(9)) * 100 * time.Millisecond) // .1 to .9: one digit
		}
		instants = append(instants, at)
	}
	instants = append(instants, base.Add(-time.Nanosecond), base.Add(time.Nanosecond), base.Add(999999999), time.Date(2025, 12, 31, 23, 59, 59, 999999999, time.UTC), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range instants {
		// prepareUpdateTimestamp's layout; a whole second prints as CURRENT_TIMESTAMP does.
		text := at.Format("2006-01-02 15:04:05.999999999")
		if at.Nanosecond() == 0 && !frameworkSecondSpelling.MatchString(text) {
			t.Fatalf("%q is not the CURRENT_TIMESTAMP spelling", text)
		}
		if _, err := tx.Exec("INSERT INTO ticks (at) VALUES (?)", text); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rows, err := app.DB.Query("SELECT CAST(at AS TEXT) FROM ticks ORDER BY at ASC")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var previous time.Time
	var previousText string
	seen := 0
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			t.Fatal(err)
		}
		at, ok := parseUpdateTimestamp(text)
		if !ok {
			t.Fatalf("%q does not parse", text)
		}
		if seen > 0 && at.Before(previous) {
			t.Errorf("text order put %q (%s) after %q (%s)", text, at.Format(time.RFC3339Nano), previousText, previous.Format(time.RFC3339Nano))
		}
		if seen > 0 && at.Equal(previous) && text != previousText {
			t.Errorf("one instant has two spellings: %q and %q", previousText, text)
		}
		previous, previousText = at, text
		seen++
	}
	if seen != len(instants) {
		t.Fatalf("read %d of %d rows", seen, len(instants))
	}
}

func datetimeFilterPlan(t *testing.T, app *App, sqlText string, args []any) string {
	t.Helper()
	rows, err := app.DB.Query("EXPLAIN QUERY PLAN "+sqlText, args...)
	if err != nil {
		t.Fatalf("%s: %v", sqlText, err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		rows.Scan(&id, &parent, &unused, &detail)
		plan = append(plan, detail)
	}
	return strings.Join(plan, "; ")
}

// A sort on created_at or updated_at stays the plain ORDER BY, so SQLite
// walks the column's index and stops after the page: no temporary sort, alone
// or behind an instant range filter on the same column. A column a client can
// write orders by instant and is sorted.
func TestListDateTimeSortOnManagedTimestampsWalksIndex(t *testing.T) {
	app, mux, sid := datetimeFilterFixture(t)
	cols, err := GetTableColumns(app.DB, "events")
	if err != nil {
		t.Fatal(err)
	}
	allow := listColumnAllowlist(app, "events", cols)
	build := func(query string) (string, string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "https://app.example.com/api/events?"+query, nil)
		sqlText, args := applyAPIFiltersWithApp("SELECT * FROM events", r, "events", app, nil, allow)
		return sqlText, datetimeFilterPlan(t, app, sqlText, args)
	}
	for query, want := range map[string]struct{ order, plan string }{
		"sort=created_at&order=desc": {`ORDER BY "events"."created_at" DESC`, "SCAN events USING INDEX idx_events_created"},
		"orderBy=created_at:asc":     {`ORDER BY "events"."created_at" ASC`, "SCAN events USING INDEX idx_events_created"},
		"created_at__gte=2026-01-15T00:00:00Z&sort=created_at&order=desc": {`ORDER BY "events"."created_at" DESC`, "SEARCH events USING INDEX idx_events_created (created_at>?)"},
		"created_at__lt=2026-01-15T00:00:00Z&orderBy=created_at:desc":     {`ORDER BY "events"."created_at" DESC`, "SEARCH events USING INDEX idx_events_created (created_at<?)"},
		"sort=updated_at&order=desc":                                      {`ORDER BY "events"."updated_at" DESC`, "SCAN events USING INDEX idx_events_updated"},
		"orderBy=updated_at:asc":                                          {`ORDER BY "events"."updated_at" ASC`, "SCAN events USING INDEX idx_events_updated"},
		"updated_at__gte=2026-01-15T00:00:00Z&orderBy=updated_at:desc":    {`ORDER BY "events"."updated_at" DESC`, "SEARCH events USING INDEX idx_events_updated (updated_at>?)"},
	} {
		sqlText, plan := build(query)
		if !strings.Contains(sqlText, want.order) || strings.Contains(sqlText, "ORDER BY julianday") {
			t.Errorf("%s: want the plain %q, got %s", query, want.order, sqlText)
		}
		if !strings.Contains(plan, want.plan) || strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("%s: plan %q, want %q and no temporary sort\n%s", query, plan, want.plan, sqlText)
		}
	}
	// The range filter in front of the plain sort still compares instants.
	for _, column := range []string{"created_at", "updated_at"} {
		if sqlText, _ := build(column + "__gte=2026-01-15T00:00:00Z&sort=" + column); !strings.Contains(sqlText, `julianday("events".`+`"`+column+`") >= julianday(?)`) {
			t.Errorf("%s filter is not an instant comparison: %s", column, sqlText)
		}
	}
	if sqlText, plan := build("sort=starts_at&order=desc"); !strings.Contains(sqlText, `ORDER BY julianday("events"."starts_at") DESC, "events"."starts_at" DESC`) || !strings.Contains(plan, "USE TEMP B-TREE FOR ORDER BY") {
		t.Errorf("sort=starts_at: want the instant sort (a temporary sort), got %s\nplan %s", sqlText, plan)
	}

	// /api/_query makes the same choice.
	admin := &Session{UserID: 1, Role: "admin"}
	for column, instant := range map[string]bool{"created_at": false, "updated_at": false, "starts_at": true} {
		spec := &querySpec{Table: "events", Select: []string{"name"}, OrderBy: []queryOrder{{Col: column, Dir: "desc"}}}
		sqlText, _, err := buildQuery(app, spec, columnSet(app, "events"), admin)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(sqlText, "ORDER BY julianday(") != instant {
			t.Errorf("order_by %s: instant sort = %v, want %v: %s", column, !instant, instant, sqlText)
		}
	}

	// Both framework spellings of updated_at in one list come back in
	// instant order from the plain sort.
	uid := gateScalar(t, app, "SELECT id FROM _benmore_users LIMIT 1")
	mustExec(t, app.DB, "DELETE FROM events")
	for name, updated := range map[string]string{
		"d-10h-half": "2026-01-15 10:00:00.5", "b-10h": "2026-01-15 10:00:00", "a-before": "2026-01-15 09:59:59.999999999",
		"c-10h-fraction": "2026-01-15 10:00:00.123456789", "e-11h": "2026-01-15 11:00:00",
	} {
		mustExecArgs(t, app.DB, "INSERT INTO events (user_id, name, updated_at) VALUES (?, ?, ?)", uid, name, updated)
	}
	var rows []map[string]any
	w := datetimeFilterGet(t, mux, sid, "sort=updated_at&order=asc")
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || datetimeFilterNames(rows) != "a-before,b-10h,c-10h-fraction,d-10h-half,e-11h" {
		t.Errorf("updated_at sort gave %q, want a-before,b-10h,c-10h-fraction,d-10h-half,e-11h", datetimeFilterNames(rows))
	}
	w = datetimeFilterGet(t, mux, sid, "orderBy=updated_at:desc&updated_at__gte=2026-01-15T10:00:00Z")
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || datetimeFilterNames(rows) != "e-11h,d-10h-half,c-10h-fraction,b-10h" {
		t.Errorf("updated_at sort after a filter gave %q, want e-11h,d-10h-half,c-10h-fraction,b-10h", datetimeFilterNames(rows))
	}

	// The stated residual: a created_at written in another spelling by SQL
	// the app wrote sorts by its text, as it did before, while a filter on
	// it compares the instant.
	mustExec(t, app.DB, "DELETE FROM events")
	mustExecArgs(t, app.DB, "INSERT INTO events (user_id, name, created_at) VALUES (?, 'framework-10h', '2026-01-15 10:00:00'), (?, 'raw-sql-09h', '2026-01-15T09:00:00Z')", uid, uid)
	w = datetimeFilterGet(t, mux, sid, "sort=created_at&order=asc")
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || datetimeFilterNames(rows) != "framework-10h,raw-sql-09h" {
		t.Errorf("created_at sort gave %q, want the text order framework-10h,raw-sql-09h", datetimeFilterNames(rows))
	}
	w = datetimeFilterGet(t, mux, sid, "created_at__lt=2026-01-15T09:30:00Z")
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || datetimeFilterNames(rows) != "raw-sql-09h" {
		t.Errorf("created_at filter matched %q, want raw-sql-09h", datetimeFilterNames(rows))
	}
}

func TestInstantSortsAsText(t *testing.T) {
	for _, c := range []Column{
		{Name: "created_at", Type: "DATETIME", Default: "CURRENT_TIMESTAMP"},
		{Name: "created_at", Type: "datetime", Default: "current_timestamp"},
		{Name: "CREATED_AT", Type: "TIMESTAMP", Default: "datetime('now')"},
		{Name: "created_at", Type: "DATETIME", Default: "(datetime( 'now' ))"},
		{Name: "updated_at", Type: "DATETIME", Default: "CURRENT_TIMESTAMP"},
		{Name: "UPDATED_AT", Type: "datetime", Default: "datetime('now')"},
		{Name: "updated_at", Type: "DATETIME"},                  // +timestamps shorthand: NULL until the first update stamps it
		{Name: "updated_at", Type: "DATETIME", Default: "NULL"}, // the same, spelled out
	} {
		if !instantSortsAsText(c) {
			t.Errorf("%+v: want the plain sort", c)
		}
	}
	for _, c := range []Column{
		{Name: "created_at", Type: "DATETIME"}, // no default: the framework writes nothing there
		{Name: "created_at", Type: "DATETIME", Default: "strftime('%Y-%m-%dT%H:%M:%fZ','now')"},
		{Name: "created_at", Type: "DATETIME", Default: "'2026-01-01T00:00:00Z'"},
		{Name: "created_at", Type: "DATETIME", Default: "datetime('now','localtime')"},
		{Name: "created_at", Type: "TEXT", Default: "CURRENT_TIMESTAMP"},
		{Name: "createdAt", Type: "DATETIME", Default: "CURRENT_TIMESTAMP"}, // not the protected name: clients can write it
		{Name: "updated_at", Type: "DATETIME", Default: "strftime('%Y-%m-%dT%H:%M:%fZ','now')"},
		{Name: "updated_at", Type: "TEXT", Default: "CURRENT_TIMESTAMP"},
		{Name: "updatedAt", Type: "DATETIME", Default: "CURRENT_TIMESTAMP"}, // not the protected name
		{Name: "deleted_at", Type: "DATETIME"},
		{Name: "starts_at", Type: "DATETIME", Default: "CURRENT_TIMESTAMP"},
	} {
		if instantSortsAsText(c) {
			t.Errorf("%+v: want the instant sort", c)
		}
	}
}
