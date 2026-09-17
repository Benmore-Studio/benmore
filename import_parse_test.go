//go:build !cli

package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestIsTextAffinity(t *testing.T) {
	// SQLite type-affinity rules: TEXT affinity when the declared type
	// contains CHAR, CLOB or TEXT. Everything else is numeric/blob here.
	cases := []struct {
		declared string
		want     bool
	}{
		{"TEXT", true},
		{"VARCHAR(255)", true},
		{"CHARACTER(20)", true},
		{"CLOB", true},
		{"text", true},
		{"INTEGER", false},
		{"REAL", false},
		{"NUMERIC", false},
		{"BOOLEAN", false},
		{"DATETIME", false},
		{"BLOB", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isTextAffinity(c.declared); got != c.want {
			t.Errorf("isTextAffinity(%q) = %v, want %v", c.declared, got, c.want)
		}
	}
}

func TestCoerceCSVValue(t *testing.T) {
	textCol := Column{Name: "name", Type: "TEXT"}
	intCol := Column{Name: "qty", Type: "INTEGER"}

	cases := []struct {
		desc   string
		raw    string
		col    Column
		nullAs string
		want   any
	}{
		// The contract from the spec: empty -> NULL for non-TEXT,
		// empty string for TEXT. This is the line that silently
		// corrupts data if it is wrong.
		{"empty into TEXT stays empty string", "", textCol, "", ""},
		{"empty into INTEGER becomes NULL", "", intCol, "", nil},
		{"value passes through as string", "42", intCol, "", "42"},
		{"text value passes through", "widget", textCol, "", "widget"},
		// null_as sentinel wins over the empty rule, for both affinities.
		{"pg_dump sentinel into TEXT is NULL", `\N`, textCol, `\N`, nil},
		{"pg_dump sentinel into INTEGER is NULL", `\N`, intCol, `\N`, nil},
		{"mysql sentinel is NULL", "NULL", textCol, "NULL", nil},
		// An unset null_as must not accidentally match empty input.
		{"empty null_as does not swallow literal NULL text", "NULL", textCol, "", "NULL"},
		// Sentinel matching is exact (== "\N"), not prefix/substring: "\Name"
		// genuinely starts with "\N" but must pass through unchanged.
		{"sentinel prefix is not matched", `\Name`, textCol, `\N`, `\Name`},
	}
	for _, c := range cases {
		got := coerceCSVValue(c.raw, c.col, c.nullAs)
		if got != c.want {
			t.Errorf("%s: coerceCSVValue(%q, %s, %q) = %#v, want %#v",
				c.desc, c.raw, c.col.Type, c.nullAs, got, c.want)
		}
	}
}

func TestCSVSourceHeaderMapping(t *testing.T) {
	cols := []Column{
		{Name: "sku", Type: "TEXT"},
		{Name: "qty", Type: "INTEGER"},
	}
	// Header order deliberately reversed from column order, plus a UTF-8
	// BOM (Excel writes one) and CRLF line endings.
	in := "\uFEFFqty,sku\r\n7,ABC\r\n,DEF\r\n"
	src, eff, err := newCSVSource(strings.NewReader(in), cols, "")
	if err != nil {
		t.Fatalf("newCSVSource: %v", err)
	}
	if len(eff) != 2 || eff[0].Name != "sku" || eff[1].Name != "qty" {
		t.Fatalf("effective cols = %#v, want [sku qty]", eff)
	}

	row, err := src.Next()
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	// Values must come back in COLUMN order (sku, qty), not header order.
	if row[0] != "ABC" || row[1] != "7" {
		t.Fatalf("first row = %#v, want [ABC 7]", row)
	}

	row, err = src.Next()
	if err != nil {
		t.Fatalf("second Next: %v", err)
	}
	if row[0] != "DEF" || row[1] != nil {
		t.Fatalf("second row = %#v, want [DEF <nil>]", row)
	}

	if _, err := src.Next(); err != io.EOF {
		t.Fatalf("third Next err = %v, want io.EOF", err)
	}
}

func TestCSVSourceQuotedAndEmbedded(t *testing.T) {
	cols := []Column{{Name: "title", Type: "TEXT"}, {Name: "n", Type: "INTEGER"}}
	in := "title,n\n\"a, comma\",1\n\"line\nbreak\",2\n\"say \"\"hi\"\"\",3\n"
	src, _, err := newCSVSource(strings.NewReader(in), cols, "")
	if err != nil {
		t.Fatalf("newCSVSource: %v", err)
	}
	want := []string{"a, comma", "line\nbreak", `say "hi"`}
	for i, w := range want {
		row, err := src.Next()
		if err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		if row[0] != w {
			t.Errorf("row %d title = %#v, want %#v", i, row[0], w)
		}
	}
}

func TestCSVSourceRejectsUnknownHeader(t *testing.T) {
	cols := []Column{{Name: "sku", Type: "TEXT"}}
	_, _, err := newCSVSource(strings.NewReader("sku,nope\nA,B\n"), cols, "")
	if err == nil {
		t.Fatal("expected an error for a header naming an unknown column")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should name the offending column, got: %v", err)
	}
}

func TestCSVSourceRejectsDuplicateNormalizedHeaders(t *testing.T) {
	cols := []Column{{Name: "sku", Type: "TEXT"}}
	_, _, err := newCSVSource(strings.NewReader(" sku ,\uFEFFsku\nA,B\n"), cols, "")
	if err == nil {
		t.Fatal("expected duplicate normalized CSV headers to be rejected")
	}
	if !strings.Contains(err.Error(), "sku") {
		t.Fatalf("duplicate-header error should name sku, got %v", err)
	}
}

// TestCSVSourceOmittedColumn covers the "-1" branch the original
// implementation never exercised: a table column the file doesn't provide
// must be dropped from the effective list (so the caller's INSERT leaves
// it out and SQLite applies its DEFAULT), not passed through as NULL.
func TestCSVSourceOmittedColumn(t *testing.T) {
	cols := []Column{
		{Name: "sku", Type: "TEXT"},
		{Name: "qty", Type: "INTEGER"},
		{Name: "price", Type: "REAL", Default: "0"},
	}
	// The file only provides sku and qty; price is absent entirely.
	in := "sku,qty\nABC,7\n"
	src, eff, err := newCSVSource(strings.NewReader(in), cols, "")
	if err != nil {
		t.Fatalf("newCSVSource: %v", err)
	}
	if len(eff) != 2 || eff[0].Name != "sku" || eff[1].Name != "qty" {
		t.Fatalf("effective cols = %#v, want [sku qty] (price omitted)", eff)
	}

	row, err := src.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	// Row must be aligned to the effective (2-column) list, not the
	// original 3-column one.
	if len(row) != 2 || row[0] != "ABC" || row[1] != "7" {
		t.Fatalf("row = %#v, want [ABC 7]", row)
	}
}

func TestCSVSourceDisjointHeaderErrors(t *testing.T) {
	cols := []Column{{Name: "sku", Type: "TEXT"}}
	_, _, err := newCSVSource(strings.NewReader("foo,bar\n1,2\n"), cols, "")
	if err == nil {
		t.Fatal("expected an error when the header shares no columns with the table")
	}
}

func TestNDJSONSource(t *testing.T) {
	cols := []Column{{Name: "sku", Type: "TEXT"}, {Name: "qty", Type: "INTEGER"}}
	// Blank lines are skipped; an absent key (present in the first object,
	// missing from a later one) is NULL; JSON types survive.
	in := "{\"sku\":\"ABC\",\"qty\":7}\n\n{\"sku\":\"DEF\"}\n"
	src, eff, err := newNDJSONSource(strings.NewReader(in), cols)
	if err != nil {
		t.Fatalf("newNDJSONSource: %v", err)
	}
	if len(eff) != 2 || eff[0].Name != "sku" || eff[1].Name != "qty" {
		t.Fatalf("effective cols = %#v, want [sku qty]", eff)
	}

	row, err := src.Next()
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if row[0] != "ABC" {
		t.Errorf("sku = %#v, want ABC", row[0])
	}
	if n, ok := row[1].(json.Number); !ok || n.String() != "7" {
		t.Errorf("qty = %#v, want json.Number(7)", row[1])
	}

	row, err = src.Next()
	if err != nil {
		t.Fatalf("second Next: %v", err)
	}
	if row[1] != nil {
		t.Errorf("absent key should be nil, got %#v", row[1])
	}

	if _, err := src.Next(); err != io.EOF {
		t.Fatalf("third Next err = %v, want io.EOF", err)
	}
}

func TestNDJSONSourceReportsBadLine(t *testing.T) {
	cols := []Column{{Name: "sku", Type: "TEXT"}}
	src, _, err := newNDJSONSource(strings.NewReader("{\"sku\":\"A\"}\n{bad\n"), cols)
	if err != nil {
		t.Fatalf("newNDJSONSource: %v", err)
	}
	if _, err := src.Next(); err != nil {
		t.Fatalf("first row should parse: %v", err)
	}
	// A malformed line must be a hard error, not a skipped row - this
	// import is all-or-nothing, unlike /ingest.
	if _, err := src.Next(); err == nil || err == io.EOF {
		t.Fatalf("malformed line must error, got %v", err)
	}
}

// TestNDJSONSourceOmittedColumn covers the JSON analogue of the CSV
// omitted-column case: the first object drives the effective column list,
// so a cols entry it doesn't carry must be dropped from that list.
func TestNDJSONSourceOmittedColumn(t *testing.T) {
	cols := []Column{{Name: "sku", Type: "TEXT"}, {Name: "qty", Type: "INTEGER"}}
	src, eff, err := newNDJSONSource(strings.NewReader("{\"sku\":\"ABC\"}\n"), cols)
	if err != nil {
		t.Fatalf("newNDJSONSource: %v", err)
	}
	if len(eff) != 1 || eff[0].Name != "sku" {
		t.Fatalf("effective cols = %#v, want [sku] (qty omitted)", eff)
	}

	row, err := src.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(row) != 1 || row[0] != "ABC" {
		t.Fatalf("row = %#v, want [ABC]", row)
	}
}

// TestNDJSONSourceRejectsLateColumn covers the mid-stream data-loss case:
// a later object introduces a key that IS one of cols but was absent from
// the first object (so it never made the effective list). Silently
// dropping it would lose that column's data from every row it appears in.
func TestNDJSONSourceRejectsLateColumn(t *testing.T) {
	cols := []Column{{Name: "sku", Type: "TEXT"}, {Name: "qty", Type: "INTEGER"}}
	in := "{\"sku\":\"ABC\"}\n{\"sku\":\"DEF\",\"qty\":5}\n"
	src, eff, err := newNDJSONSource(strings.NewReader(in), cols)
	if err != nil {
		t.Fatalf("newNDJSONSource: %v", err)
	}
	if len(eff) != 1 || eff[0].Name != "sku" {
		t.Fatalf("effective cols = %#v, want [sku]", eff)
	}

	if _, err := src.Next(); err != nil {
		t.Fatalf("first row should parse: %v", err)
	}
	_, err = src.Next()
	if err == nil {
		t.Fatal("expected an error when a later object introduces a column absent from the first")
	}
	if !strings.Contains(err.Error(), "qty") {
		t.Errorf("error should name the offending column, got: %v", err)
	}
}

func TestNDJSONSourceEmptyInputErrors(t *testing.T) {
	cols := []Column{{Name: "sku", Type: "TEXT"}}
	_, _, err := newNDJSONSource(strings.NewReader(""), cols)
	if err == nil {
		t.Fatal("expected an error for empty NDJSON input")
	}
}
