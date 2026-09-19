//go:build !cli

package main

// Streaming row sources for bulk import.
//
// Both sources are pull-based and hold at most one row in memory, so a
// 50 GB file costs the same as a 50 KB one. Neither touches the database
// or the network - that keeps the type-coercion contract (the part that
// silently corrupts data when wrong) testable in isolation.

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// rowSource streams rows aligned to the *effective* column list handed
// back by the constructor that built it (newCSVSource / newNDJSONSource),
// not necessarily the full list the caller asked for. Next returns io.EOF
// when the input is exhausted. Any other error is fatal to the import -
// unlike /ingest, a bad row aborts the whole load.
type rowSource interface {
	Next() ([]any, error)
}

// isTextAffinity reports whether a declared SQLite type has TEXT affinity.
// SQLite's rule: TEXT affinity when the declared type contains "CHAR",
// "CLOB" or "TEXT". We only need to separate text from everything else,
// because that is what decides whether an empty CSV field means "" or NULL.
func isTextAffinity(sqlType string) bool {
	u := strings.ToUpper(sqlType)
	return strings.Contains(u, "CHAR") || strings.Contains(u, "CLOB") || strings.Contains(u, "TEXT")
}

// coerceCSVValue applies the import typing contract to one raw CSV field:
//
//	raw == nullAs (exact, and nullAs non-empty) -> NULL
//	raw == ""     -> "" for TEXT columns, NULL otherwise
//	otherwise     -> the raw string, left to SQLite's column affinity
//
// Values are deliberately passed through as strings: SQLite applies the
// column's type affinity on bind, which is the same coercion auto-CRUD
// performs today. Parsing numbers here would only add a second, divergent
// implementation of the same rule.
func coerceCSVValue(raw string, col Column, nullAs string) any {
	if nullAs != "" && raw == nullAs {
		return nil
	}
	if raw == "" {
		if isTextAffinity(col.Type) {
			return ""
		}
		return nil
	}
	return raw
}

type csvSource struct {
	r *csv.Reader
	// order[i] is the CSV record index that feeds effective column i.
	// Every entry is a real index - a table column the file omits was
	// dropped from cols entirely at construction, so there is no sentinel
	// case left for Next() to special-case.
	order  []int
	cols   []Column // the effective column list; see newCSVSource
	nullAs string
}

// newCSVSource reads the header line and intersects it with cols to get
// the *effective* column list - the columns this import will actually
// write, in cols order. The caller must build its INSERT from the
// returned list, not the input one: a column the file omits is simply
// absent from the statement, so SQLite applies its own DEFAULT instead of
// the loader binding an explicit NULL over it.
//
// A header naming something that is NOT an importable column is still a
// hard error (not merely excluded) - that means the caller has the wrong
// file or the wrong table, and silently ignoring it would lose data. An
// empty intersection is also an error: a file sharing no columns with the
// table is a mistake, not a legitimately empty import.
//
// normalizeImportHeaderName strips a leading UTF-8 BOM (Excel writes one on
// the first field) and surrounding whitespace from a declared column /
// CSV header name. Shared by newCSVSource below and validateImportColumns
// (import_run.go) so the two never disagree about what counts as a match:
// pre-fix, a caller sending raw header names to the `columns` field on the
// create request (import_http.go handleImportCreate) - as any third-party
// client not going through `benmore import`'s own csvHeaderColumns, which
// already normalizes identically - got a spurious 400 for a file the
// loader itself would have accepted at load time.
func normalizeImportHeaderName(h string) string {
	return strings.TrimSpace(strings.TrimPrefix(h, "\uFEFF"))
}

// A UTF-8 BOM (Excel writes one) is stripped from the first header field.
// CRLF line endings are handled by encoding/csv.
func newCSVSource(r io.Reader, cols []Column, nullAs string) (rowSource, []Column, error) {
	cr := csv.NewReader(r)
	// Records are ragged only if the file is malformed; let csv enforce a
	// consistent field count against the header.
	cr.FieldsPerRecord = 0
	cr.ReuseRecord = true

	header, err := cr.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("read CSV header: %w", err)
	}
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\uFEFF")
	}

	pos := make(map[string]int, len(header))
	for i, h := range header {
		h = normalizeImportHeaderName(h)
		if _, exists := pos[h]; exists {
			return nil, nil, fmt.Errorf("CSV header has duplicate column %q", h)
		}
		pos[h] = i
	}

	// The reverse check: a header naming something that is not an
	// importable column means the caller has the wrong file or the wrong
	// table, and silently dropping it would lose data.
	known := make(map[string]bool, len(cols))
	for _, c := range cols {
		known[c.Name] = true
	}
	for _, h := range header {
		h = normalizeImportHeaderName(h)
		if !known[h] {
			return nil, nil, fmt.Errorf("CSV header column %q is not an importable column of this table", h)
		}
	}

	// The effective list is the intersection of the header with cols, kept
	// in cols order. A table column absent from the header is simply left
	// out - it never reaches Next(), so it never reaches the INSERT.
	eff := make([]Column, 0, len(cols))
	order := make([]int, 0, len(cols))
	for _, c := range cols {
		idx, ok := pos[c.Name]
		if !ok {
			continue
		}
		eff = append(eff, c)
		order = append(order, idx)
	}
	if len(eff) == 0 {
		return nil, nil, fmt.Errorf("CSV header shares no columns with this table")
	}

	return &csvSource{r: cr, order: order, cols: eff, nullAs: nullAs}, eff, nil
}

func (s *csvSource) Next() ([]any, error) {
	rec, err := s.r.Read()
	if err != nil {
		return nil, err // io.EOF passes through untouched
	}
	out := make([]any, len(s.cols))
	for i, idx := range s.order {
		out[i] = coerceCSVValue(rec[idx], s.cols[i], s.nullAs)
	}
	return out, nil
}

type ndjsonSource struct {
	dec *json.Decoder
	// cols is the effective column list, derived from the first object's
	// keys; see newNDJSONSource.
	cols []Column
	// allNames/effNames back the mid-stream key check in Next(): a name in
	// allNames but not effNames is a column the first row didn't carry, so
	// silently accepting it from row 2 onward would lose that column's
	// data for every row before it appeared.
	allNames map[string]bool
	effNames map[string]bool
	// pending is the first object, already decoded during construction to
	// derive the effective column list; the first Next() call drains it
	// instead of reading the decoder again.
	pending map[string]any
}

// newNDJSONSource streams newline-delimited JSON objects. JSON has no
// header, so the effective column list is derived by peeking the first
// object: its keys, intersected with cols and kept in cols order. That
// first object is buffered so the first Next() call still returns it.
//
// The caller must build its INSERT from the returned effective list, same
// contract as newCSVSource: a column no row carries is simply absent from
// the statement, so SQLite applies its DEFAULT rather than the loader
// binding an explicit NULL over it.
//
// An empty input, a malformed first object, or a first object sharing no
// keys with cols are all errors - there is no effective column list to
// hand back. A later object introducing a key that IS in cols but was NOT
// in the first object is also an error naming that key: silently dropping
// it would lose that column's data the same way an unhandled table column
// would, just discovered a row later. JSON is already typed, so present
// values are handed to the driver as their JSON type - the CSV empty/NULL
// coercion contract does not apply.
func newNDJSONSource(r io.Reader, cols []Column) (rowSource, []Column, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()

	var first map[string]any
	if err := dec.Decode(&first); err != nil {
		if err == io.EOF {
			return nil, nil, fmt.Errorf("NDJSON input is empty")
		}
		return nil, nil, fmt.Errorf("parse first NDJSON object: %w", err)
	}

	allNames := make(map[string]bool, len(cols))
	for _, c := range cols {
		allNames[c.Name] = true
	}

	eff := make([]Column, 0, len(cols))
	effNames := make(map[string]bool, len(cols))
	for _, c := range cols {
		if _, ok := first[c.Name]; ok {
			eff = append(eff, c)
			effNames[c.Name] = true
		}
	}
	if len(eff) == 0 {
		return nil, nil, fmt.Errorf("NDJSON first object shares no keys with this table's columns")
	}

	return &ndjsonSource{
		dec:      dec,
		cols:     eff,
		allNames: allNames,
		effNames: effNames,
		pending:  first,
	}, eff, nil
}

func (s *ndjsonSource) Next() ([]any, error) {
	var obj map[string]any
	if s.pending != nil {
		obj = s.pending
		s.pending = nil
	} else {
		if err := s.dec.Decode(&obj); err != nil {
			return nil, err // io.EOF passes through; a parse error aborts the load
		}
		for k := range obj {
			if s.allNames[k] && !s.effNames[k] {
				return nil, fmt.Errorf("NDJSON object has key %q absent from the first object; cannot add columns mid-stream", k)
			}
		}
	}
	out := make([]any, len(s.cols))
	for i, c := range s.cols {
		if v, ok := obj[c.Name]; ok {
			out[i] = v
		}
	}
	return out, nil
}
