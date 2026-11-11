//go:build !cli && !windows

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// Each kind of result value gets the cell artifact.create would give it.
func TestAppMCPReceiptCellTypesValuesLikeArtifactCreate(t *testing.T) {
	for _, tc := range []struct {
		name         string
		value        any
		raw, display string
		format       string
	}{
		{"string", "approved", "approved", "approved", xlsxText},
		{"numeric-looking string stays text", "007", "007", "007", xlsxText},
		{"formula-looking string stays text", "=1+1", "=1+1", "=1+1", xlsxText},
		{"integer", json.Number("1234"), "1234", "1,234", xlsxInteger},
		{"decimal", json.Number("12.5"), "12.5", "12.5", xlsxNumber},
		{"true", true, "Yes", "Yes", xlsxText},
		{"false", false, "No", "No", xlsxText},
		{"null", nil, "", "", xlsxText},
		{"object stays JSON", map[string]any{"a": json.Number("1")}, `{"a":1}`, `{"a":1}`, xlsxText},
		{"array stays JSON", []any{"x", json.Number("2")}, `["x",2]`, `["x",2]`, xlsxText},
	} {
		cell, format, err := appMCPReceiptCell(tc.value)
		if err != nil || cell.Raw != tc.raw || cell.Display != tc.display || format != tc.format {
			t.Errorf("%s: cell=%#v format=%q err=%v, want raw=%q display=%q format=%q", tc.name, cell, format, err, tc.raw, tc.display, tc.format)
		}
	}

	// In the workbook a text cell is never sniffed into a number, a typed
	// number is a number, and a formula-looking text is not a formula.
	data, err := WriteXLSXSheets([]XLSXSheet{{Name: "Result", Headers: []string{"field", "value"},
		Rows:        [][]string{{"code", "007"}, {"count", "1234"}, {"note", "=1+1"}},
		CellFormats: [][]string{{xlsxText, xlsxText}, {xlsxText, xlsxInteger}, {xlsxText, xlsxText}}}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := IngestXLSX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if err != nil || !res.Complete {
		t.Fatalf("ingest: complete=%t err=%v", res.Complete, err)
	}
	cells := map[string]SourceBlock{}
	for _, block := range res.Blocks {
		cells[block.Ref] = block
	}
	if cells["B2"].Value != "007" || cells["B2"].Type != "string" || cells["B3"].Value != "1234" || cells["B3"].Type != "number" || cells["B4"].Type != "string" || cells["B4"].Formula {
		t.Fatalf("typed cells: %#v %#v %#v", cells["B2"], cells["B3"], cells["B4"])
	}
}

// exportCommittedTask commits the harness's task operation and exports its
// receipt in format, returning the stored bytes.
func exportCommittedTask(t *testing.T, h *exposureHarness, operationID, format string) []byte {
	t.Helper()
	exported, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": operationID, "format": format})
	if code != "" {
		t.Fatalf("%s export: %s", format, code)
	}
	id, _ := exported["artifact_id"].(string)
	status, data := mcpArtifactGet(t, h.app, id, h.cookie)
	if status != http.StatusOK {
		t.Fatalf("%s artifact retrieval status=%d", format, status)
	}
	return data
}

// A receipt export writes a string field as its text, not as a JSON literal
// with quotes, and keeps a number a number cell.
func TestAppMCPReceiptExportWritesPlainCellValues(t *testing.T) {
	h := newExposureHarness(t)
	operationID := h.prepare()
	h.approveOK(operationID)
	if result, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": operationID}); code != "" || result["outcome"] != "applied" {
		t.Fatalf("commit: code=%q result=%#v", code, result)
	}

	html := exportCommittedTask(t, h, operationID, "html")
	if !bytes.Contains(html, []byte("<td>done</td>")) || !bytes.Contains(html, []byte("<td>task-actor@example.com</td>")) {
		t.Errorf("HTML string cells are not plain text: %s", html)
	}
	if bytes.Contains(html, []byte("&#34;done&#34;")) || bytes.Contains(html, []byte(`"done"`)) {
		t.Errorf("HTML string cell kept its JSON quotes: %s", html)
	}

	data := exportCommittedTask(t, h, operationID, "xlsx")
	res, err := IngestXLSX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if err != nil || !res.Complete {
		t.Fatalf("ingest export: complete=%t err=%v", res.Complete, err)
	}
	cells := map[string]SourceBlock{}
	for _, block := range res.Blocks {
		cells[block.Ref] = block
	}
	// Rows are sorted by field: actor_email, completed_at, completed_by, id, status.
	for ref, want := range map[string]string{"A2": "actor_email", "A5": "id", "A6": "status", "B2": "task-actor@example.com", "B6": "done", "B5": "1"} {
		if got := cells[ref].Value; got != want {
			t.Errorf("cell %s = %q, want %q", ref, got, want)
		}
	}
	if cells["B6"].Type != "string" || cells["B5"].Type != "number" {
		t.Errorf("cell types: status=%q id=%q", cells["B6"].Type, cells["B5"].Type)
	}
}
