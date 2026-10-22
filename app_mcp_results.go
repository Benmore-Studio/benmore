//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const appMCPInputLimit = 64 << 10
const appMCPResultLimit = 4 << 20

// appMCPErrorCodes is the one stable error-code set for connector reads and
// writes (the `error_code` in a failed tool result's _meta). Producers: read
// failures use appMCPResultFailure; command failures map their class through
// appMCPCommandErrorClass. in_progress is reserved for an attempt of the same
// operation that is still running; no runtime path emits it yet.
var appMCPErrorCodes = []string{
	"denied", "invalid_input", "conflict", "expired_intent", "approval_required",
	"operation_limit", "hook_refused", "unavailable_provider", "incomplete_result",
	"unknown_execution", "in_progress",
}

type appMCPResultError struct{ Code, Message string }

func (e *appMCPResultError) Error() string { return e.Message }
func appMCPResultFailure(code string) error {
	return &appMCPResultError{code, "Connector operation could not produce an authorized, validated result."}
}

type appMCPReadResult struct {
	Data            any                `json:"data"`
	ProcessingID    string             `json:"processing_id,omitempty"`
	ObservedAt      string             `json:"observed_at"`
	SourceRevisions map[string]string  `json:"source_revisions,omitempty"`
	Completeness    appMCPCompleteness `json:"completeness"`
	Pagination      *appMCPPagination  `json:"pagination"`
	Freshness       string             `json:"freshness"`
	Warnings        []string           `json:"warnings"`
}
type appMCPCompleteness struct {
	State              string `json:"state"`
	Basis              string `json:"basis"`
	SnapshotConsistent bool   `json:"snapshot_consistent"`
}
type appMCPPagination struct {
	Page    int  `json:"page"`
	PerPage int  `json:"per_page"`
	Total   int  `json:"total"`
	HasNext bool `json:"has_next"`
}

// A bounded, request-local capture. No raw canonical response enters a tool
// result, text fallback, log or global cache before projection and validation.
type appMCPReadCapture struct {
	header http.Header
	status int
	bytes.Buffer
	overflow bool
}

func (w *appMCPReadCapture) Header() http.Header { return w.header }
func (w *appMCPReadCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *appMCPReadCapture) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if len(data) > appMCPResultLimit-w.Len() {
		w.overflow = true
		return 0, errors.New("connector result limit exceeded")
	}
	return w.Buffer.Write(data)
}

// OutputSchema describes a projected row. List results validate every row;
// the transport wraps that schema in the shared envelope and an array for list.
func runAppMCPNativeRead(ctx context.Context, app *App, raw, resource, name string, input map[string]any) (*appMCPReadResult, error) {
	return runAppMCPNativeReadGeneration(ctx, app, snapshotAppMCPGeneration(app), raw, resource, name, input)
}

func runAppMCPNativeReadGeneration(ctx context.Context, origin *App, generation *appMCPRuntimeGeneration, raw, resource, name string, input map[string]any) (*appMCPReadResult, error) {
	if generation == nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	app := generation.view
	manifest := generation.manifest
	if manifest == nil || ctx.Err() != nil {
		return nil, appMCPResultFailure("denied")
	}
	_, actor, err := resolveAppMCPAccessForGeneration(ctx, origin, generation, raw, resource, time.Now())
	tool := appMCPReadTool(app, name)
	if err != nil || tool == nil || !appMCPGenerationCurrent(origin, generation) || !scopesWithin(actor.Scopes, strings.Join(tool.Permissions, " ")) {
		return nil, appMCPResultFailure("denied")
	}
	if validateAppMCPSchemaValue(tool.InputSchema, input) != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	payload, err := json.Marshal(input)
	if err != nil || len(payload) > appMCPInputLimit {
		return nil, appMCPResultFailure("invalid_input")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var args map[string]any
	if decoder.Decode(&args) != nil || args == nil || validateAppMCPSchemaValue(tool.InputSchema, args) != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	if tool.Handler.Operation == "flow.call" {
		return runAppMCPReadFlowGeneration(ctx, origin, generation, raw, resource, tool, args)
	}
	columns, err := appMCPReadColumns(ctx, app, tool.Handler.Table)
	if err != nil {
		return nil, appMCPResultFailure("incomplete_result")
	}
	path, query, err := appMCPNativeReadInput(app, tool, args, columns)
	if err != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	known := map[string]bool{}
	for _, column := range columns {
		known[column.Name] = true
	}
	for _, field := range tool.Output.Include {
		if !known[field] || !isValidColumnName(field) || apiHiddenColumn(app, tool.Handler.Table, field) {
			return nil, appMCPResultFailure("incomplete_result")
		}
	}
	fields := append([]string(nil), tool.Output.Include...)
	if known["user_id"] {
		fields = append(fields, "user_id")
	}
	// Row revisions need each returned row's id even when the tool does not
	// project it; projection drops it again. A point-in-time read returns
	// history, which the current ledger does not describe.
	_, historical := args["as_of"]
	var pin *appMCPRevisionPin
	if known["id"] && !historical {
		fields = append(fields, "id")
		if pin = pinAppMCPReadRevisions(ctx, origin); pin != nil {
			defer pin.close()
		}
	}
	query.Set("fields", strings.Join(fields, ","))
	source, err := http.NewRequestWithContext(ctx, http.MethodGet, path+"?"+query.Encode(), nil)
	if err != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	request, err := newAppMCPNativeRequestWithGeneration(origin, app, generation, source, raw, resource, name, columns)
	if err != nil {
		return nil, appMCPResultFailure("denied")
	}
	capture := &appMCPReadCapture{header: make(http.Header)}
	if tool.Handler.Operation == "table.list" {
		handleList(capture, request, app, tool.Handler.Table)
	} else {
		handleRead(capture, request, app, tool.Handler.Table)
	}
	if capture.overflow || ctx.Err() != nil {
		return nil, appMCPResultFailure("incomplete_result")
	}
	if capture.status != http.StatusOK {
		if capture.status == 401 || capture.status == 403 || capture.status == 404 {
			return nil, appMCPResultFailure("denied")
		}
		return nil, appMCPResultFailure("incomplete_result")
	}
	result := &appMCPReadResult{ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceRevisions: map[string]string{"contract": manifest.ContractDigest, "execution": manifest.ExecutionDigest}, Freshness: "observed", Warnings: []string{}, Completeness: appMCPCompleteness{State: "complete", Basis: "authorized_row"}}
	decoder = json.NewDecoder(bytes.NewReader(capture.Bytes()))
	decoder.UseNumber()
	var returned []map[string]any
	if tool.Handler.Operation == "table.read" {
		var row map[string]any
		if decoder.Decode(&row) != nil || row == nil {
			return nil, appMCPResultFailure("incomplete_result")
		}
		returned = []map[string]any{row}
		result.Data, err = appMCPProjectRow(tool, row)
	} else {
		var page struct {
			Data    []map[string]any `json:"data"`
			Total   int              `json:"total"`
			Page    int              `json:"page"`
			PerPage int              `json:"per_page"`
		}
		if decoder.Decode(&page) != nil || page.Data == nil || page.Total < 0 || page.Page < 1 || page.PerPage < 1 || page.PerPage > 500 || len(page.Data) > page.PerPage {
			return nil, appMCPResultFailure("incomplete_result")
		}
		rows := make([]map[string]any, 0, len(page.Data))
		for _, row := range page.Data {
			projected, projectionErr := appMCPProjectRow(tool, row)
			if projectionErr != nil {
				return nil, projectionErr
			}
			rows = append(rows, projected)
		}
		offset := (page.Page - 1) * page.PerPage
		returned = page.Data
		result.Data = rows
		result.Pagination = &appMCPPagination{Page: page.Page, PerPage: page.PerPage, Total: page.Total, HasNext: offset < page.Total && len(rows) < page.Total-offset}
		result.Completeness = appMCPCompleteness{State: "partial", Basis: "reported_total"}
		if page.Page == 1 && len(rows) == page.Total {
			result.Completeness.State = "complete"
		}
		if len(rows) > page.Total || len(rows) < page.PerPage && result.Pagination.HasNext {
			result.Completeness.State = "indeterminate"
			result.Warnings = append(result.Warnings, "rows_and_total_changed")
		}
		result.Warnings = append(result.Warnings, "rows_and_total_observed_separately")
	}
	if err != nil {
		return nil, err
	}
	// Revisions are read after the data and prove the same state, or are omitted.
	if found, ok := pin.revisions(ctx, tool.Handler.Table, returned, slices.Contains(tool.Output.Include, "id")); ok {
		maps.Copy(result.SourceRevisions, found)
	} else {
		result.Warnings = append([]string{"data_revision_unavailable"}, result.Warnings...)
	}
	encoded, encodeErr := json.Marshal(result)
	if encodeErr != nil || len(encoded) > appMCPResultLimit {
		return nil, appMCPResultFailure("incomplete_result")
	}
	// Authority loss during query/encoding must not release the captured result.
	if actor, _ := appMCPPrivateSession(app, request); actor == nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	return result, nil
}
func appMCPProjectRow(tool *AppMCPTool, row map[string]any) (map[string]any, error) {
	projected := make(map[string]any, len(tool.Output.Include))
	for _, key := range tool.Output.Include {
		if value, ok := row[key]; ok {
			projected[key] = value
		}
	}
	if validateAppMCPSchemaValue(tool.OutputSchema, projected) != nil {
		return nil, appMCPResultFailure("incomplete_result")
	}
	return projected, nil
}

func appMCPNativePositiveInt(value any, maxValue int) (int, bool) {
	number, ok := appMCPExactNumber(value)
	if !ok || !number.IsInt() || !number.Num().IsInt64() {
		return 0, false
	}
	n := number.Num().Int64()
	if n < 1 || n > int64(maxValue) {
		return 0, false
	}
	return int(n), true
}
func appMCPNativeScalar(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case bool:
		return jsonToFormValue(v), true
	case json.Number:
		return v.String(), true
	}
	return "", false
}
func appMCPNativeReadInput(app *App, tool *AppMCPTool, args map[string]any, columns []Column) (string, url.Values, error) {
	denied := errors.New("unsupported native read input")
	path := "/api/" + tool.Handler.Table
	query := make(url.Values)
	if tool.Handler.Operation == "table.read" {
		for key := range args {
			if key != "id" && key != "as_of" {
				return "", nil, denied
			}
		}
		id, ok := appMCPNativeScalar(args["id"])
		if !ok || id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/?#\\") {
			return "", nil, denied
		}
		path += "/" + url.PathEscape(id)
		if value, exists := args["as_of"]; exists {
			stamp, ok := value.(string)
			if !ok {
				return "", nil, denied
			}
			if _, err := time.Parse(time.RFC3339, stamp); err != nil {
				return "", nil, denied
			}
			query.Set("as_of", stamp)
		}
		return path, query, nil
	}
	page, perPage := 1, 50
	maxInt := int(^uint(0) >> 1)
	if value, exists := args["per_page"]; exists {
		var ok bool
		perPage, ok = appMCPNativePositiveInt(value, 500)
		if !ok {
			return "", nil, denied
		}
	}
	if value, exists := args["page"]; exists {
		var ok bool
		page, ok = appMCPNativePositiveInt(value, maxInt)
		if !ok || page-1 > maxInt/perPage {
			return "", nil, denied
		}
	}
	allowed := listColumnAllowlist(app, tool.Handler.Table, columns)
	encrypted := map[string]bool{}
	if app.Encrypted != nil {
		for _, field := range app.Encrypted.Fields[tool.Handler.Table] {
			encrypted[field.Column] = true
		}
	}
	for key, value := range args {
		switch key {
		case "page", "per_page":
		case "sort":
			field, ok := value.(string)
			if !ok || !isValidColumnName(field) || !allowed[field] || apiHiddenColumn(app, tool.Handler.Table, field) || encrypted[field] {
				return "", nil, denied
			}
			query.Set("sort", field)
		case "order":
			order, ok := value.(string)
			if !ok || order != "asc" && order != "desc" {
				return "", nil, denied
			}
			query.Set("order", order)
		case "q":
			search, ok := value.(string)
			fts, cols := FTSTableFor(app.Tables, tool.Handler.Table)
			if !ok || strings.TrimSpace(search) == "" || fts == "" || len(cols) == 0 {
				return "", nil, denied
			}
			query.Set("q", search)
		case "filters":
			filters, ok := value.(map[string]any)
			if !ok {
				return "", nil, denied
			}
			for field, value := range filters {
				if strings.HasPrefix(field, "where[") {
					return "", nil, denied
				}
				column, op := splitAPIFilterKey(field)
				if column == "" || !isValidColumnName(column) || !allowed[column] || apiHiddenColumn(app, tool.Handler.Table, column) {
					return "", nil, denied
				}
				if encrypted[column] && (!BlindIndexColumnsForTable(app.Encrypted, tool.Handler.Table)[column] || op != "=" && op != "IN") {
					return "", nil, denied
				}
				scalar, ok := appMCPNativeScalar(value)
				if op == "IN" {
					values, array := value.([]any)
					if !array || len(values) == 0 {
						return "", nil, denied
					}
					parts := make([]string, len(values))
					for i, item := range values {
						part, valid := appMCPNativeScalar(item)
						if !valid || strings.Contains(part, ",") {
							return "", nil, denied
						}
						parts[i] = part
					}
					scalar, ok = strings.Join(parts, ","), true
				}
				if !ok {
					return "", nil, denied
				}
				if encrypted[column] {
					for _, part := range strings.Split(scalar, ",") {
						if hash, err := blindIndexForApp(app, part); err != nil || hash == "" {
							return "", nil, denied
						}
					}
				}
				query.Set("where["+field+"]", scalar)
			}
		default:
			return "", nil, denied
		}
	}
	if query.Get("order") != "" && query.Get("sort") == "" {
		return "", nil, denied
	}
	query.Set("page", fmt.Sprint(page))
	query.Set("per_page", fmt.Sprint(perPage))
	return path, query, nil
}
