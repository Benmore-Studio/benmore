//go:build !cli

package main

// Read-tool artifacts: a reviewed read tool may declare `artifact:` in mcp.yaml,
// and the companion tool artifact.create then re-runs that read with the
// caller's authority and stores its validated result as an XLSX workbook, a
// printable HTML report or a PDF. The data is the tool's own output; the layout
// (which array becomes which sheet, column order, labels, number formats) is
// reviewed contract content. Nothing in the model's arguments reaches layout.
//
// The bytes go through the same immutable store as command artifacts
// (createAppMCPArtifact), so retrieval stays GET /api/_mcp/artifacts/{id}:
// direct interactive session only, owner, tenant, current role and the producing
// tool's scopes rechecked on every read.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpArtifactCreateTool = "artifact.create"

	// Bounds on what one artifact may contain. The read result itself is already
	// capped at appMCPResultLimit; these keep the rendered file proportionate.
	mcpReadArtifactMaxSheets    = 8
	mcpReadArtifactMaxColumns   = 50
	mcpReadArtifactMaxRows      = 5000   // per sheet
	mcpReadArtifactMaxCells     = 100000 // whole artifact
	mcpReadArtifactMaxCellChars = 8192
	mcpReadArtifactMaxBytes     = 16 << 20

	// Per-user storage budget. Read artifacts are a ring: creating one past
	// either limit deletes the user's oldest read artifacts (manifest and bytes),
	// so a connector cannot fill the store and a user is never locked out.
	mcpReadArtifactKeepPerUser  = 25
	mcpReadArtifactBytesPerUser = 128 << 20

	// A read artifact is a snapshot of data the caller could read then; it stops
	// being downloadable after this long (same 404 as an unknown id) and is
	// deleted the next time its owner makes one.
	mcpReadArtifactTTL = 7 * 24 * time.Hour

	mcpReadArtifactTemplateVersion = "artifact-report/1"
	mcpReadArtifactOperationPrefix = "read:"
)

// mcpReadArtifactLimiter bounds artifact creation of every format per user. A
// PDF additionally draws from the shared pdfLimiter, as GET /pdf/ and
// artifact.export do, because each one starts a headless Chrome.
var mcpReadArtifactLimiter = NewRateLimiter(20, time.Hour)

// ---- manifest declaration --------------------------------------------------

// AppMCPArtifactDecl is a read tool's reviewed artifact layout. It is part of the
// contract digest; omitempty on the tool field keeps the digest of every
// manifest that declares none.
type AppMCPArtifactDecl struct {
	Title   string                `yaml:"title" json:"Title"`
	Formats []string              `yaml:"formats" json:"Formats"`
	Sheets  []AppMCPArtifactSheet `yaml:"sheets" json:"Sheets"`
}

// AppMCPArtifactSheet is one sheet (XLSX) or section (HTML/PDF). Source names an
// array property of the tool's output whose objects are the rows; empty means
// the tool's own data: the rows of a table.list tool, or the one object a
// table.read or flow.call tool returns (a single-row summary sheet).
type AppMCPArtifactSheet struct {
	Name    string                 `yaml:"name" json:"Name"`
	Source  string                 `yaml:"source,omitempty" json:"Source,omitempty"`
	Columns []AppMCPArtifactColumn `yaml:"columns" json:"Columns"`
}

// AppMCPArtifactColumn maps one scalar field of the row to a column. Format is
// one of text, integer, number, money, percent (the field holds a fraction:
// 0.0525 shows as 5.25%), date, datetime; empty derives it from the field type.
type AppMCPArtifactColumn struct {
	Field  string `yaml:"field" json:"Field"`
	Label  string `yaml:"label" json:"Label"`
	Format string `yaml:"format,omitempty" json:"Format,omitempty"`
}

var mcpArtifactFormats = []string{"xlsx", "html", "pdf"}

func appMCPArtifactFormatKnown(kind string) bool { return slices.Contains(mcpArtifactFormats, kind) }

// appMCPArtifactColumnFormat resolves a column's format against its schema, or
// explains why the pair is invalid.
func appMCPArtifactColumnFormat(column AppMCPArtifactColumn, schema *AppMCPSchema) (string, error) {
	if schema == nil {
		return "", fmt.Errorf("field %q is not a property of the rows", column.Field)
	}
	switch schema.Type {
	case "string", "number", "integer", "boolean":
	default:
		return "", fmt.Errorf("field %q has type %q; a column must be a string, number, integer or boolean", column.Field, schema.Type)
	}
	format := column.Format
	if format == "" {
		format = map[string]string{"string": xlsxText, "boolean": xlsxText, "integer": xlsxInteger, "number": xlsxNumber}[schema.Type]
	}
	ok := false
	switch format {
	case xlsxText:
		ok = true
	case xlsxInteger:
		ok = schema.Type == "integer"
	case xlsxNumber, xlsxMoney, xlsxPercent:
		ok = schema.Type == "integer" || schema.Type == "number"
	case xlsxDate, xlsxDateTime:
		ok = schema.Type == "string"
	default:
		return "", fmt.Errorf("column %q has unknown format %q (text, integer, number, money, percent, date, datetime)", column.Field, format)
	}
	if !ok {
		return "", fmt.Errorf("column %q: format %q does not fit a %s field", column.Field, format, schema.Type)
	}
	return format, nil
}

// appMCPArtifactSheetSchema returns the schema of one sheet's rows and the
// property names a row may be read from.
func appMCPArtifactSheetSchema(tool AppMCPTool, sheet AppMCPArtifactSheet) (*AppMCPSchema, error) {
	if sheet.Source == "" {
		return tool.OutputSchema, nil
	}
	if tool.Handler.Operation == "table.list" {
		return nil, fmt.Errorf("sheet %q: a table.list tool's rows are its data; omit source", sheet.Name)
	}
	property := tool.OutputSchema.Properties[sheet.Source]
	if property == nil || property.Type != "array" || property.Items == nil || property.Items.Type != "object" {
		return nil, fmt.Errorf("sheet %q: source %q must be an array-of-objects property of the output schema", sheet.Name, sheet.Source)
	}
	if !slices.Contains(tool.Output.Include, sheet.Source) {
		return nil, fmt.Errorf("sheet %q: source %q is not in the output projection", sheet.Name, sheet.Source)
	}
	return property.Items, nil
}

func validateAppMCPArtifactDecl(tool AppMCPTool) error {
	decl := tool.Artifact
	if tool.Effect != "read" || tool.Handler.Kind != "native" || (tool.Handler.Operation != "table.list" && tool.Handler.Operation != "table.read" && tool.Handler.Operation != "flow.call") {
		return errors.New("artifact is declared only on a native read tool (table.list, table.read or flow.call)")
	}
	if err := validateAppMCPReviewText("artifact title", decl.Title, 120); err != nil || decl.Title == "" {
		return fmt.Errorf("artifact title is required (at most 120 characters, no control characters): %v", err)
	}
	if len(decl.Formats) == 0 || len(decl.Formats) > len(mcpArtifactFormats) {
		return errors.New("artifact formats must list one or more of xlsx, html, pdf")
	}
	for i, format := range decl.Formats {
		if !appMCPArtifactFormatKnown(format) || slices.Contains(decl.Formats[:i], format) {
			return fmt.Errorf("artifact format %q is unknown or repeated (xlsx, html, pdf)", format)
		}
	}
	if len(decl.Sheets) == 0 || len(decl.Sheets) > mcpReadArtifactMaxSheets {
		return fmt.Errorf("artifact needs 1 to %d sheets", mcpReadArtifactMaxSheets)
	}
	names := map[string]bool{}
	for _, sheet := range decl.Sheets {
		// The XLSX writer's own sheet-name rule, so a declaration it would refuse never loads.
		if err := validateAppMCPReviewText("artifact sheet name", sheet.Name, 31); err != nil || sheet.Name == "" || len(sheet.Name) > 31 ||
			strings.ContainsAny(sheet.Name, `[]:*?/\`) || strings.HasPrefix(sheet.Name, "'") || strings.HasSuffix(sheet.Name, "'") {
			return fmt.Errorf("artifact sheet name %q must be 1 to 31 bytes with none of [ ] : * ? / \\ and no edge apostrophe", sheet.Name)
		}
		if lower := strings.ToLower(sheet.Name); names[lower] {
			return fmt.Errorf("artifact sheet name %q is repeated", sheet.Name)
		} else {
			names[lower] = true
		}
		rows, err := appMCPArtifactSheetSchema(tool, sheet)
		if err != nil {
			return err
		}
		if len(sheet.Columns) == 0 || len(sheet.Columns) > mcpReadArtifactMaxColumns {
			return fmt.Errorf("sheet %q needs 1 to %d columns", sheet.Name, mcpReadArtifactMaxColumns)
		}
		seen := map[string]bool{}
		for _, column := range sheet.Columns {
			if seen[column.Field] {
				return fmt.Errorf("sheet %q lists field %q twice", sheet.Name, column.Field)
			}
			seen[column.Field] = true
			if err := validateAppMCPReviewText("column label", column.Label, 80); err != nil || column.Label == "" {
				return fmt.Errorf("sheet %q column %q needs a label of at most 80 characters with no control characters: %v", sheet.Name, column.Field, err)
			}
			if sheet.Source == "" && !slices.Contains(tool.Output.Include, column.Field) {
				return fmt.Errorf("sheet %q column %q is not in the output projection", sheet.Name, column.Field)
			}
			if _, err := appMCPArtifactColumnFormat(column, rows.Properties[column.Field]); err != nil {
				return fmt.Errorf("sheet %q: %w", sheet.Name, err)
			}
		}
	}
	return nil
}

// ---- document model --------------------------------------------------------

type appMCPArtifactCell struct{ Raw, Display string }

type appMCPArtifactColumnData struct{ Label, Format string }

type appMCPArtifactSheetData struct {
	Name    string
	Columns []appMCPArtifactColumnData
	Rows    [][]appMCPArtifactCell
}

type appMCPArtifactDoc struct {
	Title       string
	Note        string // set when the read returned one page of a larger set
	GeneratedAt time.Time
	Sheets      []appMCPArtifactSheetData
}

func appMCPArtifactGroup(digits string) string {
	sign := ""
	if strings.HasPrefix(digits, "-") {
		sign, digits = "-", digits[1:]
	}
	var out strings.Builder
	for i, c := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(c)
	}
	return sign + out.String()
}

func appMCPArtifactDecimal(r *big.Rat, places int) string {
	text := r.FloatString(places)
	whole, fraction, _ := strings.Cut(text, ".")
	if fraction != "" {
		return appMCPArtifactGroup(whole) + "." + fraction
	}
	return appMCPArtifactGroup(whole)
}

var appMCPArtifactDateLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"}

func appMCPArtifactParseTime(text string) (time.Time, error) {
	for _, layout := range appMCPArtifactDateLayouts {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("not an ISO 8601 date or time")
}

// appMCPArtifactFormatCell types one value by its column format. A value that
// does not fit its declared format fails the artifact: a spreadsheet silently
// holding text where a number was promised is worse than no spreadsheet.
func appMCPArtifactFormatCell(value any, format string) (appMCPArtifactCell, error) {
	if value == nil {
		return appMCPArtifactCell{}, nil
	}
	switch format {
	case xlsxText:
		var text string
		switch v := value.(type) {
		case string:
			text = v
		case json.Number:
			text = v.String()
		case bool:
			text = map[bool]string{true: "Yes", false: "No"}[v]
		default:
			return appMCPArtifactCell{}, errors.New("a text column holds a string, number or boolean")
		}
		if !utf8.ValidString(text) || utf8.RuneCountInString(text) > mcpReadArtifactMaxCellChars {
			return appMCPArtifactCell{}, errors.New("a text value is invalid or too long")
		}
		return appMCPArtifactCell{Raw: text, Display: text}, nil
	case xlsxInteger, xlsxNumber, xlsxMoney, xlsxPercent:
		number, ok := appMCPExactNumber(value)
		if !ok || format == xlsxInteger && !number.IsInt() {
			return appMCPArtifactCell{}, fmt.Errorf("a %s column holds a finite %s", format, map[bool]string{true: "whole number", false: "number"}[format == xlsxInteger])
		}
		raw := ""
		switch v := value.(type) {
		case json.Number:
			raw = v.String()
		default:
			raw = strings.TrimRight(strings.TrimRight(number.FloatString(12), "0"), ".")
		}
		cell := appMCPArtifactCell{Raw: raw}
		switch format {
		case xlsxInteger:
			cell.Display = appMCPArtifactDecimal(number, 0)
		case xlsxMoney:
			cell.Display = appMCPArtifactDecimal(number, 2)
		case xlsxPercent:
			cell.Display = appMCPArtifactDecimal(new(big.Rat).Mul(number, big.NewRat(100, 1)), 2) + "%"
		default:
			display := number.FloatString(6)
			if strings.Contains(display, ".") {
				display = strings.TrimRight(strings.TrimRight(display, "0"), ".")
			}
			whole, fraction, _ := strings.Cut(display, ".")
			cell.Display = appMCPArtifactGroup(whole)
			if fraction != "" {
				cell.Display += "." + fraction
			}
		}
		return cell, nil
	case xlsxDate, xlsxDateTime:
		text, ok := value.(string)
		if !ok {
			return appMCPArtifactCell{}, fmt.Errorf("a %s column holds an ISO 8601 string", format)
		}
		parsed, err := appMCPArtifactParseTime(text)
		if err != nil {
			return appMCPArtifactCell{}, err
		}
		if format == xlsxDate {
			// The calendar day as written, not shifted by the offset.
			parsed = time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 0, 0, 0, 0, time.UTC)
		}
		serial, err := xlsxSerial(parsed)
		if err != nil {
			return appMCPArtifactCell{}, err
		}
		display := parsed.UTC().Format("2006-01-02")
		if format == xlsxDateTime {
			display = parsed.UTC().Format("2006-01-02 15:04") + " UTC"
		}
		return appMCPArtifactCell{Raw: serial, Display: display}, nil
	}
	return appMCPArtifactCell{}, fmt.Errorf("unknown column format %q", format)
}

// appMCPArtifactSourceRows picks a sheet's rows out of the tool's projected data.
func appMCPArtifactSourceRows(data any, source string) ([]map[string]any, error) {
	if source == "" {
		switch v := data.(type) {
		case []map[string]any:
			return v, nil
		case map[string]any:
			return []map[string]any{v}, nil
		}
		return nil, errors.New("tool data has an unexpected shape")
	}
	object, ok := data.(map[string]any)
	if !ok {
		return nil, errors.New("tool data has an unexpected shape")
	}
	switch v := object[source].(type) {
	case nil:
		return nil, nil
	case []map[string]any:
		return v, nil
	case []any:
		rows := make([]map[string]any, len(v))
		for i, item := range v {
			row, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("source %q holds a non-object row", source)
			}
			rows[i] = row
		}
		return rows, nil
	}
	return nil, fmt.Errorf("source %q is not an array", source)
}

// buildAppMCPArtifactDoc lays out the tool's data as its declaration says. The
// declaration was validated against the output schema when the manifest
// loaded and the data against the same schema when the read ran; the checks here
// are the budgets and the per-cell typing.
func buildAppMCPArtifactDoc(tool AppMCPTool, data any, generatedAt time.Time) (*appMCPArtifactDoc, error) {
	if tool.Artifact == nil {
		return nil, errors.New("tool declares no artifact")
	}
	doc := &appMCPArtifactDoc{Title: tool.Artifact.Title, GeneratedAt: generatedAt.UTC()}
	cells := 0
	for _, sheet := range tool.Artifact.Sheets {
		schema, err := appMCPArtifactSheetSchema(tool, sheet)
		if err != nil {
			return nil, err
		}
		rows, err := appMCPArtifactSourceRows(data, sheet.Source)
		if err != nil {
			return nil, err
		}
		if len(rows) > mcpReadArtifactMaxRows {
			return nil, fmt.Errorf("sheet %q has %d rows (limit %d)", sheet.Name, len(rows), mcpReadArtifactMaxRows)
		}
		if cells += len(rows) * len(sheet.Columns); cells > mcpReadArtifactMaxCells {
			return nil, fmt.Errorf("artifact exceeds %d cells", mcpReadArtifactMaxCells)
		}
		out := appMCPArtifactSheetData{Name: sheet.Name}
		for _, column := range sheet.Columns {
			format, err := appMCPArtifactColumnFormat(column, schema.Properties[column.Field])
			if err != nil {
				return nil, err
			}
			out.Columns = append(out.Columns, appMCPArtifactColumnData{Label: column.Label, Format: format})
		}
		for _, row := range rows {
			line := make([]appMCPArtifactCell, len(sheet.Columns))
			for i, column := range sheet.Columns {
				if line[i], err = appMCPArtifactFormatCell(row[column.Field], out.Columns[i].Format); err != nil {
					return nil, fmt.Errorf("sheet %q field %q: %w", sheet.Name, column.Field, err)
				}
			}
			out.Rows = append(out.Rows, line)
		}
		doc.Sheets = append(doc.Sheets, out)
	}
	return doc, nil
}

// ---- renderers ---------------------------------------------------------------

func renderAppMCPReadArtifactXLSX(doc *appMCPArtifactDoc) ([]byte, error) {
	sheets := make([]XLSXSheet, len(doc.Sheets))
	for i, sheet := range doc.Sheets {
		out := XLSXSheet{Name: sheet.Name, FreezeHeader: true, Formats: make([]string, len(sheet.Columns))}
		for j, column := range sheet.Columns {
			out.Headers = append(out.Headers, column.Label)
			out.Formats[j] = column.Format
		}
		for _, row := range sheet.Rows {
			line := make([]string, len(row))
			for j, cell := range row {
				line[j] = cell.Raw
			}
			out.Rows = append(out.Rows, line)
		}
		sheets[i] = out
	}
	return WriteXLSXSheets(sheets)
}

const appMCPReportCSS = `*{box-sizing:border-box}
@page{margin:14mm}
body{margin:0;background:#fff;color:#14161b;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.page{max-width:1000px;margin:0 auto;padding:32px 24px}
.top{display:flex;align-items:center;gap:14px;margin:0 0 24px;padding:0 0 16px;border-bottom:3px solid var(--primary)}
.mark{flex:none;display:grid;place-items:center;width:42px;height:42px;border-radius:11px;background:var(--primary);color:var(--on-primary);font-weight:700;font-size:20px;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.appname{font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#5a6270;overflow-wrap:anywhere}
h1{margin:0;font-size:24px;line-height:1.25;letter-spacing:-.02em;overflow-wrap:anywhere}
.meta{margin:2px 0 0;font-size:13px;color:#5a6270}
.note{margin:0 0 18px;padding:10px 14px;border:1px solid #e0c36b;border-radius:8px;background:#fff6dd;color:#6b4a00}
section{margin:0 0 28px}
h2{margin:0 0 8px;font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#5a6270}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:6px 10px;border-bottom:1px solid #e2e5ea;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f3f4f7;font-size:12px;font-weight:600;border-bottom:2px solid var(--primary);-webkit-print-color-adjust:exact;print-color-adjust:exact}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tbody tr:nth-child(even) td{background:#fafbfc}
.empty{color:#5a6270}
@media print{.page{max-width:none;padding:0}thead{display:table-header-group}tr{break-inside:avoid}h2{break-after:avoid}section{break-inside:auto}}`

type appMCPReportCell struct {
	Display string
	Numeric bool
}

type appMCPReportSheet struct {
	Name    string
	Columns []appMCPReportCell // Display is the label
	Rows    [][]appMCPReportCell
}

type appMCPReportView struct {
	App, Title, Note, Initial, GeneratedISO, GeneratedText string
	BaseCSS, ThemeCSS                                      template.CSS
	Sheets                                                 []appMCPReportSheet
}

func appMCPReportNumeric(format string) bool {
	return format != xlsxText && format != xlsxDate && format != xlsxDateTime
}

var appMCPReportHTML = template.Must(template.New("mcp-report").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><title>{{.Title}} - {{.App}}</title><style>{{.BaseCSS}}</style><style>{{.ThemeCSS}}</style></head>
<body><div class="page"><header class="top"><span class="mark" aria-hidden="true">{{.Initial}}</span><div><div class="appname">{{.App}}</div><h1>{{.Title}}</h1><p class="meta">Generated <time datetime="{{.GeneratedISO}}">{{.GeneratedText}}</time></p></div></header>
{{if .Note}}<p class="note">{{.Note}}</p>{{end}}
{{range .Sheets}}<section><h2>{{.Name}}</h2>{{if .Rows}}<table><thead><tr>{{range .Columns}}<th scope="col"{{if .Numeric}} class="n"{{end}}>{{.Display}}</th>{{end}}</tr></thead><tbody>{{range .Rows}}<tr>{{range .}}<td{{if .Numeric}} class="n"{{end}}>{{.Display}}</td>{{end}}</tr>{{end}}</tbody></table>{{else}}<p class="empty">No rows.</p>{{end}}</section>
{{end}}</div></body></html>
`))

// renderAppMCPReadArtifactHTML is the printable report: the app's name and
// theme colour (the same helpers as the connector pages, light scheme only so a
// printed or PDF copy never inherits a dark palette), the title, the generation
// time and one table per declared sheet. Every value is escaped by html/template
// and the document carries a no-network CSP.
func renderAppMCPReadArtifactHTML(app *App, doc *appMCPArtifactDoc) ([]byte, error) {
	theme := string(appMCPPageThemeCSS(app))
	light, _, _ := strings.Cut(theme, "@media")
	name := appSiteName(app)
	view := appMCPReportView{App: name, Title: doc.Title, Note: doc.Note, Initial: appMCPPageInitial(name),
		GeneratedISO: doc.GeneratedAt.Format(time.RFC3339), GeneratedText: doc.GeneratedAt.Format("2006-01-02 15:04 UTC"),
		BaseCSS: template.CSS(appMCPReportCSS), ThemeCSS: template.CSS(light)}
	for _, sheet := range doc.Sheets {
		out := appMCPReportSheet{Name: sheet.Name}
		for _, column := range sheet.Columns {
			out.Columns = append(out.Columns, appMCPReportCell{Display: column.Label, Numeric: appMCPReportNumeric(column.Format)})
		}
		for _, row := range sheet.Rows {
			line := make([]appMCPReportCell, len(row))
			for i, cell := range row {
				line[i] = appMCPReportCell{Display: cell.Display, Numeric: appMCPReportNumeric(sheet.Columns[i].Format)}
			}
			out.Rows = append(out.Rows, line)
		}
		view.Sheets = append(view.Sheets, out)
	}
	var out bytes.Buffer
	if err := appMCPReportHTML.Execute(&out, view); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ---- production ----------------------------------------------------------

func appMCPArtifactCompletenessNote(result *appMCPReadResult) string {
	page := result.Pagination
	if page == nil || result.Completeness.State == "complete" {
		return ""
	}
	rows, _ := result.Data.([]map[string]any)
	first := (page.Page-1)*page.PerPage + 1
	return fmt.Sprintf("Partial data: rows %d to %d of %d. Ask for the other pages to see the rest.", first, first+len(rows)-1, page.Total)
}

// createAppMCPReadArtifact formats a read result as the tool declared and stores
// it for the caller. It never reads data itself: result is what
// runAppMCPNativeReadGeneration validated and projected for this caller.
func createAppMCPReadArtifact(ctx context.Context, app *App, tool AppMCPTool, flow *Flow, actor *Session, kind string, result *appMCPReadResult) (appMCPArtifact, error) {
	var out appMCPArtifact
	if app == nil || tool.Artifact == nil || actor == nil || result == nil || !slices.Contains(tool.Artifact.Formats, kind) {
		return out, errors.New("invalid read artifact request")
	}
	doc, err := buildAppMCPArtifactDoc(tool, result.Data, time.Now())
	if err != nil {
		return out, err
	}
	doc.Note = appMCPArtifactCompletenessNote(result)
	var data []byte
	engine := "benmore-xlsx/2; " + runtime.Version()
	templateVersion := mcpReadArtifactTemplateVersion
	switch kind {
	case "xlsx":
		data, err = renderAppMCPReadArtifactXLSX(doc)
		templateVersion = "artifact-xlsx/1"
	case "html", "pdf":
		var html []byte
		if html, err = renderAppMCPReadArtifactHTML(app, doc); err != nil {
			return out, err
		}
		if kind == "html" {
			data, engine = html, mcpReadArtifactTemplateVersion+"; "+runtime.Version()
			break
		}
		if engine, err = appMCPArtifactChromeVersion(ctx); err != nil {
			return out, err
		}
		data, err = renderAppMCPArtifactPDF(ctx, app, html)
	}
	if err != nil {
		return out, err
	}
	if len(data) == 0 || len(data) > mcpReadArtifactMaxBytes {
		return out, fmt.Errorf("artifact exceeds %d bytes", mcpReadArtifactMaxBytes)
	}
	var ownerCreatedAt string
	if err := app.DB.QueryRowContext(ctx, "SELECT COALESCE(created_at,'') FROM _benmore_users WHERE id=?", actor.UserID).Scan(&ownerCreatedAt); err != nil || ownerCreatedAt == "" {
		return out, errors.New("artifact owner account is unavailable")
	}
	// Retrieval requires every scope that let this read run: the tool's own and,
	// for a flow tool, the flow's; and the role the flow demands, else the caller's.
	scopes, role := slices.Clone(tool.Permissions), actor.Role
	if flow != nil {
		scopes = append(scopes, flow.Permissions...)
		if flow.Role != "" {
			role = flow.Role
		}
	}
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	encoded, err := json.Marshal(result.Data)
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(encoded)
	return storeAppMCPArtifact(ctx, app, actor.UserID, ownerCreatedAt, actor.GroupID, role, scopes, mcpReadArtifactOperationPrefix+tool.Name, kind, data,
		hex.EncodeToString(sum[:]), result.SourceRevisions, engine, templateVersion, true)
}

// appMCPRegisterReadArtifactTool exposes artifact.create when at least one read
// tool this caller may run declares an artifact. The model names the tool, the
// format and the tool's normal arguments; the framework re-runs that read
// through the same gates as a direct call, so nothing here widens what the
// caller could already read.
func appMCPRegisterReadArtifactTool(server *sdk.Server, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session, raw, resource string) {
	if server == nil || app == nil || generation == nil || generation.manifest == nil || generation.view == nil || grant == nil || actor == nil {
		return
	}
	eligible := map[string]AppMCPTool{}
	for _, declared := range generation.manifest.Tools {
		if declared.Name == mcpArtifactCreateTool {
			return // A reviewed declaration owns this name; never collide at registration.
		}
		tool := declared
		permissions := strings.Join(tool.Permissions, " ")
		if tool.Artifact != nil && appMCPToolAllowed(generation.view, &tool, actor) && scopesWithin(grant.Scopes, permissions) {
			eligible[tool.Name] = tool
		}
	}
	if len(eligible) == 0 {
		return
	}
	names := make([]string, 0, len(eligible))
	for name := range eligible {
		names = append(names, name)
	}
	sort.Strings(names)
	enum := make([]any, len(names))
	menu := make([]string, len(names))
	for i, name := range names {
		enum[i] = name
		menu[i] = name + " (" + strings.Join(eligible[name].Artifact.Formats, ", ") + ")"
	}
	formats := []any{"xlsx", "html", "pdf"}
	no := false
	input := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tool", "format"}, "properties": map[string]any{
		"tool":      map[string]any{"type": "string", "enum": enum},
		"format":    map[string]any{"type": "string", "enum": formats},
		"arguments": map[string]any{"type": "object", "description": "The arguments you would pass to that tool; omit when it takes none."},
	}}
	server.AddTool(&sdk.Tool{Name: mcpArtifactCreateTool,
		Description: "Create an immutable spreadsheet (xlsx), printable report (html) or PDF from one of the read tools below, which is re-run with your authority and formatted exactly as the app's reviewed layout says. Tools: " + strings.Join(menu, "; ") +
			". A list tool yields one page of rows; read_completeness reports whether it was all of them. The user downloads the file from download_url in their own signed-in browser.",
		InputSchema: input, OutputSchema: appMCPClosedObject(map[string]any{
			"artifact_id":       map[string]any{"type": "string", "maxLength": 128},
			"kind":              map[string]any{"type": "string", "enum": formats},
			"sha256":            map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
			"size":              map[string]any{"type": "integer", "minimum": 1, "maximum": mcpReadArtifactMaxBytes},
			"download_url":      map[string]any{"type": "string", "maxLength": 2048},
			"read_completeness": map[string]any{"type": "string", "enum": []any{"complete", "partial", "indeterminate"}},
		}), Annotations: &sdk.ToolAnnotations{DestructiveHint: &no, OpenWorldHint: &no}},
		func(ctx context.Context, call *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			args, ok := appMCPDecodeToolArguments(call.Params.Arguments)
			name, nameOK := args["tool"].(string)
			kind, kindOK := args["format"].(string)
			readInput := map[string]any{}
			if given, present := args["arguments"]; present {
				if readInput, ok = given.(map[string]any); !ok {
					return appMCPSDKFailure(appMCPResultFailure("invalid_input")), nil
				}
			}
			for key := range args {
				if key != "tool" && key != "format" && key != "arguments" {
					ok = false
				}
			}
			if !ok || !nameOK || !kindOK || !appMCPArtifactFormatKnown(kind) {
				return appMCPSDKFailure(appMCPResultFailure("invalid_input")), nil
			}
			tool, found := eligible[name]
			if !found || !slices.Contains(tool.Artifact.Formats, kind) {
				return appMCPSDKFailure(appMCPResultFailure("denied")), nil
			}
			limitKey := fmt.Sprintf("user:%d", actor.UserID)
			if !mcpReadArtifactLimiter.Allow(appLimiterKey(app, "mcp-artifact", limitKey)) || kind == "pdf" && !pdfLimiter.Allow(appLimiterKey(app, "pdf", limitKey)) {
				return appMCPSDKFailure(appMCPResultFailure("operation_limit")), nil
			}
			result, err := runAppMCPNativeReadGeneration(ctx, app, generation, raw, resource, tool.Name, readInput)
			if err != nil {
				return appMCPSDKFailure(err), nil
			}
			// Bind the artifact to the authority in force now, not at registration.
			_, current, err := resolveAppMCPAccessForGeneration(ctx, app, generation, raw, resource, time.Now())
			if err != nil || !appMCPAuthorityUnchanged(actor, current) || !appMCPToolAllowed(generation.view, &tool, current) {
				return appMCPSDKFailure(appMCPResultFailure("denied")), nil
			}
			var flow *Flow
			if tool.Handler.Operation == "flow.call" {
				flow = appMCPFlowSnapshot(generation.view, tool.Handler.Flow)
			}
			artifact, err := createAppMCPReadArtifact(ctx, app, tool, flow, current, kind, result)
			if err != nil {
				log.Printf("MCP artifact.create %s (%s): %v", tool.Name, kind, err) // layout and budget text only, never a value
				code := "incomplete_result"
				if strings.Contains(err.Error(), "PDF") {
					code = "unavailable_provider"
				}
				return appMCPSDKFailure(appMCPResultFailure(code)), nil
			}
			return appMCPCommandResult(map[string]any{"artifact_id": artifact.ID, "kind": artifact.Kind, "sha256": artifact.SHA256, "size": artifact.Size,
				"download_url": appMCPOAuthOrigin(resource) + "/api/_mcp/artifacts/" + artifact.ID, "read_completeness": result.Completeness.State}), nil
		})
}

func appMCPReadArtifactExpired(createdAt string, now time.Time) bool {
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	return err != nil || now.Sub(created) > mcpReadArtifactTTL
}

// appMCPReadArtifactStillAllowed is the retrieval-time check specific to a read
// artifact, on top of owner, tenant, role and scopes: it must be inside its
// TTL, the current reviewed manifest must still declare the producing tool with
// an artifact in this format, and for a table tool the caller's current access
// rule for that table (member-of, owner_or_role, role, ...) must still admit a
// read, so a user who lost access to the data cannot keep downloading an earlier
// snapshot. Row-level ACLs are not re-run; the TTL bounds that.
func appMCPReadArtifactStillAllowed(app *App, session *Session, artifact appMCPArtifact, now time.Time) bool {
	if appMCPReadArtifactExpired(artifact.CreatedAt, now) {
		return false
	}
	tool := appMCPReadTool(app, strings.TrimPrefix(artifact.OperationID, mcpReadArtifactOperationPrefix))
	if tool == nil || tool.Artifact == nil || !slices.Contains(tool.Artifact.Formats, artifact.Kind) {
		return false
	}
	if tool.Handler.Operation == "table.list" || tool.Handler.Operation == "table.read" {
		return SessionCanAccessTable(app, tool.Handler.Table, OpRead, session)
	}
	return true
}
