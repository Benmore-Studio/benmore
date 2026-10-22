//go:build !cli && !windows

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// pinnedPlainManifestDigest is the contract digest of readArtifactPlainManifest
// computed by the code BEFORE the artifact field existed. A manifest that
// declares no artifact must keep it, or every reviewed connector would need a
// fresh review.
const pinnedPlainManifestDigest = "7a519c9e4bcdf5560c9b3c4bc6c940a763df6e2a7ed3815113b4ca31e9b4765a"

const readArtifactPlainManifest = `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
execution_digest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
tools:
  - name: list_notes
    description: List notes
    handler: {kind: native, operation: table.list, table: notes}
    input_schema: {type: object, additionalProperties: false, properties: {}}
    output_schema:
      type: object
      additionalProperties: false
      required: [id, title]
      properties:
        id: {type: integer}
        title: {type: string}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, title]}
    component: none
resources: []
connections: []
`

func TestAppMCPArtifactDeclarationKeepsOldContractDigest(t *testing.T) {
	plain, err := decodeAppMCPManifest([]byte(readArtifactPlainManifest))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := appMCPContractDigest(plain)
	if err != nil || digest != pinnedPlainManifestDigest {
		t.Fatalf("a manifest with no artifact changed digest: %s (%v), want %s", digest, err, pinnedPlainManifestDigest)
	}
	declared, err := decodeAppMCPManifest([]byte(readArtifactPlainManifest))
	if err != nil {
		t.Fatal(err)
	}
	declared.Tools[0].Artifact = &AppMCPArtifactDecl{Title: "Notes", Formats: []string{"xlsx"}, Sheets: []AppMCPArtifactSheet{{Name: "Notes", Columns: []AppMCPArtifactColumn{{Field: "id", Label: "Id"}}}}}
	changed, err := appMCPContractDigest(declared)
	if err != nil || changed == digest {
		t.Fatalf("an artifact layout is reviewed content and must change the digest: %s (%v)", changed, err)
	}
	declared.Tools[0].Artifact.Sheets[0].Columns[0].Label = "Note id"
	if relabelled, _ := appMCPContractDigest(declared); relabelled == changed {
		t.Fatal("a changed column label did not change the digest")
	}
}

// readArtifactYAML is the manifest the end-to-end tests load: one flow tool with
// a 2-sheet layout (a one-row summary and an array), one table.list tool with a
// layout, and one list tool that declares none.
func readArtifactYAML() string {
	return `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: ` + strings.Repeat("a", 64) + `
execution_digest: ` + strings.Repeat("b", 64) + `
tools:
  - name: forecast
    description: Forecast notes
    handler: {kind: native, operation: flow.call, flow: forecast}
    input_schema: {type: object, additionalProperties: false, properties: {}}
    output_schema:
      type: object
      additionalProperties: false
      required: [project, total, notes]
      properties:
        project: {type: string}
        total: {type: number}
        notes:
          type: array
          maxItems: 1000
          items:
            type: object
            additionalProperties: false
            required: [id, title, amount, rate, noted_at]
            properties:
              id: {type: integer}
              title: {type: string}
              amount: {type: number}
              rate: {type: number}
              noted_at: {type: string}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [project, total, notes]}
    component: none
    artifact:
      title: Cash-flow forecast
      formats: [xlsx, html, pdf]
      sheets:
        - name: Summary
          columns:
            - {field: project, label: Project}
            - {field: total, label: Total (USD), format: money}
        - name: Notes
          source: notes
          columns:
            - {field: id, label: Id}
            - {field: title, label: Title}
            - {field: amount, label: Amount (USD), format: money}
            - {field: rate, label: Rate, format: percent}
            - {field: noted_at, label: Noted on, format: date}
  - name: list_notes
    description: List notes
    handler: {kind: native, operation: table.list, table: notes}
    input_schema:
      type: object
      additionalProperties: false
      properties:
        page: {type: integer, minimum: 1}
        per_page: {type: integer, minimum: 1, maximum: 500}
    output_schema:
      type: object
      additionalProperties: false
      required: [id, title]
      properties:
        id: {type: integer}
        title: {type: string}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, title]}
    component: none
    artifact:
      title: Notes
      formats: [xlsx, html]
      sheets:
        - name: Notes
          columns:
            - {field: id, label: Id}
            - {field: title, label: Title}
  - name: plain_notes
    description: List notes without an artifact
    handler: {kind: native, operation: table.list, table: notes}
    input_schema: {type: object, additionalProperties: false, properties: {}}
    output_schema:
      type: object
      additionalProperties: false
      required: [id]
      properties:
        id: {type: integer}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id]}
    component: none
resources: []
connections: []
`
}

const readArtifactFlow = `on:
  request:
    method: GET
    path: /api/mcp-forecast
    auth: required
    role: editor
    permissions: [notes:read]
jobs:
  forecast:
    steps:
      - id: notes
        query: SELECT id, title, id * 1000.5 AS amount, 0.0525 AS rate, '2026-10-14T09:30:00Z' AS noted_at FROM notes WHERE user_id = :user_id ORDER BY id
      - id: sum
        query: SELECT COALESCE(SUM(id * 1000.5), 0) AS total FROM notes WHERE user_id = :user_id
      - run: respond
        with:
          body:
            project: Solar One
            total: ${{ steps.sum.outputs.rows[0].total }}
            notes: ${{ steps.notes.outputs.rows }}
`

type readArtifactEnv struct {
	t        *testing.T
	app      *App
	uid      int64
	cookie   string
	resource string
	token    string
	client   *sdk.ClientSession
}

func newReadArtifactEnv(t *testing.T, yaml string) *readArtifactEnv {
	t.Helper()
	app, uid, _ := appMCPGrantFixture(t)
	writeTestFile(t, app.Dir, "flows/forecast.yaml", readArtifactFlow)
	writeTestFile(t, app.Dir, "mcp.yaml", yaml)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatalf("load reviewed manifest: %v", err)
	}
	app.MCP, app.Flows, app.sourceFiles = config.mcp, config.flows, config.sourceFiles
	app.DB.SetMaxOpenConns(1)
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'=SUM(1,2)'),(2,?,'<script>alert(1)</script>'),(3,999,'foreign-secret')", uid, uid)
	e := &readArtifactEnv{t: t, app: app, uid: uid}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveAppMCP(w, r, app, e.resource) }))
	t.Cleanup(server.Close)
	e.resource = server.URL + "/api/_mcp"
	pair, err := createAppMCPGrant(app, uid, "17", "client-fixture", e.resource, "notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.token = pair.AccessToken
	e.client = appMCPClient(t, server, pair.AccessToken, nil)
	e.cookie = CreateSession(app.DB, uid, "delegate@example.com", "17", time.Hour)
	return e
}

// create calls artifact.create and returns the structured result or the
// connector error code.
func (e *readArtifactEnv) create(args map[string]any) (map[string]any, string) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := e.client.CallTool(ctx, &sdk.CallToolParams{Name: mcpArtifactCreateTool, Arguments: args})
	if err != nil {
		return nil, "protocol:" + err.Error()
	}
	if result.IsError {
		code, _ := result.Meta["error_code"].(string)
		return nil, code
	}
	out, _ := result.StructuredContent.(map[string]any)
	return out, ""
}

func (e *readArtifactEnv) download(id string) []byte {
	e.t.Helper()
	status, body := mcpArtifactGet(e.t, e.app, id, e.cookie)
	if status != http.StatusOK {
		e.t.Fatalf("download %s: status %d: %s", id, status, body)
	}
	return body
}

func zipPart(t *testing.T, data []byte, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			return string(b)
		}
	}
	t.Fatalf("no %s in workbook", name)
	return ""
}

func TestAppMCPReadArtifactXLSXHasDeclaredSheetsHeadersAndTypedValues(t *testing.T) {
	e := newReadArtifactEnv(t, readArtifactYAML())
	out, code := e.create(map[string]any{"tool": "forecast", "format": "xlsx"})
	if code != "" {
		t.Fatalf("artifact.create: %s", code)
	}
	id, _ := out["artifact_id"].(string)
	wantURL := strings.TrimSuffix(e.resource, "/api/_mcp") + "/api/_mcp/artifacts/" + id
	if id == "" || out["kind"] != "xlsx" || out["download_url"] != wantURL || out["read_completeness"] != "indeterminate" {
		t.Fatalf("result = %#v, want download_url %s", out, wantURL)
	}
	data := e.download(id)
	res, err := IngestXLSX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if err != nil || !res.Complete {
		t.Fatalf("the in-tree reader cannot open the workbook: complete=%t err=%v", res.Complete, err)
	}
	if len(res.Sheets) != 2 || res.Sheets[0].Name != "Summary" || res.Sheets[1].Name != "Notes" {
		t.Fatalf("sheets = %+v, want Summary then Notes", res.Sheets)
	}
	cell := func(sheet, ref string) SourceBlock {
		for _, b := range res.Blocks {
			if b.Sheet == sheet && b.Ref == ref {
				return b
			}
		}
		t.Fatalf("no cell %s!%s", sheet, ref)
		return SourceBlock{}
	}
	for ref, want := range map[string]string{"A1": "Project", "B1": "Total (USD)", "A2": "Solar One"} {
		if got := cell("Summary", ref).Value; got != want {
			t.Errorf("Summary!%s = %q, want %q", ref, got, want)
		}
	}
	for ref, want := range map[string]string{"A1": "Id", "B1": "Title", "C1": "Amount (USD)", "D1": "Rate", "E1": "Noted on"} {
		if got := cell("Notes", ref).Value; got != want {
			t.Errorf("Notes!%s = %q, want %q", ref, got, want)
		}
	}
	if total := cell("Summary", "B2"); total.Value != "3001.5" || total.Type != "number" || total.NumFmt == "" {
		t.Errorf("money cell = %+v, want 3001.5 typed number with a number format", total)
	}
	if id := cell("Notes", "A3"); id.Value != "2" || id.Type != "number" {
		t.Errorf("integer cell = %+v", id)
	}
	if amount := cell("Notes", "C3"); amount.Value != "2001" || amount.NumFmt == "" {
		t.Errorf("amount cell = %+v", amount)
	}
	if rate := cell("Notes", "D2"); rate.Value != "0.0525" || !strings.Contains(rate.NumFmt, "%") && rate.NumFmt != "builtin:10" && rate.NumFmt != "0.00%" {
		t.Errorf("percent cell = %+v, want the 0.0525 fraction under a percent format", rate)
	}
	if date := cell("Notes", "E2"); !strings.HasPrefix(date.Value, "2026-10-14") {
		t.Errorf("date cell = %+v, want 2026-10-14", date)
	}
	// Text stays text, and a formula-shaped value is neutralized.
	if title := cell("Notes", "B2"); title.Type == "number" || strings.HasPrefix(title.Value, "=") {
		t.Errorf("title cell = %+v, want inert text", title)
	}
	if strings.Contains(string(data), "foreign-secret") {
		t.Fatal("another user's row reached the workbook")
	}
	sheet := zipPart(t, data, "xl/worksheets/sheet2.xml")
	for _, want := range []string{`state="frozen"`, `ySplit="1"`, `<c r="C2" s="3"><v>1000.5</v></c>`, `<c r="D2" s="4"><v>0.0525</v></c>`, `<c r="E2" s="5"><v>46309</v></c>`} {
		if !strings.Contains(sheet, want) {
			t.Errorf("sheet XML lacks %s:\n%s", want, sheet)
		}
	}
	if strings.Index(sheet, "<sheetViews>") > strings.Index(sheet, "<sheetData>") {
		t.Error("sheetViews must precede sheetData")
	}
	var recordedOperation, templateVersion, scopes, role string
	if err := e.app.DB.QueryRow(`SELECT operation_id,template_version,required_scopes,required_role FROM _benmore_mcp_artifacts WHERE id=?`, id).Scan(&recordedOperation, &templateVersion, &scopes, &role); err != nil {
		t.Fatal(err)
	}
	if recordedOperation != "read:forecast" || scopes != `["notes:read"]` || role != "editor" {
		t.Fatalf("manifest provenance operation=%q template=%q scopes=%s role=%s", recordedOperation, templateVersion, scopes, role)
	}
}

func TestAppMCPReadArtifactTableListAndPartialCompleteness(t *testing.T) {
	e := newReadArtifactEnv(t, readArtifactYAML())
	out, code := e.create(map[string]any{"tool": "list_notes", "format": "html", "arguments": map[string]any{"page": 1, "per_page": 1}})
	if code != "" {
		t.Fatalf("artifact.create: %s", code)
	}
	if out["read_completeness"] != "partial" {
		t.Fatalf("one page of two rows must be reported partial: %#v", out)
	}
	html := string(e.download(out["artifact_id"].(string)))
	for _, want := range []string{"Partial data: rows 1 to 1 of 2", "<h2>Notes</h2>", "Benmore app", "Generated"} {
		if !strings.Contains(html, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(html, "script>alert") || strings.Contains(html, "foreign-secret") {
		t.Fatal("report holds a foreign row or an unescaped value")
	}
	// The complete read says so.
	if out, code = e.create(map[string]any{"tool": "list_notes", "format": "xlsx"}); code != "" || out["read_completeness"] != "complete" {
		t.Fatalf("complete list: code=%q out=%#v", code, out)
	}
}

func TestAppMCPReadArtifactHTMLReportIsBrandedPrintableAndEscaped(t *testing.T) {
	app := &App{Design: &DesignConfig{SEO: map[string]string{"site_name": `Example <Solar>`}, Colors: map[string]string{"_brand": "#0a7d4b"}}}
	doc := &appMCPArtifactDoc{Title: `Pipeline <script>alert(1)</script>`, GeneratedAt: time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC), Note: `<b>note</b>`,
		Sheets: []appMCPArtifactSheetData{{Name: "Leads", Columns: []appMCPArtifactColumnData{{Label: `<img src=x onerror=alert(1)>`, Format: "text"}, {Label: "Value", Format: "money"}},
			Rows: [][]appMCPArtifactCell{{{Raw: `<script>row</script>`, Display: `<script>row</script>`}, {Raw: "1234.5", Display: "1,234.50"}}}}, {Name: "Empty", Columns: []appMCPArtifactColumnData{{Label: "A", Format: "text"}}}}}
	html, err := renderAppMCPReadArtifactHTML(app, doc)
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	for _, bad := range []string{"<script>", "<img", "<b>note"} {
		if strings.Contains(text, bad) {
			t.Fatalf("unescaped %q in report:\n%s", bad, text)
		}
	}
	for _, want := range []string{"Example &lt;Solar&gt;", "Pipeline &lt;script&gt;", "&lt;script&gt;row&lt;/script&gt;", "#0a7d4b", "Generated", "2026-10-14 09:30 UTC", `<td class="n">1,234.50</td>`, "No rows.", "@media print", "Content-Security-Policy", "default-src 'none'"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(text, "prefers-color-scheme") {
		t.Error("a printed report must not carry the dark palette")
	}
}

func TestAppMCPReadArtifactRefusesUndeclaredToolAndFormat(t *testing.T) {
	e := newReadArtifactEnv(t, readArtifactYAML())
	// plain_notes is a reviewed read tool, but declares no artifact: it is not in
	// the enum and the handler refuses it anyway.
	if _, code := e.create(map[string]any{"tool": "plain_notes", "format": "xlsx"}); code == "" {
		t.Fatal("an undeclared read tool produced an artifact")
	}
	// list_notes declares xlsx and html only.
	if _, code := e.create(map[string]any{"tool": "list_notes", "format": "pdf"}); code != "denied" {
		t.Fatalf("an undeclared format: code=%q, want denied", code)
	}
	if _, code := e.create(map[string]any{"tool": "forecast", "format": "xlsx", "layout": "x"}); code == "" {
		t.Fatal("a model-supplied extra argument was accepted")
	}
	if _, code := e.create(map[string]any{"tool": "forecast", "format": "xlsx", "arguments": map[string]any{"sheets": "x"}}); code != "invalid_input" {
		t.Fatalf("an argument the read tool does not accept: code=%q, want invalid_input", code)
	}
	var count int
	if err := ensureAppMCPArtifactTables(e.app.DB); err != nil {
		t.Fatal(err)
	}
	if err := e.app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_artifacts`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("refused calls stored %d artifacts (%v)", count, err)
	}
}

func TestAppMCPReadArtifactNotOfferedWithoutDeclarationOrScope(t *testing.T) {
	// No declared artifact: the companion tool is not even listed.
	e := newReadArtifactEnv(t, readArtifactPlainManifest2())
	listed, err := e.client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range listed.Tools {
		if tool.Name == mcpArtifactCreateTool {
			t.Fatal("artifact.create listed for a manifest that declares no artifact")
		}
	}
	e = newReadArtifactEnv(t, readArtifactYAML())
	if listed, err = e.client.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range listed.Tools {
		found = found || tool.Name == mcpArtifactCreateTool
	}
	if !found {
		t.Fatal("artifact.create is not listed for a declared read tool")
	}
}

// readArtifactPlainManifest2 is readArtifactYAML without any artifact block.
func readArtifactPlainManifest2() string {
	y := readArtifactYAML()
	for _, block := range []string{"    artifact:\n      title: Cash-flow forecast", "    artifact:\n      title: Notes"} {
		i := strings.Index(y, block)
		j := strings.Index(y[i+1:], "\n  - name:")
		if j < 0 {
			j = strings.Index(y[i:], "resources:") - 1
		} else {
			j++
		}
		y = y[:i] + y[i+1+j:]
	}
	return y
}

func TestAppMCPReadArtifactRetrievalStaysBoundToOwnerTenantAndScopes(t *testing.T) {
	e := newReadArtifactEnv(t, readArtifactYAML())
	out, code := e.create(map[string]any{"tool": "forecast", "format": "xlsx"})
	if code != "" {
		t.Fatal(code)
	}
	id := out["artifact_id"].(string)
	// Another user in the same tenant.
	other := createCrudScopeSession(t, e.app, "other-reader@example.com", "editor", "17", "")
	if status, _ := mcpArtifactGet(t, e.app, id, other); status != http.StatusNotFound {
		t.Fatalf("another user status = %d", status)
	}
	// The owner, signed in to another tenant.
	elsewhere := CreateSession(e.app.DB, e.uid, "delegate@example.com", "29", time.Hour)
	if status, _ := mcpArtifactGet(t, e.app, id, elsewhere); status != http.StatusNotFound {
		t.Fatalf("another tenant status = %d", status)
	}
	// The connector credential is not a browser session.
	mux := http.NewServeMux()
	registerAppMCPArtifactRoutes(mux, e.app)
	req := httptest.NewRequest(http.MethodGet, "/api/_mcp/artifacts/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+e.token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("connector bearer status = %d", rec.Code)
	}
	// Removing the scope the producing tool required blocks the owner too.
	if status, _ := mcpArtifactGet(t, e.app, id, e.cookie); status != http.StatusOK {
		t.Fatalf("owner status = %d", status)
	}
	roles := e.app.Roles.Roles["editor"]
	e.app.Roles.Roles["editor"] = RoleDef{Scopes: "other:read"}
	if status, _ := mcpArtifactGet(t, e.app, id, e.cookie); status != http.StatusNotFound {
		t.Fatalf("owner after scope removal status = %d", status)
	}
	e.app.Roles.Roles["editor"] = roles
	if status, _ := mcpArtifactGet(t, e.app, id, e.cookie); status != http.StatusOK {
		t.Fatalf("owner after scope restored status = %d", status)
	}
}

func TestAppMCPReadArtifactLimits(t *testing.T) {
	t.Run("rate", func(t *testing.T) {
		e := newReadArtifactEnv(t, readArtifactYAML())
		previous, previousPDF := mcpReadArtifactLimiter, pdfLimiter
		mcpReadArtifactLimiter = NewRateLimiter(1, time.Hour)
		pdfLimiter = NewRateLimiter(1, time.Hour)
		t.Cleanup(func() { mcpReadArtifactLimiter, pdfLimiter = previous, previousPDF })
		if _, code := e.create(map[string]any{"tool": "list_notes", "format": "xlsx"}); code != "" {
			t.Fatalf("first artifact: %s", code)
		}
		if _, code := e.create(map[string]any{"tool": "list_notes", "format": "xlsx"}); code != "operation_limit" {
			t.Fatalf("second artifact past the per-user budget: code=%q, want operation_limit", code)
		}
		// A PDF also draws from the shared PDF budget, before any read or render.
		mcpReadArtifactLimiter = NewRateLimiter(100, time.Hour)
		if !pdfLimiter.Allow(appLimiterKey(e.app, "pdf", fmt.Sprintf("user:%d", e.uid))) {
			t.Fatal("fresh PDF budget refused")
		}
		if _, code := e.create(map[string]any{"tool": "forecast", "format": "pdf"}); code != "operation_limit" {
			t.Fatalf("PDF past the shared budget: code=%q, want operation_limit", code)
		}
	})
	t.Run("rows cells and value", func(t *testing.T) {
		tool := AppMCPTool{Handler: AppMCPHandler{Kind: "native", Operation: "table.list"}, OutputSchema: &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{"n": {Type: "integer"}, "s": {Type: "string"}}},
			Artifact: &AppMCPArtifactDecl{Title: "T", Formats: []string{"xlsx"}, Sheets: []AppMCPArtifactSheet{{Name: "A", Columns: []AppMCPArtifactColumn{{Field: "n", Label: "N"}, {Field: "s", Label: "S"}}}, {Name: "B", Columns: []AppMCPArtifactColumn{{Field: "n", Label: "N"}}}}}}
		rows := func(n int) []map[string]any {
			out := make([]map[string]any, n)
			for i := range out {
				out[i] = map[string]any{"n": json.Number("1"), "s": "x"}
			}
			return out
		}
		if _, err := buildAppMCPArtifactDoc(tool, rows(mcpReadArtifactMaxRows), time.Now()); err != nil {
			t.Fatalf("rows at the limit refused: %v", err)
		}
		if _, err := buildAppMCPArtifactDoc(tool, rows(mcpReadArtifactMaxRows+1), time.Now()); err == nil {
			t.Fatal("rows past the per-sheet limit accepted")
		}
		// Every sheet of a table.list tool reads the same rows, so the whole-artifact cell budget binds.
		wide := make([]AppMCPArtifactColumn, 8)
		for i := range wide {
			wide[i] = AppMCPArtifactColumn{Field: "n", Label: "N"}
		}
		tool.Artifact.Sheets = []AppMCPArtifactSheet{{Name: "A", Columns: wide}, {Name: "B", Columns: wide}, {Name: "C", Columns: wide}}
		if _, err := buildAppMCPArtifactDoc(tool, rows(mcpReadArtifactMaxRows), time.Now()); err == nil {
			t.Fatal("cells past the artifact limit accepted")
		}
		tool.Artifact.Sheets = []AppMCPArtifactSheet{{Name: "A", Columns: []AppMCPArtifactColumn{{Field: "n", Label: "N"}, {Field: "s", Label: "S"}}}}
		long := []map[string]any{{"n": json.Number("1"), "s": strings.Repeat("x", mcpReadArtifactMaxCellChars+1)}}
		if _, err := buildAppMCPArtifactDoc(tool, long, time.Now()); err == nil {
			t.Fatal("an oversized cell accepted")
		}
	})
	t.Run("storage ring", func(t *testing.T) {
		e := newReadArtifactEnv(t, readArtifactYAML())
		var createdAt string
		if err := e.app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, e.uid).Scan(&createdAt); err != nil {
			t.Fatal(err)
		}
		store := func(operation string, budgeted bool, data string) appMCPArtifact {
			a, err := storeAppMCPArtifact(context.Background(), e.app, e.uid, createdAt, "17", "editor", []string{"notes:read"}, operation, "html", []byte(data), "digest", nil, "test", "test/1", budgeted)
			if err != nil {
				t.Fatal(err)
			}
			return a
		}
		command := store("0123456789abcdef0123456789abcdef", false, "a committed command receipt")
		var first appMCPArtifact
		for i := 0; i < mcpReadArtifactKeepPerUser+3; i++ {
			a := store("read:list_notes", true, fmt.Sprintf("report %d", i))
			if i == 0 {
				first = a
			}
			time.Sleep(0) // created_at has nanosecond resolution; ordering is by it
		}
		var reads, commands int
		if err := e.app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_artifacts WHERE operation_id LIKE 'read:%'`).Scan(&reads); err != nil {
			t.Fatal(err)
		}
		if err := e.app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_artifacts WHERE id=?`, command.ID).Scan(&commands); err != nil {
			t.Fatal(err)
		}
		if reads != mcpReadArtifactKeepPerUser || commands != 1 {
			t.Fatalf("after %d creates: %d read artifacts (want %d), command artifact kept=%d", mcpReadArtifactKeepPerUser+3, reads, mcpReadArtifactKeepPerUser, commands)
		}
		if artifactBytesExist(t, e.app, first) {
			t.Fatal("an evicted artifact kept its stored bytes")
		}
		if !artifactBytesExist(t, e.app, command) {
			t.Fatal("eviction deleted a command artifact")
		}
		// The byte budget evicts the oldest too: one artifact that nearly fills it leaves room for no other.
		tx, err := e.app.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		refs, err := evictAppMCPReadArtifacts(context.Background(), tx, e.uid, mcpReadArtifactBytesPerUser)
		if err != nil || len(refs) != mcpReadArtifactKeepPerUser {
			t.Fatalf("a full-budget artifact evicted %d (%v), want all %d", len(refs), err, mcpReadArtifactKeepPerUser)
		}
		_ = tx.Rollback()
	})
}

func TestAppMCPReadArtifactByteBudgetEvictsOldestFirst(t *testing.T) {
	e := newReadArtifactEnv(t, readArtifactYAML())
	if err := ensureAppMCPArtifactTables(e.app.DB); err != nil {
		t.Fatal(err)
	}
	// Inserted oldest to newest: 1 MiB, 20 MiB, 100 MiB; a new 16 MiB artifact
	// leaves room for 112 MiB of the 128 MiB budget. The 20 MiB one is the first
	// that does not fit, so it AND the older 1 MiB go, though the 1 MiB would fit.
	const mib = 1 << 20
	for i, size := range []int64{1 * mib, 20 * mib, 100 * mib} {
		_, err := e.app.DB.Exec(`INSERT INTO _benmore_mcp_artifacts(id,owner_user_id,owner_created_at,tenant,kind,content_sha256,size,storage_ref,source_bundle_digest,source_revisions,template_version,engine_version,created_at,operation_id,required_role,required_scopes)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, fmt.Sprintf("a%d", i), e.uid, "x", "17", "html", strings.Repeat("a", 64), size, fmt.Sprintf("uploads/private/mcp-artifacts/artifact_%064d.html", i), "d", "{}", "t", "e", time.Now().UTC().Format(time.RFC3339Nano), "read:list_notes", "editor", `["notes:read"]`)
		if err != nil {
			t.Fatal(err)
		}
	}
	tx, err := e.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	refs, err := evictAppMCPReadArtifacts(context.Background(), tx, e.uid, 16*mib)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := tx.Query(`SELECT id FROM _benmore_mcp_artifacts ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		left = append(left, id)
	}
	rows.Close()
	if len(refs) != 2 || len(left) != 1 || left[0] != "a2" {
		t.Fatalf("evicted %d refs, left %v; want the 20 MiB and the older 1 MiB gone and only the newest 100 MiB kept", len(refs), left)
	}
}

func TestAppMCPReadArtifactExpiresAndRechecksTableAccess(t *testing.T) {
	e := newReadArtifactEnv(t, readArtifactYAML())
	out, code := e.create(map[string]any{"tool": "list_notes", "format": "xlsx"})
	if code != "" {
		t.Fatal(code)
	}
	id := out["artifact_id"].(string)
	get := func() int { status, _ := mcpArtifactGet(t, e.app, id, e.cookie); return status }
	if get() != http.StatusOK {
		t.Fatal("owner cannot download a fresh artifact")
	}
	// The access rule that admitted the read no longer admits the caller.
	rules := e.app.Access
	e.app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"notes": {"all": "role:admin"}}}
	if status := get(); status != http.StatusNotFound {
		t.Fatalf("after losing table access status = %d, want 404", status)
	}
	e.app.Access = rules
	if get() != http.StatusOK {
		t.Fatal("restoring access did not restore the download")
	}
	// The reviewed manifest no longer offers an artifact for the tool.
	declared := e.app.MCP.Tools[1].Artifact
	e.app.MCP.Tools[1].Artifact = nil
	if status := get(); status != http.StatusNotFound {
		t.Fatalf("after the declaration was removed status = %d, want 404", status)
	}
	e.app.MCP.Tools[1].Artifact = declared
	// Past the TTL it is the same 404 as an unknown id; the manifest is immutable,
	// so age it by replacing the row.
	if _, err := e.app.DB.Exec(`DROP TRIGGER _benmore_mcp_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-mcpReadArtifactTTL - time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := e.app.DB.Exec(`UPDATE _benmore_mcp_artifacts SET created_at=? WHERE id=?`, old, id); err != nil {
		t.Fatal(err)
	}
	if status := get(); status != http.StatusNotFound {
		t.Fatalf("after the TTL status = %d, want 404", status)
	}
	// The expired one is also deleted when its owner makes the next one.
	if _, code := e.create(map[string]any{"tool": "list_notes", "format": "xlsx"}); code != "" {
		t.Fatal(code)
	}
	var count int
	if err := e.app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_artifacts WHERE id=?`, id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired artifact survived the next create: count=%d err=%v", count, err)
	}
}

func TestXLSXSerialErrorHoldsNoValue(t *testing.T) {
	_, err := xlsxSerial(time.Date(1850, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil || strings.Contains(err.Error(), "1850") {
		t.Fatalf("err = %v, want a refusal that names no value", err)
	}
	if _, err := appMCPArtifactFormatCell("1850-01-01", "date"); err == nil || strings.Contains(err.Error(), "1850") {
		t.Fatalf("cell err = %v, want no value", err)
	}
}

func TestAppMCPReadArtifactPDFRendersThroughSandbox(t *testing.T) {
	if findChrome() == "" {
		if os.Getenv("BENMORE_REQUIRE_CHROME_ARTIFACT") == "1" {
			t.Fatal("mandatory Chrome artifact renderer is unavailable")
		}
		t.Skip("Chrome is required for PDF artifact rendering")
	}
	e := newReadArtifactEnv(t, readArtifactYAML())
	out, code := e.create(map[string]any{"tool": "forecast", "format": "pdf"})
	if code != "" {
		t.Fatalf("pdf artifact: %s", code)
	}
	if data := e.download(out["artifact_id"].(string)); !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Fatalf("not a PDF: %q", data[:min(len(data), 8)])
	}
}

func TestAppMCPArtifactDeclarationValidation(t *testing.T) {
	load := func(mutate func(*AppMCPManifest)) error {
		m, err := decodeAppMCPManifest([]byte(readArtifactYAML()))
		if err != nil {
			t.Fatal(err)
		}
		mutate(m)
		return validateAppMCPManifestGated(m, true)
	}
	if err := load(func(*AppMCPManifest) {}); err != nil {
		t.Fatalf("the fixture itself must be valid: %v", err)
	}
	forecast := func(m *AppMCPManifest) *AppMCPArtifactDecl { return m.Tools[0].Artifact }
	for name, mutate := range map[string]func(*AppMCPManifest){
		"unknown format":        func(m *AppMCPManifest) { forecast(m).Formats = []string{"docx"} },
		"repeated format":       func(m *AppMCPManifest) { forecast(m).Formats = []string{"xlsx", "xlsx"} },
		"no formats":            func(m *AppMCPManifest) { forecast(m).Formats = nil },
		"no title":              func(m *AppMCPManifest) { forecast(m).Title = "" },
		"bidi title":            func(m *AppMCPManifest) { forecast(m).Title = "Report\u202e" },
		"no sheets":             func(m *AppMCPManifest) { forecast(m).Sheets = nil },
		"sheet name chars":      func(m *AppMCPManifest) { forecast(m).Sheets[0].Name = "A/B" },
		"sheet name too long":   func(m *AppMCPManifest) { forecast(m).Sheets[0].Name = strings.Repeat("x", 32) },
		"duplicate sheet name":  func(m *AppMCPManifest) { forecast(m).Sheets[1].Name = "summary" },
		"source not an array":   func(m *AppMCPManifest) { forecast(m).Sheets[1].Source = "project" },
		"unknown source":        func(m *AppMCPManifest) { forecast(m).Sheets[1].Source = "nope" },
		"unknown field":         func(m *AppMCPManifest) { forecast(m).Sheets[1].Columns[0].Field = "nope" },
		"duplicate field":       func(m *AppMCPManifest) { forecast(m).Sheets[1].Columns[1].Field = "id" },
		"money on a string":     func(m *AppMCPManifest) { forecast(m).Sheets[1].Columns[1].Format = "money" },
		"date on a number":      func(m *AppMCPManifest) { forecast(m).Sheets[1].Columns[2].Format = "date" },
		"unknown number format": func(m *AppMCPManifest) { forecast(m).Sheets[1].Columns[2].Format = "currency" },
		"no label":              func(m *AppMCPManifest) { forecast(m).Sheets[1].Columns[0].Label = "" },
		"too many sheets": func(m *AppMCPManifest) {
			for i := 0; i < mcpReadArtifactMaxSheets; i++ {
				forecast(m).Sheets = append(forecast(m).Sheets, AppMCPArtifactSheet{Name: fmt.Sprintf("X%d", i), Columns: forecast(m).Sheets[0].Columns})
			}
		},
		"source on a table.list tool": func(m *AppMCPManifest) { m.Tools[1].Artifact.Sheets[0].Source = "id" },
		"column outside projection":   func(m *AppMCPManifest) { m.Tools[1].Output.Include = []string{"id"} },
	} {
		if err := load(mutate); err == nil || !strings.Contains(err.Error(), "artifact") {
			t.Errorf("%s: invalid artifact declaration: err=%v", name, err)
		}
	}
	// Only a native read tool may declare one: a command, an external read and a file tool may not.
	for name, tool := range map[string]AppMCPTool{
		"command":  {Effect: "write", Handler: AppMCPHandler{Kind: "flow", Operation: "command"}},
		"external": {Effect: "read", Handler: AppMCPHandler{Kind: "external", Connection: "c", OperationID: "o"}},
		"file":     {Effect: "read", Handler: AppMCPHandler{Kind: "file", Operation: "ingest", Table: "notes"}},
		"update":   {Effect: "write", Handler: AppMCPHandler{Kind: "native", Operation: "table.update", Table: "notes"}},
	} {
		tool.Artifact = &AppMCPArtifactDecl{Title: "T", Formats: []string{"xlsx"}}
		if err := validateAppMCPArtifactDecl(tool); err == nil || !strings.Contains(err.Error(), "native read tool") {
			t.Errorf("%s tool: err=%v, want the native-read-tool refusal", name, err)
		}
	}
	// YAML is strict: an unknown key in the declaration does not load.
	if _, err := decodeAppMCPManifest([]byte(strings.Replace(readArtifactYAML(), "      title: Notes\n", "      title: Notes\n      layout: free\n", 1))); err == nil {
		t.Error("an unknown artifact key was accepted")
	}
	if _, err := decodeAppMCPManifest([]byte(strings.Replace(readArtifactYAML(), "    artifact:\n      title: Notes", "    artifact: null\n    x:\n      title: Notes", 1))); err == nil {
		t.Error("artifact: null was accepted")
	}
}

func TestAppMCPArtifactCellFormatting(t *testing.T) {
	for _, tc := range []struct {
		format       string
		value        any
		raw, display string
	}{
		{"money", json.Number("1234567.891"), "1234567.891", "1,234,567.89"},
		{"money", json.Number("-0.5"), "-0.5", "-0.50"},
		{"money", json.Number("1e3"), "1e3", "1,000.00"},
		{"percent", json.Number("0.0525"), "0.0525", "5.25%"},
		{"integer", json.Number("9007199254740993"), "9007199254740993", "9,007,199,254,740,993"},
		{"number", json.Number("12.50"), "12.50", "12.5"},
		{"date", "2026-10-14", "46309", "2026-10-14"},
		{"date", "2026-10-14T23:30:00-05:00", "46309", "2026-10-14"},
		{"datetime", "2026-10-14T09:30:00Z", "46309.395833333336", "2026-10-14 09:30 UTC"},
		{"text", "007", "007", "007"},
		{"text", true, "Yes", "Yes"},
		{"money", nil, "", ""},
	} {
		got, err := appMCPArtifactFormatCell(tc.value, tc.format)
		if err != nil || got.Raw != tc.raw || got.Display != tc.display {
			t.Errorf("%s %v = %+v (%v), want raw %q display %q", tc.format, tc.value, got, err, tc.raw, tc.display)
		}
	}
	for _, tc := range []struct {
		format string
		value  any
	}{{"integer", json.Number("1.5")}, {"money", "12"}, {"date", "yesterday"}, {"date", json.Number("5")}, {"date", "1850-01-01"}, {"text", []any{"x"}}} {
		if got, err := appMCPArtifactFormatCell(tc.value, tc.format); err == nil {
			t.Errorf("%s %v accepted as %+v", tc.format, tc.value, got)
		}
	}
}

func TestWriteXLSXSheetsLegacyRowsStillSniffNumbers(t *testing.T) {
	data, err := WriteXLSXSheets([]XLSXSheet{{Name: "A", Headers: []string{"h"}, Rows: [][]string{{"12"}, {"x"}}}})
	if err != nil {
		t.Fatal(err)
	}
	sheet := zipPart(t, data, "xl/worksheets/sheet1.xml")
	if !strings.Contains(sheet, `<c r="A2"><v>12</v></c>`) || !strings.Contains(sheet, `<c r="A3" t="inlineStr">`) || strings.Contains(sheet, "<sheetViews>") || strings.Contains(sheet, "<cols>") {
		t.Fatalf("legacy output changed: %s", sheet)
	}
}
