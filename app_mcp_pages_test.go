//go:build !cli && !windows

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

var pageStyleBlocks = regexp.MustCompile(`(?s)<style>(.*?)</style>`)

// assertMCPPageHeaders is the CSP contract of every connector page: no
// 'unsafe-inline', the strict directives, and a sha256 for each inline style
// block that matches the bytes actually served.
func assertMCPPageHeaders(t *testing.T, resp *http.Response, body string) {
	t.Helper()
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "script-src") {
		t.Errorf("CSP admits inline code: %q", csp)
	}
	blocks := pageStyleBlocks.FindAllStringSubmatch(body, -1)
	if len(blocks) == 0 {
		t.Error("page has no style block")
	}
	for _, b := range blocks {
		sum := sha256.Sum256([]byte(b[1]))
		if !strings.Contains(csp, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
			t.Errorf("style block %.40q is not admitted by %q", b[1], csp)
		}
	}
	if strings.Contains(body, "<script") || strings.Contains(body, " style=") {
		t.Error("page carries a script or an inline style attribute")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", resp.Header)
	}
}

// The batch_review_url a prepared result EMITS must itself open the page: a
// signed-in person sees their operation, a signed-out probe goes to /login with
// the query kept, and a malformed grant never turns into a bare 404 for a
// signed-out viewer (#770).
func TestAppMCPEmittedBatchReviewURLOpens(t *testing.T) {
	h := newExposureHarness(t)
	out, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if code != "" {
		t.Fatal(code)
	}
	op, _ := out["operation_id"].(string)
	emitted, _ := out["batch_review_url"].(string)
	u, err := url.Parse(emitted)
	if err != nil || u.Query().Get("grant") != h.pair.GrantID {
		t.Fatalf("emitted url %q: %v", emitted, err)
	}
	target := u.RequestURI()

	resp, body := h.do("GET", target, h.cookie, nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `name="op" value="`+op+`"`) {
		t.Fatalf("signed in: %d %s", resp.StatusCode, body)
	}
	assertMCPPageHeaders(t, resp, body)

	resp, _ = h.do("GET", target, "", nil, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?next="+url.QueryEscape(target) {
		t.Fatalf("signed out: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Malformed grant: signed out is sent to sign in; signed in gets the page.
	probe := appMCPBatchRoute + "?grant=x"
	if resp, _ = h.do("GET", probe, "", nil, nil); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Fatalf("signed-out probe: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body = h.do("GET", probe, h.cookie, nil, nil)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "This request can&#39;t be shown") || !strings.Contains(body, `href="/"`) {
		t.Fatalf("signed-in malformed grant: %d %s", resp.StatusCode, body)
	}
	assertMCPPageHeaders(t, resp, body)
	// Same for the single page.
	if resp, _ = h.do("GET", appMCPOperationRoute+"nothex", "", nil, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("signed-out single probe: %d", resp.StatusCode)
	}
	if resp, body = h.do("GET", appMCPOperationRoute+"nothex", h.cookie, nil, nil); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "can&#39;t be shown") {
		t.Fatalf("signed-in single probe: %d %s", resp.StatusCode, body)
	}
}

// Unknown, foreign and malformed operations look the same to the viewer: same
// status, same bytes. Anything that differed would tell a prober which ids exist.
func TestAppMCPUnknownAndForeignOperationsAreIdentical(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	other := createCrudScopeSession(t, h.app, "other-user@example.com", "editor", "17", "")
	foreignResp, foreign := h.do("GET", appMCPOperationRoute+id, other, nil, nil)
	unknownResp, unknown := h.do("GET", appMCPOperationRoute+strings.Repeat("a", 32), h.cookie, nil, nil)
	malformedResp, malformed := h.do("GET", appMCPOperationRoute+"zz", h.cookie, nil, nil)
	if foreignResp.StatusCode != http.StatusNotFound || foreign != unknown || foreign != malformed ||
		unknownResp.StatusCode != foreignResp.StatusCode || malformedResp.StatusCode != foreignResp.StatusCode ||
		unknownResp.Header.Get("Content-Security-Policy") != foreignResp.Header.Get("Content-Security-Policy") {
		t.Fatalf("pages differ: foreign %d, unknown %d, malformed %d\n%s\n---\n%s", foreignResp.StatusCode, unknownResp.StatusCode, malformedResp.StatusCode, foreign, unknown)
	}
	if strings.Contains(foreign, id) {
		t.Fatal("error page echoes the id")
	}
	assertMCPPageHeaders(t, foreignResp, foreign)
}

func TestAppMCPApprovalsOffPageNamesTheApp(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.app.Design = &DesignConfig{SEO: map[string]string{"site_name": "Task Hub"}}
	if _, err := setAppMCPApprovedWrites(h.app.Dir, false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{appMCPOperationRoute + id, appMCPBatchRoute + "?grant=" + h.pair.GrantID} {
		resp, body := h.do("GET", path, h.cookie, nil, nil)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Approving assistant changes is currently turned off for Task Hub. Ask the app owner to turn it on.") {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
		assertMCPPageHeaders(t, resp, body)
		// Signed out, a writes-off app answers exactly like a writes-on app: the
		// same redirect, so a stranger cannot tell which apps have writes on.
		if resp, _ := h.do("GET", path, "", nil, nil); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
			t.Fatalf("%s signed out: %d %q", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

// A title is up to 80 runes; the sealed record caps approval_reason at 256
// BYTES, so the reason must never carry the title (70 CJK runes = 210 bytes).
func TestAppMCPApprovalReasonFitsTheRecord(t *testing.T) {
	for _, r := range []string{"This kind of change always needs your approval", "Auto-approve is turned off for this app",
		"This connection was not allowed to auto-approve this kind of change",
		"The app's tools changed since you connected; reconnect the assistant to re-enable auto-approve",
		"Auto-approve was switched off and on since you connected; reconnect to re-enable it"} {
		if len(r) > 256 {
			t.Fatalf("reason over 256 bytes: %q", r)
		}
	}
	src, err := os.ReadFile("app_mcp_review_fields.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := string(src)[strings.Index(string(src), "func appMCPApprovalReason("):]
	fn = fn[:strings.Index(fn, "\n}\n")]
	if strings.Contains(fn, "Title") || strings.Contains(fn, "+ name") {
		t.Fatal("approval reason must not include the tool title (byte cap on the sealed record)")
	}
}

func TestAppMCPReviewShowsClearedFieldsAndExactData(t *testing.T) {
	view := map[string]any{"Heading": "Edit", "Preview": "{\n  \"name\": \"Acme\",\n  \"notes\": \"\"\n}",
		"Changes": []appMCPReviewChange{{Label: "Name", After: "Acme"}, {Label: "Notes", After: ""}}}
	var b strings.Builder
	if err := appMCPReviewPage.ExecuteTemplate(&b, "changes", view); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, ">Notes<") || !strings.Contains(out, "(empty)") || !strings.Contains(out, "Exact data") || !strings.Contains(out, "&#34;notes&#34;") {
		t.Fatalf("cleared field or exact data missing: %s", out)
	}
	if got := appMCPReviewValueText(json.Number("123456789012345678.9")); got != "123456789012345678.9" {
		t.Fatalf("decimal shown as %q", got)
	}
}

func TestAppMCPReviewPageRendersHumanFields(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	// Rendering is checked on the view directly: the fields are populated by
	// the review text elsewhere, this page only shows them.
	review := &appMCPReview{Tool: "complete_item", Description: "model-facing words", Preview: "{\n  \"id\": 1\n}", State: "prepared",
		ExpiresAt: time.Now().Add(14*time.Minute + 30*time.Second).Unix(), Title: "Mark task done", Summary: "Closes <b>one</b> task.", AutoApprove: "it edits a record",
		Changes: []appMCPReviewChange{{Label: "Status", Before: "open", After: "done", Changed: true}, {Label: "Owner", Before: "me", After: "me"}}}
	view := newAppMCPReviewView(review, id, time.Now())
	view.Approvable, view.CSRF, view.Action = true, "tok", "/x"
	rec := httptest.NewRecorder()
	writeAppMCPPage(rec, h.app, 200, appMCPReviewPage, appMCPReviewPageOpts, view)
	body := rec.Body.String()
	for _, want := range []string{"<h1>Mark task done</h1>", "Closes &lt;b&gt;one&lt;/b&gt; task.", "<code>complete_item</code>", `<th scope="col">Before</th>`,
		`class="changed"`, "Why this needs your approval: it edits a record", "Expires in 14 minutes", `<time datetime="`, "Approve this exact change"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// The exact preview stays available, but only collapsed under the table.
	if strings.Contains(body, "model-facing words") || strings.Count(body, "<pre>") != 1 || !strings.Contains(body, `<details class="raw"><summary>Exact data</summary><pre>`) {
		t.Error("description shown, or raw preview not collapsed under the changes")
	}
	// No title, no summary, no changes: tool name heading, collapsed description, raw preview.
	review.Title, review.Summary, review.Changes = "", "", nil
	rec = httptest.NewRecorder()
	writeAppMCPPage(rec, h.app, 200, appMCPReviewPage, appMCPReviewPageOpts, newAppMCPReviewView(review, id, time.Now()))
	body = rec.Body.String()
	if !strings.Contains(body, "<h1>complete_item</h1>") || !strings.Contains(body, "<details><summary>What the assistant was told</summary>") || !strings.Contains(body, "<pre>") {
		t.Errorf("fallback page: %s", body)
	}
	// A create has no Before column.
	review.Changes = []appMCPReviewChange{{Label: "Name", After: "x", Changed: true}}
	rec = httptest.NewRecorder()
	writeAppMCPPage(rec, h.app, 200, appMCPReviewPage, appMCPReviewPageOpts, newAppMCPReviewView(review, id, time.Now()))
	if strings.Contains(rec.Body.String(), ">Before<") {
		t.Error("Before column shown when every Before is empty")
	}
}

func TestAppMCPPageThemeRejectsInjectedColours(t *testing.T) {
	themed := func(brand string) string {
		return string(appMCPPageThemeCSS(&App{Design: &DesignConfig{Colors: map[string]string{"_brand": brand}}}))
	}
	def := themed("")
	for _, bad := range []string{"red;}body{display:none}", "url(http://evil.example/x)", "#fff;}", "#ggg", "expression(1)", "rgb(1,2,300)", "hsl(1,2%,300%)", "#3366ff;background:url(x)", "var(--x)", strings.Repeat("a", 200)} {
		if got := themed(bad); got != def || strings.ContainsAny(got, "(") && strings.Contains(got, "url") {
			t.Errorf("%q was accepted: %s", bad, got)
		}
	}
	for _, good := range []string{"#3366ff", "#36f", "rgb(51, 102, 255)", "rgb(51 102 255)"} {
		got := themed(good)
		if !strings.Contains(got, "--primary:#3366ff;") || strings.Contains(got, "hsl") {
			t.Errorf("%q: %s", good, got)
		}
	}
	if got := themed("hsl(220, 100%, 60%)"); !strings.Contains(got, "--primary:#3377ff;") {
		t.Errorf("hsl: %s", got)
	}
	// The preset follows theme:, and the page itself carries only the vetted block.
	preset := string(appMCPPageThemeCSS(&App{Design: &DesignConfig{Colors: map[string]string{"_theme": "blue"}}}))
	if preset == def || !strings.HasPrefix(preset, ":root{--primary:#") {
		t.Errorf("blue preset: %s", preset)
	}
	app := &App{Design: &DesignConfig{Colors: map[string]string{"_brand": "red;}body{display:none}"}, SEO: map[string]string{"site_name": "Acme <Portal>"}}}
	rec := httptest.NewRecorder()
	writeAppMCPCannotShow(rec, app)
	body := rec.Body.String()
	if strings.Contains(body, "display:none") || !strings.Contains(body, "Acme &lt;Portal&gt;") {
		t.Errorf("page: %s", body)
	}
}

func TestAppMCPPageFaviconOnlySameOrigin(t *testing.T) {
	page := func(favicon string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		writeAppMCPCannotShow(rec, &App{Design: &DesignConfig{SEO: map[string]string{"favicon": favicon}}})
		return rec
	}
	rec := page("/static/fav.png")
	if !strings.Contains(rec.Body.String(), `<link rel="icon" href="/static/fav.png">`) || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "img-src 'self'") {
		t.Errorf("same-origin favicon not linked: %s %v", rec.Body.String(), rec.Header())
	}
	for _, off := range []string{"", "https://evil.example/x.png", "//evil.example/x.png", "javascript:alert(1)", `/a"onerror="x`} {
		rec := page(off)
		if strings.Contains(rec.Body.String(), `rel="icon"`) || strings.Contains(rec.Header().Get("Content-Security-Policy"), "img-src") {
			t.Errorf("favicon %q linked: %s", off, rec.Header().Get("Content-Security-Policy"))
		}
	}
}

func TestAppMCPWorkspacePickerShowsNamesAndSkipsForOne(t *testing.T) {
	f := newAppMCPOAuthHTTPFixture(t)
	auditExec(t, f.app.DB, "CREATE TABLE orgs(id TEXT PRIMARY KEY, name TEXT)")
	auditExec(t, f.app.DB, "INSERT INTO orgs(id,name) VALUES ('17','Acme <Co>'),('29','Beta')")
	f.app.Group.Label = &GroupLabelConfig{Table: "orgs", Key: "id", Field: "name"}

	w := f.request(t, http.MethodGet, "/oauth/authorize?"+f.values.Encode(), nil, "", "")
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `<option value="17">Acme &lt;Co&gt;</option>`) || !strings.Contains(body, `<option value="29">Beta</option>`) {
		t.Fatalf("picker: %d %s", w.Code, body)
	}
	if strings.Contains(body, ">17<") {
		t.Error("picker shows the raw id")
	}
	assertMCPPageHeaders(t, w.Result(), body)

	// A label lookup that finds nothing falls back to the id.
	auditExec(t, f.app.DB, "DELETE FROM orgs WHERE id='29'")
	if body := f.request(t, http.MethodGet, "/oauth/authorize?"+f.values.Encode(), nil, "", "").Body.String(); !strings.Contains(body, `<option value="29">29</option>`) {
		t.Fatalf("no id fallback: %s", body)
	}

	// One workspace: no picker, straight to consent with the name.
	auditExec(t, f.app.DB, "DELETE FROM members WHERE org_id='29'")
	w = f.request(t, http.MethodGet, "/oauth/authorize?"+f.values.Encode(), nil, "", "")
	body = w.Body.String()
	fields := appMCPOAuthHTTPHidden(t, body)
	if w.Code != 200 || strings.Contains(body, `<select`) || fields.Get("workspace") != "17" || fields.Get("connector_nonce") == "" || !strings.Contains(body, "notes:read in workspace Acme &lt;Co&gt;") {
		t.Fatalf("single workspace: %d %s", w.Code, body)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self' https://") && !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Errorf("consent CSP: %s", w.Header().Get("Content-Security-Policy"))
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Error("consent page admits unsafe-inline")
	}
	// The skipped picker still goes through the consent checks: no membership, no page.
	auditExec(t, f.app.DB, "DELETE FROM members")
	if w := f.request(t, http.MethodGet, "/oauth/authorize?"+f.values.Encode(), nil, "", ""); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "No workspace available") {
		t.Fatalf("no workspace: %d %s", w.Code, w.Body.String())
	}
}

func TestGroupLabelConfigIsValidated(t *testing.T) {
	base := "name: x\ngroups:\n  table: members\n  key: org_id\n  user_field: email\n"
	gc := parseGroupConfig([]byte(base + "  label:\n    table: orgs\n    field: name\n"))
	if gc == nil || gc.Label == nil || *gc.Label != (GroupLabelConfig{Table: "orgs", Key: "id", Field: "name"}) {
		t.Fatalf("label not read: %+v", gc)
	}
	if gc := parseGroupConfig([]byte(base + "  label:\n    table: \"orgs; DROP\"\n    field: name\n")); gc.Label != nil {
		t.Fatal("non-identifier label table loaded")
	}
	for _, bad := range []string{"table: 'o rgs'\n    field: name", "table: orgs\n    field: 'na\"me'", "table: orgs\n    key: '1x'\n    field: name", "table: orgs", "field: name"} {
		if _, _, err := parseAppConfigDocument([]byte(base + "  label:\n    " + bad + "\n")); err == nil {
			t.Errorf("accepted label %q", bad)
		}
	}
	if _, _, err := parseAppConfigDocument([]byte(base + "  label:\n    table: orgs\n    field: name\n")); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"groups": map[string]any{"label": map[string]any{"table": "orgs", "field": "name", "extra": "x"}}}
	if msg := appYAMLSectionKeyViolation(doc); !strings.Contains(msg, "groups.label.extra") {
		t.Fatalf("unknown label key not refused: %q", msg)
	}
}

// A browser posts the approve form with "Origin: null" when the page's
// Referrer-Policy is no-referrer. The pages now send same-origin, and the
// approve gate follows the shared rule (security.md 5b): the literal "null"
// counts only with Sec-Fetch-Site: same-origin.
func TestAppMCPApproveOriginNullFollowsTheSharedGate(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	resp, body := h.do("GET", appMCPOperationRoute+id, h.cookie, nil, nil)
	if resp.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("review Referrer-Policy %q", resp.Header.Get("Referrer-Policy"))
	}
	token := exposureCSRF.FindStringSubmatch(body)[1]
	if resp, _ := h.do("GET", appMCPBatchRoute+"?grant="+h.pair.GrantID, h.cookie, nil, nil); resp.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("batch Referrer-Policy %q", resp.Header.Get("Referrer-Policy"))
	}
	for name, header := range map[string]map[string]string{
		"null, no fetch metadata": {"Origin": "null"},
		"null, cross-site":        {"Origin": "null", "Sec-Fetch-Site": "cross-site"},
		"null, same-site":         {"Origin": "null", "Sec-Fetch-Site": "same-site"},
		"other origin":            {"Origin": "https://evil.example", "Sec-Fetch-Site": "same-origin"},
	} {
		if got := h.approve(h.cookie, id, token, header); got == http.StatusSeeOther {
			t.Fatalf("%s was approved", name)
		}
	}
	if h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 0 {
		t.Fatal("a refused post approved")
	}
	if got := h.approve(h.cookie, id, token, map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}); got != http.StatusSeeOther {
		t.Fatalf("same-origin Origin:null post refused: %d", got)
	}
	if h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 1 {
		t.Fatal("approval not recorded")
	}
}

func TestAppMCPBatchApproveOriginNull(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	_, body := h.do("GET", appMCPBatchRoute+"?grant="+h.pair.GrantID, h.cookie, nil, nil)
	token := exposureCSRF.FindStringSubmatch(body)[1]
	form := url.Values{"_csrf": {token}, "grant": {h.pair.GrantID}, "op": {id}}
	post := func(header map[string]string) int {
		resp, _ := h.do("POST", appMCPBatchRoute+"/approve", h.cookie, form, header)
		return resp.StatusCode
	}
	if got := post(map[string]string{"Origin": "null"}); got == http.StatusSeeOther {
		t.Fatal("Origin:null without fetch metadata approved")
	}
	if got := post(map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}); got != http.StatusSeeOther {
		t.Fatalf("same-origin Origin:null post refused: %d", got)
	}
}

// A connector whose mcp.yaml review went stale (app.mcpWithheld) used to answer every review and batch link
// with the framework's generic "no API route matches this path", the same bytes as a route that does not
// exist. A signed-in direct session now gets a
// page that says the connector is off; signed out it is the same redirect a live connector app gives.
func TestAppMCPWithheldConnectorExplainsItself(t *testing.T) {
	h := newExposureHarness(t)
	h.app.Design = &DesignConfig{SEO: map[string]string{"site_name": "Task Hub"}}
	mux := http.NewServeMux()
	registerAppMCPWithheldRoutes(mux, h.app)
	h.server.Close()
	h.server = httptest.NewTLSServer(mux)
	t.Cleanup(h.server.Close)
	h.browser = &http.Client{Transport: h.server.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	id := strings.Repeat("a", 32)
	for _, path := range []string{appMCPOperationRoute + id, appMCPBatchRoute + "?grant=" + id} {
		resp, body := h.do("GET", path, h.cookie, nil, nil)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "The assistant connector is off") || !strings.Contains(body, "Task Hub") {
			t.Fatalf("%s signed in: %d %s", path, resp.StatusCode, body)
		}
		assertMCPPageHeaders(t, resp, body)
		if resp, _ := h.do("GET", path, "", nil, nil); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
			t.Fatalf("%s signed out: %d %q", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// An approval POST is never honoured, signed out or in.
	for cookie, want := range map[string]int{"": http.StatusForbidden, h.cookie: http.StatusNotFound} {
		if resp, body := h.do("POST", appMCPOperationRoute+id+"/approve", cookie, url.Values{"x": {"1"}}, nil); resp.StatusCode != want {
			t.Fatalf("withheld connector answered an approval POST with %d, want %d: %s", resp.StatusCode, want, body)
		}
	}
}

// The withheld pages are wired into the real route build, not only registrable: an app with a withheld
// connector (mcp.yaml present, review stale) must mount the review and batch URLs.
func TestAppMCPWithheldRoutesAreMountedByTheRouteBuild(t *testing.T) {
	h := newExposureHarness(t)
	h.app.MCP, h.app.mcpWithheld = nil, "mcp.yaml's review does not match the current source"
	mux := buildAppRouteMux(h.app, false, "https://example.test", false, nil)
	for _, path := range []string{appMCPOperationRoute + strings.Repeat("a", 32), appMCPBatchRoute} {
		req := httptest.NewRequest("GET", path, nil)
		if _, pattern := mux.Handler(req); pattern == "" || strings.HasSuffix(pattern, "/") {
			t.Fatalf("%s is not mounted for a withheld connector (pattern %q)", path, pattern)
		}
	}
	h.app.mcpWithheld = ""
	plain := buildAppRouteMux(h.app, false, "https://example.test", false, nil)
	if _, pattern := plain.Handler(httptest.NewRequest("GET", appMCPBatchRoute, nil)); strings.Contains(pattern, "operations/batch") {
		t.Fatalf("an app with no connector at all must not mount the pages, got %q", pattern)
	}
}
