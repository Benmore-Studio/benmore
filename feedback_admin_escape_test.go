//go:build !cli

package main

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The /_admin/feedback detail modal builds <img src="'+escH(fb.screenshot)+'">
// from a row any visitor can write (POST /api/_feedback is open in testing
// mode). The page never defined escH, so the modal threw instead of
// rendering, and the widget's escH (text node -> innerHTML) leaves '"'
// alone, so defining it would have let a screenshot value add an onerror
// handler in the admin's session. Both now use a quote-safe escH.
func TestFeedbackAdminDetailEscapesAttributes(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping feedback admin escaping test")
	}
	app := authzApp(t)
	EnsureFeedbackTables(app.DB)
	admin := authzUser(t, app, "admin@example.com", "admin")
	sid := authzSession(t, app, admin, "admin@example.com")
	w := httptest.NewRecorder()
	ServeFeedbackAdmin(w, authzReq("GET", "/_admin/feedback", sid, ""), app)
	page := w.Body.String()
	m := regexp.MustCompile(`(?s)<script>\s*(function showFeedbackDetail.*?)</script>`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("feedback admin page has no detail script (status %d)", w.Code)
	}
	harness := `
const shown = {};
globalThis.document = {
  getElementById: (id) => id === 'fb-detail-content'
    ? { set innerHTML(v) { shown.html = v; } }
    : { showModal() { shown.opened = true; }, value: '' },
};
globalThis.fetch = () => Promise.resolve({ json: () => ({
  id: 7, status: 'open', visitor_name: 'v', visitor_email: 'v@example.test', page_url: '/p', body: 'b',
  screenshot: 'x" onerror="alert(1)', element_selector: '<b>', comments: [{ user_email: 'a"b', created_at: 'c', body: '<i>' }],
}) });
process.on('unhandledRejection', (e) => { console.error('detail modal threw:', e && e.message); process.exit(1); });
` + m[1] + `
showFeedbackDetail(7);
setTimeout(() => {
  if (!shown.html || !shown.opened) { console.error('detail modal did not render'); process.exit(1); }
  if (/onerror=/.test(shown.html.replace(/&quot;/g, '')) && shown.html.includes('" onerror=')) { console.error('screenshot broke out of src: ' + shown.html); process.exit(1); }
  if (!shown.html.includes('src="x&quot; onerror=&quot;alert(1)"')) { console.error('screenshot not attribute-escaped: ' + shown.html); process.exit(1); }
  if (shown.html.includes('<b>') || shown.html.includes('<i>')) { console.error('text not escaped: ' + shown.html); process.exit(1); }
  console.log('feedback detail escaped');
}, 20);
`
	path := filepath.Join(t.TempDir(), "detail.js")
	if err := os.WriteFile(path, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "feedback detail escaped") {
		t.Fatalf("feedback admin detail: %v\n%s", err, out)
	}

	// The visitor widget renders the same rows; its escH must be the
	// quote-safe one too.
	if !strings.Contains(FeedbackWidgetHTML(true), feedbackEscHJS) {
		t.Error("feedback widget does not use the quote-safe escH")
	}
}
