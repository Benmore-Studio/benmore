//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func devPageRequest(handler http.Handler, token, lang string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/desk?lang="+lang, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// The test runner uses dev=true for diagnostics. It must serve the published
// page generation, just as the hosted runtime does, until a validated reload.
func devPageSnapshotFixture(t *testing.T, files map[string]string) (*App, *hotHandler) {
	t.Helper()
	app, handler := rootPageReloadFixture(t, files)
	mux := http.NewServeMux()
	registerAppPageRoutes(mux, app, true)
	handler.swap(wrapMiddleware(mux, app, true))
	return app, handler
}

// Two actors read a loaded page while its on-disk replacement has different
// content and a stricter role gate. Neither the published page nor its partials
// may be changed by a request; the eventual reload activates body and gate together.
func TestDevPageKeepsPublishedSnapshotUntilReload(t *testing.T) {
	const published = "---\nauth: required\nrole: user\nlayout: none\ntitle: Published title\n---\n" +
		`<include src="partials/navigation.html" /><output>{{t "message"}}</output><span>{{user_role}}</span><section>published-body</section>`
	const replacement = "---\nauth: required\nrole: admin\nlayout: none\ntitle: Activated title\n---\n" +
		`<include src="partials/navigation.html" /><output>{{t "message"}}</output><span>{{user_role}}</span><section>activated-body</section>`
	app, handler := devPageSnapshotFixture(t, map[string]string{
		"desk.html":                published,
		"partials/navigation.html": "<nav>published-navigation</nav>",
		"i18n/en.yaml":             "message: English request\n",
		"i18n/es.yaml":             "message: Solicitud espanola\n",
	})
	user := createCrudScopeSession(t, app, "reader@example.test", "user", "", "")
	admin := createCrudScopeSession(t, app, "admin@example.test", "admin", "", "")
	publishedPage := *app.Pages["/desk"]
	writeTestFile(t, app.Dir, "desk.html", replacement)
	writeTestFile(t, app.Dir, "partials/navigation.html", "<nav>activated-navigation</nav>")
	start := make(chan struct{})
	results := make(chan error, 2)
	const requestsPerActor = 12
	for _, actor := range []struct{ token, lang, role, message, other string }{
		{user, "en", "user", "English request", "Solicitud espanola"},
		{admin, "es", "admin", "Solicitud espanola", "English request"},
	} {
		go func() {
			<-start
			for i := 0; i < requestsPerActor; i++ {
				rec := devPageRequest(handler, actor.token, actor.lang)
				body := rec.Body.String()
				if rec.Code != http.StatusOK || !strings.Contains(body, "<output>"+actor.message+"</output>") ||
					!strings.Contains(body, "<span>"+actor.role+"</span>") || !strings.Contains(body, "published-navigation") ||
					!strings.Contains(body, "Published title") || !strings.Contains(body, "published-body") ||
					strings.Contains(body, actor.other) || strings.Contains(body, "activated-") {
					results <- fmt.Errorf("%s/%s request %d: status %d, response did not preserve published source and caller", actor.role, actor.lang, i, rec.Code)
					return
				}
			}
			results <- nil
		}()
	}
	close(start)
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Error(err)
			}
		case <-deadline.C:
			t.Fatal("bounded two-actor page read did not finish")
		}
	}
	if got := *app.Pages["/desk"]; got != publishedPage {
		t.Errorf("request mutated published page: title %q -> %q", publishedPage.Title, got.Title)
	}
	if got := app.Partials["partials/navigation.html"]; got != "<nav>published-navigation</nav>" {
		t.Errorf("request replaced published partial: %q", got)
	}

	if err := hotReloadApp(app, true); err != nil {
		t.Fatal(err)
	}
	if rec := devPageRequest(handler, user, "en"); rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "activated-body") {
		t.Errorf("published stricter role gate: status %d, want 403 without replacement body", rec.Code)
	}
	rec := devPageRequest(handler, admin, "es")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "activated-body") || !strings.Contains(body, "Activated title") ||
		!strings.Contains(body, "activated-navigation") || !strings.Contains(body, "<output>Solicitud espanola</output>") ||
		!strings.Contains(body, "<span>admin</span>") || strings.Contains(body, "published-body") {
		t.Errorf("authorized read after reload: status %d, want activated page, partial, locale and caller", rec.Code)
	}
}

func TestDevPageFailedReloadRetainsPublishedSource(t *testing.T) {
	app, handler := devPageSnapshotFixture(t, map[string]string{
		"desk.html": "---\nauth: none\nlayout: none\n---\npublic-before-edit",
	})
	published := *app.Pages["/desk"]
	writeTestFile(t, app.Dir, "desk.html", "---\nauth: required\nrole: admin\nlayout: none\n---\nprivate-rejected-source")
	writeTestFile(t, app.Dir, "workflows.yaml", "invalid: [\n")
	if err := hotReloadApp(app, true); err == nil {
		t.Fatal("malformed workflow must reject reload")
	}
	for i := 0; i < 2; i++ {
		rec := devPageRequest(handler, "", "en")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "public-before-edit") || strings.Contains(rec.Body.String(), "private-rejected-source") {
			t.Errorf("request %d after rejected reload: status %d, want published source", i, rec.Code)
		}
	}
	if got := *app.Pages["/desk"]; got != published {
		t.Error("request mutated the page retained after rejected reload")
	}
}
