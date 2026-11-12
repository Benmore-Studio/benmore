//go:build !cli

package main

// Scoped credentials on server-rendered pages.
//
// A scoped credential (scopedCredential: an API token or Bearer session
// minted with explicit scopes, a connector grant) is narrowed by auto-CRUD
// table by table. A page has no table of its own: its gates looked at the
// account and its <query> tags and gotmpl queries ran as the account, so a
// notes:read token read every other table a page selects from, on the page
// route and through GET /pdf/<page>.
//
// The rule: a page is for a person at a browser. A page that requires
// sign-in (auth, role or require) refuses a scoped credential, on its route
// and on its PDF, before any gate, query or render. A public page renders
// for it exactly as for a caller with no credential: the page's viewer is
// nobody, so the token adds nothing. Unscoped credentials ("" or "*") and
// ordinary sign-ins are never affected.
//
// Every page render resolves its viewer through pageCaller; a new route that
// renders a page must do the same and call refuseScopedCredentialPage when
// pageRequiresSignIn.

import "net/http"

// scopedCredentialPageCode is the `error` of the 403 a scoped credential gets
// from a page that requires sign-in.
const scopedCredentialPageCode = "scoped_credential_page"

// scopedCredentialPageMessage says why and what to do instead.
const scopedCredentialPageMessage = "pages are for browser sign-ins, and this credential is limited to the scopes it was issued with: a scoped API token or session cannot open a page that requires sign-in, or its PDF. Read the data through the API routes its scopes name, or open the page from a browser sign-in or with an unscoped credential"

// pageCaller resolves who a server-rendered page runs for. scoped reports a
// scoped credential, for which the viewer is nil: the page renders as for an
// anonymous caller, and one that requires sign-in is refused
// (refuseScopedCredentialPage).
func pageCaller(app *App, r *http.Request) (viewer *Session, scoped bool) {
	session := getSession(app, r)
	if scopedCredential(session) && !platformPageSession(app, session) {
		return nil, true
	}
	return session, false
}

// pageRenderRequest is the request a page renders with. For a scoped
// credential it is a copy that presents no credential (the session cookies
// and the Authorization header are dropped, every other cookie and header
// kept), so the parts of a render that resolve the caller from the request
// (typed `sources:`, a <fetch> tag's descriptor) also see nobody.
func pageRenderRequest(r *http.Request, scoped bool) *http.Request {
	if !scoped || r == nil {
		return r
	}
	render := r.Clone(r.Context())
	render.Header.Del("Authorization")
	cookies := render.Cookies()
	render.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != sessionCookieName && c.Name != devSessionCookieName {
			render.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	return render
}

// pageRequiresSignIn reports whether any of the page's gates asks for a
// signed-in caller: auth, require, or a role other than "public".
func pageRequiresSignIn(page *Page) bool {
	if page == nil {
		return false
	}
	if page.Auth == "required" || page.Require != "" {
		return true
	}
	role := pageRole(page)
	return role != "" && role != "public"
}

// refuseScopedCredentialPage answers a scoped credential that asked for a
// page requiring sign-in, or for its PDF.
func refuseScopedCredentialPage(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	httpJSON(w, http.StatusForbidden, withRefusalDocs(map[string]any{
		"error":   scopedCredentialPageCode,
		"message": scopedCredentialPageMessage,
	}, scopedCredentialPageCode))
}

// scopedCredentialPageGate is the outermost wrapper of a page route: a scoped
// credential gets the one refusal before the page's own auth, role and
// require gates answer (a login redirect or a role 403 would say nothing
// about why an integration cannot read the page).
func scopedCredentialPageGate(app *App, page *Page, next http.HandlerFunc) http.HandlerFunc {
	if !pageRequiresSignIn(page) {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if _, scoped := pageCaller(app, r); scoped {
			refuseScopedCredentialPage(w)
			return
		}
		next(w, r)
	}
}
