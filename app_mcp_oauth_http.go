//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The audience comes from the canonical route builder, never from Host.
func appMCPResourceAt(app *App, baseURL string) string {
	origin := strings.TrimSuffix(appMCPBaseURL(app, baseURL), "/")
	resource := origin + "/api/_mcp"
	if !validAppMCPResource(app, resource) {
		return ""
	}
	return resource
}
func appMCPOAuthOrigin(resource string) string { return strings.TrimSuffix(resource, "/api/_mcp") }
func appMCPOAuthHost(r *http.Request, app *App, resource string) bool {
	u, err := url.Parse(resource)
	return err == nil && validAppMCPResource(app, resource) && strings.EqualFold(r.Host, u.Host)
}
func appMCPOAuthTarget(values url.Values) bool {
	for _, resource := range values["resource"] {
		u, err := url.Parse(resource)
		if err == nil && (u.Path == "/api/_mcp" || strings.HasPrefix(u.Path, "/api/_mcp/")) {
			return true
		}
	}
	return len(values["connector_nonce"]) > 0
}
func appMCPOAuthTokenTarget(values url.Values) bool {
	if appMCPOAuthTarget(values) || values.Get("grant_type") == "refresh_token" {
		return true
	}
	for _, key := range []string{"code", "refresh_token"} {
		for _, value := range values[key] {
			if strings.HasPrefix(value, "bmcc_") || strings.HasPrefix(value, "bmcr_") {
				return true
			}
		}
	}
	return false
}
func appMCPOAuthMetadata(w http.ResponseWriter, r *http.Request, app *App, resource string, protected bool) {
	manifest := appMCPManifestSnapshot(app)
	if manifest == nil || !appMCPOAuthHost(r, app, resource) {
		http.NotFound(w, r)
		return
	}
	origin := appMCPOAuthOrigin(resource)
	scopes := strings.Fields(appMCPLiveScopes(app, manifest, snapshotAppMCPGeneration(app)))
	if len(scopes) == 1 && scopes[0] == "_none_:read" {
		scopes = []string{}
	}
	w.Header().Set("Cache-Control", "no-store")
	if protected {
		httpJSON(w, 200, map[string]any{"resource": resource, "resource_name": appSiteName(app), "authorization_servers": []string{origin}, "scopes_supported": scopes, "bearer_methods_supported": []string{"header"}})
		return
	}
	httpJSON(w, 200, map[string]any{"issuer": origin, "authorization_endpoint": origin + "/oauth/authorize", "token_endpoint": origin + "/oauth/token", "registration_endpoint": origin + "/oauth/register", "revocation_endpoint": origin + "/oauth/revoke", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"}, "revocation_endpoint_auth_methods_supported": []string{"none"}, "scopes_supported": scopes, "resource_parameter_supported": true})
}

// Keep legacy registry/storage and registration behavior on apps without MCP.
// New registrations on connector apps have explicit supported scopes.
func appMCPOAuthRegister(w http.ResponseWriter, r *http.Request, app *App, resource string) {
	if appMCPManifestSnapshot(app) == nil {
		appOAuthRegister(w, r, app)
		return
	}
	if !appMCPOAuthHost(r, app, resource) {
		httpJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	raw, err := io.ReadAll(r.Body)
	var request struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		Scope        string   `json:"scope"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err != nil || !utf8.Valid(raw) || decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.ClientName == "" || len(request.ClientName) > 256 || !utf8.ValidString(request.ClientName) || len(request.RedirectURIs) == 0 || len(request.RedirectURIs) > 16 {
		httpJSON(w, 400, map[string]any{"error": "invalid_client_metadata"})
		return
	}
	for _, redirect := range request.RedirectURIs {
		if len(redirect) > 8192 || !validAppMCPOAuthRedirect(redirect) {
			httpJSON(w, 400, map[string]any{"error": "invalid_redirect_uri"})
			return
		}
	}
	// Clients add scopes of their own (claude.ai sends "claudeai"); RFC 7591
	// lets the server register fewer than requested, so unknown values are
	// dropped and an empty result takes the live default, as on the platform.
	live := appMCPLiveScopes(app, appMCPManifestSnapshot(app), snapshotAppMCPGeneration(app))
	var kept []string
	for _, scope := range strings.Fields(request.Scope) {
		if scopesWithin(live, scope) {
			kept = append(kept, scope)
		}
	}
	request.Scope = strings.Join(kept, " ")
	if request.Scope == "" {
		request.Scope = live
	}
	requested, err := appMCPExplicitScopes(request.Scope)
	if err != nil || !scopesWithin(live, strings.Join(requested, " ")) {
		httpJSON(w, 400, map[string]any{"error": "invalid_scope"})
		return
	}
	request.Scope = strings.Join(requested, " ")
	raw, _ = json.Marshal(request)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	// Existing registration validates redirects and stores the client once.
	appOAuthRegister(w, r, app)
}
func appMCPOAuthFields(p oauthAuthorizeParams) map[string]string {
	return map[string]string{"response_type": "code", "client_id": p.ClientID, "redirect_uri": p.RedirectURI, "state": p.State, "scope": p.Scope, "code_challenge": p.CodeChallenge, "code_challenge_method": p.CodeChallengeMethod, "resource": p.Resource}
}
func appMCPOAuthWorkspaces(app *App, session *Session) ([]string, error) {
	return appMCPOAuthWorkspacesFor(context.Background(), app, session)
}

func appMCPOAuthWorkspacesFor(ctx context.Context, app *App, session *Session) ([]string, error) {
	g := app.Group
	if g == nil || g.Table == "" {
		return []string{""}, nil
	}
	for _, name := range []string{g.Table, g.Key, g.UserField} {
		if !membershipIdentRe.MatchString(name) {
			return nil, errAppMCPGrantDenied
		}
	}
	member, ok := groupMemberValue(g, session)
	if !ok {
		return nil, errAppMCPGrantDenied
	}
	q, closeRead, err := openAppMCPOAuthRead(ctx, app)
	if err != nil {
		return nil, errAppMCPGrantDenied
	}
	defer closeRead()
	hasCol, metadataErr := dbColumnCheckerWith(q, g.Table, "main")
	live := membershipLiveConds(g, g.Table, "", hasCol)
	if metadataErr() != nil {
		return nil, errAppMCPGrantDenied
	}
	key, err := cryptoKeyForQuerierChecked(q)
	if err != nil {
		return nil, errAppMCPGrantDenied
	}
	tenant := quoteColumn(g.Table, g.Key)
	rows, err := queryRowsWithKeyContextDecrypt(ctx, q, key, nativeRowDecryptor(nil, ""), fmt.Sprintf("SELECT DISTINCT %s AS workspace FROM main.%s WHERE %s=? AND %s IS NOT NULL%s LIMIT 501", tenant, quoteIdent(g.Table), quoteColumn(g.Table, g.UserField), tenant, live), member)
	if err != nil || q.ctx.Err() != nil || len(rows) > 500 {
		return nil, errAppMCPGrantDenied
	}
	workspaces := []string{}
	for _, row := range rows {
		v := fmt.Sprint(row["workspace"])
		if v != "" && v != "0" {
			workspaces = append(workspaces, v)
		}
	}
	sort.Strings(workspaces)
	return workspaces, nil
}

// appMCPOAuthWorkspaceLabels looks up the display name of each workspace in
// groups.label (display only: the ids were already authorized for this
// session). Any failure, a missing row or an unreadable column leaves the id as
// the name, so a label can never block or widen a connection.
func appMCPOAuthWorkspaceLabels(ctx context.Context, app *App, workspaces []string) map[string]string {
	labels := map[string]string{}
	if app.Group == nil || app.Group.Label == nil || len(workspaces) == 0 || len(workspaces) > 500 {
		return labels
	}
	l := app.Group.Label
	// An encrypted label column has unmask roles this page cannot apply, and a
	// framework table is never a label source: show ids instead.
	if encryptedDefFor(app, l.Table, l.Field) != nil || strings.HasPrefix(l.Table, "_benmore_") || strings.HasPrefix(strings.ToLower(l.Table), "sqlite_") {
		return labels
	}
	for _, name := range []string{l.Table, l.Key, l.Field} {
		if !membershipIdentRe.MatchString(name) {
			return labels
		}
	}
	q, closeRead, err := openAppMCPOAuthRead(ctx, app)
	if err != nil {
		return labels
	}
	defer closeRead()
	key, err := cryptoKeyForQuerierChecked(q)
	if err != nil {
		return labels
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(workspaces)), ",")
	args := make([]any, len(workspaces))
	for i, w := range workspaces {
		args[i] = w
	}
	rows, err := queryRowsWithKeyContextDecrypt(ctx, q, key, nativeRowDecryptor(nil, ""), fmt.Sprintf("SELECT %s AS id, %s AS label FROM main.%s WHERE %s IN (%s)",
		quoteColumn(l.Table, l.Key), quoteColumn(l.Table, l.Field), quoteIdent(l.Table), quoteColumn(l.Table, l.Key), marks), args...)
	if err != nil || q.ctx.Err() != nil {
		return labels
	}
	for _, row := range rows {
		if row["label"] == nil {
			continue
		}
		if name := clampLabel(fmt.Sprint(row["label"])); name != "" {
			labels[fmt.Sprint(row["id"])] = name
		}
	}
	return labels
}

type appMCPPageField struct{ Name, Value string }

func appMCPOAuthPageFields(fields map[string]string) []appMCPPageField {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]appMCPPageField, len(keys))
	for i, key := range keys {
		out[i] = appMCPPageField{key, fields[key]}
	}
	return out
}

type appMCPWorkspaceChoice struct{ ID, Name string }

func appMCPOAuthChooser(w http.ResponseWriter, r *http.Request, app *App, p oauthAuthorizeParams, workspaces []string) {
	labels := appMCPOAuthWorkspaceLabels(r.Context(), app, workspaces)
	seen := map[string]int{}
	for _, id := range workspaces {
		seen[labels[id]]++
	}
	choices := make([]appMCPWorkspaceChoice, len(workspaces))
	for i, id := range workspaces {
		name := labels[id]
		if name == "" {
			name = id
		} else if seen[name] > 1 {
			name += " (" + id + ")" // two workspaces with one name stay distinguishable
		}
		choices[i] = appMCPWorkspaceChoice{id, name}
	}
	sort.SliceStable(choices, func(i, j int) bool {
		a, b := strings.ToLower(choices[i].Name), strings.ToLower(choices[j].Name)
		return a < b || a == b && choices[i].ID < choices[j].ID
	})
	writeAppMCPPage(w, app, http.StatusOK, appMCPPickerPage, appMCPPageOpts{Title: "Choose a workspace", Referrer: "same-origin"},
		map[string]any{"Client": p.clientName, "Fields": appMCPOAuthPageFields(appMCPOAuthFields(p)), "Workspaces": choices})
}

// appMCPOAuthRefuse is the styled page for a refused authorization step. The
// statuses are the ones these steps always used.
func appMCPOAuthRefuse(w http.ResponseWriter, app *App, status int, title, message string) {
	writeAppMCPError(w, app, status, title, message)
}

const appMCPOAuthRestart = "Go back to your assistant and start the connection again."

func appMCPOAuthAuthorize(w http.ResponseWriter, r *http.Request, app *App, resource string) {
	w.Header().Set("Cache-Control", "no-store")
	if !appMCPOAuthHost(r, app, resource) {
		appMCPOAuthRefuse(w, app, 400, "This connection link isn't valid", appMCPOAuthRestart)
		return
	}
	values := r.URL.Query()
	p, err := parseAppMCPOAuthRequestFor(r.Context(), app, values, resource)
	if err != nil {
		appMCPOAuthRefuse(w, app, 400, "This connection link isn't valid", "The request is incomplete or has expired. "+appMCPOAuthRestart)
		return
	}
	session := getSession(app, r)
	if session == nil {
		http.Redirect(w, r, app.Paths.Login+"?next="+url.QueryEscape(r.URL.RequestURI()), 302)
		return
	}
	session = appMCPDirectOAuthSessionFor(r.Context(), app, session)
	if session == nil {
		appMCPOAuthRefuse(w, app, 403, "Sign in directly to connect an app",
			"Connecting an assistant needs your own sign-in to "+appSiteName(app)+", not a support or admin session. Sign out, sign back in, then try again.")
		return
	}
	tenant := ""
	if app.Group != nil && app.Group.Table != "" {
		if len(values["workspace"]) > 1 {
			appMCPOAuthRefuse(w, app, 400, "This connection link isn't valid", appMCPOAuthRestart)
			return
		}
		tenant = values.Get("workspace")
		if tenant == "" {
			workspaces, err := appMCPOAuthWorkspacesFor(r.Context(), app, session)
			if err != nil || len(workspaces) == 0 {
				appMCPOAuthRefuse(w, app, 403, "No workspace available",
					"Your account doesn't belong to a workspace in "+appSiteName(app)+" yet, so there is nothing to connect. Ask a workspace admin to add you.")
				return
			}
			if len(workspaces) > 1 {
				appMCPOAuthChooser(w, r, app, p, workspaces)
				return
			}
			// One workspace: nothing to choose. It came from this session's own
			// membership, and prepareAppMCPOAuthConsentFor below re-checks it
			// exactly as it does for a workspace the person picked.
			tenant = workspaces[0]
		}
	}
	consent, err := prepareAppMCPOAuthConsentFor(r.Context(), app, session, values, resource, tenant, time.Now())
	if err != nil {
		appMCPOAuthRefuse(w, app, 403, "This authorization can't be completed", appMCPOAuthRestart)
		return
	}
	fields := appMCPOAuthFields(consent.Params)
	fields["workspace"], fields["connector_nonce"], fields["consent"] = tenant, consent.Nonce, consent.Token
	redirect, _ := url.Parse(p.RedirectURI)
	scopeText := consent.Params.Scope
	if tenant != "" {
		name := appMCPOAuthWorkspaceLabels(r.Context(), app, []string{tenant})[tenant]
		if name == "" {
			name = tenant
		}
		scopeText += " in workspace " + name
	}
	autoApprove := ""
	if len(consent.AutoApprove) > 0 {
		// Unticked by default; a plain checkbox, so the page needs no script.
		autoApprove = strings.Join(consent.AutoApprove, ", ")
	}
	writeAppMCPPage(w, app, http.StatusOK, appMCPConsentPage,
		// The POST's 302 back to the client is governed by form-action too.
		appMCPPageOpts{Title: "Authorize access", Referrer: "same-origin", FormAction: oauthConsentFormAction(fields["redirect_uri"])},
		map[string]any{"Client": p.clientName, "Subject": session.Email, "Host": redirect.Host, "Scope": scopeText,
			"Fields": appMCPOAuthPageFields(fields), "AutoApprove": autoApprove,
			// html/template drops comments in the template text; Cloudflare's
			// email obfuscation needs these markers around the address.
			"EmailOpen": template.HTML("<!--email_off-->"), "EmailClose": template.HTML("<!--/email_off-->")})
}
func appMCPOAuthSingleFields(values url.Values, keys ...string) bool {
	for _, key := range keys {
		if len(values[key]) != 1 || len(values[key][0]) > 8192 || !utf8.ValidString(values[key][0]) || strings.ContainsRune(values[key][0], 0) {
			return false
		}
	}
	return true
}
func appMCPOAuthDecision(w http.ResponseWriter, r *http.Request, app *App, resource string) {
	w.Header().Set("Cache-Control", "no-store")
	values := r.PostForm
	// Consent is same-origin and request/body-only; query parameters cannot
	// substitute any part of the signed form or its selected workspace.
	if !appMCPOAuthHost(r, app, resource) || r.URL.RawQuery != "" || !sameOriginPost(r) || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != appMCPOAuthOrigin(resource)) || !appMCPOAuthSingleFields(values, "workspace", "connector_nonce", "consent", "decision") {
		appMCPOAuthRefuse(w, app, 403, "This authorization can't be completed", "The request may have expired or been changed. "+appMCPOAuthRestart)
		return
	}
	// The checkbox is absent when unticked; a ticked one sends exactly "1".
	autoApprove := false
	switch box := values["auto_approve"]; {
	case len(box) == 0:
	case len(box) == 1 && box[0] == "1":
		autoApprove = true
	default:
		appMCPOAuthRefuse(w, app, 403, "This authorization can't be completed", "The request may have expired or been changed. "+appMCPOAuthRestart)
		return
	}
	session := getSession(app, r)
	var code string
	var err error
	switch values.Get("decision") {
	case "approve":
		code, err = approveAppMCPOAuthConsentFor(r.Context(), app, session, values, resource, values.Get("workspace"), values.Get("connector_nonce"), values.Get("consent"), time.Now(), autoApprove)
	case "deny":
		_, err = consumeAppMCPOAuthConsentFor(r.Context(), app, session, values, resource, values.Get("workspace"), values.Get("connector_nonce"), values.Get("consent"), time.Now())
	default:
		err = errAppMCPGrantDenied
	}
	if err != nil {
		appMCPOAuthRefuse(w, app, 403, "This authorization can't be completed", "The request may have expired or been changed. "+appMCPOAuthRestart)
		return
	}
	redirect, _ := url.Parse(values.Get("redirect_uri"))
	query := redirect.Query()
	query.Set("state", values.Get("state"))
	if code != "" {
		query.Set("code", code)
	} else {
		query.Set("error", "access_denied")
	}
	redirect.RawQuery = query.Encode()
	http.Redirect(w, r, redirect.String(), 302)
}
func appMCPOAuthToken(w http.ResponseWriter, r *http.Request, app *App, resource string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	values := r.PostForm
	if !appMCPOAuthHost(r, app, resource) || r.URL.RawQuery != "" || !appMCPOAuthSingleFields(values, "grant_type", "client_id", "resource") || values.Get("resource") != resource {
		httpJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	now := time.Now()
	var pair *appMCPTokenPair
	var err error
	switch values.Get("grant_type") {
	case "authorization_code":
		if !appMCPOAuthSingleFields(values, "code", "redirect_uri", "code_verifier") {
			httpJSON(w, 400, map[string]any{"error": "invalid_request"})
			return
		}
		pair, err = exchangeAppMCPOAuthCodeFor(r.Context(), app, values.Get("code"), values.Get("client_id"), values.Get("redirect_uri"), resource, values.Get("code_verifier"), resource, now)
	case "refresh_token":
		if !appMCPOAuthSingleFields(values, "refresh_token") || len(values["scope"]) > 1 || (len(values["scope"]) == 1 && !appMCPOAuthSingleFields(values, "scope")) {
			httpJSON(w, 400, map[string]any{"error": "invalid_request"})
			return
		}
		pair, err = refreshAppMCPGrantFor(r.Context(), app, values.Get("refresh_token"), values.Get("client_id"), resource, values.Get("scope"), now)
	default:
		httpJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
		return
	}
	if err != nil {
		httpJSON(w, 400, map[string]any{"error": "invalid_grant"})
		return
	}
	httpJSON(w, 200, map[string]any{"access_token": pair.AccessToken, "refresh_token": pair.RefreshToken, "token_type": "Bearer", "expires_in": pair.AccessExpiresAt - now.Unix(), "scope": pair.Scopes})
}
func appMCPOAuthRevoke(w http.ResponseWriter, r *http.Request, app *App, resource string) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if r.ParseForm() != nil || !appMCPOAuthHost(r, app, resource) || r.URL.RawQuery != "" || !appMCPOAuthSingleFields(r.PostForm, "client_id", "resource", "token") || r.PostForm.Get("resource") != resource {
		httpJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	raw := r.PostForm.Get("token")
	kind := "access"
	if strings.HasPrefix(raw, "bmcr_") {
		kind = "refresh"
	}
	hash, err := appMCPCredentialHash(raw, kind)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	grant, err := readAppMCPCredentialGrant(r.Context(), app, hash, kind, resource, time.Now(), false)
	if errors.Is(err, errAppMCPGrantDenied) {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err != nil {
		serverErrorCode(w, r, app, "connector oauth revoke", err, "server_error")
		return
	}
	if grant.Client == r.PostForm.Get("client_id") && grant.Resource == resource {
		if err := revokeAppMCPGrant(app, grant.ID); err != nil {
			serverErrorCode(w, r, app, "connector oauth revoke", err, "server_error")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}
