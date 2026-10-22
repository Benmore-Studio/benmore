//go:build !cli

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mattn/go-sqlite3"
)

// Browser consent and code exchange remain separate from legacy broad OAuth.
// These helpers receive their resource from trusted app route registration.
type appMCPOAuthConsent struct {
	Nonce, Token, Tenant string
	Params               oauthAuthorizeParams
	// AutoApprove is what the consent page may offer to auto-approve; the
	// same list is stored in the server-side binding, so the form can only
	// accept or decline it, never name another tool.
	AutoApprove []string
}
type appMCPOAuthBinding struct {
	Version                  int
	Grant                    appMCPGrant
	Params                   oauthAuthorizeParams
	SessionHash, ConsentHash string
}

func validAppMCPPKCEChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == challenge
}
func validAppMCPPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, c := range verifier {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}
func validAppMCPOAuthRedirect(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" || parsed.String() != raw {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(parsed.Hostname())
	return parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || ip != nil && ip.IsLoopback())
}
func parseAppMCPOAuthRequest(app *App, values url.Values, resource string) (oauthAuthorizeParams, error) {
	return parseAppMCPOAuthRequestFor(context.Background(), app, values, resource)
}

func parseAppMCPOAuthRequestFor(ctx context.Context, app *App, values url.Values, resource string) (oauthAuthorizeParams, error) {
	var empty oauthAuthorizeParams
	if appMCPManifestSnapshot(app) == nil || !validAppMCPResource(app, resource) {
		return empty, errAppMCPGrantDenied
	}
	for _, key := range []string{"response_type", "client_id", "redirect_uri", "state", "scope", "code_challenge", "code_challenge_method", "resource"} {
		if len(values[key]) != 1 || len(values[key][0]) > 8192 || !utf8.ValidString(values[key][0]) || strings.ContainsRune(values[key][0], 0) {
			return empty, errAppMCPGrantDenied
		}
	}
	if values.Get("resource") != resource || values.Get("scope") == "" || values.Get("state") == "" || len(values.Get("state")) > 512 || !validAppMCPPKCEChallenge(values.Get("code_challenge")) || !validAppMCPOAuthRedirect(values.Get("redirect_uri")) {
		return empty, errAppMCPGrantDenied
	}
	// Client-defined scopes with no resource part (claude.ai's "claudeai",
	// openid, offline_access) can never name an app permission, so they are
	// dropped; when nothing else is asked for, the client's registered scopes
	// are used. Anything shaped like an app scope stays strictly checked.
	var named []string
	for _, scope := range strings.Fields(values.Get("scope")) {
		if scope == "*" || strings.Contains(scope, ":") {
			named = append(named, scope)
		}
	}
	defaultScopes := len(named) == 0
	requested, err := appMCPExplicitScopes(strings.Join(named, " "))
	if defaultScopes {
		requested, err = nil, nil
	}
	if err != nil {
		return empty, err
	}
	known := strings.Fields(appMCPLiveScopes(app, appMCPManifestSnapshot(app), snapshotAppMCPGeneration(app)))
	for _, scope := range requested {
		found := false
		for _, supported := range known {
			if scope == supported {
				found = true
				break
			}
		}
		if !found {
			return empty, errAppMCPGrantDenied
		}
	}
	q, closeRead, err := openAppMCPOAuthRead(ctx, app)
	if err != nil {
		return empty, errAppMCPGrantDenied
	}
	defer closeRead()
	p, status, _ := appParseAuthorizeWith(q, values, true)
	if status != 0 {
		return empty, errAppMCPGrantDenied
	}
	clientScopes := p.clientScopes
	if defaultScopes {
		for _, scope := range strings.Fields(clientScopes) {
			if slices.Contains(known, scope) {
				requested = append(requested, scope)
			}
		}
		sort.Strings(requested)
		if len(requested) == 0 {
			return empty, errAppMCPGrantDenied
		}
	}
	if q.ctx.Err() != nil || clientScopes == "" || validateScopes(clientScopes) != nil || !scopesWithin(clientScopes, strings.Join(requested, " ")) || len(p.ClientID) > 256 {
		return empty, errAppMCPGrantDenied
	}
	p.Scope = strings.Join(requested, " ")
	return p, nil
}
func appMCPDirectOAuthSession(app *App, session *Session) *Session {
	return appMCPDirectOAuthSessionFor(context.Background(), app, session)
}

func appMCPDirectOAuthSessionFor(ctx context.Context, app *App, session *Session) *Session {
	if session == nil || session.ID == "" || session.connectorGrant {
		return nil
	}
	q, closeRead, err := openAppMCPOAuthRead(ctx, app)
	if err != nil {
		return nil
	}
	defer closeRead()
	current := loadStoredSessionWith(q, true, session.ID)
	if current == nil || current.UserID != session.UserID || !directLoginSessionWith(q, current, true) || q.ctx.Err() != nil {
		return nil
	}
	return current
}
func appMCPOAuthConsentSubject(session *Session, binding *appMCPOAuthBinding, nonce string) string {
	value, _ := json.Marshal([]string{appOAuthSubject(session), binding.Grant.App, binding.Grant.Epoch, binding.Grant.Tenant, nonce, binding.SessionHash})
	return "connector-consent:" + hashBytesSHA256(value)
}
func storeAppMCPOAuthAuthorization(app *App, raw, kind string, binding *appMCPOAuthBinding, expiry int64) error {
	return storeAppMCPOAuthAuthorizationFor(context.Background(), app, raw, kind, binding, expiry, time.Now())
}

func storeAppMCPOAuthAuthorizationFor(ctx context.Context, app *App, raw, kind string, binding *appMCPOAuthBinding, expiry int64, now time.Time) error {
	key, err := appMCPCredentialHash(raw, kind)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(binding)
	if err != nil || len(payload) > appMCPInputLimit {
		return errAppMCPGrantDenied
	}
	// Every consent page load stores a row; expired consents and codes can
	// never be claimed, so drop them before adding one to keep the table bounded.
	if _, err := app.DB.ExecContext(ctx, "DELETE FROM main._benmore_mcp_authorizations WHERE expires_at<=?", now.Unix()); err != nil {
		return err
	}
	_, err = app.DB.ExecContext(ctx, "INSERT INTO main._benmore_mcp_authorizations(key_hash,kind,user_id,app,payload,expires_at) VALUES(?,?,?,?,?,?)", key, kind, binding.Grant.UserID, binding.Grant.App, string(payload), expiry)
	return err
}
func readAppMCPOAuthAuthorization(app *App, raw, kind string, now time.Time) (*appMCPOAuthBinding, string, error) {
	return readAppMCPOAuthAuthorizationFor(context.Background(), app, raw, kind, now)
}

func readAppMCPOAuthAuthorizationFor(ctx context.Context, app *App, raw, kind string, now time.Time) (*appMCPOAuthBinding, string, error) {
	key, err := appMCPCredentialHash(raw, kind)
	if err != nil {
		return nil, "", err
	}
	q, closeRead, err := openAppMCPOAuthRead(ctx, app)
	if err != nil {
		return nil, "", errAppMCPGrantDenied
	}
	defer closeRead()
	var payload, appKey string
	var userID int64
	if q.QueryRow("SELECT payload,user_id,app FROM main._benmore_mcp_authorizations WHERE key_hash=? AND kind=? AND used=0 AND expires_at>?", key, kind, now.Unix()).Scan(&payload, &userID, &appKey) != nil || len(payload) > appMCPInputLimit {
		return nil, "", errAppMCPGrantDenied
	}
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.DisallowUnknownFields()
	var binding appMCPOAuthBinding
	if decoder.Decode(&binding) != nil || decoder.Decode(new(any)) != io.EOF || binding.Version != 1 || binding.Grant.UserID != userID || binding.Grant.App != appKey || binding.Grant.Client != binding.Params.ClientID || binding.Grant.Resource != binding.Params.Resource || binding.Grant.Scopes != binding.Params.Scope {
		return nil, "", errAppMCPGrantDenied
	}
	return &binding, payload, nil
}

// One conditional write claims the immutable payload, even on deferred WAL.
// There is no open transaction while account/role helpers or grant minting run.
func claimAppMCPOAuthAuthorization(app *App, raw, kind, payload string, now time.Time) error {
	return claimAppMCPOAuthAuthorizationFor(context.Background(), app, raw, kind, payload, now)
}

func claimAppMCPOAuthAuthorizationFor(ctx context.Context, app *App, raw, kind, payload string, now time.Time) error {
	key, err := appMCPCredentialHash(raw, kind)
	if err != nil {
		return err
	}
	var claimed string
	if app.DB.QueryRowContext(ctx, "UPDATE main._benmore_mcp_authorizations SET used=1 WHERE key_hash=? AND kind=? AND payload=? AND used=0 AND expires_at>? RETURNING key_hash", key, kind, payload, now.Unix()).Scan(&claimed) != nil || claimed != key {
		return errAppMCPGrantDenied
	}
	return nil
}
func prepareAppMCPOAuthConsent(app *App, session *Session, values url.Values, resource, tenant string, now time.Time) (*appMCPOAuthConsent, error) {
	return prepareAppMCPOAuthConsentFor(context.Background(), app, session, values, resource, tenant, now)
}

func prepareAppMCPOAuthConsentFor(ctx context.Context, app *App, session *Session, values url.Values, resource, tenant string, now time.Time) (*appMCPOAuthConsent, error) {
	session = appMCPDirectOAuthSessionFor(ctx, app, session)
	if session == nil {
		return nil, errAppMCPGrantDenied
	}
	p, err := parseAppMCPOAuthRequestFor(ctx, app, values, resource)
	if err != nil {
		return nil, err
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil || !state.Exposed {
		return nil, errAppMCPGrantDenied
	}
	grant := appMCPGrant{App: state.App, Epoch: state.Epoch, UserID: session.UserID, Tenant: tenant, Client: p.ClientID, Resource: resource, Scopes: p.Scope, ExpiresAt: now.Add(oauthConsentTTL).Unix()}
	grant.UserCreated, err = readAppMCPUserCreatedFor(ctx, app, session.UserID)
	if err != nil {
		return nil, errAppMCPGrantDenied
	}
	actor, err := appMCPGrantActorFor(ctx, app, &grant, now)
	if err != nil {
		return nil, err
	}
	p.Scope = actor.Scopes
	grant.Scopes = p.Scope
	offer, offerEpoch := appMCPAutoApproveOffer(app, snapshotAppMCPGeneration(app), grant.Scopes)
	grant.AutoApprove, grant.AutoApproveEpoch = strings.Join(offer, " "), offerEpoch
	var offerNames []string
	for _, entry := range offer {
		offerNames = append(offerNames, appMCPAutoApproveDisplayName(entry))
	}
	nonce, err := appMCPRandomToken("bmcs_")
	if err != nil {
		return nil, err
	}
	binding := &appMCPOAuthBinding{Version: 1, Grant: grant, Params: p, SessionHash: hashBytesSHA256([]byte(session.ID))}
	token := mintOAuthConsent(appMCPOAuthConsentSubject(session, binding, nonce), p, now)
	binding.ConsentHash = hashBytesSHA256([]byte(token))
	if err := storeAppMCPOAuthAuthorizationFor(ctx, app, nonce, "consent", binding, grant.ExpiresAt, now); err != nil {
		return nil, err
	}
	if validateAppMCPEpoch(app.Dir, grant.Epoch) != nil {
		return nil, errAppMCPGrantDenied
	}
	return &appMCPOAuthConsent{Nonce: nonce, Token: token, Tenant: tenant, Params: p, AutoApprove: offerNames}, nil
}
func consumeAppMCPOAuthConsent(app *App, session *Session, values url.Values, resource, tenant, nonce, token string, now time.Time) (*appMCPOAuthBinding, error) {
	return consumeAppMCPOAuthConsentFor(context.Background(), app, session, values, resource, tenant, nonce, token, now)
}

func consumeAppMCPOAuthConsentFor(ctx context.Context, app *App, session *Session, values url.Values, resource, tenant, nonce, token string, now time.Time) (*appMCPOAuthBinding, error) {
	session = appMCPDirectOAuthSessionFor(ctx, app, session)
	if session == nil {
		return nil, errAppMCPGrantDenied
	}
	binding, payload, err := readAppMCPOAuthAuthorizationFor(ctx, app, nonce, "consent", now)
	if err != nil {
		return nil, err
	}
	p, err := parseAppMCPOAuthRequestFor(ctx, app, values, resource)
	if err != nil || tenant != binding.Grant.Tenant || session.UserID != binding.Grant.UserID || !SecureCompare(binding.SessionHash, hashBytesSHA256([]byte(session.ID))) || !SecureCompare(binding.ConsentHash, hashBytesSHA256([]byte(token))) || oauthConsentDigest("", p) != oauthConsentDigest("", binding.Params) || !verifyOAuthConsent(token, appMCPOAuthConsentSubject(session, binding, nonce), p, now) {
		return nil, errAppMCPGrantDenied
	}
	actor, err := appMCPGrantActorFor(ctx, app, &binding.Grant, now)
	if err != nil || actor.Scopes != binding.Grant.Scopes {
		return nil, errAppMCPGrantDenied
	}
	if err := claimAppMCPOAuthAuthorizationFor(ctx, app, nonce, "consent", payload, now); err != nil {
		return nil, err
	}
	return binding, nil
}

func approveAppMCPOAuthConsent(app *App, session *Session, values url.Values, resource, tenant, nonce, token string, now time.Time) (string, error) {
	return approveAppMCPOAuthConsentFor(context.Background(), app, session, values, resource, tenant, nonce, token, now, false)
}

// approveAppMCPOAuthConsentFor issues the code. autoApprove is the consent
// page's checkbox: unticked clears the offered list; ticked keeps only what the
// server offered and still offers now, under the same owner epoch and
// manifest digest. It can never add a tool.
func approveAppMCPOAuthConsentFor(ctx context.Context, app *App, session *Session, values url.Values, resource, tenant, nonce, token string, now time.Time, autoApprove bool) (string, error) {
	binding, err := consumeAppMCPOAuthConsentFor(ctx, app, session, values, resource, tenant, nonce, token, now)
	if err != nil {
		return "", err
	}
	if autoApprove {
		appMCPNarrowGrantAutoApprove(app, &binding.Grant)
	} else {
		binding.Grant.AutoApprove, binding.Grant.AutoApproveEpoch = "", ""
	}
	code, err := appMCPRandomToken("bmcc_")
	if err != nil {
		return "", err
	}
	binding.Grant.ExpiresAt = now.Add(appOAuthCodeTTL).Unix()
	if err := storeAppMCPOAuthAuthorizationFor(ctx, app, code, "code", binding, binding.Grant.ExpiresAt, now); err != nil {
		return "", err
	}
	if validateAppMCPEpoch(app.Dir, binding.Grant.Epoch) != nil {
		return "", errAppMCPGrantDenied
	}
	return code, nil
}
func exchangeAppMCPOAuthCode(app *App, raw, client, redirect, resource, verifier, pinnedResource string, now time.Time) (*appMCPTokenPair, error) {
	return exchangeAppMCPOAuthCodeFor(context.Background(), app, raw, client, redirect, resource, verifier, pinnedResource, now)
}

func exchangeAppMCPOAuthCodeFor(ctx context.Context, app *App, raw, client, redirect, resource, verifier, pinnedResource string, now time.Time) (*appMCPTokenPair, error) {
	binding, payload, err := readAppMCPOAuthAuthorizationFor(ctx, app, raw, "code", now)
	if err != nil {
		return nil, err
	}
	// As with canonical legacy OAuth, a presented code is burned on failure.
	if err := claimAppMCPOAuthAuthorizationFor(ctx, app, raw, "code", payload, now); err != nil {
		return nil, err
	}
	if resource != pinnedResource || binding.Params.Resource != resource || binding.Params.ClientID != client || binding.Params.RedirectURI != redirect || !validAppMCPPKCEVerifier(verifier) || !SecureCompare(oauthPKCEChallenge(verifier), binding.Params.CodeChallenge) {
		return nil, errAppMCPGrantDenied
	}
	values := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {redirect}, "state": {binding.Params.State}, "scope": {binding.Params.Scope}, "code_challenge": {binding.Params.CodeChallenge}, "code_challenge_method": {"S256"}, "resource": {resource}}
	if _, err := parseAppMCPOAuthRequestFor(ctx, app, values, pinnedResource); err != nil {
		return nil, err
	}
	if _, err := appMCPGrantActorFor(ctx, app, &binding.Grant, now); err != nil {
		return nil, err
	}
	grant := binding.Grant
	grant.ID, err = appMCPRandomToken("")
	if err != nil {
		return nil, err
	}
	grant.ExpiresAt = now.Add(appMCPGrantLifetime).Unix()
	return persistAppMCPGrantFor(ctx, app, &grant, now)
}

// Reuses the canonical SQLite lease and rollback cleanup; all OAuth authority
// queries for a single read operation share its deferred snapshot.
func openAppMCPOAuthRead(ctx context.Context, app *App) (*appMCPActorQuerier, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, readOnlyQueryTimeout)
	if app == nil || app.DB == nil {
		cancel()
		return nil, nil, errAppMCPGrantDenied
	}
	conn, _, closeConn, err := openReadOnlyQueryConn(ctx, app.DB)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	closeRead := func() { rollbackAppMCPReadConn(conn); closeConn(); cancel() }
	if err = conn.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(authorizeAppMCPOAuth); return nil }); err == nil {
		_, err = conn.ExecContext(ctx, "BEGIN")
	}
	if err != nil {
		closeRead()
		return nil, nil, err
	}
	return &appMCPActorQuerier{ctx: ctx, conn: conn}, closeRead, nil
}

func authorizeAppMCPOAuth(action int, arg1, arg2, database string) int {
	if action == sqlite3.SQLITE_READ && database == "main" &&
		(strings.EqualFold(arg1, "_benmore_sessions") && strings.EqualFold(arg2, "id") ||
			strings.EqualFold(arg1, "_benmore_mcp_authorizations") && strings.EqualFold(arg2, "key_hash")) {
		return sqlite3.SQLITE_OK
	}
	return authorizeAppMCPActor(action, arg1, arg2, database)
}

func readAppMCPUserCreatedFor(ctx context.Context, app *App, userID int64) (string, error) {
	q, closeRead, err := openAppMCPOAuthRead(ctx, app)
	if err != nil {
		return "", errAppMCPGrantDenied
	}
	defer closeRead()
	var created string
	if q.QueryRow("SELECT COALESCE(created_at,'') FROM main._benmore_users WHERE id=?", userID).Scan(&created) != nil || created == "" || q.ctx.Err() != nil {
		return "", errAppMCPGrantDenied
	}
	return created, nil
}
