//go:build !cli

package main

// Router -> app data channel, app side.
//
// The platform router must not open tenant databases (router isolation). It
// asks the app instance's own process instead: POST /api/_internal/data with
// one named, typed operation. The process that owns data.db runs the
// operation with its own connection pool, encryption key, storage ceiling and
// SQL guards, and writes the audit row for every mutating operation.
//
// Trust model. The router authorizes the platform user for this app with the
// existing gates (owner/collaborator role, dashboard session, MCP scopes)
// BEFORE it calls; the request names that actor and the app applies the
// operation-level rules on top (viewer = read-only operations; writes need
// editor or owner; the same statement gates, row caps and timeouts as the
// router used). A request is accepted only with a token the router minted:
//
//   - HMAC-SHA256 with a purpose key derived from THIS instance's server
//     secret, so it never verifies as any other token signed with that secret
//     (import, types, connector control) and never at another instance;
//   - audience = this instance's app directory;
//   - expiry at most appDataTokenTTL ahead;
//   - bound to the SHA-256 of the exact request body (operation, actor and
//     arguments), so a captured token authorizes nothing else;
//   - a random nonce accepted once per process (appDataNonces).
//
// The route is served only by hosted tenant processes (BENMORE_BIND_LOOPBACK),
// only to loopback peers, and never to a request the router proxied from the
// public front door (those carry X-Benmore-App / X-Forwarded-*); the router
// and `benmore host` also refuse the path on public requests
// (isAppDataChannelPath). It sits in front of the whole middleware chain, so
// no tenant flow or page can claim the path and the request log, rate limiter
// and demo gate never see it. No cookie, CSRF token, API token or in-app admin
// session reaches it. Under `benmore host` the router side calls
// appDataDispatch in process instead of over HTTP.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	appDataRoute = "/api/_internal/data"
	// appDataTokenHeader carries the router-minted token.
	appDataTokenHeader = "X-Benmore-Data-Token"
	// appDataChannelHeader is set on every answer from the channel, refusals
	// included, so the router can tell "this runtime has no channel yet"
	// (an older binary during a rollout) from an operation's own error.
	appDataChannelHeader = "X-Benmore-Data-Channel"
	// appDataMACHeader carries the answer's MAC (appDataResponseMAC): only the
	// process holding the instance's secret, which accepted this request's
	// nonce, can produce it, so a process that took over a stopped
	// instance's port cannot hand the router a fabricated answer.
	appDataMACHeader = "X-Benmore-Data-MAC"
	appDataTokenTTL  = 60 * time.Second
	// appDataMaxRequestBytes admits the largest MCP request (8 MiB) plus the
	// envelope, so moving a tool onto the channel shortens no statement.
	appDataMaxRequestBytes = 9 << 20
	// appDataNonceCap bounds the replay cache. Entries live at most
	// appDataTokenTTL; a full cache refuses new tokens (fails closed).
	appDataNonceCap = 1 << 16
	// appDataDefaultTimeout bounds an operation that declares none.
	appDataDefaultTimeout = 30 * time.Second
	appDataTokenTag       = "appdata"
	// appDataMaxConcurrent bounds the channel operations one app process runs
	// at once, so platform reads cannot take every connection of the pool
	// that serves the app's own traffic (they used to run on the router's
	// separate pool).
	appDataMaxConcurrent = 4
)

// appDataRoles are the platform collaborator roles an actor may carry.
var appDataRoles = map[string]int{"viewer": 1, "editor": 2, "owner": 3}

// appDataSurfaces name where the call came from (recorded in audit rows).
var appDataSurfaces = map[string]bool{"mcp": true, "dashboard": true, "ops": true}

// appDataActor is the platform user the router authorized for this call.
type appDataActor struct {
	PlatformUserID int64  `json:"platform_user_id"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	Surface        string `json:"surface"`
}

type appDataRequest struct {
	Op        string          `json:"op"`
	Actor     appDataActor    `json:"actor"`
	Args      json.RawMessage `json:"args,omitempty"`
	RequestID string          `json:"request_id"`
}

type appDataResponse struct {
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
	Message string          `json:"message,omitempty"`
	// release frees the router's large-answer slot once the caller has
	// decoded Result (nil when none was taken).
	release func()
}

// appDataError is an operation's refusal or failure. Code is a fixed word the
// router branches on; Message is what the caller already showed users for
// the same failure.
type appDataError struct {
	Code    string
	Message string
	// known is the caller-side sentinel error this refusal stands for, so
	// errors.Is keeps working across the process boundary.
	known error
}

func (e *appDataError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

func (e *appDataError) Unwrap() error { return e.known }

func appDataFail(code, format string, args ...any) *appDataError {
	return &appDataError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// appDataStatus maps an error code to the HTTP status of the answer. The
// router branches on the code; the status keeps logs readable.
func appDataStatus(code string) int {
	switch code {
	case "bad_request", "rejected":
		return http.StatusBadRequest
	case "forbidden":
		return http.StatusForbidden
	case "not_found":
		return http.StatusNotFound
	case "conflict":
		return http.StatusConflict
	case "timeout":
		return http.StatusGatewayTimeout
	case "busy":
		return http.StatusServiceUnavailable
	case "storage_full":
		return storageFullStatus
	case "too_large":
		return http.StatusRequestEntityTooLarge
	case "unsupported":
		return http.StatusNotImplemented
	case "query_failed", "exec_failed":
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}

// appDataOpCall is one operation's view of its request.
type appDataOpCall struct {
	App       *App
	Actor     appDataActor
	Args      json.RawMessage
	RequestID string
	audited   bool
}

// decodeArgs strictly decodes the operation's arguments: an unknown field is
// never silently ignored. It is "unsupported" (this runtime predates it), so a
// newer router can tell that nothing ran; every operation decodes before it
// does anything.
func (c *appDataOpCall) decodeArgs(dst any) *appDataError {
	if len(c.Args) == 0 || string(c.Args) == "null" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(c.Args)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if appDataUnknownField(err) {
			return appDataFail("unsupported", "unsupported argument: %s", err.Error())
		}
		return appDataFail("bad_request", "invalid arguments: %s", err.Error())
	}
	if dec.More() {
		return appDataFail("bad_request", "invalid arguments: trailing data")
	}
	return nil
}

// appDataUnknownField reports a strict decode's unknown-field refusal.
func appDataUnknownField(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "json: unknown field ")
}

// session is the audit identity of the platform actor: no app user id, the
// platform email (the same shape the connector switches record).
func (c *appDataOpCall) session() *Session {
	return &Session{Email: c.Actor.Email}
}

// audit records a mutating operation, inside the operation's own transaction
// when exec is one.
func (c *appDataOpCall) audit(exec sqlExecutor, action, table, rowID string, values map[string]any) error {
	if exec == nil || exec == sqlExecutor((*sql.DB)(nil)) {
		return fmt.Errorf("no database to record the audit row in")
	}
	if values == nil {
		values = map[string]any{}
	}
	values["surface"] = c.Actor.Surface
	values["role"] = c.Actor.Role
	if c.Actor.PlatformUserID != 0 {
		values["platform_user_id"] = c.Actor.PlatformUserID
	}
	if c.RequestID != "" {
		values["request_id"] = c.RequestID
	}
	b, err := json.Marshal(values)
	if err != nil {
		return err
	}
	if err := insertAuditRowChecked(exec, action, table, rowID, c.session(), "", string(b)); err != nil {
		return err
	}
	c.audited = true
	return nil
}

// A tenant answer is bounded by structure as well as bytes: decoding grows
// it, and three bytes of `{}` became a whole typed row that the router wrote
// out again (a 63 MiB answer of them made the router hold over 9 GiB).
// appDataDefaultAnswerTokens and appDataLargeAnswerTokens (operations that
// return query rows, schemas or documents) bound the tokens the router's
// appDataAnswerWithin counts before it decodes an answer.
const (
	appDataDefaultAnswerTokens = 250_000
	appDataLargeAnswerTokens   = 2_000_000
)

// appDataOp is one named operation. Mutating operations need at least editor
// and must audit; read operations may allow viewer.
type appDataOp struct {
	MinRole  string
	Mutating bool
	Timeout  time.Duration
	// AnswerTokens bounds the JSON structure of the answer the router accepts
	// (see appDataAnswerWithin); 0 is appDataDefaultAnswerTokens.
	AnswerTokens int
	Run          func(ctx context.Context, c *appDataOpCall) (any, error)
}

var (
	appDataOpsMu sync.RWMutex
	appDataOps   = map[string]appDataOp{}
)

// registerAppDataOp adds an operation. Operation code is compiled into both
// the router and the app processes (one binary), so the router reads the same
// table for timeouts. It panics on a malformed registration: that is a
// programming error caught by any test that loads the package.
func registerAppDataOp(name string, op appDataOp) {
	if name == "" || op.Run == nil || appDataRoles[op.MinRole] == 0 {
		panic("registerAppDataOp: malformed operation " + name)
	}
	if op.Mutating && appDataRoles[op.MinRole] < appDataRoles["editor"] {
		panic("registerAppDataOp: mutating operation " + name + " must require editor or owner")
	}
	appDataOpsMu.Lock()
	defer appDataOpsMu.Unlock()
	if _, dup := appDataOps[name]; dup {
		panic("registerAppDataOp: duplicate operation " + name)
	}
	appDataOps[name] = op
}

func lookupAppDataOp(name string) (appDataOp, bool) {
	appDataOpsMu.RLock()
	defer appDataOpsMu.RUnlock()
	op, ok := appDataOps[name]
	return op, ok
}

// appDataOpAnswerTokens is the structural bound of the named operation's
// answer.
func appDataOpAnswerTokens(name string) int {
	if op, ok := lookupAppDataOp(name); ok && op.AnswerTokens > 0 {
		return op.AnswerTokens
	}
	return appDataDefaultAnswerTokens
}

// appDataOpTimeout is how long the named operation may run.
func appDataOpTimeout(name string) time.Duration {
	if op, ok := lookupAppDataOp(name); ok && op.Timeout > 0 {
		return op.Timeout
	}
	return appDataDefaultTimeout
}

// appDataOpNames lists the registered operations (tests, docs).
func appDataOpNames() []string {
	appDataOpsMu.RLock()
	defer appDataOpsMu.RUnlock()
	names := make([]string, 0, len(appDataOps))
	for name := range appDataOps {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validAppDataRequestID accepts the router's hex ids and similar short tokens.
func validAppDataRequestID(id string) bool {
	if len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// decodeAppDataRequest parses and validates the envelope.
func decodeAppDataRequest(body []byte) (appDataRequest, appDataOp, *appDataError) {
	var req appDataRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if appDataUnknownField(err) {
			return req, appDataOp{}, appDataFail("unsupported", "unsupported request field: %s", err.Error())
		}
		return req, appDataOp{}, appDataFail("bad_request", "invalid request: %s", err.Error())
	}
	if dec.More() {
		return req, appDataOp{}, appDataFail("bad_request", "invalid request: trailing data")
	}
	op, ok := lookupAppDataOp(req.Op)
	if !ok {
		// A newer router asking an older runtime: nothing ran.
		return req, appDataOp{}, appDataFail("unsupported", "unknown operation %q", req.Op)
	}
	a := req.Actor
	// A role or surface this runtime does not know is a newer router's (as
	// with an unknown operation): unsupported, so nothing runs and the router
	// can tell it apart from a refusal.
	if appDataRoles[a.Role] == 0 {
		return req, op, appDataFail("unsupported", "unsupported actor role %q (this runtime knows owner, editor and viewer)", a.Role)
	}
	if !appDataSurfaces[a.Surface] {
		return req, op, appDataFail("unsupported", "unsupported actor surface %q (this runtime knows mcp, dashboard and ops)", a.Surface)
	}
	email := strings.TrimSpace(a.Email)
	if email == "" || len(email) > 320 || email != a.Email || strings.ContainsAny(email, "\r\n\x00") {
		return req, op, appDataFail("bad_request", "actor email is required")
	}
	if a.PlatformUserID < 0 {
		return req, op, appDataFail("bad_request", "invalid actor id")
	}
	if !validAppDataRequestID(req.RequestID) {
		return req, op, appDataFail("bad_request", "invalid request id")
	}
	if appDataRoles[a.Role] < appDataRoles[op.MinRole] {
		return req, op, appDataFail("forbidden", "access denied: %s needs %s access (actor role: %s)", req.Op, op.MinRole, a.Role)
	}
	if op.Mutating && a.Role == "viewer" {
		return req, op, appDataFail("forbidden", "access denied: a viewer cannot change data")
	}
	return req, op, nil
}

// appDataDispatch runs one request against app. The HTTP handler calls it
// after the token checks; `benmore host` (one process) calls it directly.
func appDataDispatch(ctx context.Context, app *App, body []byte) (int, appDataResponse) {
	req, op, derr := decodeAppDataRequest(body)
	if derr != nil {
		return appDataStatus(derr.Code), appDataResponse{Error: derr.Code, Message: derr.Message}
	}
	return runAppDataOp(ctx, app, req, op)
}

func runAppDataOp(ctx context.Context, app *App, req appDataRequest, op appDataOp) (status int, resp appDataResponse) {
	if app == nil || app.DB == nil {
		return http.StatusServiceUnavailable, appDataResponse{Error: "unavailable", Message: "app database is not open"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := op.Timeout
	if timeout <= 0 {
		timeout = appDataDefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	slots := appDataSlotsFor(app)
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return http.StatusServiceUnavailable, appDataResponse{Error: "busy", Message: "the app is busy with other platform requests; retry shortly"}
	}
	call := &appDataOpCall{App: app, Actor: req.Actor, Args: req.Args, RequestID: req.RequestID}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[data] %s %s panicked: %s", req.Op, req.RequestID, appDataLogText(fmt.Sprint(rec)))
			status, resp = http.StatusInternalServerError, appDataResponse{Error: "internal", Message: "internal error (request " + req.RequestID + ")"}
		}
	}()
	result, err := op.Run(ctx, call)
	if err != nil {
		var de *appDataError
		if !errors.As(err, &de) {
			de = &appDataError{Code: "internal", Message: err.Error()}
		}
		if de.Code == "internal" {
			// The message can carry tenant text (an SQL error naming the
			// app's own objects), and in the router fallback and `benmore
			// host` this line lands in the platform's log: quoted, bounded.
			log.Printf("[data] %s by %s (%s) request %s failed: %s", req.Op, req.Actor.Email, req.Actor.Surface, req.RequestID, appDataLogText(de.Message))
		}
		return appDataStatus(de.Code), appDataResponse{Error: de.Code, Message: de.Message}
	}
	if op.Mutating {
		if !call.audited {
			// Every mutating operation records itself in its transaction; one
			// that did not is a bug, and the change must still be attributable.
			log.Printf("[data] %s request %s returned without an audit row; recording one", req.Op, req.RequestID)
			if aerr := call.audit(app.DB, "data_"+req.Op, "", "", map[string]any{"late": true}); aerr != nil {
				log.Printf("[data] %s request %s: audit failed: %v", req.Op, req.RequestID, aerr)
			}
		}
		log.Printf("[data] %s by %s (%s, %s) request %s", req.Op, req.Actor.Email, req.Actor.Role, req.Actor.Surface, req.RequestID)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return http.StatusInternalServerError, appDataResponse{Error: "internal", Message: "failed to encode result: " + err.Error()}
	}
	return http.StatusOK, appDataResponse{OK: true, Result: encoded}
}

// appDataLogText bounds and quotes text an app process returned (tenant
// code), for router logs and error messages.
func appDataLogText(s string) string {
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return strconv.Quote(s)
}

// appDataSlots holds each app's channel concurrency slots (one app per
// process when hosted; many under `benmore host`).
var appDataSlots sync.Map // app.Dir -> chan struct{}

func appDataSlotsFor(app *App) chan struct{} {
	if v, ok := appDataSlots.Load(app.Dir); ok {
		return v.(chan struct{})
	}
	v, _ := appDataSlots.LoadOrStore(app.Dir, make(chan struct{}, appDataMaxConcurrent))
	return v.(chan struct{})
}

// ===== Token =====

// appDataTokenKey derives the channel's purpose key from the server secret.
func appDataTokenKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("benmore-app-data-v1"))
	return mac.Sum(nil)
}

// mintAppDataToken signs "appdata.<exp>.<nonce>.<sha256(body)>.<appDir>".
// appDir may contain '.', so it is the last field.
func mintAppDataToken(appDir string, exp time.Time, secret, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	payload := fmt.Sprintf("%s.%d.%s.%s.%s", appDataTokenTag, exp.Unix(), nonce, hex.EncodeToString(sum[:]), appDir)
	mac := hmac.New(sha256.New, appDataTokenKey(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// appDataResponseKey derives the key that authenticates the app's answers;
// it differs from the token key, so neither can stand in for the other.
func appDataResponseKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("benmore-app-data-response-v1"))
	return mac.Sum(nil)
}

// appDataResponseMAC authenticates one answer: the request's nonce (which the
// router minted and the app accepted once) and the exact answer bytes.
func appDataResponseMAC(secret, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, appDataResponseKey(secret))
	mac.Write([]byte(nonce))
	mac.Write([]byte{0})
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validAppDataNonce accepts the router's base64url nonces.
func validAppDataNonce(nonce string) bool {
	if len(nonce) < 16 || len(nonce) > 64 {
		return false
	}
	for _, r := range nonce {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// verifyAppDataToken checks, in order: MAC (constant time), tag, expiry, the
// TTL ceiling, audience and the body hash (constant time). It returns the
// nonce and expiry for the replay check.
func verifyAppDataToken(app *App, secret, token string, body []byte, now time.Time) (nonce string, exp time.Time, ok bool) {
	if app == nil || app.Dir == "" || len(secret) < routerSigMinSecret || token == "" {
		return "", time.Time{}, false
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", time.Time{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", time.Time{}, false
	}
	mac := hmac.New(sha256.New, appDataTokenKey(secret))
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", time.Time{}, false
	}
	fields := strings.SplitN(string(payload), ".", 5)
	if len(fields) != 5 || fields[0] != appDataTokenTag {
		return "", time.Time{}, false
	}
	unix, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	exp = time.Unix(unix, 0)
	if !now.Before(exp) || exp.Sub(now) > appDataTokenTTL || fields[4] != app.Dir {
		return "", time.Time{}, false
	}
	if !validAppDataNonce(fields[2]) {
		return "", time.Time{}, false
	}
	sum := sha256.Sum256(body)
	if !hmac.Equal([]byte(fields[3]), []byte(hex.EncodeToString(sum[:]))) {
		return "", time.Time{}, false
	}
	return fields[2], exp, true
}

// appDataNonceCache remembers accepted nonces until their token expires.
type appDataNonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var appDataNonces = &appDataNonceCache{seen: map[string]time.Time{}}

// claim records nonce for audience and reports whether it was unused. A full
// cache (after dropping expired entries) refuses: a token is never accepted
// twice, even under a flood.
func (c *appDataNonceCache) claim(audience, nonce string, exp, now time.Time) bool {
	key := audience + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, used := c.seen[key]; used {
		return false
	}
	if len(c.seen) >= appDataNonceCap/2 {
		for k, until := range c.seen {
			if !now.Before(until) {
				delete(c.seen, k)
			}
		}
	}
	if len(c.seen) >= appDataNonceCap {
		return false
	}
	c.seen[key] = exp
	return true
}

// ===== HTTP =====

// isAppDataChannelPath reports whether a request path names the channel, in
// any spelling a mux or a later redirect could route there. Front doors
// refuse these paths on public requests.
func isAppDataChannelPath(p string) bool {
	clean := strings.ToLower(path.Clean("/" + p))
	return clean == appDataRoute || strings.HasPrefix(clean, appDataRoute+"/")
}

// appDataFromLoopback reports whether the peer is a loopback address.
func appDataFromLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// appDataProxied reports whether the request came through a front door: the
// router marks every proxied request, and a direct loopback call carries none
// of these.
func appDataProxied(r *http.Request) bool {
	// X-Internal-Probe marks a request the router fires on an operator's
	// behalf (probe_route, api calls): never a channel call.
	for _, h := range []string{"X-Benmore-App", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "CF-Connecting-IP", "X-Real-Ip", "X-Internal-Probe"} {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

func writeAppDataResponse(w http.ResponseWriter, status int, resp appDataResponse) {
	writeAppDataAnswer(w, status, resp, "")
}

// writeAppDataAnswer writes an answer; once a token's nonce was accepted the
// answer carries its MAC (appDataResponseMAC).
func writeAppDataAnswer(w http.ResponseWriter, status int, resp appDataResponse, nonce string) {
	body, err := json.Marshal(resp)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"ok":false,"error":"internal","message":"failed to encode answer"}`)
	}
	body = append(body, '\n')
	if nonce != "" {
		w.Header().Set(appDataMACHeader, appDataResponseMAC(serverSecret, nonce, body))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func refuseAppData(w http.ResponseWriter, status int, code, message string) {
	writeAppDataResponse(w, status, appDataResponse{Error: code, Message: message})
}

// appDataChannelMiddleware serves the channel in front of the app's whole
// middleware chain (hosted tenant processes only; see wrapMiddleware).
func appDataChannelMiddleware(next http.Handler, app *App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAppDataChannelPath(r.URL.Path) {
			serveAppDataChannel(w, r, app)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveAppDataChannel is the HTTP endpoint.
func serveAppDataChannel(w http.ResponseWriter, r *http.Request, app *App) {
	w.Header().Set(appDataChannelHeader, "1")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != appDataRoute {
		refuseAppData(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		refuseAppData(w, http.StatusMethodNotAllowed, "bad_request", "POST only")
		return
	}
	if !appDataFromLoopback(r) || appDataProxied(r) {
		refuseAppData(w, http.StatusForbidden, "forbidden", "data channel is internal")
		return
	}
	token := r.Header.Get(appDataTokenHeader)
	if token == "" {
		refuseAppData(w, http.StatusForbidden, "forbidden", "data token required")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, appDataMaxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			refuseAppData(w, http.StatusRequestEntityTooLarge, "too_large", "request too large")
			return
		}
		refuseAppData(w, http.StatusBadRequest, "bad_request", "unreadable request")
		return
	}
	now := time.Now()
	nonce, exp, ok := verifyAppDataToken(app, serverSecret, token, body, now)
	if !ok {
		refuseAppData(w, http.StatusForbidden, "forbidden", "data token refused")
		return
	}
	if !appDataNonces.claim(app.Dir, nonce, exp, now) {
		refuseAppData(w, http.StatusForbidden, "forbidden", "data token already used")
		return
	}
	req, op, derr := decodeAppDataRequest(body)
	if derr != nil {
		writeAppDataAnswer(w, appDataStatus(derr.Code), appDataResponse{Error: derr.Code, Message: derr.Message}, nonce)
		return
	}
	// The server's WriteTimeout (30s) is shorter than a write or reset may
	// run; give this answer its operation's budget instead.
	timeout := op.Timeout
	if timeout <= 0 {
		timeout = appDataDefaultTimeout
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout + 15*time.Second))
	status, resp := runAppDataOp(r.Context(), app, req, op)
	writeAppDataAnswer(w, status, resp, nonce)
}
