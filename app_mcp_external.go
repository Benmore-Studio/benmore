//go:build !cli

package main

// External read tools: a reviewed manifest tool bound (kind: external) to one
// operation of a pinned local OpenAPI document and one declared connection.
//
// The call maps ONLY parameters the operation declares from the validated tool
// input, sends them to the manifest's base_url (never an input URL), attaches
// the calling user's own stored credential, and projects the declared JSON
// response through the tool's output projection. Nothing from the inbound MCP
// request (headers, bearer token, cookies) is ever forwarded. Upstream OAuth
// flows are out of scope: bearer and header (api key) credentials only.

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	appMCPConnectionCredentialsTable = "_benmore_mcp_connection_credentials"
	appMCPConnectionSecretColumn     = "secret_ciphertext"
	appMCPConnectionSecretLimit      = 4096
	appMCPConnectionRoutePrefix      = "/api/_mcp/connections/"
	appMCPExternalTimeout            = 30 * time.Second
)

var appMCPExternalHeaderName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// appMCPExternalReservedHeaders can never be mapped from tool input: they carry
// framing, routing or ambient authority the connector owns, or (the
// method-override family) would make the upstream run another method than
// the reviewed GET or POST.
var appMCPExternalReservedHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "host": true, "cookie": true, "content-length": true,
	"content-type": true, "accept": true, "transfer-encoding": true, "connection": true, "upgrade": true, "te": true, "trailer": true,
	"x-http-method-override": true, "x-http-method": true, "x-method-override": true,
}

// appMCPExternalOperation is one pinned OpenAPI operation, captured at load
// from the bytes the execution digest bound.
type appMCPExternalOperation struct {
	Method string
	Path   string
	Input  *AppMCPSchema // object keyed path/query/header/body, as the document declares them
	Output *AppMCPSchema
}

type appMCPTransferOperations struct {
	Operation *appMCPExternalOperation
	Reconcile *appMCPExternalOperation
}

func newAppMCPExternalOperation(m *AppMCPManifest, connection string, c appMCPOpenAPICandidate) (*appMCPExternalOperation, error) {
	if c.Method != "GET" && c.Method != "POST" {
		return nil, fmt.Errorf("read tools may bind only GET or POST operations, not %s", c.Method)
	}
	if c.InputSchema.Properties["cookie"] != nil {
		return nil, fmt.Errorf("cookie parameters are unsupported")
	}
	authHeader := ""
	for _, declared := range m.Connections {
		if declared.Name == connection {
			authHeader = strings.ToLower(declared.Auth.Header)
		}
	}
	if headers := c.InputSchema.Properties["header"]; headers != nil {
		for name := range headers.Properties {
			lower := strings.ToLower(name)
			if !appMCPExternalHeaderName.MatchString(name) || appMCPExternalReservedHeaders[lower] || lower == authHeader {
				return nil, fmt.Errorf("header parameter %q is reserved or invalid", name)
			}
		}
	}
	if c.OutputSchema == nil || c.OutputSchema.Type != "object" {
		return nil, fmt.Errorf("the success response must be a JSON object")
	}
	return &appMCPExternalOperation{Method: c.Method, Path: c.Path, Input: c.InputSchema, Output: c.OutputSchema}, nil
}

// ---- Per-user credential store ----------------------------------------------

// The secret is sealed under the app key with AAD "<table>\x00secret_ciphertext|<user>|<connection>|<host hash>",
// so a ciphertext cannot be replayed for another user, connection, table or
// upstream host. The host hash is also stored on the row: repointing a
// connection's base_url to another host makes every stored credential unusable
// until each user enters it again.
func appMCPConnectionAADColumn(userID int64, connection, hostHash string) string {
	return appMCPConnectionSecretColumn + "|" + strconv.FormatInt(userID, 10) + "|" + connection + "|" + hostHash
}

// appMCPConnectionHostHash identifies the upstream host (and port) of a base URL.
func appMCPConnectionHostHash(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return hashBytesSHA256([]byte("benmore:mcp:connection-host:v1\x00" + strings.ToLower(parsed.Host)))
}

var errAppMCPConnectionHost = errors.New("connection credential was stored for a different upstream host")

func appMCPConnectionKey(app *App) ([]byte, error) {
	keys := cryptoKeysForDBPath(filepath.Join(app.Dir, "data.db"))
	if keys == nil || len(keys.aes) != 32 || keys.ephemeral {
		return nil, errors.New("connection credentials require a durable ENCRYPTION_KEY")
	}
	return keys.aes, nil
}
func sealAppMCPConnectionSecret(key []byte, userID int64, connection, hostHash, secret string) (string, error) {
	if len(key) != 32 || secret == "" || hostHash == "" {
		return "", errors.New("invalid connection credential")
	}
	return fieldEncryptCtx(key, appMCPConnectionCredentialsTable, appMCPConnectionAADColumn(userID, connection, hostHash), secret)
}
func openAppMCPConnectionSecret(key []byte, userID int64, connection, hostHash, sealed string) (string, error) {
	column := appMCPConnectionAADColumn(userID, connection, hostHash)
	body, ok := strings.CutPrefix(sealed, encPrefixV2)
	sep := strings.IndexByte(body, ':')
	if len(key) != 32 || !ok || sep < 0 {
		return "", errors.New("connection credential is not sealed")
	}
	aad, err := hex.DecodeString(body[:sep])
	if err != nil {
		return "", errors.New("connection credential is not sealed")
	}
	if table, got, parsed := cryptoParseAAD(aad); !parsed || table != appMCPConnectionCredentialsTable || got != column {
		return "", errors.New("connection credential context mismatch")
	}
	secret, err := fieldDecryptCtx(key, column, sealed)
	if err != nil || secret == "" {
		return "", errors.New("connection credential authentication failed")
	}
	return secret, nil
}

// appMCPValidSecret keeps a stored credential usable as one header value.
func appMCPValidSecret(value string) bool {
	if len(value) == 0 || len(value) > appMCPConnectionSecretLimit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func setAppMCPConnectionCredential(ctx context.Context, app *App, userID int64, connection *AppMCPConnection, secret string) error {
	key, err := appMCPConnectionKey(app)
	if err != nil {
		return err
	}
	host := appMCPConnectionHostHash(connection.BaseURL)
	sealed, err := sealAppMCPConnectionSecret(key, userID, connection.Name, host, secret)
	if err != nil {
		return err
	}
	_, err = app.DB.ExecContext(ctx, `INSERT INTO main._benmore_mcp_connection_credentials(user_id,connection,upstream_host,secret_ciphertext,updated_at) VALUES(?,?,?,?,?)
 ON CONFLICT(user_id,connection) DO UPDATE SET upstream_host=excluded.upstream_host, secret_ciphertext=excluded.secret_ciphertext, updated_at=excluded.updated_at`, userID, connection.Name, host, sealed, time.Now().Unix())
	return err
}
func clearAppMCPConnectionCredential(ctx context.Context, app *App, userID int64, connection string) error {
	_, err := app.DB.ExecContext(ctx, `DELETE FROM main._benmore_mcp_connection_credentials WHERE user_id=? AND connection=?`, userID, connection)
	return err
}

// purgeAppMCPConnectionCredentials deletes every user's stored credential
// except those of the connections named in keep (nil deletes them all: a
// revoke). Run with the loaded manifest's credentialed connections, it drops
// the credentials of a connection removed from mcp.yaml, so re-adding the same
// name and host later starts empty instead of bringing them back.
func purgeAppMCPConnectionCredentials(ctx context.Context, db *sql.DB, keep []string) (int64, error) {
	if db == nil {
		return 0, nil
	}
	var present int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name=?`, appMCPConnectionCredentialsTable).Scan(&present); err != nil || present == 0 {
		return 0, err
	}
	query, args := `DELETE FROM main._benmore_mcp_connection_credentials`, []any{}
	if len(keep) > 0 {
		query += ` WHERE connection NOT IN (?` + strings.Repeat(`,?`, len(keep)-1) + `)`
		for _, name := range keep {
			args = append(args, name)
		}
	}
	res, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// purgeUndeclaredAppMCPConnectionCredentials runs at manifest load: only the
// credentialed connections manifest declares keep their stored credentials
// (no manifest keeps none). Failures are logged; the next load retries.
func purgeUndeclaredAppMCPConnectionCredentials(db *sql.DB, manifest *AppMCPManifest) {
	var keep []string
	if manifest != nil {
		for _, connection := range manifest.Connections {
			if connection.Auth.Kind != "none" {
				keep = append(keep, connection.Name)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := purgeAppMCPConnectionCredentials(ctx, db, keep)
	if err != nil {
		log.Printf("ERROR mcp: purging credentials of removed connections failed (retried at next load): %v", err)
	} else if n > 0 {
		log.Printf("mcp: deleted %d stored credential(s) of connection(s) no longer in mcp.yaml", n)
	}
}

// hasAppMCPConnectionCredential reports a credential usable for the connection's
// current upstream host; one stored for another host counts as not configured.
func hasAppMCPConnectionCredential(ctx context.Context, app *App, userID int64, connection *AppMCPConnection) (bool, error) {
	var n int
	err := app.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM main._benmore_mcp_connection_credentials WHERE user_id=? AND connection=? AND upstream_host=?`, userID, connection.Name, appMCPConnectionHostHash(connection.BaseURL)).Scan(&n)
	return n > 0, err
}
func loadAppMCPConnectionSecret(ctx context.Context, app *App, userID int64, connection *AppMCPConnection) (string, error) {
	key, err := appMCPConnectionKey(app)
	if err != nil {
		return "", err
	}
	var sealed, host string
	if err := app.DB.QueryRowContext(ctx, `SELECT upstream_host,secret_ciphertext FROM main._benmore_mcp_connection_credentials WHERE user_id=? AND connection=?`, userID, connection.Name).Scan(&host, &sealed); err != nil {
		return "", err
	}
	if current := appMCPConnectionHostHash(connection.BaseURL); current == "" || host != current {
		return "", errAppMCPConnectionHost
	}
	return openAppMCPConnectionSecret(key, userID, connection.Name, host, sealed)
}

// appMCPConnectionCredentialRows reports whether the store exists and its size,
// for the key-rotation plan.
func appMCPConnectionCredentialRows(db *sql.DB) (bool, int, error) {
	var present int
	if err := db.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name=?`, appMCPConnectionCredentialsTable).Scan(&present); err != nil || present == 0 {
		return false, 0, err
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM main._benmore_mcp_connection_credentials`).Scan(&n)
	return true, n, err
}

// rotateAppMCPConnectionCredentialsTx reseals every credential under newKey in
// the caller's transaction. A row that no longer authenticates under oldKey is
// already unusable (tampered or moved), so it is deleted rather than allowed to
// block rotation; its owner re-enters the credential.
func rotateAppMCPConnectionCredentialsTx(ctx context.Context, tx *sql.Tx, oldKey, newKey []byte) (int, error) {
	type row struct {
		user       int64
		connection string
		host       string
		sealed     string
	}
	rows, err := tx.QueryContext(ctx, `SELECT user_id,connection,upstream_host,secret_ciphertext FROM main._benmore_mcp_connection_credentials`)
	if err != nil {
		return 0, err
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.user, &r.connection, &r.host, &r.sealed); err != nil {
			_ = rows.Close()
			return 0, err
		}
		all = append(all, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, err
	}
	moved, dropped := 0, 0
	defer func() {
		if dropped > 0 {
			log.Printf("ERROR encryption-rotate: deleted %d connection credential(s) that no longer authenticated; those users must re-enter them", dropped)
		}
	}()
	for _, r := range all {
		secret, err := openAppMCPConnectionSecret(oldKey, r.user, r.connection, r.host, r.sealed)
		if err != nil {
			dropped++
			if _, err := tx.ExecContext(ctx, `DELETE FROM main._benmore_mcp_connection_credentials WHERE user_id=? AND connection=? AND secret_ciphertext COLLATE BINARY=?`, r.user, r.connection, r.sealed); err != nil {
				return 0, err
			}
			continue
		}
		resealed, err := sealAppMCPConnectionSecret(newKey, r.user, r.connection, r.host, secret)
		if err != nil {
			return 0, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE main._benmore_mcp_connection_credentials SET secret_ciphertext=? WHERE user_id=? AND connection=? AND secret_ciphertext COLLATE BINARY=?`, resealed, r.user, r.connection, r.sealed)
		if err != nil {
			return 0, err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return 0, errors.New("connection credential reseal compare-and-swap failed")
		}
		moved++
	}
	return moved, nil
}

// ---- Set / clear route -------------------------------------------------------

// registerAppMCPConnectionRoutes serves the first-party credential endpoint:
// GET reports whether the signed-in user has stored one, PUT {"secret": "..."}
// stores it, DELETE clears it. The credential is never returned.
func registerAppMCPConnectionRoutes(mux appRouteRegistrar, app *App, resource string) {
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		mux.HandleFunc(method+" "+appMCPConnectionRoutePrefix+"{name}/credential", func(w http.ResponseWriter, r *http.Request) {
			serveAppMCPConnectionCredential(w, r, app, resource)
		})
	}
}

func serveAppMCPConnectionCredential(w http.ResponseWriter, r *http.Request, app *App, resource string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	generation := snapshotAppMCPGeneration(app)
	if generation == nil || generation.manifest == nil || !appMCPOAuthHost(r, app, resource) {
		http.NotFound(w, r)
		return
	}
	var connection *AppMCPConnection
	for i := range generation.manifest.Connections {
		if generation.manifest.Connections[i].Name == r.PathValue("name") {
			connection = &generation.manifest.Connections[i]
		}
	}
	if connection == nil || connection.Auth.Kind == "none" {
		http.NotFound(w, r)
		return
	}
	// Only a signed-in browser session: never a bearer/connector credential, API
	// token, edge identity, impersonation or scoped session.
	cookie, cookieErr := requestSessionCookie(r)
	var session *Session
	if cookieErr == nil && len(r.Header.Values("Authorization")) == 0 {
		session = GetSessionFromDB(app.DB, cookie.Value)
	}
	if session == nil || session.ImpersonatorUserID != 0 || session.ActingAsGroup != "" || !directLoginSession(app, session) {
		http.Error(w, "Connection credentials can be managed only from a signed-in browser session.", http.StatusForbidden)
		return
	}
	fail := func(error) { // nothing is logged: no payload, no error text
		w.Header().Set(requestIDHeader, recordRequestError(r, "[connection credential] store or read failed"))
		http.Error(w, "The credential could not be stored.", http.StatusServiceUnavailable)
	}
	if r.Method == http.MethodGet {
		configured, err := hasAppMCPConnectionCredential(r.Context(), app, session.UserID, connection)
		if err != nil {
			fail(err)
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"configured": configured})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if !validateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodDelete {
		if err := clearAppMCPConnectionCredential(r.Context(), app, session.UserID, connection.Name); err != nil {
			fail(err)
			return
		}
		LogAudit(app, "mcp_connection_credential_clear", appMCPConnectionCredentialsTable, connection.Name, session, nil, nil)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var body struct {
		Secret string `json:"secret"`
	}
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || !appMCPValidSecret(body.Secret) {
		http.Error(w, "Send a JSON object with a non-empty single-line secret.", http.StatusBadRequest)
		return
	}
	if err := setAppMCPConnectionCredential(r.Context(), app, session.UserID, connection, body.Secret); err != nil {
		fail(err)
		return
	}
	LogAudit(app, "mcp_connection_credential_set", appMCPConnectionCredentialsTable, connection.Name, session, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Execution ---------------------------------------------------------------

// appMCPExternalTransport builds the outbound transport. Tests swap it to reach
// a local TLS server; production always dials through publicOnlyDialer, which
// refuses private, loopback and reserved addresses after DNS resolution. There
// is no proxy: a credentialed request must not traverse one.
var appMCPExternalTransport = func() *http.Transport {
	return &http.Transport{
		DialContext:            publicOnlyDialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
	}
}

func appMCPExternalFailure(code, message string) error { return &appMCPResultError{code, message} }

// appMCPExternalDo sends one request and returns the status and the body, capped
// at appMCPResultLimit. Every redirect is refused (a credentialed request is
// never replayed to another host).
func appMCPExternalDo(ctx context.Context, method, rawURL string, header http.Header, body []byte) (int, http.Header, []byte, error) {
	return appMCPExternalDoLimit(ctx, method, rawURL, header, body, appMCPResultLimit)
}

func appMCPExternalDoLimit(ctx context.Context, method, rawURL string, header http.Header, body []byte, limit int64) (int, http.Header, []byte, error) {
	if limit <= 0 || limit > appMCPTransferWireLimit {
		return 0, nil, nil, appMCPResultFailure("invalid_input")
	}
	ctx, cancel := context.WithTimeout(ctx, appMCPExternalTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return 0, nil, nil, appMCPResultFailure("invalid_input")
	}
	request.Header = header
	client := &http.Client{
		Transport:     appMCPExternalTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, nil, appMCPExternalFailure("unavailable_provider", "The external provider could not be reached.")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return 0, nil, nil, appMCPExternalFailure("unavailable_provider", "The external provider response could not be read.")
	}
	if int64(len(data)) > limit {
		return 0, nil, nil, appMCPExternalFailure("incomplete_result", "The external provider response exceeded the size limit.")
	}
	return response.StatusCode, response.Header, data, nil
}

func appMCPExternalScalar(value any) (string, bool) {
	text, ok := appMCPNativeScalar(value)
	if !ok {
		return "", false
	}
	for _, r := range text {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return "", false
		}
	}
	return text, true
}

// buildAppMCPExternalRequest maps the validated tool input onto the pinned
// operation. Only parameters the operation declares are read; every other input
// key is dropped. The URL is the manifest base_url plus the document's path.
func buildAppMCPExternalRequest(base *url.URL, connection *AppMCPConnection, op *appMCPExternalOperation, input map[string]any, secret string) (rawURL string, header http.Header, body []byte, err error) {
	return buildAppMCPExternalRequestLimit(base, connection, op, input, secret, appMCPInputLimit)
}

func buildAppMCPExternalRequestLimit(base *url.URL, connection *AppMCPConnection, op *appMCPExternalOperation, input map[string]any, secret string, bodyLimit int) (rawURL string, header http.Header, body []byte, err error) {
	if bodyLimit <= 0 || bodyLimit > int(appMCPTransferWireLimit) {
		return "", nil, nil, appMCPResultFailure("invalid_input")
	}
	invalid := appMCPResultFailure("invalid_input")
	mapped := map[string]any{}
	for _, location := range []string{"path", "query", "header"} {
		declared := op.Input.Properties[location]
		if declared == nil {
			continue
		}
		given, _ := input[location].(map[string]any)
		picked := map[string]any{}
		for name := range declared.Properties {
			if value, present := given[name]; present {
				picked[name] = value
			}
		}
		if len(picked) > 0 {
			mapped[location] = picked
		}
	}
	if op.Input.Properties["body"] != nil {
		if value, present := input["body"]; present {
			mapped["body"] = value
		}
	}
	if validateAppMCPSchemaValue(op.Input, mapped) != nil {
		return "", nil, nil, invalid
	}

	var path strings.Builder
	route := op.Path
	pathValues, _ := mapped["path"].(map[string]any)
	for len(route) > 0 {
		open := strings.IndexByte(route, '{')
		if open < 0 {
			path.WriteString(route)
			break
		}
		path.WriteString(route[:open])
		end := strings.IndexByte(route[open:], '}')
		if end < 0 {
			return "", nil, nil, invalid
		}
		text, ok := appMCPExternalScalar(pathValues[route[open+1:open+end]])
		// No separators or escapes: an encoded slash must not reach another upstream endpoint.
		if !ok || text == "" || text == "." || text == ".." || strings.ContainsAny(text, `/\%`) {
			return "", nil, nil, invalid
		}
		path.WriteString(url.PathEscape(text))
		route = route[open+end+1:]
	}
	target, parseErr := url.Parse("https://" + base.Host + strings.TrimRight(base.EscapedPath(), "/") + path.String())
	if parseErr != nil || target.Scheme != "https" || target.Host != base.Host || target.User != nil {
		return "", nil, nil, invalid
	}
	query := url.Values{}
	queryValues, _ := mapped["query"].(map[string]any)
	names := make([]string, 0, len(queryValues))
	for name := range queryValues {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		items, isList := queryValues[name].([]any)
		if !isList {
			items = []any{queryValues[name]}
		}
		for _, item := range items {
			text, ok := appMCPExternalScalar(item)
			if !ok {
				return "", nil, nil, invalid
			}
			query.Add(name, text)
		}
	}
	target.RawQuery = query.Encode()

	header = http.Header{"Accept": {"application/json"}}
	headerValues, _ := mapped["header"].(map[string]any)
	for name, value := range headerValues {
		text, ok := appMCPExternalScalar(value)
		if !ok {
			return "", nil, nil, invalid
		}
		header.Set(name, text)
	}
	if value, present := mapped["body"]; present {
		if body, err = json.Marshal(value); err != nil || len(body) > bodyLimit {
			return "", nil, nil, invalid
		}
		header.Set("Content-Type", "application/json")
	}
	switch connection.Auth.Kind {
	case "bearer":
		header.Set("Authorization", "Bearer "+secret)
	case "header":
		header.Set(connection.Auth.Header, secret)
	}
	return target.String(), header, body, nil
}

// runAppMCPExternalRead runs one external read tool for the caller the bearer
// token resolves to, and returns the shared result envelope without source
// revisions (the provider's state is not part of the app's ledger).
func runAppMCPExternalRead(ctx context.Context, origin *App, generation *appMCPRuntimeGeneration, raw, resource, name string, input map[string]any) (*appMCPReadResult, error) {
	denied := appMCPResultFailure("denied")
	if generation == nil || generation.manifest == nil || !appMCPGenerationCurrent(origin, generation) || ctx.Err() != nil {
		return nil, denied
	}
	manifest := generation.manifest
	var tool *AppMCPTool
	for i := range manifest.Tools {
		if manifest.Tools[i].Name == name && manifest.Tools[i].Handler.Kind == "external" && manifest.Tools[i].Effect == "read" {
			tool = &manifest.Tools[i]
		}
	}
	_, actor, err := resolveAppMCPAccessForGeneration(ctx, origin, generation, raw, resource, time.Now())
	if err != nil || tool == nil || !scopesWithin(actor.Scopes, strings.Join(tool.Permissions, " ")) {
		return nil, denied
	}
	if validateAppMCPSchemaValue(tool.InputSchema, input) != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	operation := manifest.external[name]
	var connection *AppMCPConnection
	for i := range manifest.Connections {
		if manifest.Connections[i].Name == tool.Handler.Connection {
			connection = &manifest.Connections[i]
		}
	}
	if operation == nil || connection == nil {
		return nil, appMCPResultFailure("incomplete_result")
	}
	base, err := url.Parse(connection.BaseURL)
	if err != nil {
		return nil, appMCPResultFailure("incomplete_result")
	}
	secret := ""
	if connection.Auth.Kind != "none" {
		if secret, err = loadAppMCPConnectionSecret(ctx, generation.view, actor.UserID, connection); err == errAppMCPConnectionHost {
			return nil, appMCPExternalFailure("denied", fmt.Sprintf("The stored credential for connection %q was entered for a different upstream host. Set it again with PUT %s%s/credential from a signed-in session.", connection.Name, appMCPConnectionRoutePrefix, connection.Name))
		} else if err != nil || !appMCPValidSecret(secret) {
			return nil, appMCPExternalFailure("denied", fmt.Sprintf("No credential is stored for connection %q. Set yours with PUT %s%s/credential from a signed-in session.", connection.Name, appMCPConnectionRoutePrefix, connection.Name))
		}
	}
	rawURL, header, body, err := buildAppMCPExternalRequest(base, connection, operation, input, secret)
	if err != nil {
		return nil, err
	}
	status, responseHeader, data, err := appMCPExternalDo(ctx, operation.Method, rawURL, header, body)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil, appMCPExternalFailure("denied", fmt.Sprintf("The provider rejected your credential for connection %q.", connection.Name))
	case status == http.StatusNotFound:
		return nil, denied
	case status < 200 || status > 299 || status == http.StatusNoContent:
		return nil, appMCPExternalFailure("unavailable_provider", "The external provider did not return a result.")
	}
	if media, _, err := mime.ParseMediaType(responseHeader.Get("Content-Type")); err != nil || media != "application/json" && !strings.HasSuffix(media, "+json") {
		return nil, appMCPResultFailure("incomplete_result")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document map[string]any
	if decoder.Decode(&document) != nil || document == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, appMCPResultFailure("incomplete_result")
	}
	// The declared response is the contract: required fields must be present
	// and every projected field must validate against its declared schema.
	// Undeclared extra fields are not projected, so a provider adding one does
	// not break the tool.
	for _, field := range operation.Output.Required {
		if _, present := document[field]; !present {
			return nil, appMCPResultFailure("incomplete_result")
		}
	}
	for _, field := range tool.Output.Include {
		declared := operation.Output.Properties[field]
		if value, present := document[field]; declared == nil || present && validateAppMCPSchemaValueAt(declared, value, 0) != nil {
			return nil, appMCPResultFailure("incomplete_result")
		}
	}
	document = appMCPProjectSchemaValue(operation.Output, document).(map[string]any)
	for _, field := range tool.Output.Include {
		if value, present := document[field]; present {
			if schema := tool.OutputSchema.Properties[field]; schema != nil {
				document[field] = appMCPProjectSchemaValue(schema, value)
			}
		}
	}
	projected, err := appMCPProjectRow(tool, document)
	if err != nil {
		return nil, err
	}
	// Authority loss during the call must not release the result.
	_, after, err := resolveAppMCPAccessForGeneration(ctx, origin, generation, raw, resource, time.Now())
	if err != nil || !appMCPAuthorityUnchanged(actor, after) || !appMCPGenerationCurrent(origin, generation) {
		return nil, denied
	}
	return &appMCPReadResult{Data: projected, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Freshness: "observed", Warnings: []string{"external_source"},
		Completeness: appMCPCompleteness{State: "complete", Basis: "declared_output"}}, nil
}

// appMCPExternalEnvelopeSchema is the shared envelope minus source_revisions:
// a provider's state has no revision in the app's ledger, so none is claimed.
func appMCPExternalEnvelopeSchema(tool *AppMCPTool) map[string]any {
	schema := appMCPEnvelopeSchema(tool)
	delete(schema["properties"].(map[string]any), "source_revisions")
	required := []string{}
	for _, name := range schema["required"].([]string) {
		if name != "source_revisions" {
			required = append(required, name)
		}
	}
	schema["required"] = required
	return schema
}

func appMCPRegisterExternalTools(server *sdk.Server, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session, raw, resource string) {
	if grant == nil || actor == nil || generation == nil || generation.manifest == nil {
		return
	}
	open := true
	for _, declared := range generation.manifest.Tools {
		tool := declared
		if tool.Handler.Kind != "external" || tool.Effect != "read" || generation.manifest.external[tool.Name] == nil {
			continue
		}
		permissions := strings.Join(tool.Permissions, " ")
		if !scopesWithin(grant.Scopes, permissions) || !scopesWithin(actor.Scopes, permissions) {
			continue
		}
		server.AddTool(&sdk.Tool{Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema, OutputSchema: appMCPExternalEnvelopeSchema(&tool),
			Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &open}},
			func(ctx context.Context, request *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				input, ok := appMCPDecodeToolArguments(request.Params.Arguments)
				if !ok {
					return appMCPSDKFailure(appMCPResultFailure("invalid_input")), nil
				}
				result, err := runAppMCPExternalRead(ctx, app, generation, raw, resource, tool.Name, input)
				if err != nil {
					return appMCPSDKFailure(err), nil
				}
				text, err := json.Marshal(result)
				if err != nil {
					return appMCPSDKFailure(err), nil
				}
				return &sdk.CallToolResult{Meta: sdk.Meta{"observed_at": result.ObservedAt}, StructuredContent: result, Content: []sdk.Content{&sdk.TextContent{Text: string(text)}}}, nil
			})
	}
}
