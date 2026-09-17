//go:build !cli

package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Item #1 - encrypted `?include=` child/parent rows must be masked.
//
// The primary read path (crud.go handleList/handleRead) calls
// MaskEncryptedFields; ResolveIncludes did NOT, so `?include=` expanded a
// related table's rows straight from the (decrypting) DB and returned the
// plaintext of a column whose `unmask_roles:` gate the direct GET enforces.
// These tests prove the include path now masks for an unauthorized role and
// still returns plaintext for an authorized (admin) role - the legit path.
// ============================================================================

// encIncludeApp builds an app with a parent `accounts` table carrying an
// AES-encrypted `secret_note` (unmask_roles:[admin]) and a child `orders`
// table with a FK to it, so both `?include=account` (parent) and
// `?include=orders` (child) exercise the masking on included rows.
func encIncludeApp(t *testing.T) (*App, *http.ServeMux, func()) {
	t.Helper()
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	appEncryptionKey = key
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatalf("SetBlindIndexKey: %v", err)
	}

	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	cleanup := func() { db.Close(); appEncryptionKey = oldKey }

	mustExec(t, db, `CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, secret_note TEXT)`)
	mustExec(t, db, `CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER, title TEXT,
		FOREIGN KEY(account_id) REFERENCES accounts(id))`)

	cfg := &EncryptedFieldConfig{
		Fields: map[string][]EncryptedFieldDef{
			"accounts": {{Column: "secret_note", Roles: []string{"admin"}}},
		},
	}
	InstallEncryptionTriggers(db, cfg)

	mustExec(t, db, `INSERT INTO accounts (id, title, secret_note) VALUES (1, 'Acme', 'TOPSECRETvalue9999')`)
	mustExec(t, db, `INSERT INTO orders (id, account_id, title) VALUES (1, 1, 'first order')`)

	// Sanity: the column is ciphertext at rest.
	var stored string
	if err := db.QueryRow("SELECT secret_note FROM accounts WHERE id = 1").Scan(&stored); err != nil {
		t.Fatalf("read secret_note: %v", err)
	}
	if !cryptoIsEncrypted(stored) {
		t.Fatalf("secret_note not encrypted at rest: %q", stored)
	}

	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Encrypted:       cfg,
		JoinMap:         BuildJoinMap(db),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"accounts": {OpRead: "everyone"},
			"orders":   {OpRead: "everyone"},
		}},
		Tables: []Table{
			{Name: "accounts", Columns: []Column{{Name: "id"}, {Name: "title"}, {Name: "secret_note"}}},
			{Name: "orders", Columns: []Column{{Name: "id"}, {Name: "account_id"}, {Name: "title"}}},
		},
	}
	return app, buildAppMux(app, true, "http://localhost"), cleanup
}

func fetchAccountViaInclude(t *testing.T, mux *http.ServeMux, token string) map[string]any {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/orders?include=account", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list orders?include=account status=%d body=%s", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	mustDecodeBody(t, rec, &rows)
	if len(rows) != 1 {
		t.Fatalf("want 1 order, got %d: %#v", len(rows), rows)
	}
	acct, ok := rows[0]["account"].(map[string]any)
	if !ok {
		t.Fatalf("order has no included `account` object: %#v", rows[0])
	}
	return acct
}

func TestEncryptedInclude_MaskedForUnauthorizedRole(t *testing.T) {
	app, mux, cleanup := encIncludeApp(t)
	defer cleanup()

	userTok := createCrudScopeSession(t, app, "user-a@example.com", "user", "", "")
	acct := fetchAccountViaInclude(t, mux, userTok)

	got, _ := acct["secret_note"].(string)
	if got == "TOPSECRETvalue9999" {
		t.Fatalf("SECURITY: `?include=` leaked encrypted parent plaintext to a non-unmask role: %q", got)
	}
	if !strings.Contains(got, "*") {
		t.Fatalf("included encrypted column not masked for non-admin: %q", got)
	}
	if cryptoIsEncrypted(got) {
		t.Fatalf("included column returned raw ciphertext (should be masked plaintext): %q", got)
	}
}

func TestEncryptedInclude_PlaintextForAdmin(t *testing.T) {
	app, mux, cleanup := encIncludeApp(t)
	defer cleanup()

	adminTok := createCrudScopeSession(t, app, "admin-a@example.com", "admin", "", "")
	acct := fetchAccountViaInclude(t, mux, adminTok)

	got, _ := acct["secret_note"].(string)
	if got != "TOPSECRETvalue9999" {
		t.Fatalf("legit path broken: admin should see plaintext via include, got %q", got)
	}
}

func TestEncryptedInclude_ChildRowsMasked(t *testing.T) {
	// Child-include direction: GET /api/accounts?include=orders. orders has no
	// encrypted column, so this asserts the parent (accounts) is still masked
	// on the LIST and the child path returns rows (no regression / no leak).
	app, mux, cleanup := encIncludeApp(t)
	defer cleanup()

	userTok := createCrudScopeSession(t, app, "user-b@example.com", "user", "", "")
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/accounts?include=orders", userTok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	mustDecodeBody(t, rec, &rows)
	if len(rows) != 1 {
		t.Fatalf("want 1 account, got %d", len(rows))
	}
	if sn, _ := rows[0]["secret_note"].(string); sn == "TOPSECRETvalue9999" {
		t.Fatalf("SECURITY: primary account row leaked plaintext to non-admin: %q", sn)
	}
	if _, ok := rows[0]["orders"].([]any); !ok {
		t.Fatalf("child include `orders` missing: %#v", rows[0])
	}
}

// TestEncryptedAsOf_MaskedForUnauthorizedRole proves the point-in-time
// (`?as_of=`) read path masks encrypted columns like the live read path. The
// as_of fallback reads the CURRENT row (ciphertext at rest -> decrypted by
// QueryRows) when there's no history, so a non-admin must not recover the
// plaintext through it.
func TestEncryptedAsOf_MaskedForUnauthorizedRole(t *testing.T) {
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*5 + 11)
	}
	appEncryptionKey = key
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatalf("SetBlindIndexKey: %v", err)
	}
	defer func() { appEncryptionKey = oldKey }()

	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE vaults (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, secret TEXT, created_at TEXT DEFAULT '2000-01-01')`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"vaults": {{Column: "secret", Roles: []string{"admin"}}},
	}}
	InstallEncryptionTriggers(db, cfg)
	mustExec(t, db, `INSERT INTO vaults (id, user_id, secret) VALUES (1, 1, 'ASOFSECRETvalue42')`)

	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Access:    &AccessConfig{rules: map[string]map[AccessOp]string{"vaults": {OpRead: "everyone"}}},
		Tables:    []Table{{Name: "vaults", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "secret"}, {Name: "created_at"}}}},
	}
	mux := buildAppMux(app, true, "http://localhost")

	userTok := createCrudScopeSession(t, app, "asof-user@example.com", "user", "", "")
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/vaults/1?as_of=2999-01-01T00:00:00Z", userTok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("as_of status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "ASOFSECRETvalue42") {
		t.Fatalf("SECURITY: `?as_of=` leaked encrypted plaintext to a non-unmask role: %s", rec.Body.String())
	}

	adminTok := createCrudScopeSession(t, app, "asof-admin@example.com", "admin", "", "")
	rec = crudScopeRequest(t, mux, http.MethodGet, "/api/vaults/1?as_of=2999-01-01T00:00:00Z", adminTok, nil)
	if !strings.Contains(rec.Body.String(), "ASOFSECRETvalue42") {
		t.Fatalf("legit path broken: admin should see plaintext via `?as_of=`: %s", rec.Body.String())
	}
}

// TestEncryptedCursor_MaskedForUnauthorizedRole proves the keyset/cursor
// pagination branch (`?cursor=`) masks encrypted columns like the offset
// (`?page=`) path. The cursor branch returns early with its own encode, so a
// non-admin must not recover the plaintext by paging with ?cursor= instead.
func TestEncryptedCursor_MaskedForUnauthorizedRole(t *testing.T) {
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*9 + 17)
	}
	appEncryptionKey = key
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatalf("SetBlindIndexKey: %v", err)
	}
	defer func() { appEncryptionKey = oldKey }()

	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE vaults (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, secret TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"vaults": {{Column: "secret", Roles: []string{"admin"}}},
	}}
	InstallEncryptionTriggers(db, cfg)
	mustExec(t, db, `INSERT INTO vaults (id, user_id, secret) VALUES (1, 1, 'CURSORSECRET555')`)

	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Access:    &AccessConfig{rules: map[string]map[AccessOp]string{"vaults": {OpRead: "everyone"}}},
		Tables:    []Table{{Name: "vaults", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "secret"}}}},
	}
	mux := buildAppMux(app, true, "http://localhost")

	userTok := createCrudScopeSession(t, app, "cursor-user@example.com", "user", "", "")
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/vaults?cursor=0&limit=50", userTok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("cursor status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "CURSORSECRET555") {
		t.Fatalf("SECURITY: `?cursor=` leaked encrypted plaintext to a non-unmask role: %s", rec.Body.String())
	}

	adminTok := createCrudScopeSession(t, app, "cursor-admin@example.com", "admin", "", "")
	rec = crudScopeRequest(t, mux, http.MethodGet, "/api/vaults?cursor=0&limit=50", adminTok, nil)
	if !strings.Contains(rec.Body.String(), "CURSORSECRET555") {
		t.Fatalf("legit path broken: admin should see plaintext via `?cursor=`: %s", rec.Body.String())
	}
}

// ============================================================================
// Item #3 - signed-URL authorization for private LOCAL-disk files.
//
// GenerateSignedURL prepends /uploads/, so the canonical `path` a caller
// passes is the uploads-relative "private/x.pdf". Pre-fix the mint handler
// tested isPrivateUploadPath on that RAW value, which is FALSE for
// "private/x.pdf" (it only matches "uploads/private/..." or a "/private/"
// segment) - so the record-authorization gate was SKIPPED and any logged-in
// user could sign ANY private file (session-only auth). These tests prove the
// bypass is closed and the legit owner path still mints a URL that serves.
// ============================================================================

func signedURLApp(t *testing.T) (*App, *http.ServeMux, func()) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	cleanup := func() { db.Close() }

	// The private file on disk + a `docs` row (owned by user 1) that
	// references it via file_url stored in the /api/_upload return shape.
	if err := os.MkdirAll(filepath.Join(dir, "uploads", "private"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uploads", "private", "secret.pdf"), []byte("PRIVATE-BYTES"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	mustExec(t, db, `CREATE TABLE _benmore_permissions (resource_type TEXT, resource_id INTEGER, grant_type TEXT, grantee_id TEXT, permission TEXT, expires_at TEXT)`)
	mustExec(t, db, `CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, file_url TEXT)`)
	mustExec(t, db, `INSERT INTO docs (id, user_id, file_url) VALUES (1, 1, '/uploads/private/secret.pdf')`)

	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"docs": {OpRead: "self"}, // owner-scoped: only the row's user_id may read
		}},
		Tables: []Table{
			{Name: "docs", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "file_url"}}},
		},
	}
	return app, buildAppMux(app, true, "http://localhost"), cleanup
}

// mintSignedURL calls GET /api/_signed_url and returns (status, path-field).
func mintSignedURL(t *testing.T, mux *http.ServeMux, token, query string) (int, string) {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_signed_url?"+query, token, nil)
	if rec.Code != http.StatusOK {
		return rec.Code, ""
	}
	var out map[string]any
	mustDecodeBody(t, rec, &out)
	p, _ := out["path"].(string)
	return rec.Code, p
}

func TestSignedURL_LocalPrivate_CanonicalSpellingRequiresAuthz(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	// user 1 OWNS the doc that references the file, but omits record_table/id.
	// Pre-fix: "private/secret.pdf" slipped past isPrivateUploadPath -> signed
	// with only a session (200 bypass). Post-fix: private file signing REQUIRES
	// the owning record -> 403.
	ownerTok := createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "")
	code, _ := mintSignedURL(t, mux, ownerTok, "path=private/secret.pdf")
	if code != http.StatusForbidden {
		t.Fatalf("SECURITY: canonical private path signed without record authz: status=%d (want 403)", code)
	}
}

func TestSignedURL_LocalPrivate_CrossUserDenied(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	// user 2 names user 1's doc as the owning record; they cannot READ it
	// (owner-scoped) so signing must be refused. Create the OWNER (id 1) first
	// so `other` is a genuine non-owner (id 2), not the doc's owner.
	_ = createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "")
	otherTok := createCrudScopeSession(t, app, "other-b@example.com", "user", "", "")
	code, _ := mintSignedURL(t, mux, otherTok, "path=private/secret.pdf&record_table=docs&record_id=1")
	if code != http.StatusForbidden {
		t.Fatalf("SECURITY: cross-user signed a private file they can't read: status=%d (want 403)", code)
	}
}

func TestSignedURL_LocalPrivate_OwnerLegitPathServes(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	ownerTok := createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "")

	// Legit: owner names the owning record -> 200 + a valid signed path.
	code, signedPath := mintSignedURL(t, mux, ownerTok, "path=private/secret.pdf&record_table=docs&record_id=1")
	if code != http.StatusOK || signedPath == "" {
		t.Fatalf("legit owner sign failed: status=%d path=%q", code, signedPath)
	}
	if strings.Contains(signedPath, "/uploads/uploads/") {
		t.Fatalf("minted a double-/uploads/ path (would 404): %q", signedPath)
	}

	// The signed path SERVES the file (legit path works end-to-end).
	rec := crudScopeRequest(t, mux, http.MethodGet, signedPath, "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "PRIVATE-BYTES" {
		t.Fatalf("signed URL did not serve the file: status=%d body=%q", rec.Code, rec.Body.String())
	}

	// Forged signature -> 403.
	forged := tamperSig(signedPath)
	rec = crudScopeRequest(t, mux, http.MethodGet, forged, "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forged signature served the file: status=%d", rec.Code)
	}

	// Unsigned raw path -> 403 (the exposure that would exist if audio/docs
	// were public-tier; proves the private gate).
	rec = crudScopeRequest(t, mux, http.MethodGet, "/uploads/private/secret.pdf", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("raw private path served without a signature: status=%d", rec.Code)
	}
}

func TestSignedURL_LocalPrivate_StaleDenied(t *testing.T) {
	_, mux, cleanup := signedURLApp(t)
	defer cleanup()
	// A correctly-signed but EXPIRED URL must be refused at serve.
	req := httptest.NewRequest(http.MethodGet,
		GenerateSignedURL("example.com", "private/secret.pdf", -time.Hour), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stale signed URL served the file: status=%d", rec.Code)
	}
}

func tamperSig(signedPath string) string {
	i := strings.Index(signedPath, "sig=")
	if i < 0 {
		return signedPath
	}
	// Flip the last hex nibble of the signature.
	b := []byte(signedPath)
	last := len(b) - 1
	if b[last] == '0' {
		b[last] = '1'
	} else {
		b[last] = '0'
	}
	return string(b)
}

// ============================================================================
// Item #2 - onboarding audio moved to the private tier; transcription still
// works. The private-CDN signer for the transcribe fetch is a strict no-op
// off-platform (getPlatformMedia()==nil), and transcribe reads a private-tier
// file straight off local disk (no HTTP hop, no public exposure needed).
// ============================================================================

func TestSignPrivateCDNURLForApp_NoOpOffPlatform(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	// No platform media configured (the test/off-platform case): must be a
	// safe no-op so the plain URL path is unchanged.
	if _, ok := signPrivateCDNURLForApp(app, "https://cdn.example.com/private/x/uploads/private/a.webm"); ok {
		t.Fatalf("signPrivateCDNURLForApp signed a URL with no media CDN configured")
	}
	if _, ok := signPrivateCDNURLForApp(app, "https://evil.example.com/whatever"); ok {
		t.Fatalf("signPrivateCDNURLForApp signed an arbitrary URL")
	}
}

func TestTranscribe_ReadsPrivateTierLocalFile(t *testing.T) {
	// Onboarding audio now lands at uploads/private/... . resolveTranscribeInput
	// must still resolve it off local disk (the whole point: private + readable
	// server-side, never public). We only check input resolution, not the
	// whisper/ffmpeg exec (host binaries absent in CI).
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "uploads", "private"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uploads", "private", "brief.webm"), []byte("AUDIO"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	app := &App{Dir: dir}
	// Same shape the transcribe flow feeds: audio_url "/uploads/private/..."
	// with the leading slash trimmed (ltrim in transcribe_brief.yaml).
	got, audioRef, cleanup, err := resolveTranscribeInput(context.Background(), app, "uploads/private/brief.webm", transcribeConfig())
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()
	if err != nil {
		t.Fatalf("resolveTranscribeInput on a private-tier file failed: %v", err)
	}
	if want := filepath.Join(dir, "uploads", "private", "brief.webm"); got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
	if audioRef != "uploads/private/brief.webm" {
		t.Fatalf("audio_path ref = %q", audioRef)
	}
}
