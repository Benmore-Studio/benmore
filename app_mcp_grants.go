//go:build !cli

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mattn/go-sqlite3"
)

const appMCPAccessLifetime = 15 * time.Minute
const appMCPGrantLifetime = 30 * 24 * time.Hour

var errAppMCPGrantDenied = errors.New("connector grant is unavailable or denied")

type appMCPGrant struct {
	ID, App, Tenant, Client, Resource, Epoch, Scopes, UserCreated string
	UserID                                                        int64
	ExpiresAt                                                     int64
	Revoked                                                       bool
	// AutoApprove is the space-separated list of approval: grant command tools
	// the user ticked at consent, each as name@<manifest contract digest>. It
	// is set once when the grant is minted and can only shrink from what
	// consent offered; refresh never touches it. AutoApproveEpoch is the
	// owner's auto-approve epoch the user consented under: an owner off/on
	// cycle (or any write-epoch rotation) and a reviewed mcp.yaml change each
	// stop the list matching, so the user must consent again.
	AutoApprove      string `json:",omitempty"`
	AutoApproveEpoch string `json:",omitempty"`
}
type appMCPTokenPair struct {
	AccessToken, RefreshToken, Scopes, GrantID string
	AccessExpiresAt, GrantExpiresAt            int64
}

func ensureAppMCPGrantTables(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS _benmore_mcp_grants (
   id TEXT PRIMARY KEY, app TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES _benmore_users(id) ON DELETE CASCADE,
   user_created TEXT NOT NULL, tenant TEXT NOT NULL, client TEXT NOT NULL, resource TEXT NOT NULL,
   epoch TEXT NOT NULL, scopes TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
   auto_approve TEXT NOT NULL DEFAULT '', auto_approve_epoch TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS _benmore_mcp_credentials (
   token_hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES _benmore_mcp_grants(id) ON DELETE CASCADE,
   kind TEXT NOT NULL CHECK(kind IN ('access','refresh')), expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1)))`,
		`CREATE INDEX IF NOT EXISTS _benmore_mcp_credentials_grant ON _benmore_mcp_credentials(grant_id)`,
		`CREATE TABLE IF NOT EXISTS _benmore_mcp_authorizations (
 key_hash TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('consent','code')),
 user_id INTEGER NOT NULL REFERENCES _benmore_users(id) ON DELETE CASCADE,
 app TEXT NOT NULL, payload TEXT NOT NULL, expires_at INTEGER NOT NULL,
 used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1)))`,
		// Per-user upstream credentials for external connections: sealed under the
		// app key with user and connection in the AAD (app_mcp_external.go).
		`CREATE TABLE IF NOT EXISTS _benmore_mcp_connection_credentials (
 user_id INTEGER NOT NULL REFERENCES _benmore_users(id) ON DELETE CASCADE, connection TEXT NOT NULL,
 upstream_host TEXT NOT NULL, secret_ciphertext TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (user_id, connection))`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	// Grant tables created before auto-approval lack its columns. An existing
	// grant gets an empty epoch, so it never auto-approves until reconsent.
	for _, column := range []string{"auto_approve", "auto_approve_epoch"} {
		var has int
		if err := tx.QueryRow("SELECT count(*) FROM pragma_table_info('_benmore_mcp_grants') WHERE name=?", column).Scan(&has); err != nil {
			return err
		}
		if has == 0 {
			if _, err := tx.Exec("ALTER TABLE _benmore_mcp_grants ADD COLUMN " + column + " TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// appMCPAutoApproveEntry is how a consented tool is stored on a grant: bound
// to the reviewed manifest's contract digest, so a changed declaration
// (description, permissions, schema, handler) no longer matches.
// The entry binds the consent to the reviewed contract AND execution digests:
// the contract digest covers only mcp.yaml (it names the handler flow, not its
// body), so an edited flow behind the same tool name would otherwise keep
// auto-applying under an old tick. Any reviewed source change therefore sends
// users back to per-write review until they consent again (fails safe).
func appMCPAutoApproveEntry(name, contractDigest, executionDigest string) string {
	return name + "@" + contractDigest + "." + executionDigest
}

// appMCPAutoApproveDisplayName is the tool name of a stored entry.
func appMCPAutoApproveDisplayName(entry string) string {
	name, _, _ := strings.Cut(entry, "@")
	return name
}

// appMCPAutoApproveOffer lists the command tools a grant with these scopes may
// auto-approve right now (as name@digest entries, sorted, deduplicated) and the
// owner epoch they are offered under: declared approval: grant, not a
// transfer, live (writes on), the owner switch on, and every permission within
// scopes.
func appMCPAutoApproveOffer(app *App, generation *appMCPRuntimeGeneration, scopes string) ([]string, string) {
	state, live := appMCPWritesLive(app)
	if !live || !state.AutoApprove || !appMCPOperationHex(state.AutoApproveEpoch, 32) || generation == nil || generation.manifest == nil || generation.manifest.ContractDigest == "" {
		return nil, ""
	}
	var offer []string
	for _, command := range appMCPLiveCommands(app, generation) {
		entry := appMCPAutoApproveEntry(command.tool.Name, generation.manifest.ContractDigest, generation.manifest.ExecutionDigest)
		if command.tool.Approval == "grant" && command.tool.Transfer == nil && scopesWithin(scopes, strings.Join(command.tool.Permissions, " ")) && !slices.Contains(offer, entry) {
			offer = append(offer, entry)
		}
	}
	if len(offer) == 0 {
		return nil, ""
	}
	sort.Strings(offer)
	return offer, state.AutoApproveEpoch
}

// appMCPNarrowGrantAutoApprove keeps only the entries still offered now, and
// only while the owner epoch is the one the user consented under; otherwise it
// clears the list and its epoch. Approval and minting both call it.
func appMCPNarrowGrantAutoApprove(app *App, grant *appMCPGrant) {
	offer, epoch := appMCPAutoApproveOffer(app, snapshotAppMCPGeneration(app), grant.Scopes)
	if grant.AutoApproveEpoch != "" && epoch != "" && SecureCompare(grant.AutoApproveEpoch, epoch) {
		grant.AutoApprove = appMCPNarrowAutoApprove(grant.AutoApprove, offer)
	} else {
		grant.AutoApprove = ""
	}
	if grant.AutoApprove == "" {
		grant.AutoApproveEpoch = ""
	}
}

// appMCPNarrowAutoApprove keeps the entries of list that are also offered.
func appMCPNarrowAutoApprove(list string, offer []string) string {
	var kept []string
	for _, name := range strings.Fields(list) {
		if slices.Contains(offer, name) && !slices.Contains(kept, name) {
			kept = append(kept, name)
		}
	}
	sort.Strings(kept)
	return strings.Join(kept, " ")
}

func appMCPRandomToken(prefix string) (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(data[:]), nil
}
func appMCPCredentialHash(raw, kind string) (string, error) {
	prefix := ""
	switch kind {
	case "access":
		prefix = "bmca_"
	case "refresh":
		prefix = "bmcr_"
	case "consent":
		prefix = "bmcs_"
	case "code":
		prefix = "bmcc_"
	default:
		return "", errAppMCPGrantDenied
	}
	if !strings.HasPrefix(raw, prefix) || len(raw) != len(prefix)+64 {
		return "", errAppMCPGrantDenied
	}
	suffix := strings.TrimPrefix(raw, prefix)
	decoded, err := hex.DecodeString(suffix)
	if err != nil || suffix != hex.EncodeToString(decoded) {
		return "", errAppMCPGrantDenied
	}
	return hashBytesSHA256([]byte(raw)), nil
}
func validAppMCPResource(app *App, resource string) bool {
	parsed, err := url.Parse(resource)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.EscapedPath() != "/api/_mcp" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.String() != resource {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	address := net.ParseIP(parsed.Hostname())
	return (app.DevMode || app.MCPLocal) && parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || address != nil && address.IsLoopback())
}
func appMCPExplicitScopes(scopes string) ([]string, error) {
	values := strings.Fields(scopes)
	if len(values) == 0 || validateFlowPermissions(values) != nil {
		return nil, errAppMCPGrantDenied
	}
	for _, value := range values {
		if value == "_none_:read" {
			return nil, errAppMCPGrantDenied
		}
	}
	sort.Strings(values)
	return values, nil
}
func appMCPSupportedScopes(manifest *AppMCPManifest) string {
	known := map[string]bool{}
	if manifest != nil {
		for _, tool := range manifest.Tools {
			if tool.Effect != "read" {
				continue
			}
			for _, scope := range tool.Permissions {
				known[scope] = true
			}
		}
	}
	values := make([]string, 0, len(known))
	for scope := range known {
		values = append(values, scope)
	}
	sort.Strings(values)
	if len(values) == 0 {
		return "_none_:read"
	}
	return strings.Join(values, " ")
}

// Reuses canonical account/membership/role resolution without creating a login.
// Tenant selection is explicit, and delegated identities cannot use admin bypass.
func appMCPGrantActor(app *App, grant *appMCPGrant, now time.Time) (*Session, error) {
	return appMCPGrantActorFor(context.Background(), app, grant, now)
}

func appMCPGrantActorFor(ctx context.Context, app *App, grant *appMCPGrant, now time.Time) (*Session, error) {
	return appMCPGrantActorForGeneration(ctx, app, snapshotAppMCPGeneration(app), grant, now)
}

func appMCPGrantActorForGeneration(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, now time.Time) (*Session, error) {
	manifest := (*AppMCPManifest)(nil)
	if generation != nil {
		manifest = generation.manifest
	}
	// Write-command scopes count only while owner approved writes are live.
	return appMCPGrantActorForGenerationScopes(ctx, app, generation, grant, now, appMCPLiveScopes(app, manifest, generation))
}

func appMCPGrantActorForGenerationScopes(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, now time.Time, allowedScopes string) (*Session, error) {
	if app == nil {
		return nil, errAppMCPGrantDenied
	}
	// Reload publishes these immutable policy references together. Pass that
	// generation to the canonical loader; a final manifest check alone left
	// its intermediate Group/Roles reads racing with staged publication.
	// Construct a policy-only view: never copy App or its synchronization state.
	if generation == nil || generation.origin != app {
		return nil, errAppMCPGrantDenied
	}
	manifest, authority := generation.manifest, generation.view
	if manifest == nil || grant.Revoked || grant.ExpiresAt <= now.Unix() || grant.UserID <= 0 || !validAppMCPResource(app, grant.Resource) || grant.Client == "" {
		return nil, errAppMCPGrantDenied
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil || !state.Exposed || grant.App != state.App || !SecureCompare(grant.Epoch, state.Epoch) {
		return nil, errAppMCPGrantDenied
	}
	if validateAppMCPDigests(app.Dir, manifest) != nil {
		return nil, errAppMCPGrantDenied
	}
	if _, err := appMCPExplicitScopes(grant.Scopes); err != nil {
		return nil, err
	}
	if authority.Group != nil && authority.Group.Table != "" && (grant.Tenant == "" || grant.Tenant == "0") {
		return nil, errAppMCPGrantDenied
	}
	ctx, cancel := context.WithTimeout(ctx, readOnlyQueryTimeout)
	defer cancel()
	conn, _, closeConn, err := openReadOnlyQueryConn(ctx, app.DB)
	if err != nil {
		return nil, errAppMCPGrantDenied
	}
	defer func() { rollbackAppMCPReadConn(conn); closeConn() }()
	if err = conn.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(authorizeAppMCPActor); return nil }); err != nil {
		return nil, errAppMCPGrantDenied
	}
	// Literal deferred BEGIN, independent of the ordinary mutation DSN's txlock.
	if _, err = conn.ExecContext(ctx, "BEGIN"); err != nil {
		return nil, errAppMCPGrantDenied
	}
	q := &appMCPActorQuerier{ctx: ctx, conn: conn}
	actor, err := loadScheduledActorWith(authority, q, grant.UserID, &grant.Tenant, true)
	if err != nil || ctx.Err() != nil {
		return nil, errAppMCPGrantDenied
	}
	var created string
	if err := q.QueryRow("SELECT COALESCE(created_at,'') FROM _benmore_users WHERE id=?", grant.UserID).Scan(&created); err != nil || created == "" || created != grant.UserCreated || ctx.Err() != nil {
		return nil, errAppMCPGrantDenied
	}
	actor.Scopes = appMCPRequestedScopeTokens(intersectScopes(grant.Scopes, intersectScopes(actor.Scopes, allowedScopes)), grant.Scopes)
	if actor.Scopes == "_none_:read" || actor.Scopes == "" {
		return nil, errAppMCPGrantDenied
	}
	if ctx.Err() != nil || !appMCPGenerationCurrent(app, generation) {
		return nil, errAppMCPGrantDenied
	}
	// The credential is the grant as the live manifest still allows it: a
	// write scope dropped from the live set (writes off, tool removed) must
	// not keep implying a table read through the table_scopes: access path.
	actor.CredentialScopes = actor.Scopes
	actor.Permissions = strings.Fields(actor.Scopes)
	actor.ID = "connector:" + grant.ID
	actor.connectorGrant = true
	return actor, nil
}

// Called only after server-owned consent/code authorization; this is not an
// HTTP mint endpoint and accepts no caller-selected account from tool input.
func createAppMCPGrant(app *App, userID int64, tenant, client, resource, requested string, now time.Time) (*appMCPTokenPair, error) {
	return createAppMCPGrantFor(context.Background(), app, userID, tenant, client, resource, requested, now)
}

func createAppMCPGrantFor(ctx context.Context, app *App, userID int64, tenant, client, resource, requested string, now time.Time) (*appMCPTokenPair, error) {
	return createAppMCPGrantWithScopeSet(ctx, app, userID, tenant, client, resource, requested, now, appMCPLiveScopes(app, appMCPManifestSnapshot(app), snapshotAppMCPGeneration(app)))
}

// createAppMCPNativeGrantFor is private native admission machinery. Its callers
// must already hold trusted first-party authorization; public OAuth continues
// to use createAppMCPGrantFor and the B1 read-only scope set.
func createAppMCPNativeGrantFor(ctx context.Context, app *App, userID int64, tenant, client, resource, declaration string, now time.Time) (*appMCPTokenPair, error) {
	manifest := appMCPManifestSnapshot(app)
	tool := appMCPUpdateTool(manifest, declaration)
	if tool != nil {
		if validateAppMCPUpdateDeclaration(*tool) != nil {
			return nil, errAppMCPGrantDenied
		}
	} else {
		generation := snapshotAppMCPGeneration(app)
		var found *AppMCPTool
		if generation != nil && generation.manifest == manifest {
			for i := range manifest.Tools {
				candidate := &manifest.Tools[i]
				if candidate.Name == declaration && candidate.Handler.Kind == "flow" && candidate.Handler.Operation == "command" {
					if found != nil {
						return nil, errAppMCPGrantDenied
					}
					found = candidate
				}
			}
			if found != nil {
				flow := appMCPCommandFlowByName(generation, found.Handler.Flow)
				if flow == nil || validateAppMCPCommandDeclaration(found, flow.Command) != nil {
					return nil, errAppMCPGrantDenied
				}
			}
		}
		tool = found
	}
	if tool == nil {
		return nil, errAppMCPGrantDenied
	}
	requested := strings.Join(tool.Permissions, " ")
	return createAppMCPGrantWithScopeSet(ctx, app, userID, tenant, client, resource, requested, now, requested)
}

func createAppMCPGrantWithScopeSet(ctx context.Context, app *App, userID int64, tenant, client, resource, requested string, now time.Time, allowed string) (*appMCPTokenPair, error) {
	if app.MCP == nil || !validAppMCPResource(app, resource) || client == "" || client != strings.TrimSpace(client) || len(client) > 256 || !utf8.ValidString(client) {
		return nil, errAppMCPGrantDenied
	}
	scopes, err := appMCPExplicitScopes(requested)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, scope := range strings.Fields(allowed) {
		known[scope] = true
	}
	for _, scope := range scopes {
		if !known[scope] {
			return nil, errAppMCPGrantDenied
		}
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil || !state.Exposed {
		return nil, errAppMCPGrantDenied
	}
	id, err := appMCPRandomToken("")
	if err != nil {
		return nil, err
	}
	grant := &appMCPGrant{ID: id, App: state.App, UserID: userID, Tenant: tenant, Client: client, Resource: resource, Epoch: state.Epoch, Scopes: strings.Join(scopes, " "), ExpiresAt: now.Add(appMCPGrantLifetime).Unix()}
	grant.UserCreated, err = readAppMCPUserCreatedFor(ctx, app, userID)
	if err != nil {
		return nil, errAppMCPGrantDenied
	}
	return persistAppMCPGrantForScopes(ctx, app, grant, now, allowed)
}

// The supplied grant keeps the original consent epoch/account/tenant binding.
func persistAppMCPGrant(app *App, grant *appMCPGrant, now time.Time) (*appMCPTokenPair, error) {
	return persistAppMCPGrantFor(context.Background(), app, grant, now)
}

func persistAppMCPGrantFor(ctx context.Context, app *App, grant *appMCPGrant, now time.Time) (*appMCPTokenPair, error) {
	return persistAppMCPGrantForScopes(ctx, app, grant, now, appMCPLiveScopes(app, appMCPManifestSnapshot(app), snapshotAppMCPGeneration(app)))
}

func persistAppMCPGrantForScopes(ctx context.Context, app *App, grant *appMCPGrant, now time.Time, allowedScopes string) (*appMCPTokenPair, error) {
	actor, err := appMCPGrantActorForGenerationScopes(ctx, app, snapshotAppMCPGeneration(app), grant, now, allowedScopes)
	if err != nil {
		return nil, err
	}
	grant.Scopes = actor.Scopes // returned scopes equal the persisted effective scopes
	// The consented list only ever shrinks to what is offerable at minting.
	appMCPNarrowGrantAutoApprove(app, grant)
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO main._benmore_mcp_grants(id,app,user_id,user_created,tenant,client,resource,epoch,scopes,expires_at,auto_approve,auto_approve_epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, grant.ID, grant.App, grant.UserID, grant.UserCreated, grant.Tenant, grant.Client, grant.Resource, grant.Epoch, grant.Scopes, grant.ExpiresAt, grant.AutoApprove, grant.AutoApproveEpoch); err != nil {
		return nil, err
	}
	pair, err := insertAppMCPCredentials(tx, grant, now)
	if err != nil {
		return nil, err
	}
	if err := validateAppMCPEpoch(app.Dir, grant.Epoch); err != nil {
		return nil, errAppMCPGrantDenied
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pair, nil
}
func insertAppMCPCredentials(tx *sql.Tx, grant *appMCPGrant, now time.Time) (*appMCPTokenPair, error) {
	access, err := appMCPRandomToken("bmca_")
	if err != nil {
		return nil, err
	}
	refresh, err := appMCPRandomToken("bmcr_")
	if err != nil {
		return nil, err
	}
	accessExpiry := now.Add(appMCPAccessLifetime).Unix()
	if accessExpiry > grant.ExpiresAt {
		accessExpiry = grant.ExpiresAt
	}
	for _, credential := range []struct {
		raw, kind string
		expiry    int64
	}{{access, "access", accessExpiry}, {refresh, "refresh", grant.ExpiresAt}} {
		hash, err := appMCPCredentialHash(credential.raw, credential.kind)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec("INSERT INTO main._benmore_mcp_credentials(token_hash,grant_id,kind,expires_at) VALUES(?,?,?,?)", hash, grant.ID, credential.kind, credential.expiry); err != nil {
			return nil, err
		}
	}
	return &appMCPTokenPair{AccessToken: access, RefreshToken: refresh, Scopes: grant.Scopes, GrantID: grant.ID, AccessExpiresAt: accessExpiry, GrantExpiresAt: grant.ExpiresAt}, nil
}

func readAppMCPGrant(q rowQuerier, id string) (*appMCPGrant, error) {
	return scanAppMCPGrant(q.QueryRow(`SELECT id,app,user_id,user_created,tenant,client,resource,epoch,scopes,expires_at,revoked FROM main._benmore_mcp_grants WHERE id=?`, id))
}

func scanAppMCPGrant(row *sql.Row) (*appMCPGrant, error) {
	var grant appMCPGrant
	var revoked int
	if err := row.Scan(&grant.ID, &grant.App, &grant.UserID, &grant.UserCreated, &grant.Tenant, &grant.Client, &grant.Resource, &grant.Epoch, &grant.Scopes, &grant.ExpiresAt, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errAppMCPGrantDenied
		}
		return nil, err
	}
	grant.Revoked = revoked != 0
	return &grant, nil
}

// Internal comparison may see the stored credential hash; viewer SQL retains
// its existing masks. No connection-control or write permission is added.
func authorizeAppMCPAccess(action int, arg1, arg2, database string) int {
	if action == sqlite3.SQLITE_READ && database != "main" {
		return sqlite3.SQLITE_DENY
	}
	if action == sqlite3.SQLITE_READ && database == "main" && strings.EqualFold(arg1, "_benmore_mcp_credentials") && strings.EqualFold(arg2, "token_hash") {
		return sqlite3.SQLITE_OK
	}
	return authorizeReadOnlyQuery(action, arg1, arg2, database)
}

func readAppMCPAccessGrant(ctx context.Context, app *App, hash, resource string, now time.Time) (*appMCPGrant, error) {
	return readAppMCPCredentialGrant(ctx, app, hash, "access", resource, now, true)
}

// Refresh replay still needs the spent credential; revocation also accepts
// expired credentials. Only live access/refresh preflight checks expiry.
func readAppMCPCredentialGrant(ctx context.Context, app *App, hash, kind, resource string, now time.Time, requireLive bool) (*appMCPGrant, error) {
	ctx, cancel := context.WithTimeout(ctx, readOnlyQueryTimeout)
	defer cancel()
	conn, _, closeConn, err := openReadOnlyQueryConn(ctx, app.DB)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	if err := conn.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(authorizeAppMCPAccess); return nil }); err != nil {
		return nil, err
	}
	// One statement binds the live credential to its grant under one snapshot.
	grant, err := scanAppMCPGrant(conn.QueryRowContext(ctx, `SELECT g.id,g.app,g.user_id,g.user_created,g.tenant,g.client,g.resource,g.epoch,g.scopes,g.expires_at,g.revoked
 FROM main._benmore_mcp_credentials c JOIN main._benmore_mcp_grants g ON g.id=c.grant_id
 WHERE c.token_hash=? AND c.kind=? AND (?=0 OR c.expires_at>?) AND g.resource=?`, hash, kind, requireLive, now.Unix(), resource))
	return grant, err
}

func resolveAppMCPAccess(app *App, raw, resource string, now time.Time) (*appMCPGrant, *Session, error) {
	return resolveAppMCPAccessFor(context.Background(), app, raw, resource, now)
}

func resolveAppMCPAccessFor(ctx context.Context, app *App, raw, resource string, now time.Time) (*appMCPGrant, *Session, error) {
	return resolveAppMCPAccessForGeneration(ctx, app, snapshotAppMCPGeneration(app), raw, resource, now)
}

func resolveAppMCPAccessForGeneration(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, raw, resource string, now time.Time) (*appMCPGrant, *Session, error) {
	hash, err := appMCPCredentialHash(raw, "access")
	if err != nil {
		return nil, nil, err
	}
	grant, err := readAppMCPAccessGrant(ctx, app, hash, resource, now)
	if err != nil {
		return nil, nil, errAppMCPGrantDenied
	}
	// The protected lease is closed before canonical actor helpers use the pool.
	actor, err := appMCPGrantActorForGeneration(ctx, app, generation, grant, now)
	return grant, actor, err
}

func refreshAppMCPGrant(app *App, raw, client, resource string, now time.Time) (*appMCPTokenPair, error) {
	return refreshAppMCPGrantFor(context.Background(), app, raw, client, resource, "", now)
}

func refreshAppMCPGrantFor(ctx context.Context, app *App, raw, client, resource, requested string, now time.Time) (*appMCPTokenPair, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	hash, err := appMCPCredentialHash(raw, "refresh")
	if err != nil {
		return nil, err
	}
	before, err := readAppMCPCredentialGrant(ctx, app, hash, "refresh", resource, now, true)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || before.Client != client {
		return nil, errAppMCPGrantDenied
	}
	id := before.ID
	var scopeErr error
	if requested != "" {
		_, scopeErr = appMCPExplicitScopes(requested)
		if !scopesWithin(before.Scopes, requested) {
			scopeErr = errAppMCPGrantDenied
		}
	}
	actor, authorityErr := appMCPGrantActorFor(ctx, app, before, now)
	var tx *sql.Tx
	var result sql.Result
	// The consuming write is first: a deferred SQLite transaction must not
	// acquire a read snapshot before competing for the writer lock.
	// ponytail: one family writer with a five-second lock retry ceiling.
	deadline := time.Now().Add(5 * time.Second)
	for {
		tx, err = app.DB.BeginTx(ctx, nil)
		if err == nil {
			result, err = tx.ExecContext(ctx, "UPDATE main._benmore_mcp_credentials SET used=1 WHERE token_hash=? AND grant_id=? AND kind='refresh' AND used=0 AND expires_at>?", hash, id, now.Unix())
		}
		if err == nil {
			break
		}
		if tx != nil {
			tx.Rollback()
		}
		var sqliteErr sqlite3.Error
		if !errors.As(err, &sqliteErr) || (sqliteErr.Code != sqlite3.ErrBusy && sqliteErr.Code != sqlite3.ErrLocked) || !time.Now().Before(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer tx.Rollback()
	grant, err := readAppMCPGrant(tx, id)
	if err != nil || grant.App != before.App || grant.UserID != before.UserID || grant.UserCreated != before.UserCreated || grant.Tenant != before.Tenant || grant.Client != client || grant.Resource != resource || grant.Epoch != before.Epoch || grant.ExpiresAt != before.ExpiresAt || grant.Revoked || grant.ExpiresAt <= now.Unix() {
		return nil, errAppMCPGrantDenied
	}
	consumed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if consumed != 1 {
		var used int
		if err := tx.QueryRow("SELECT used FROM main._benmore_mcp_credentials WHERE token_hash=? AND grant_id=? AND kind='refresh'", hash, id).Scan(&used); err != nil || used != 1 {
			return nil, errAppMCPGrantDenied
		}
		if _, err := tx.Exec("UPDATE main._benmore_mcp_grants SET revoked=1 WHERE id=?", id); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, errAppMCPGrantDenied // spent hashes persist until fixed grant expiry
	}
	if authorityErr != nil {
		return nil, authorityErr
	}
	if scopeErr != nil {
		return nil, scopeErr
	}
	grant.Scopes = intersectScopes(grant.Scopes, actor.Scopes)
	if requested != "" {
		grant.Scopes = intersectScopes(grant.Scopes, requested)
	}
	if grant.Scopes == "_none_:read" || grant.Scopes == "" {
		return nil, errAppMCPGrantDenied
	}
	if _, err := tx.Exec("UPDATE main._benmore_mcp_grants SET scopes=? WHERE id=?", grant.Scopes, id); err != nil {
		return nil, err
	}
	pair, err := insertAppMCPCredentials(tx, grant, now)
	if err != nil {
		return nil, err
	}
	if err := validateAppMCPEpoch(app.Dir, grant.Epoch); err != nil {
		return nil, errAppMCPGrantDenied
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pair, nil
}

// revokeAppMCPUserGrants ends every connector grant and pending connector
// consent/code of one account, in the caller's transaction. Password
// replacement and account claims call it beside session and API-token
// revocation: a grant is a reusable delegated credential the old password
// could have produced. Grant rows stay as revoked history, as on restore. The
// tables exist only once a connector app created them.
func revokeAppMCPUserGrants(tx *sql.Tx, userID int64) error {
	for _, step := range []struct{ table, query string }{
		{"_benmore_mcp_grants", "UPDATE main._benmore_mcp_grants SET revoked=1 WHERE user_id=? AND revoked=0"},
		{"_benmore_mcp_authorizations", "DELETE FROM main._benmore_mcp_authorizations WHERE user_id=?"},
	} {
		var exists int
		if err := tx.QueryRow("SELECT COUNT(*) FROM main.sqlite_master WHERE type='table' AND name=?", step.table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		if _, err := tx.Exec(step.query, userID); err != nil {
			return err
		}
	}
	return nil
}

func revokeAppMCPGrant(app *App, id string) error {
	root, key, err := appMCPAuthorityRoot(app.Dir)
	if err != nil {
		return errAppMCPGrantDenied
	}
	root.Close()
	_, err = app.DB.Exec("UPDATE main._benmore_mcp_grants SET revoked=1 WHERE id=? AND app=?", id, key)
	return err
}

// Carries one existing canonical querier through the protected actor snapshot.
type appMCPActorQuerier struct {
	ctx  context.Context
	conn *sql.Conn
}

func (q *appMCPActorQuerier) Query(query string, args ...any) (*sql.Rows, error) {
	return q.conn.QueryContext(q.ctx, query, args...)
}
func (q *appMCPActorQuerier) QueryRow(query string, args ...any) *sql.Row {
	return q.conn.QueryRowContext(q.ctx, query, args...)
}

// Framework-owned actor SQL may read the reset flag and main physical metadata.
// Viewer masks are unchanged; foreign/temp authority cannot participate.
func authorizeAppMCPActor(action int, arg1, arg2, database string) int {
	if action == sqlite3.SQLITE_TRANSACTION && (arg1 == "BEGIN" || arg1 == "ROLLBACK") {
		return sqlite3.SQLITE_OK
	}
	if action == sqlite3.SQLITE_READ {
		if database != "main" {
			return sqlite3.SQLITE_DENY
		}
		if arg2 == "password_change_required" {
			return sqlite3.SQLITE_OK
		}
		if readOnlyQueryMaskedColumn(arg1, arg2) {
			return sqlite3.SQLITE_DENY
		}
	}
	if action == sqlite3.SQLITE_PRAGMA {
		if strings.EqualFold(arg1, "table_info") && isValidColumnName(arg2) && database == "main" {
			return sqlite3.SQLITE_OK
		}
		if strings.EqualFold(arg1, "database_list") && arg2 == "" {
			return sqlite3.SQLITE_OK
		}
	}
	return authorizeReadOnlyQuery(action, arg1, arg2, database)
}

// appMCPRequestedScopeTokens keeps only the tokens of an intersection that the
// grant itself names. intersectScopes derives `x:read` from `x:write` ∩ a role's
// `x:read`, so a write grant held by a role with both came back carrying a read
// token nobody requested and the connector does not advertise: consent then
// echoed it and the approve step refused it as an unknown scope, which made
// every connector with write tools unconnectable for such roles. Dropping an
// implied token never widens anything (hasScope still lets write imply read),
// and keeps the actor's scopes a literal subset of what was consented to.
func appMCPRequestedScopeTokens(scopes, requested string) string {
	named := map[string]bool{}
	for _, token := range strings.Fields(requested) {
		named[token] = true
	}
	var kept []string
	for _, token := range strings.Fields(scopes) {
		if named[token] {
			kept = append(kept, token)
		}
	}
	if len(kept) == 0 {
		return "_none_:read"
	}
	return strings.Join(kept, " ")
}
