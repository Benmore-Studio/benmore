//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpArtifactsTable          = "_benmore_mcp_artifacts"
	mcpArtifactManifestVersion = 1
	mcpArtifactMaxBytes        = 50 << 20
	mcpArtifactTemplateVersion = "artifact-html/1"
	mcpArtifactExportTool      = "artifact.export"
)

type appMCPArtifact struct {
	SchemaVersion      int               `json:"schema_version"`
	ID                 string            `json:"id"`
	OwnerUserID        int64             `json:"owner_user_id"`
	OwnerCreatedAt     string            `json:"owner_created_at"`
	Tenant             string            `json:"tenant"`
	Kind               string            `json:"kind"`
	SHA256             string            `json:"sha256"`
	Size               int64             `json:"size"`
	StorageRef         string            `json:"-"`
	SourceBundleDigest string            `json:"source_bundle_digest"`
	SourceRevisions    map[string]string `json:"source_revisions"`
	TemplateVersion    string            `json:"template_version"`
	EngineVersion      string            `json:"engine_version"`
	CreatedAt          string            `json:"created_at"`
	OperationID        string            `json:"operation_id"`
	RequiredRole       string            `json:"required_role"`
	RequiredScopes     []string          `json:"required_scopes"`
}

func ensureAppMCPArtifactTables(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS _benmore_mcp_artifacts (
 id TEXT PRIMARY KEY, owner_user_id INTEGER NOT NULL REFERENCES _benmore_users(id) ON DELETE CASCADE, owner_created_at TEXT NOT NULL,
 tenant TEXT NOT NULL, schema_version INTEGER NOT NULL DEFAULT 1 CHECK(schema_version = 1), kind TEXT NOT NULL CHECK(kind IN ('xlsx','html','pdf')), content_sha256 TEXT NOT NULL,
 size INTEGER NOT NULL CHECK(size >= 0), storage_ref TEXT NOT NULL, source_bundle_digest TEXT NOT NULL,
 source_revisions TEXT NOT NULL, template_version TEXT NOT NULL, engine_version TEXT NOT NULL,
 created_at TEXT NOT NULL, operation_id TEXT NOT NULL, required_role TEXT NOT NULL, required_scopes TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS _benmore_mcp_artifacts_owner ON _benmore_mcp_artifacts(owner_user_id, tenant, created_at)`,
		`CREATE TRIGGER IF NOT EXISTS _benmore_mcp_artifacts_immutable BEFORE UPDATE ON _benmore_mcp_artifacts BEGIN SELECT RAISE(ABORT, 'MCP artifact manifests are immutable'); END`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	for _, column := range []struct{ name, declaration string }{
		{"owner_created_at", "TEXT NOT NULL DEFAULT ''"},
		{"required_scopes", "TEXT NOT NULL DEFAULT '[]'"},
		{"schema_version", "INTEGER NOT NULL DEFAULT 1 CHECK(schema_version = 1)"},
	} {
		rows, err := tx.Query("PRAGMA table_info(" + quoteIdent(mcpArtifactsTable) + ")")
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var cid, notNull, primaryKey int
			var name, dataType string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
				rows.Close()
				return err
			}
			found = found || name == column.name
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if !found {
			if _, err := tx.Exec("ALTER TABLE " + quoteIdent(mcpArtifactsTable) + " ADD COLUMN " + quoteIdent(column.name) + " " + column.declaration); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func carryForwardMCPArtifacts(ctx context.Context, tx *sql.Tx, live map[string]*credTable, pairs map[int64]int64, summary *restoreCredentialSummary) error {
	cand, err := readCredTable(ctx, tx, mcpArtifactsTable, false, nil)
	if err != nil || cand == nil {
		return err
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM "+quoteIdent(mcpArtifactsTable))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil {
		summary.Removed[mcpArtifactsTable] += int(n)
	}
	lt := live[mcpArtifactsTable]
	if lt == nil || !cand.has["owner_user_id"] || !lt.has["owner_user_id"] || !lt.has["owner_created_at"] {
		return nil
	}
	users, err := readCredTable(ctx, tx, "_benmore_users", false, []string{"id", "created_at"})
	if err != nil || users == nil || !users.has["id"] || !users.has["created_at"] {
		return err
	}
	createdAtByID := map[int64]string{}
	for i := range users.rows {
		id, ok := credInt(users.get(i, "id"))
		createdAt := credText(users.get(i, "created_at"))
		valid := createdAt != ""
		if ok && valid {
			createdAtByID[id] = createdAt
		}
	}
	toCandidate := map[int64]int64{}
	for candidateID, liveID := range pairs {
		toCandidate[liveID] = candidateID
	}
	cols := present(cand.cols, lt)
	if len(cols) == 0 {
		return nil
	}
	quoted := make([]string, len(cols))
	for i, col := range cols {
		quoted[i] = quoteIdent(col)
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO "+quoteIdent(mcpArtifactsTable)+" ("+strings.Join(quoted, ", ")+") VALUES ("+strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")+")")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range lt.rows {
		owner, ok := credInt(lt.get(i, "owner_user_id"))
		candidateID, paired := toCandidate[owner]
		ownerCreatedAt := credText(lt.get(i, "owner_created_at"))
		validCreatedAt := ownerCreatedAt != ""
		if !ok || !paired || !validCreatedAt || !sameAccountIncarnation(createdAtByID[candidateID], ownerCreatedAt) {
			continue
		}
		values := make([]any, len(cols))
		for j, col := range cols {
			values[j] = lt.get(i, col)
			if col == "owner_user_id" {
				values[j] = candidateID
			}
		}
		if _, err := stmt.ExecContext(ctx, values...); err != nil {
			return err
		}
		summary.Kept[mcpArtifactsTable]++
	}
	return nil
}

const (
	mcpArtifactStoragePrefix = "uploads/private/mcp-artifacts/"
	// createAppMCPArtifact stores the bytes before it records the manifest, so
	// the orphan sweep leaves files this young alone.
	mcpArtifactOrphanGrace = 10 * time.Minute
)

var mcpArtifactFileName = regexp.MustCompile(`^artifact_[0-9a-f]{64}\.(xlsx|html|pdf)$`)

// appMCPArtifactRefsOwnedBy lists the stored bytes of uid's artifact
// manifests, read inside the purge transaction before the rows go.
func appMCPArtifactRefsOwnedBy(tx *sql.Tx, uid int64) ([]string, error) {
	cols, exists, err := purgeTableColumns(tx, mcpArtifactsTable)
	if err != nil || !exists {
		return nil, err
	}
	if err := purgeRequireColumns(mcpArtifactsTable, cols, "owner_user_id", "storage_ref"); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT storage_ref FROM _benmore_mcp_artifacts WHERE owner_user_id=?`, uid)
	if err != nil {
		return nil, fmt.Errorf("purge account: list artifact storage: %w", err)
	}
	defer rows.Close()
	var refs []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, fmt.Errorf("purge account: list artifact storage: %w", err)
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// deleteAppMCPArtifactBytes removes stored artifact bytes after the
// transaction that deleted their manifests committed. It is best effort: a
// failure is logged, and the local orphan sweep retries at the next start.
// A ref some manifest still names is kept.
func deleteAppMCPArtifactBytes(app *App, refs []string) {
	if app == nil || app.DB == nil || len(refs) == 0 {
		return
	}
	backend := storageBackendForApp(app)
	if backend == nil {
		log.Printf("MCP artifacts: storage unavailable; %d purged artifact file(s) left for the orphan sweep", len(refs))
		return
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref, mcpArtifactStoragePrefix) || !mcpArtifactFileName.MatchString(strings.TrimPrefix(ref, mcpArtifactStoragePrefix)) {
			continue
		}
		var referenced int
		if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_artifacts WHERE storage_ref=?`, ref).Scan(&referenced); err != nil || referenced != 0 {
			if err != nil {
				log.Printf("MCP artifacts: could not confirm %s is unreferenced: %v", ref, err)
			}
			continue
		}
		if err := backend.Delete(ref); err != nil {
			log.Printf("MCP artifacts: could not delete purged artifact bytes %s: %v", ref, err)
		}
	}
}

// sweepAppMCPOrphanArtifacts deletes local artifact files no manifest names:
// bytes a purge's post-commit delete missed, or that a restore orphaned by
// dropping manifests. It touches only framework-named files in the artifact
// directory, only when the manifest table exists, and keeps files younger
// than mcpArtifactOrphanGrace. S3 and CDN storage cannot be listed; they rely
// on the post-commit delete.
func sweepAppMCPOrphanArtifacts(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	local, ok := storageBackendForApp(app).(*LocalStorage)
	if !ok {
		return
	}
	entries, err := os.ReadDir(filepath.Join(local.Dir, filepath.FromSlash(mcpArtifactStoragePrefix)))
	if err != nil {
		return // usually absent: no artifact was ever stored
	}
	var tables int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, mcpArtifactsTable).Scan(&tables); err != nil || tables == 0 {
		return
	}
	rows, err := app.DB.Query(`SELECT storage_ref FROM _benmore_mcp_artifacts`)
	if err != nil {
		log.Printf("MCP artifacts: orphan sweep skipped: %v", err)
		return
	}
	referenced := map[string]bool{}
	for rows.Next() {
		var ref string
		if rows.Scan(&ref) == nil {
			referenced[ref] = true
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		log.Printf("MCP artifacts: orphan sweep skipped: %v", err)
		return
	}
	cutoff := time.Now().Add(-mcpArtifactOrphanGrace)
	removed := 0
	for _, entry := range entries {
		ref := mcpArtifactStoragePrefix + entry.Name()
		if !entry.Type().IsRegular() || !mcpArtifactFileName.MatchString(entry.Name()) || referenced[ref] {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := local.Delete(ref); err != nil {
			log.Printf("MCP artifacts: could not delete orphaned artifact %s: %v", ref, err)
			continue
		}
		removed++
	}
	if removed > 0 {
		log.Printf("MCP artifacts: removed %d orphaned artifact file(s)", removed)
	}
}

func createAppMCPArtifact(ctx context.Context, app *App, ownerUserID int64, ownerCreatedAt, tenant, role string, requiredScopes []string, operationID, kind string, data []byte, bundleDigest string, revisions map[string]string, engineVersion string) (appMCPArtifact, error) {
	return storeAppMCPArtifact(ctx, app, ownerUserID, ownerCreatedAt, tenant, role, requiredScopes, operationID, kind, data, bundleDigest, revisions, engineVersion, mcpArtifactTemplateVersion, false)
}

// storeAppMCPArtifact is createAppMCPArtifact with the template version to
// record. With budgeted set the owner's read artifacts (operation_id
// "read:<tool>") are kept to mcpReadArtifactKeepPerUser and
// mcpReadArtifactBytesPerUser: the insert and the deletion of the oldest ones
// that no longer fit share one transaction, and their bytes go once it commits.
func storeAppMCPArtifact(ctx context.Context, app *App, ownerUserID int64, ownerCreatedAt, tenant, role string, requiredScopes []string, operationID, kind string, data []byte, bundleDigest string, revisions map[string]string, engineVersion, templateVersion string, budgeted bool) (appMCPArtifact, error) {
	var out appMCPArtifact
	if app == nil || app.DB == nil || ownerUserID <= 0 || ownerCreatedAt == "" || !appMCPArtifactTenantValid(app, tenant) || role == "" || len(requiredScopes) == 0 || strings.TrimSpace(operationID) == "" {
		return out, errors.New("artifact owner and operation are required")
	}
	if kind != "xlsx" && kind != "html" && kind != "pdf" {
		return out, fmt.Errorf("unsupported artifact kind %q", kind)
	}
	if len(data) == 0 || len(data) > mcpArtifactMaxBytes {
		return out, fmt.Errorf("artifact size must be between 1 and %d bytes", mcpArtifactMaxBytes)
	}
	if err := ensureAppMCPArtifactTables(app.DB); err != nil {
		return out, err
	}
	if revisions == nil {
		revisions = map[string]string{}
	}
	revisionJSON, err := json.Marshal(revisions)
	if err != nil {
		return out, err
	}
	scopes := append([]string(nil), requiredScopes...)
	sort.Strings(scopes)
	scopeJSON, err := json.Marshal(scopes)
	if err != nil {
		return out, err
	}
	id, err := appMCPRandomToken("artifact_")
	if err != nil {
		return out, err
	}
	ext := map[string]string{"xlsx": ".xlsx", "html": ".html", "pdf": ".pdf"}[kind]
	ref := mcpArtifactStoragePrefix + id + ext
	backend := storageBackendForApp(app)
	if backend == nil {
		return out, errors.New("artifact storage unavailable")
	}
	if _, err := backend.Save(ref, bytes.NewReader(data)); err != nil {
		return out, fmt.Errorf("store artifact: %w", err)
	}
	removeOnFailure := true
	defer func() {
		if removeOnFailure {
			_ = backend.Delete(ref)
		}
	}()
	sum := sha256.Sum256(data)
	out = appMCPArtifact{SchemaVersion: mcpArtifactManifestVersion, ID: id, OwnerUserID: ownerUserID, OwnerCreatedAt: ownerCreatedAt, Tenant: tenant, Kind: kind,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), StorageRef: ref,
		SourceBundleDigest: bundleDigest, SourceRevisions: revisions,
		TemplateVersion: templateVersion, EngineVersion: engineVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), OperationID: operationID, RequiredRole: role, RequiredScopes: scopes}
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return appMCPArtifact{}, fmt.Errorf("record artifact manifest: %w", err)
	}
	defer tx.Rollback()
	var evicted []string
	if budgeted {
		if evicted, err = evictAppMCPReadArtifacts(ctx, tx, ownerUserID, len(data)); err != nil {
			return appMCPArtifact{}, fmt.Errorf("apply artifact budget: %w", err)
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO _benmore_mcp_artifacts
(id,owner_user_id,owner_created_at,tenant,schema_version,kind,content_sha256,size,storage_ref,source_bundle_digest,source_revisions,template_version,engine_version,created_at,operation_id,required_role,required_scopes)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, out.ID, out.OwnerUserID, out.OwnerCreatedAt, out.Tenant, out.SchemaVersion, out.Kind, out.SHA256, out.Size,
		out.StorageRef, out.SourceBundleDigest, string(revisionJSON), out.TemplateVersion, out.EngineVersion,
		out.CreatedAt, out.OperationID, out.RequiredRole, string(scopeJSON))
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return appMCPArtifact{}, fmt.Errorf("record artifact manifest: %w", err)
	}
	deleteAppMCPArtifactBytes(app, evicted)
	removeOnFailure = false
	return out, nil
}

// evictAppMCPReadArtifacts deletes, inside tx, the manifests of the owner's
// read artifacts that no longer fit once one more of size bytes is added, and
// returns their storage refs for deletion after the commit. It is strictly
// oldest-first: walking newest to oldest, the first artifact that breaks the
// count or byte budget (or is past mcpReadArtifactTTL) and every older one go,
// so a small old artifact never outlives a larger newer one.
func evictAppMCPReadArtifacts(ctx context.Context, tx *sql.Tx, owner int64, size int) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, storage_ref, size, created_at FROM _benmore_mcp_artifacts WHERE owner_user_id=? AND substr(operation_id,1,?)=? ORDER BY rowid DESC`,
		owner, len(mcpReadArtifactOperationPrefix), mcpReadArtifactOperationPrefix)
	if err != nil {
		return nil, err
	}
	var ids, refs []string
	kept, keptBytes, evicting := 1, int64(size), false // the artifact being added counts first
	for rows.Next() {
		var id, ref, createdAt string
		var n int64
		if err := rows.Scan(&id, &ref, &n, &createdAt); err != nil {
			rows.Close()
			return nil, err
		}
		if !evicting && (kept >= mcpReadArtifactKeepPerUser || keptBytes+n > mcpReadArtifactBytesPerUser || appMCPReadArtifactExpired(createdAt, time.Now())) {
			evicting = true
		}
		if !evicting {
			kept, keptBytes = kept+1, keptBytes+n
			continue
		}
		ids, refs = append(ids, id), append(refs, ref)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `DELETE FROM _benmore_mcp_artifacts WHERE id=?`, id); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

// appMCPArtifactTenantValid mirrors the grant authority: an app without
// groups has no workspace, so its tenant is empty; a group app refuses an
// empty or "0" tenant. The tenant is then bound to the caller by equality.
func appMCPArtifactTenantValid(app *App, tenant string) bool {
	if app.Group != nil && app.Group.Table != "" {
		return tenant != "" && tenant != "0"
	}
	return true
}

func readAppMCPArtifact(app *App, ref string, limit int64) ([]byte, error) {
	backend := storageBackendForApp(app)
	logical, err := privateUploadPath(app, backend, ref)
	if err != nil {
		return nil, err
	}
	var r io.ReadCloser
	switch store := backend.(type) {
	case *LocalStorage:
		root := filepath.Join(store.Dir, "uploads")
		f, ok := openServableFile(root, filepath.Join(store.Dir, filepath.FromSlash(logical)))
		if !ok {
			return nil, os.ErrNotExist
		}
		r = f
	case *S3Storage:
		resp, err := store.Fetch(logical)
		if err != nil {
			return nil, err
		}
		r = resp.Body
	case *CDNStorage:
		cfg := getPlatformMedia()
		unsigned := "https://" + store.CDNDomain + "/" + store.cdnKeyFor(logical)
		signed, err := signPrivateMediaURL(app, cfg, unsigned, time.Minute)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodGet, signed, nil)
		if err != nil {
			return nil, err
		}
		client := safeHTTPClientStrict(30 * time.Second)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("artifact storage returned HTTP %d", resp.StatusCode)
		}
		r = resp.Body
	default:
		return nil, errors.New("artifact storage backend does not support private reads")
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("artifact exceeds stored size limit")
	}
	return b, nil
}

// appMCPArtifactStorageReference reports whether raw (a logical upload path, a
// path under uploads/, an /uploads URL path or a CDN URL, in any letter case)
// names artifact storage. Only GET /api/_mcp/artifacts/{id} may read those
// bytes, because it rechecks owner, account incarnation, tenant, role and
// scopes; generic signed-URL and file-serving paths refuse them.
func appMCPArtifactStorageReference(raw string) bool {
	p := strings.ToLower(strings.ReplaceAll(raw, "\\", "/"))
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = path.Clean("/"+p) + "/"
	return strings.HasPrefix(p, "/private/mcp-artifacts/") || strings.Contains(p, "/uploads/private/mcp-artifacts/")
}

func registerAppMCPArtifactRoutes(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET /api/_mcp/artifacts/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		cookie, cookieErr := requestSessionCookie(r)
		if cookieErr != nil || cookie == nil || cookie.Value == "" || len(r.Header.Values("Authorization")) > 0 || edgeBridgeUserID(r) > 0 {
			http.Error(w, "interactive session required", http.StatusUnauthorized)
			return
		}
		session := getSession(app, r)
		storedSessionID, validCookie := presentedSessionKey(cookie.Value)
		if session == nil || !validCookie || session.ID != storedSessionID || session.CredentialScopes != "" || session.connectorGrant || session.ImpersonatorUserID > 0 || session.ActingAsGroup != "" || !directLoginSession(app, session) {
			http.Error(w, "interactive session required", http.StatusUnauthorized)
			return
		}
		var a appMCPArtifact
		var sourceRevisions, requiredScopes string
		err := app.DB.QueryRowContext(r.Context(), `SELECT id,owner_user_id,owner_created_at,tenant,schema_version,kind,content_sha256,size,storage_ref,source_bundle_digest,source_revisions,template_version,engine_version,created_at,operation_id,required_role,required_scopes FROM _benmore_mcp_artifacts WHERE id=?`, r.PathValue("id")).Scan(
			&a.ID, &a.OwnerUserID, &a.OwnerCreatedAt, &a.Tenant, &a.SchemaVersion, &a.Kind, &a.SHA256, &a.Size, &a.StorageRef, &a.SourceBundleDigest,
			&sourceRevisions, &a.TemplateVersion, &a.EngineVersion, &a.CreatedAt, &a.OperationID, &a.RequiredRole, &requiredScopes)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.NotFound(w, r)
			} else {
				serverError(w, r, app, "_mcp artifact", err, "artifact unavailable")
			}
			return
		}
		if a.SchemaVersion != mcpArtifactManifestVersion {
			serverError(w, r, app, "_mcp artifact", fmt.Errorf("manifest schema version %v, want %v", a.SchemaVersion, mcpArtifactManifestVersion), "artifact unavailable")
			return
		}
		if err := json.Unmarshal([]byte(sourceRevisions), &a.SourceRevisions); err != nil {
			serverError(w, r, app, "_mcp artifact", fmt.Errorf("source_revisions: %w", err), "artifact unavailable")
			return
		}
		if err := json.Unmarshal([]byte(requiredScopes), &a.RequiredScopes); err != nil || len(a.RequiredScopes) == 0 {
			if err == nil {
				err = errors.New("no required scopes")
			}
			serverError(w, r, app, "_mcp artifact", fmt.Errorf("required_scopes: %w", err), "artifact unavailable")
			return
		}
		if !appMCPArtifactAuthorized(app, session, a) {
			http.NotFound(w, r)
			return
		}
		if a.Size <= 0 || a.Size > mcpArtifactMaxBytes {
			serverError(w, r, app, "_mcp artifact", fmt.Errorf("manifest size %d outside 1..%d", a.Size, mcpArtifactMaxBytes), "artifact unavailable")
			return
		}
		data, err := readAppMCPArtifact(app, a.StorageRef, a.Size)
		if err != nil {
			serverError(w, r, app, "_mcp artifact", err, "artifact unavailable")
			return
		}
		sum := sha256.Sum256(data)
		storedHash, err := hex.DecodeString(a.SHA256)
		if err != nil || !bytes.Equal(sum[:], storedHash) || int64(len(data)) != a.Size {
			serverError(w, r, app, "_mcp artifact", fmt.Errorf("stored bytes (%d) do not match the manifest size and SHA-256", len(data)), "artifact integrity check failed")
			return
		}
		current := getSession(app, r)
		if current == nil || current.ID != session.ID || current.CredentialScopes != "" || current.connectorGrant || current.ImpersonatorUserID > 0 || current.ActingAsGroup != "" ||
			!directLoginSession(app, current) || !appMCPArtifactAuthorized(app, current, a) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", map[string]string{"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "html": "text/html; charset=utf-8", "pdf": "application/pdf"}[a.Kind])
		w.Header().Set("Content-Disposition", `attachment; filename="artifact.`+a.Kind+`"`)
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}

func appMCPArtifactAuthorized(app *App, session *Session, artifact appMCPArtifact) bool {
	if app == nil {
		return false
	}
	return appMCPArtifactAuthorizedFrom(context.Background(), app.DB, app, session, artifact)
}

func appMCPArtifactAuthorizedFrom(ctx context.Context, queryer appMCPArtifactQueryer, app *App, session *Session, artifact appMCPArtifact) bool {
	if app == nil || session == nil || session.UserID <= 0 || session.UserID != artifact.OwnerUserID || session.GroupID != artifact.Tenant || !appMCPArtifactTenantValid(app, artifact.Tenant) || len(artifact.RequiredScopes) == 0 {
		return false
	}
	var ownerCreatedAt string
	var role string
	if err := queryer.QueryRowContext(ctx, "SELECT COALESCE(created_at,''),COALESCE(role,'user') FROM _benmore_users WHERE id=?", artifact.OwnerUserID).Scan(&ownerCreatedAt, &role); err != nil || !sameAccountIncarnation(ownerCreatedAt, artifact.OwnerCreatedAt) {
		return false
	}
	if !(hasRole(role, artifact.RequiredRole) || HasAnyRole(session, []string{artifact.RequiredRole})) {
		return false
	}
	if strings.HasPrefix(artifact.OperationID, mcpReadArtifactOperationPrefix) && !appMCPReadArtifactStillAllowed(app, session, artifact, time.Now()) {
		return false
	}
	return scopesWithin(session.Scopes, strings.Join(artifact.RequiredScopes, " "))
}

func sameAccountIncarnation(a, b string) bool {
	parse := func(value string) (time.Time, bool) {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02 15:04:05.999999999"} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed.UTC(), true
			}
		}
		return time.Time{}, false
	}
	left, leftOK := parse(a)
	right, rightOK := parse(b)
	return leftOK && rightOK && left.Equal(right)
}

var mcpArtifactHTML = template.Must(template.New("mcp-artifact").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><title>{{.Title}}</title><style>body{font:14px system-ui,sans-serif;margin:2rem}table{border-collapse:collapse}th,td{border:1px solid #888;padding:.4rem;text-align:left}</style></head><body><h1>{{.Title}}</h1><table><thead><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr></thead><tbody>{{range .Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>{{end}}</tbody></table></body></html>`))

func renderAppMCPArtifactHTML(title string, headers []string, rows [][]string) ([]byte, error) {
	var out bytes.Buffer
	if err := mcpArtifactHTML.Execute(&out, struct {
		Title   string
		Headers []string
		Rows    [][]string
	}{title, headers, rows}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func renderAppMCPArtifactPDF(ctx context.Context, app *App, html []byte) ([]byte, error) {
	chrome := findChrome()
	if chrome == "" {
		return nil, errors.New("PDF provider unavailable")
	}
	dir, err := os.MkdirTemp("", "benmore-artifact-pdf-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "artifact.pdf")
	sandbox, err := newPDFSandbox(html, "default-src 'none'; style-src 'unsafe-inline'; img-src data:", nil)
	if err != nil {
		return nil, err
	}
	defer sandbox.Close()
	chromeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(chromeCtx, chrome, pdfChromeArgs(sandbox.ProxyAddr(), sandbox.DocURL(), path, filepath.Join(dir, "profile"))...)
	if _, err := runPDFChrome(chromeCtx, cmd, path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// appMCPRegisterArtifactTools exposes one reviewed producer: it formats the
// immutable receipt of a command the caller already prepared, approved, and
// committed. It never accepts caller-supplied report rows or queries live data.
func appMCPRegisterArtifactTools(server *sdk.Server, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session) {
	if server == nil || app == nil || generation == nil || generation.manifest == nil || grant == nil || actor == nil {
		return
	}
	for _, declared := range generation.manifest.Tools {
		if declared.Name == mcpArtifactExportTool {
			return // A reviewed declaration owns this name; never collide at registration.
		}
	}
	allowed := false
	for _, command := range appMCPLiveCommands(app, generation) {
		permissions := strings.Join(command.tool.Permissions, " ")
		if scopesWithin(grant.Scopes, permissions) && scopesWithin(actor.Scopes, permissions) {
			allowed = true
			break
		}
	}
	if !allowed {
		return
	}
	no := false
	input := appMCPClosedObject(map[string]any{
		"operation_id": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
		"format":       map[string]any{"type": "string", "enum": []any{"xlsx", "html", "pdf"}},
	})
	server.AddTool(&sdk.Tool{Name: mcpArtifactExportTool,
		Description: "Create an immutable XLSX, standalone HTML, or PDF artifact from a committed receipt for one of your reviewed commands. The operation must have completed successfully; this formats its frozen result and does not rerun the command.",
		InputSchema: input, OutputSchema: appMCPClosedObject(map[string]any{
			"artifact_id": map[string]any{"type": "string", "maxLength": 128},
			"kind":        map[string]any{"type": "string", "enum": []any{"xlsx", "html", "pdf"}},
			"sha256":      map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
			"size":        map[string]any{"type": "integer", "minimum": 1, "maximum": mcpArtifactMaxBytes},
		}), Annotations: &sdk.ToolAnnotations{DestructiveHint: &no, OpenWorldHint: &no}},
		func(ctx context.Context, call *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			args, ok := appMCPDecodeToolArguments(call.Params.Arguments)
			if !ok || len(args) != 2 {
				return appMCPSDKFailure(appMCPResultFailure("invalid_input")), nil
			}
			operationID, idOK := args["operation_id"].(string)
			kind, kindOK := args["format"].(string)
			if !idOK || !kindOK || !appMCPOperationHex(operationID, 32) || (kind != "xlsx" && kind != "html" && kind != "pdf") {
				return appMCPSDKFailure(appMCPResultFailure("invalid_input")), nil
			}
			// Each PDF starts a headless Chrome: share GET /pdf/'s per-user budget.
			if kind == "pdf" && !pdfLimiter.Allow(appLimiterKey(app, "pdf", fmt.Sprintf("user:%d", actor.UserID))) {
				return appMCPSDKFailure(appMCPResultFailure("operation_limit")), nil
			}
			artifact, err := exportAppMCPCommittedArtifact(ctx, app, generation, grant, actor, operationID, kind)
			if err != nil {
				return appMCPSDKFailure(appMCPResultFailure("denied")), nil
			}
			return appMCPCommandResult(map[string]any{"artifact_id": artifact.ID, "kind": artifact.Kind, "sha256": artifact.SHA256, "size": artifact.Size}), nil
		})
}

func exportAppMCPCommittedArtifact(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session, operationID, kind string) (appMCPArtifact, error) {
	var out appMCPArtifact
	if ctx == nil || app == nil || generation == nil || grant == nil || actor == nil ||
		!appMCPOperationHex(operationID, 32) || (kind != "xlsx" && kind != "html" && kind != "pdf") {
		return out, errors.New("invalid artifact export request")
	}
	tx, err := app.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	appID, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	if err != nil {
		return out, err
	}
	stored, err := appMCPReadOperationWithKey(ctx, tx, appID, key, operationID)
	if err != nil || stored == nil || stored.Receipt == nil || stored.Prepared.Origin.Kind != "connector" ||
		stored.Prepared.Origin.ActorID != actor.UserID || stored.Prepared.Origin.Tenant != actor.GroupID {
		return out, errors.New("operation receipt is not available to this caller")
	}
	var ownerCreatedAt string
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(created_at,'') FROM main._benmore_users WHERE id=?", actor.UserID).Scan(&ownerCreatedAt); err != nil || !sameAccountIncarnation(ownerCreatedAt, stored.Prepared.Origin.ActorCreated) {
		return out, errors.New("operation receipt belongs to a different account incarnation")
	}
	tool, _, err := appMCPFindCommandDeclaration(generation, stored.Prepared.Command)
	if err != nil || !scopesWithin(grant.Scopes, strings.Join(stored.Prepared.Origin.Permissions, " ")) ||
		!scopesWithin(actor.Scopes, strings.Join(stored.Prepared.Origin.Permissions, " ")) ||
		!scopesWithin(grant.Scopes, strings.Join(tool.Permissions, " ")) || !scopesWithin(actor.Scopes, strings.Join(tool.Permissions, " ")) {
		return out, errors.New("operation command is no longer authorized")
	}
	approval, err := appMCPReadCommandApprovalWithKey(ctx, tx, appID, key, stored)
	if err != nil || approval == nil || approval.State != "consumed" {
		return out, errors.New("operation receipt is not committed")
	}
	receipt, err := decodeAppMCPCommandReceipt(stored, approval)
	if err != nil {
		return out, err
	}
	if err := tx.Commit(); err != nil {
		return out, err
	}
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(receipt.Result))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil || result == nil {
		return out, errors.New("command result is not an object")
	}
	fields := make([]string, 0, len(result))
	for field := range result {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	rows := make([][]string, 0, len(fields))
	for _, field := range fields {
		value, err := json.Marshal(result[field])
		if err != nil {
			return out, err
		}
		rows = append(rows, []string{field, string(value)})
	}
	title := stored.Prepared.Command + " result"
	var data []byte
	switch kind {
	case "xlsx":
		data, err = WriteXLSXSheets([]XLSXSheet{{Name: "Result", Headers: []string{"field", "value"}, Rows: rows}})
	case "html":
		data, err = renderAppMCPArtifactHTML(title, []string{"field", "value"}, rows)
	case "pdf":
		var html []byte
		html, err = renderAppMCPArtifactHTML(title, []string{"field", "value"}, rows)
		if err == nil {
			data, err = renderAppMCPArtifactPDF(ctx, app, html)
		}
	}
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(stored.Receipt)
	revisions := map[string]string{"contract": stored.Prepared.ContractDigest, "execution": stored.Prepared.ExecutionDigest}
	engine := "benmore-xlsx/1; " + runtime.Version()
	if kind == "html" {
		engine = mcpArtifactTemplateVersion + "; " + runtime.Version()
	} else if kind == "pdf" {
		engine, err = appMCPArtifactChromeVersion(ctx)
		if err != nil {
			return out, err
		}
	}
	return createAppMCPArtifact(ctx, app, actor.UserID, stored.Prepared.Origin.ActorCreated, actor.GroupID, actor.Role, stored.Prepared.Origin.Permissions, operationID, kind, data,
		hex.EncodeToString(sum[:]), revisions, engine)
}

func appMCPArtifactChromeVersion(ctx context.Context) (string, error) {
	chrome := findChrome()
	if chrome == "" {
		return "", errors.New("PDF provider unavailable")
	}
	return appMCPProbeArtifactChromeVersion(ctx, chrome)
}

func appMCPProbeArtifactChromeVersion(ctx context.Context, chrome string) (string, error) {
	// A cold system browser can need more than three seconds even for --version.
	// Keep the probe bounded while honoring an earlier caller deadline.
	versionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(versionCtx, chrome, "--version").Output()
	if err != nil || len(output) == 0 || len(output) > 256 {
		return "", errors.New("PDF renderer version unavailable")
	}
	return strings.TrimSpace(string(output)), nil
}
