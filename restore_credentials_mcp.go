//go:build !cli

package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// The connector's grant, credential and authorization stores
// (app_mcp_grants.go). Access grants and bearer credentials are invalidated
// on every restore; sealed upstream credentials retain their separate owner
// and account-incarnation carry-forward policy.
const (
	mcpGrantsTable         = "_benmore_mcp_grants"
	mcpCredentialsTable    = "_benmore_mcp_credentials"
	mcpAuthorizationsTable = "_benmore_mcp_authorizations"
	// Per-user upstream credentials (app_mcp_external.go): sealed with the
	// owning user id in the AAD, so a row is carried forward only for the SAME id.
	mcpConnectionCredentialsTable = "_benmore_mcp_connection_credentials"
	mcpFileProcessingsTable       = "_benmore_mcp_file_processings"
)

var mcpFileProcessingRestoreColumns = []string{"id", "file_id", "file_sha256", "origin", "origin_version", "content_type", "parser_version", "limits_json", "complete", "quality_flags", "created_by", "created_at", "source_connection", "source_file_id", "source_revision", "owner_created_at", "tenant", "source_table", "record_id", "file_ref", "upload_tenant", "snapshot_version", "snapshot_sha256", "snapshot_size"}

var restoreMCPTables = []string{mcpGrantsTable, mcpCredentialsTable, mcpAuthorizationsTable, mcpConnectionCredentialsTable}

// carryForwardMCPGrants retains revoked grant history but invalidates every
// grant, token and pending authorization. Sealed upstream credentials are
// carried only for the same owner id and account incarnation.
//
// With no live grant state, candidate connector credentials and authorizations
// are removed; candidate grant rows remain revoked for auditability.
//
// This runs on every restore path, including the router's, which holds no
// connector authority directory and so cannot rotate the epoch: grants cannot
// revive even then.
func carryForwardMCPGrants(ctx context.Context, tx *sql.Tx, live map[string]*credTable, pairs map[int64]int64, summary *restoreCredentialSummary) error {
	cand := map[string]*credTable{}
	found := false
	for _, name := range restoreMCPTables {
		t, err := readCredTable(ctx, tx, name, false, []string{})
		if err != nil {
			return err
		}
		if t != nil {
			cand[name], found = t, true
		}
	}
	if !found {
		return nil
	}
	var liveGrants *credTable
	if live != nil {
		liveGrants = live[mcpGrantsTable]
	}
	if liveGrants == nil {
		for _, name := range []string{mcpCredentialsTable, mcpAuthorizationsTable, mcpConnectionCredentialsTable} {
			if cand[name] == nil {
				continue
			}
			if err := deleteAllCounted(ctx, tx, name, summary); err != nil {
				return err
			}
		}
		if g := cand[mcpGrantsTable]; g != nil && g.has["revoked"] {
			res, err := tx.ExecContext(ctx, "UPDATE "+quoteIdent(mcpGrantsTable)+" SET revoked = 1")
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err == nil {
				summary.MCPGrantsRevoked = int(n)
			}
		}
		return nil
	}

	toCandidate := map[int64]int64{} // live user id -> candidate user id
	for candidateID, liveID := range pairs {
		if prev, dup := toCandidate[liveID]; !dup || candidateID < prev {
			toCandidate[liveID] = candidateID
		}
	}
	// Snapshot grants and bearer credentials are never valid after a restore,
	// even when the router cannot rotate the app authority epoch. Keep grant
	// rows only as revoked history; every access/refresh credential and pending
	// code/consent authorization must be reissued after new consent.
	for _, name := range []string{mcpConnectionCredentialsTable, mcpAuthorizationsTable, mcpCredentialsTable} {
		if cand[name] != nil {
			if err := deleteAllCounted(ctx, tx, name, summary); err != nil {
				return err
			}
		}
	}
	insert := func(name string, keep func(t *credTable, i int) (map[string]any, bool)) error {
		c, lt := cand[name], live[name]
		if c == nil || lt == nil {
			return nil
		}
		cols := present(c.cols, lt)
		if len(cols) == 0 {
			return nil
		}
		quoted := make([]string, len(cols))
		for i, col := range cols {
			quoted[i] = quoteIdent(col)
		}
		stmt, err := tx.PrepareContext(ctx, "INSERT INTO "+quoteIdent(name)+" ("+strings.Join(quoted, ", ")+") VALUES ("+strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")+")")
		if err != nil {
			return err
		}
		defer stmt.Close()
		for i := range lt.rows {
			override, ok := keep(lt, i)
			if !ok {
				continue
			}
			values := make([]any, len(cols))
			for k, col := range cols {
				if v, set := override[col]; set {
					values[k] = v
				} else {
					values[k] = lt.get(i, col)
				}
			}
			if _, err := stmt.ExecContext(ctx, values...); err != nil {
				return err
			}
			summary.Kept[name]++
		}
		return nil
	}
	// The AAD binds the user id: a live credential whose account maps to a
	// different id in the restored database could never authenticate, so it is
	// dropped (the user re-enters it) rather than carried as dead ciphertext.
	if err := insert(mcpConnectionCredentialsTable, func(t *credTable, i int) (map[string]any, bool) {
		id, ok := credInt(t.get(i, "user_id"))
		candidateID, paired := toCandidate[id]
		if ok && paired && candidateID != id {
			summary.Removed[mcpConnectionCredentialsTable]++
		}
		return nil, ok && paired && candidateID == id
	}); err != nil {
		return err
	}
	if g := cand[mcpGrantsTable]; g != nil && g.has["revoked"] {
		res, err := tx.ExecContext(ctx, "UPDATE "+quoteIdent(mcpGrantsTable)+" SET revoked = 1")
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err == nil {
			summary.MCPGrantsRevoked = int(n)
		}
	}
	return nil
}

// carryForwardMCPFileProcessings keeps the live immutable processing history
// across restore, but only for accounts that remain in the restored database.
func carryForwardMCPFileProcessings(ctx context.Context, tx *sql.Tx, live map[string]*credTable, livePath string, pairs map[int64]int64, summary *restoreCredentialSummary) error {
	liveRows := live[mcpFileProcessingsTable]
	if err := ensureAppMCPFileProcessingSchema(tx); err != nil {
		return err
	}
	candidate, err := readCredTable(ctx, tx, mcpFileProcessingsTable, false, mcpFileProcessingRestoreColumns)
	if err != nil {
		return err
	}
	if candidate == nil {
		if _, err := tx.ExecContext(ctx, appMCPFileProcessingDDL); err != nil {
			return err
		}
		candidate, err = readCredTable(ctx, tx, mcpFileProcessingsTable, false, mcpFileProcessingRestoreColumns)
		if err != nil {
			return err
		}
	}
	if err := deleteAllCounted(ctx, tx, mcpFileProcessingsTable, summary); err != nil {
		return err
	}
	if liveRows == nil {
		return nil // Uncorroborated candidate snapshots are never restored.
	}
	toCandidate := map[int64]int64{}
	for candidateID, liveID := range pairs {
		toCandidate[liveID] = candidateID
	}
	users, err := readCredTable(ctx, tx, "_benmore_users", false, []string{"id", "created_at"})
	if err != nil {
		return err
	}
	createdAtByID := map[int64]string{}
	if users != nil && users.has["id"] && users.has["created_at"] {
		for i := range users.rows {
			if id, ok := credInt(users.get(i, "id")); ok {
				createdAtByID[id] = credText(users.get(i, "created_at"))
			}
		}
	}
	columns := present(candidate.cols, liveRows)
	hasSnapshotDataColumn := false
	for _, column := range columns {
		if column == "snapshot_data" {
			hasSnapshotDataColumn = true
			break
		}
	}
	if !hasSnapshotDataColumn && candidate.has["snapshot_data"] && liveRows.has["snapshot_data"] {
		columns = append(columns, "snapshot_data")
	}
	if len(columns) == 0 {
		return fmt.Errorf("processing table has no shared columns")
	}
	quoted := make([]string, len(columns))
	for i, col := range columns {
		quoted[i] = quoteIdent(col)
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO "+quoteIdent(mcpFileProcessingsTable)+" ("+strings.Join(quoted, ", ")+") VALUES ("+strings.TrimSuffix(strings.Repeat("?, ", len(columns)), ", ")+")")
	if err != nil {
		return err
	}
	defer stmt.Close()
	var liveDB *sql.DB
	if livePath != "" {
		liveDB, err = sql.Open(sqliteMaintenanceDriver, sqliteRestoreURI(livePath, "ro"))
		if err != nil {
			return err
		}
		defer liveDB.Close()
		liveDB.SetMaxOpenConns(1)
	}
	for i := range liveRows.rows {
		liveID, ok := credInt(liveRows.get(i, "created_by"))
		candidateID, paired := toCandidate[liveID]
		ownerCreatedAt := credText(liveRows.get(i, "owner_created_at"))
		if !ok || !paired || (ownerCreatedAt != "" && !sameAccountIncarnation(createdAtByID[candidateID], ownerCreatedAt)) {
			summary.Removed[mcpFileProcessingsTable]++
			continue
		}
		values := make([]any, len(columns))
		var snapshotData []byte
		if liveRows.has["snapshot_data"] && credIntValue(liveRows.get(i, "snapshot_version")) == appMCPFileSnapshotVersion {
			size := credIntValue(liveRows.get(i, "snapshot_size"))
			if liveDB == nil || size <= 0 || size > appMCPFileSnapshotMaxBytes {
				return fmt.Errorf("live private file snapshot has invalid bounded metadata")
			}
			if err := liveDB.QueryRowContext(ctx, `SELECT snapshot_data FROM _benmore_mcp_file_processings WHERE id=? AND created_by=? AND owner_created_at=? AND snapshot_version=? AND snapshot_size=? AND snapshot_sha256=? AND length(snapshot_data)=?`, credText(liveRows.get(i, "id")), liveID, ownerCreatedAt, appMCPFileSnapshotVersion, size, credText(liveRows.get(i, "snapshot_sha256")), size).Scan(&snapshotData); err != nil {
				return fmt.Errorf("read bounded live private file snapshot: %w", err)
			}
			if int64(len(snapshotData)) != size {
				return fmt.Errorf("live private file snapshot size changed during restore")
			}
		}
		for k, col := range columns {
			if col == "created_by" {
				values[k] = candidateID
			} else if col == "snapshot_data" {
				values[k] = snapshotData
			} else {
				values[k] = liveRows.get(i, col)
			}
		}
		if _, err := stmt.ExecContext(ctx, values...); err != nil {
			return err
		}
		summary.Kept[mcpFileProcessingsTable]++
	}
	return nil
}

func credIntValue(value any) int64 { n, _ := credInt(value); return n }

func deleteAllCounted(ctx context.Context, tx *sql.Tx, name string, summary *restoreCredentialSummary) error {
	res, err := tx.ExecContext(ctx, "DELETE FROM "+quoteIdent(name))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		summary.Removed[name] += int(n)
	}
	return nil
}
