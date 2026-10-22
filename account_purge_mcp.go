//go:build !cli

package main

import (
	"context"
	"database/sql"
	"fmt"
)

// purgeAppMCPOperations erases the connector operations (and their approvals and attempts)
// the user prepared. The actor is stored only inside each operation's
// ciphertext, so every row is authenticated and decrypted under the app key to
// learn its owner. A row that cannot be verified aborts the purge: skipping it
// could leave the user's data behind, so the caller's transaction rolls back.
func purgeAppMCPOperations(ctx context.Context, app *App, tx *sql.Tx, uid int64) (int64, error) {
	var present int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name='_benmore_mcp_operations'`).Scan(&present); err != nil {
		return 0, fmt.Errorf("purge_current_user: inspect _benmore_mcp_operations: %w", err)
	}
	if present == 0 {
		return 0, nil
	}
	var attemptsPresent int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name='_benmore_mcp_command_attempts'`).Scan(&attemptsPresent); err != nil {
		return 0, fmt.Errorf("purge_current_user: inspect _benmore_mcp_command_attempts: %w", err)
	}
	appID, key, err := appMCPOperationContext(ctx, tx, app)
	if err != nil {
		return 0, fmt.Errorf("purge_current_user: operation storage: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT operation_id FROM main._benmore_mcp_operations`)
	if err != nil {
		return 0, fmt.Errorf("purge_current_user: list _benmore_mcp_operations: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("purge_current_user: scan _benmore_mcp_operations: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("purge_current_user: read _benmore_mcp_operations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var deleted int64
	for _, id := range ids {
		operation, err := appMCPReadOperationWithKey(ctx, tx, appID, key, id)
		if err != nil {
			return 0, fmt.Errorf("purge_current_user: cannot verify an operation row: %w", err)
		}
		if operation.Prepared.Origin.ActorID != uid {
			continue
		}
		if err := purgeAppMCPTransferStateForOperation(ctx, tx, id); err != nil {
			return 0, fmt.Errorf("purge_current_user: scrub MCP transfer state: %w", err)
		}
		// The approval row (if any) goes first so no approval is orphaned.
		approval, err := tx.ExecContext(ctx, `DELETE FROM main._benmore_mcp_command_approvals WHERE operation_id=?`, id)
		if err != nil {
			return 0, fmt.Errorf("purge_current_user: delete MCP approval: %w", err)
		}
		approvals, err := approval.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("purge_current_user: count deleted MCP approvals: %w", err)
		}
		var attempts int64
		if attemptsPresent > 0 {
			attempt, err := tx.ExecContext(ctx, `DELETE FROM main._benmore_mcp_command_attempts WHERE operation_id=?`, id)
			if err != nil {
				return 0, fmt.Errorf("purge_current_user: delete MCP attempts: %w", err)
			}
			if attempts, err = attempt.RowsAffected(); err != nil {
				return 0, fmt.Errorf("purge_current_user: count deleted MCP attempts: %w", err)
			}
		}
		operationRow, err := tx.ExecContext(ctx, `DELETE FROM main._benmore_mcp_operations WHERE operation_id=?`, id)
		if err != nil {
			return 0, fmt.Errorf("purge_current_user: delete MCP operation: %w", err)
		}
		if n, err := operationRow.RowsAffected(); err != nil || n != 1 {
			return 0, fmt.Errorf("purge_current_user: MCP operation delete affected %d rows: %v", n, err)
		}
		deleted += approvals + attempts + 1
	}
	return deleted, nil
}

func purgeAppMCPTransferStateForOperation(ctx context.Context, tx *sql.Tx, operationID string) error {
	var jobsPresent int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name='_benmore_jobs'`).Scan(&jobsPresent); err != nil {
		return err
	}
	if jobsPresent > 0 {
		_, err := tx.ExecContext(ctx, `UPDATE main._benmore_jobs SET
			status=CASE WHEN status IN ('pending','running') THEN 'failed' ELSE status END,
			error=CASE WHEN status IN ('pending','running') THEN 'cancelled: account deleted' ELSE error END,
			completed_at=CASE WHEN status IN ('pending','running') THEN datetime('now') ELSE completed_at END,
			lease_expires_at=NULL,payload='{}'
			WHERE job_type=? AND json_valid(payload) AND json_extract(payload,'$._mcp_effect.operation_id')=?`, appMCPTransferJobType, operationID)
		if err != nil {
			return err
		}
	}
	var statePresent int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name='_benmore_mcp_transfer_state'`).Scan(&statePresent); err != nil {
		return err
	}
	if statePresent > 0 {
		_, err := tx.ExecContext(ctx, `DELETE FROM main._benmore_mcp_transfer_state WHERE operation_id=?`, operationID)
		return err
	}
	return nil
}
