//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mattn/go-sqlite3"
)

// `run: revoke_user_sessions` is the one apply-phase step of an approved
// command that touches the app's own credential tables. It ends every session,
// API token, OAuth code and MCP connector grant of one user of THIS app, so a
// command that removes a member can also force them out, as the app's own
// credential-change flows do (revokeUserAccessExcept).
//
//	- id: revoke
//	  run: revoke_user_sessions
//	  with:
//	    user_id: ${{ params.member_user_id }}   # required integer in prepared_schema
//
// It runs INSIDE the command transaction, not as a queued effect: a rollback
// revokes nothing, a commit revokes at the same instant the membership row
// goes, and there is no window in which the removed user keeps a live session
// because a worker has not run yet (a queued job would also be refused by the
// grant/owner currency check at delivery, leaving the session alive). The
// price is a dedicated native-metadata scope (appMCPCommandMetadataRevoke)
// whose authorizer admits exactly the deletes below and nothing else; command
// SQL itself still cannot write any _benmore_* table.
//
// The target is fixed from the captured intent before the apply starts and is
// refused (the whole apply rolls back) unless
//   - it is not the actor (the actor's own session would end mid-commit),
//   - it is not a framework admin (users.role or a global admin grant), and
//   - it held a live membership row in the actor's selected tenant when the
//     apply began. Checking at the start covers both "holds a membership" and
//     "had one removed by this same apply": the apply is one write transaction,
//     so nothing else can change the membership in between.

const appMCPCommandRevokeAudit = "mcp_command_revoke_sessions"

// revokeRefusal is a refusal of the step; the class reads as denied.
func revokeRefusal(reason string) error {
	return fmt.Errorf("%w: revoke_user_sessions %s", errAppMCPOperationDenied, reason)
}

// commandRevokeTargetID reads the captured user id: a positive integer only.
func commandRevokeTargetID(value any) (int64, error) {
	var id int64
	switch v := value.(type) {
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			return 0, revokeRefusal("needs an integer user id")
		}
		id = parsed
	case int64:
		id = v
	case int:
		id = int64(v)
	case float64:
		if v != float64(int64(v)) {
			return 0, revokeRefusal("needs an integer user id")
		}
		id = int64(v)
	default:
		return 0, revokeRefusal("needs an integer user id")
	}
	if id <= 0 || id > appMCPCommandSafeIntegerMax {
		return 0, revokeRefusal("needs a positive user id")
	}
	return id, nil
}

func (exec *appMCPCommandExecution) revokeTarget(step *FlowStep) (int64, error) {
	cap := exec.capability
	values, err := appMCPResolveCommandRefs(map[string]FlowCommandParamRef{"user_id": step.CommandRevokeRef}, exec.values, cap.actor, cap.tenant, exec)
	if err != nil {
		return 0, err
	}
	return commandRevokeTargetID(values["user_id"])
}

func commandRevokeSteps(steps []FlowStep) []*FlowStep {
	var found []*FlowStep
	for i := range steps {
		if steps[i].Type == "revoke_user_sessions" {
			found = append(found, &steps[i])
		}
		found = append(found, commandRevokeSteps(steps[i].Steps)...)
		found = append(found, commandRevokeSteps(steps[i].ElseSteps)...)
	}
	return found
}

// appMCPCommandHasRevoke reports whether an apply phase can revoke sessions.
func appMCPCommandHasRevoke(command *FlowCommand) bool {
	return command != nil && len(commandRevokeSteps(command.Apply.Steps)) > 0
}

// snapshotRevokeTargets records, before the apply's first write, which revoke
// targets hold a live membership in the actor's tenant. A target that cannot
// be resolved is simply not recorded: the step refuses it when it runs, so a
// step in an untaken branch never fails the apply.
func (exec *appMCPCommandExecution) snapshotRevokeTargets(steps []FlowStep) error {
	cap := exec.capability
	found := commandRevokeSteps(steps)
	if len(found) == 0 {
		return nil
	}
	cap.revokeMembers = map[int64]bool{}
	targets := map[int64]bool{}
	for _, step := range found {
		if id, err := exec.revokeTarget(step); err == nil {
			targets[id] = true
		}
	}
	if len(targets) == 0 {
		return nil
	}
	group := cap.generation.view.Group
	return cap.withNativeMetadata(appMCPCommandMetadataRevoke, func() error {
		for id := range targets {
			member, err := appMCPRevokeTargetIsMember(cap.tx, group, cap.tenant, id)
			if err != nil {
				return err
			}
			cap.revokeMembers[id] = member
		}
		return nil
	})
}

// appMCPRevokeTargetIsMember is groupMembershipLive for another user, pinned to
// main: a live row (not soft-deleted, active per groups.active_field) in the
// tenant. A row addressed by email counts only for an account that proved it.
func appMCPRevokeTargetIsMember(tx *sql.Tx, group *GroupConfig, tenant string, userID int64) (bool, error) {
	if group == nil || group.Table == "" || group.Key == "" || group.UserField == "" || tenant == "" || tenant == "0" ||
		!membershipIdentRe.MatchString(group.Key) || !membershipIdentRe.MatchString(group.UserField) {
		return false, nil
	}
	from, _, ok := mainAuthorityTable(group.Table)
	if !ok {
		return false, nil
	}
	var email string
	var trusted bool
	if err := tx.QueryRow("SELECT u.email, "+emailTrustedSQL("u")+" FROM main._benmore_users u WHERE u.id = ?", userID).Scan(&email, &trusted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	var member any = userID
	if emailKeyedColumn(group.UserField) {
		if !trusted || email == "" {
			return false, nil
		}
		member = email
	}
	hasCol, checkErr := dbColumnCheckerWith(tx, group.Table, "main")
	conds := membershipLiveConds(group, group.Table, "", hasCol)
	if err := checkErr(); err != nil {
		return false, err
	}
	var one int
	query := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? AND %s = ?%s LIMIT 1", from, quoteColumn(group.Table, group.Key), quoteColumn(group.Table, group.UserField), conds)
	if err := tx.QueryRow(query, tenant, member).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (exec *appMCPCommandExecution) revokeUserSessions(ctx *FlowContext, step *FlowStep) error {
	cap := exec.capability
	if exec.phase != "apply" || cap == nil || cap.tx == nil {
		return revokeRefusal("runs only in an apply")
	}
	target, err := exec.revokeTarget(step)
	if err != nil {
		return err
	}
	if target == cap.actor.UserID {
		return revokeRefusal("cannot target the acting user")
	}
	if !cap.revokeMembers[target] {
		return revokeRefusal("target is not a member of the acting tenant")
	}
	err = cap.withNativeMetadata(appMCPCommandMetadataRevoke, func() error {
		var role sql.NullString
		if err := cap.tx.QueryRow("SELECT role FROM main._benmore_users WHERE id = ?", target).Scan(&role); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return revokeRefusal("target does not exist")
			}
			return err
		}
		admin := strings.EqualFold(strings.TrimSpace(role.String), "admin")
		if !admin {
			var err error
			if admin, err = userHasGlobalAdminGrantWithSchema(cap.tx, target, "main"); err != nil {
				return err
			}
		}
		if admin {
			return revokeRefusal("cannot target a framework admin")
		}
		if err := revokeUserAccessExcept(cap.tx, target, ""); err != nil {
			return err
		}
		details, err := json.Marshal(map[string]any{"command": cap.tool.Name, "operation_id": cap.operationID})
		if err != nil {
			return err
		}
		return insertAuditRowChecked(cap.tx, appMCPCommandRevokeAudit, "_benmore_users", fmt.Sprint(target), &cap.actor, "{}", string(details))
	})
	if err != nil {
		return err
	}
	cap.revokedUsers = append(cap.revokedUsers, target)
	return nil
}

// authorizeCommandRevoke is the authorizer of the revoke scope: the framework's
// own fixed statements only. Reads stay off the connector tables except the two
// it revokes; writes are the exact credential deletes plus one audit row.
func authorizeCommandRevoke(action int, arg1, arg2, database string) int {
	table, db := strings.ToLower(arg1), strings.ToLower(database)
	switch action {
	case sqlite3.SQLITE_SELECT, sqliteRecursiveSelect:
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_FUNCTION:
		switch strings.ToLower(arg2) {
		case "load_extension", "fts3_tokenizer", "readfile", "writefile", "edit":
			return sqlite3.SQLITE_DENY
		}
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_READ:
		if db == "temp" {
			if table == "sqlite_temp_schema" || table == "sqlite_temp_master" || table == "sqlite_schema" || table == "sqlite_master" {
				return sqlite3.SQLITE_OK
			}
			return sqlite3.SQLITE_DENY
		}
		if db != "main" && !(db == "" && arg2 == "") {
			return sqlite3.SQLITE_DENY
		}
		switch {
		case table == "_benmore_mcp_grants" || table == "_benmore_mcp_authorizations":
			return sqlite3.SQLITE_OK
		case strings.HasPrefix(table, "_benmore_mcp_"):
			return sqlite3.SQLITE_DENY
		case table == "sqlite_master" || table == "sqlite_schema" || table == "sqlite_sequence" || strings.HasPrefix(table, "pragma_table_info"):
			return sqlite3.SQLITE_OK
		case strings.HasPrefix(table, "sqlite_"):
			return sqlite3.SQLITE_DENY
		}
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_PRAGMA:
		// The live-membership check asks which columns the membership
		// table has (membershipLiveConds), read-only.
		if strings.EqualFold(arg1, "table_info") && db == "main" {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_DELETE:
		if db == "main" && (table == "_benmore_sessions" || table == "_benmore_signin_challenges" || table == "_benmore_api_tokens" || table == "_benmore_oauth_codes" || table == "_benmore_mcp_authorizations") {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_UPDATE:
		if db == "main" && table == "_benmore_mcp_grants" && strings.EqualFold(arg2, "revoked") {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_INSERT:
		if db == "main" && table == "_benmore_audit_log" {
			return sqlite3.SQLITE_OK
		}
	}
	return sqlite3.SQLITE_DENY
}

// appMCPAfterCommitRevocations ends the platform-side edge grants of each
// revoked user once the command has committed (they live outside the app
// database). A failure is logged by the helper, never undoing the commit.
func appMCPAfterCommitRevocations(app *App, users []int64) {
	for _, id := range users {
		revokeEdgeGrantsAfterCredentialChange(app, id)
	}
}
