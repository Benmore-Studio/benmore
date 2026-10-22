//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// appMCPCaptureCommandDependencies executes only the captured literal queries
// and references that the existing FlowCommand compiler attached to the
// descriptor. No request value is interpreted as SQL or as a selector name.
func appMCPCaptureCommandDependencies(cap *appMCPCommandCapability, intent map[string]any) (*appMCPRevisionDependencySnapshot, error) {
	if err := cap.validateLifetime(); err != nil {
		return nil, err
	}
	if intent == nil || len(cap.command.Dependencies) == 0 || len(cap.command.Dependencies) > appMCPDependencySelectorLimit {
		return nil, errors.New("command dependency declaration is unavailable")
	}
	if err := cap.enterReadPhase("prepare", appMCPCommandDependencyTables(cap.command)); err != nil {
		return nil, err
	}
	defer cap.leaveReadPhase()
	verified := cap.enrollment
	if err := cap.withInternalRead(func() error {
		_, err := reverifyAppMCPRevisionCapability(verified)
		return err
	}); err != nil {
		return nil, err
	}
	identities := make(map[string]appMCPRevisionEnrollmentTable, len(verified.record.Tables))
	for _, identity := range verified.record.Tables {
		identities[identity.Table] = identity
	}
	sets := make([]appMCPRevisionDependencySet, 0, len(cap.command.Dependencies))
	seenSelectors := map[string]bool{}
	total := 0
	for _, dependency := range cap.command.Dependencies {
		if !commandIdent.MatchString(dependency.Name) || seenSelectors[dependency.Name] || dependency.MaxRows < 1 || dependency.MaxRows > appMCPDependencySelectorRowsLimit {
			return nil, errors.New("invalid or duplicate command dependency")
		}
		seenSelectors[dependency.Name] = true
		identity, ok := identities[dependency.Table]
		if !ok {
			return nil, fmt.Errorf("dependency %q is outside the active revision enrollment", dependency.Name)
		}
		params, err := appMCPResolveCommandRefs(dependency.Params, intent, cap.actor, cap.tenant, nil)
		if err != nil {
			return nil, fmt.Errorf("dependency %q binding: %w", dependency.Name, err)
		}
		if err := cap.validateSQLPhase(dependency.Query, "prepare", appMCPCommandDependencyTables(cap.command)); err != nil {
			return nil, fmt.Errorf("dependency %q query: %w", dependency.Name, err)
		}
		dependencyQuery, ok := sqlRunnableText(dependency.Query)
		if !ok {
			return nil, fmt.Errorf("dependency %q query failed: %w", dependency.Name, errNoSQLStatement)
		}
		rows, err := cap.tx.QueryContext(cap.ctx, dependencyQuery, commandNamedArgs(params)...)
		if err != nil {
			return nil, fmt.Errorf("dependency %q query failed: %w", dependency.Name, err)
		}
		columns, columnErr := rows.Columns()
		if columnErr != nil || len(columns) != 1 || !strings.EqualFold(columns[0], "id") {
			_ = rows.Close()
			return nil, fmt.Errorf("dependency %q must return exactly one id column", dependency.Name)
		}
		keys := make([]appMCPRevisionKey, 0, dependency.MaxRows)
		seenKeys := map[string]bool{}
		for rows.Next() {
			if len(keys) == dependency.MaxRows {
				_ = rows.Close()
				return nil, fmt.Errorf("dependency %q exceeds its reviewed row bound", dependency.Name)
			}
			var value any
			if err := rows.Scan(&value); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("dependency %q returned an unreadable id: %w", dependency.Name, err)
			}
			key, err := appMCPCommandRevisionKey(value)
			if err != nil || seenKeys[key.KeyType+"\x00"+key.RowKey] {
				_ = rows.Close()
				return nil, fmt.Errorf("dependency %q returned a null, duplicate, or noncanonical id", dependency.Name)
			}
			seenKeys[key.KeyType+"\x00"+key.RowKey] = true
			keys = append(keys, key)
		}
		rowsErr := rows.Err()
		closeErr := rows.Close()
		if rowsErr != nil || closeErr != nil {
			return nil, errors.Join(rowsErr, closeErr)
		}
		if err := appMCPCommandValidateDependencyKeyType(cap, dependency.Table, keys); err != nil {
			return nil, fmt.Errorf("dependency %q key type: %w", dependency.Name, err)
		}
		total += len(keys)
		if total > appMCPDependencyRowsLimit {
			return nil, errors.New("command dependencies exceed their total selected-row bound")
		}
		members := make([]appMCPRevisionDependencyMember, 0, len(keys))
		for _, key := range keys {
			var revision int64
			var deleted int
			err := cap.withInternalRead(func() error {
				return cap.tx.QueryRowContext(cap.ctx, `SELECT revision,deleted FROM main._benmore_mcp_row_revisions WHERE table_name=? AND incarnation=? AND key_type=? AND row_key=?`, dependency.Table, identity.Incarnation, key.KeyType, key.RowKey).Scan(&revision, &deleted)
			})
			if err != nil || revision < 1 || deleted != 0 {
				if err == nil {
					err = errors.New("dependency row is marked deleted")
				}
				return nil, fmt.Errorf("dependency row %s/%s is not enrolled: %w", dependency.Table, key.RowKey, err)
			}
			members = append(members, appMCPRevisionDependencyMember{Table: dependency.Table, Incarnation: identity.Incarnation, KeyType: key.KeyType, RowKey: key.RowKey, Revision: revision})
		}
		sort.Slice(members, func(i, j int) bool {
			if members[i].KeyType != members[j].KeyType {
				return members[i].KeyType < members[j].KeyType
			}
			return members[i].RowKey < members[j].RowKey
		})
		sets = append(sets, appMCPRevisionDependencySet{Name: dependency.Name, Table: dependency.Table, Incarnation: identity.Incarnation, SchemaDigest: identity.SchemaDigest, TriggerSetDigest: identity.TriggerSetDigest, Members: members})
	}
	if err := cap.withInternalRead(func() error {
		_, err := reverifyAppMCPRevisionCapability(verified)
		return err
	}); err != nil {
		return nil, err
	}
	return &appMCPRevisionDependencySnapshot{Command: cap.tool.Name, OwnerEpoch: verified.record.OwnerEpoch, EnrollmentID: verified.record.EnrollmentID, Sets: sets}, nil
}

// appMCPDependencyConflict marks a changed dependency set or revision: the
// result code is "conflict", which the attempt record keeps as its own state.
func appMCPDependencyConflict(format string, args ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), appMCPResultFailure("conflict"))
}

func appMCPCompareCommandDependencies(cap *appMCPCommandCapability, intent map[string]any, prepared *appMCPRevisionDependencySnapshot) error {
	if prepared == nil || prepared.Command != cap.tool.Name || prepared.OwnerEpoch != cap.enrollment.record.OwnerEpoch || prepared.EnrollmentID != cap.enrollment.record.EnrollmentID {
		return appMCPDependencyConflict("prepared dependencies belong to another source or enrollment")
	}
	current, err := appMCPCaptureCommandDependencies(cap, intent)
	if err != nil {
		return err
	}
	if len(current.Sets) != len(prepared.Sets) {
		return appMCPDependencyConflict("command dependency membership changed")
	}
	for i := range current.Sets {
		a, b := current.Sets[i], prepared.Sets[i]
		if a.Name != b.Name || a.Table != b.Table || a.Incarnation != b.Incarnation || a.SchemaDigest != b.SchemaDigest || a.TriggerSetDigest != b.TriggerSetDigest || !sameRevisionDependencyMembers(a.Members, b.Members) {
			return appMCPDependencyConflict("command dependency set %q changed", a.Name)
		}
	}
	return nil
}

func appMCPResolveCommandRefs(refs map[string]FlowCommandParamRef, intent map[string]any, actor Session, tenant string, phase *appMCPCommandExecution) (map[string]any, error) {
	values := make(map[string]any, len(refs))
	for name, ref := range refs {
		if !commandBindName.MatchString(name) {
			return nil, errors.New("invalid captured binding name")
		}
		var value any
		switch ref.Kind {
		case "intent_path":
			var ok bool
			value, ok = commandLookupPath(intent, ref.Path)
			if !ok {
				return nil, errors.New("captured intent path is missing")
			}
		case "phase_path":
			var ok bool
			value, ok = commandLookupPath(intent, ref.Path)
			if !ok {
				// Only a path the phase schema declares may be absent (optional
				// property or optional parent); it binds NULL, exactly like an
				// explicit null. Required values were enforced by schema validation.
				if phase == nil || !phase.declaredParamPath(ref.Path) {
					return nil, errors.New("captured phase path is missing")
				}
			}
			if value == nil {
				values[name] = nil
				continue
			}
		case "actor_id":
			if ref.Path != "" || actor.UserID <= 0 {
				return nil, errors.New("trusted actor binding is unavailable")
			}
			value = actor.UserID
		case "selected_tenant":
			if ref.Path != "" || tenant == "" || tenant == "0" {
				return nil, errors.New("trusted selected-tenant binding is unavailable")
			}
			value = tenant
		case "actor_role", "actor_is_admin":
			// Same live actor as actor_id for this phase; a deactivated actor
			// never gets here (loadScheduledActorWith refuses it).
			if ref.Path != "" || actor.UserID <= 0 {
				return nil, errors.New("trusted actor role binding is unavailable")
			}
			if ref.Kind == "actor_role" {
				if actor.Role == "" || !utf8.ValidString(actor.Role) || len(actor.Role) > appMCPInputLimit {
					return nil, errors.New("trusted actor role is unavailable or invalid")
				}
				value = actor.Role
			} else if actor.IsAdmin() {
				value = int64(1)
			} else {
				value = int64(0)
			}
		case "actor_email":
			if phase == nil || phase.capability == nil || phase.phase != "apply" || ref.Path != "" {
				return nil, errors.New("trusted actor email is available only to apply SQL")
			}
			value = phase.capability.actor.Email
			if value == "" || !utf8.ValidString(value.(string)) || len(value.(string)) > appMCPInputLimit {
				return nil, errors.New("trusted actor email is unavailable or invalid")
			}
		case "loop_path", "step_output":
			if phase == nil {
				return nil, errors.New("phase-local binding is unavailable in this phase")
			}
			var ok bool
			value, ok = phase.lookup(ref.Path)
			if !ok {
				return nil, errors.New("captured phase-local binding is missing or out of scope")
			}
		default:
			return nil, errors.New("captured binding kind is unsupported in this phase")
		}
		normalized, err := appMCPCommandBindScalar(value)
		if err != nil {
			return nil, err
		}
		values[name] = normalized
	}
	return values, nil
}

func commandNamedArgs(values map[string]any) []any {
	args := make([]any, 0, len(values))
	for name, value := range values {
		args = append(args, sql.Named(name, value))
	}
	return args
}

func appMCPCommandBindScalar(value any) (any, error) {
	switch value := value.(type) {
	case string:
		if len(value) > appMCPInputLimit {
			return nil, errors.New("SQL text binding exceeds its byte limit")
		}
		return value, nil
	case bool:
		if value {
			return int64(1), nil
		}
		return int64(0), nil
	case int64:
		if value > appMCPCommandSafeIntegerMax || value < -appMCPCommandSafeIntegerMax {
			return nil, errors.New("SQL integer binding is outside the safe range")
		}
		return value, nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > 1e15 {
			return nil, errors.New("SQL number binding is non-finite or outside its safe range")
		}
		return value, nil
	case int:
		return appMCPCommandBindScalar(int64(value))
	case json.Number:
		if integer, err := value.Int64(); err == nil {
			if integer > appMCPCommandSafeIntegerMax || integer < -appMCPCommandSafeIntegerMax {
				return nil, errors.New("SQL integer binding is outside the safe range")
			}
			return integer, nil
		}
		floating, err := strconv.ParseFloat(value.String(), 64)
		if err != nil || math.IsNaN(floating) || math.IsInf(floating, 0) || math.Abs(floating) > 1e15 {
			return nil, errors.New("SQL number binding is non-finite or outside its safe range")
		}
		return floating, nil
	default:
		return nil, errors.New("SQL binding must be a bounded scalar")
	}
}

func commandLookupPath(value any, path string) (any, bool) {
	if path == "" || strings.HasPrefix(path, ".") || strings.HasSuffix(path, ".") {
		return nil, false
	}
	current := value
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func appMCPCommandRevisionKey(value any) (appMCPRevisionKey, error) {
	switch key := value.(type) {
	case int64:
		return appMCPRevisionKey{KeyType: "integer", RowKey: fmt.Sprint(key)}, nil
	case string:
		return appMCPRevisionKey{KeyType: "text", RowKey: key}, nil
	default:
		return appMCPRevisionKey{}, errors.New("selector id must be integer or text")
	}
}

func appMCPCommandValidateDependencyKeyType(cap *appMCPCommandCapability, table string, keys []appMCPRevisionKey) error {
	var columns []Column
	err := cap.withInternalRead(func() error {
		var err error
		columns, err = mainTableColumnsWith(&appMCPWriteTxQuerier{ctx: cap.ctx, tx: cap.tx}, table)
		return err
	})
	if err != nil {
		return err
	}
	var id *Column
	primary := 0
	for i := range columns {
		if columns[i].PK {
			primary++
			if strings.EqualFold(columns[i].Name, "id") {
				id = &columns[i]
			}
		}
	}
	if id == nil || primary != 1 || !isAppMCPIDColumnType(id.Type) {
		return errors.New("dependency table must have one canonical id primary key")
	}
	expect := "integer"
	if strings.Contains(strings.ToLower(id.Type), "char") || strings.Contains(strings.ToLower(id.Type), "text") || strings.Contains(strings.ToLower(id.Type), "clob") {
		expect = "text"
	}
	for _, key := range keys {
		if key.KeyType != expect || expect == "integer" && !appMCPCanonicalIntegerKey(key.RowKey) || key.RowKey == "" {
			return errors.New("dependency returned an id with a lossy or wrong storage type")
		}
	}
	return nil
}

func isAppMCPIDColumnType(raw string) bool {
	typeName := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(typeName, "int") || strings.Contains(typeName, "char") || strings.Contains(typeName, "text") || strings.Contains(typeName, "clob")
}

func cloneAppMCPCommandDependencySnapshot(source *appMCPRevisionDependencySnapshot) *appMCPRevisionDependencySnapshot {
	if source == nil {
		return nil
	}
	copy := *source
	copy.Sets = append([]appMCPRevisionDependencySet(nil), source.Sets...)
	for i := range copy.Sets {
		copy.Sets[i].Members = append([]appMCPRevisionDependencyMember(nil), source.Sets[i].Members...)
	}
	return &copy
}
