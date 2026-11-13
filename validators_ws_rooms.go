//go:build !cli

package main

// Advisory checks for app.yaml ws_rooms: rules that load and close the rooms
// they were written for. Neither is refused at write time: a deployed file
// that holds one keeps pushing, and its rooms fail closed.
//
//   - A `_` directly after the placeholder ("a_:id_b"). parseWSRoomPattern
//     reads `_` as part of the placeholder's name, so the pattern restricts
//     rooms a_<value>, and a room named a_42_b is checked with the join value
//     "42_b". That reading stays (changing it would stop guarding the rooms
//     a deployed pattern guards today, such as a_42); the check says how the
//     pattern is read and names the pattern for rooms a_<value>-b.
//   - A membership table or column the app does not have. The membership
//     query fails, so every join of a matching room is refused. A member-of
//     rule in access: is judged the same way (memberOfReferenceWarnings).
//
// `benmore check` and the post-write check report both from the app's sources
// (authzWarnings); the load logs the second from the live database
// (logWSRoomRuleReferences).
//
// What the sources can say about the database: a table or view that a
// migrations/ file (or schema.sql) creates will be there, so a rule naming
// one is not reported, and its columns are not guessed at (a view's come from
// its SELECT). Only the database settles those. The post-write check runs in
// the router and never opens a tenant database, and `benmore check` in an app
// directory loads the app check-only; the one check with the database open is
// the serving process's own (the hosted check's check_live), which adds
// wsRoomLiveFindings on its pool.

import (
	"database/sql"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// wsRoomPlaceholderName returns the placeholder's name as parseWSRoomPattern
// reads it ("" for a literal or unusable pattern).
func wsRoomPlaceholderName(pattern string) (name string, p wsRoomPattern) {
	p, problem := parseWSRoomPattern(pattern)
	if problem != "" || !p.param {
		return "", p
	}
	return pattern[len(p.prefix)+1 : len(pattern)-len(p.suffix)], p
}

// wsRoomUnderscoreWarning is the warning for a pattern whose placeholder name
// holds a `_` that may have been meant as room-name text ("" otherwise). A
// name that is the rule's join column or ends in `_id` is a column-like name
// and draws none.
func wsRoomUnderscoreWarning(pattern string, rule *memberOfRule) string {
	name, p := wsRoomPlaceholderName(pattern)
	cut := strings.IndexByte(name, '_')
	if cut <= 0 || rule == nil {
		return ""
	}
	lower := strings.ToLower(name)
	if lower == rule.JoinCol || strings.HasSuffix(lower, "_id") {
		return ""
	}
	if strings.HasPrefix(lower, rule.JoinCol+"_") {
		cut = len(rule.JoinCol) // ":room_id_chat": the name is the join column
	}
	head, tail := name[:cut], name[cut+1:]
	withDash := p.prefix + ":" + head + "-" + tail + p.suffix
	withDot := p.prefix + ":" + head + "." + tail + p.suffix
	plain := ":" + head + " or :" + rule.JoinCol
	if strings.EqualFold(head, rule.JoinCol) {
		plain = ":" + head
	}
	return fmt.Sprintf("app.yaml: ws_rooms pattern %q is read as the placeholder :%s - a `_` directly after a placeholder is part of its name, not room-name text. "+
		"It restricts rooms named like %s42%s (42 is checked as %s.%s); a room named %s42_%s%s is checked with the value \"42_%s\", so its members are refused. "+
		"If `_%s` belongs to the room name, write %q (rooms like %s42-%s%s) or %q: after a placeholder, room-name text starts with `-` or `.`. "+
		"If %s is only the placeholder's name, the pattern works as written; name it %s and this warning goes.",
		pattern, name,
		p.prefix, p.suffix, rule.Table, rule.JoinCol, p.prefix, tail, p.suffix, tail,
		tail, withDash, p.prefix, tail, p.suffix, withDot,
		name, plain)
}

// wsRoomSchemaView is what a ws_rooms rule's table and columns are checked
// against: the app's sources at check time, the live database at load.
type wsRoomSchemaView struct {
	hasTable      func(table string) bool
	missingColumn func(table, column string) bool
	tableList     string                    // the app's tables, for the message ("" to leave out)
	columnList    func(table string) string // a table's columns, for the message
}

// wsRoomReferenceWarnings names each rule whose membership table, join column
// or user column the view does not have. A literal pattern (no placeholder)
// never reads its join column, so a join column the table lacks refuses
// nobody there: its warning says the name is not read and the rule works.
func wsRoomReferenceWarnings(rules []WSRoomRule, view wsRoomSchemaView) []string {
	const effect = "Every join of a room this pattern matches is refused for everyone but admins (\"not a member of this room\") until the rule names"
	var out []string
	for _, wr := range rules {
		rule := wr.Rule
		if rule == nil {
			continue
		}
		at := fmt.Sprintf("app.yaml: ws_rooms.%q = %s(%s, %s)", wr.Pattern, rule.Table, rule.JoinCol, rule.UserCol)
		if !view.hasTable(rule.Table) {
			known := ""
			if view.tableList != "" {
				known = " (tables: " + view.tableList + ")"
			}
			out = append(out, fmt.Sprintf("%s names membership table %s, which the app does not have%s. %s an existing table.", at, rule.Table, known, effect))
			continue
		}
		var missing []string
		unreadJoin := false
		if view.missingColumn(rule.Table, rule.JoinCol) {
			if _, p := wsRoomPlaceholderName(wr.Pattern); p.param {
				missing = append(missing, rule.Table+"."+rule.JoinCol)
			} else {
				unreadJoin = true
			}
		}
		if view.missingColumn(rule.Table, rule.UserCol) {
			missing = append(missing, rule.Table+"."+rule.UserCol)
		}
		known := ""
		if cols := view.columnList(rule.Table); cols != "" {
			known = fmt.Sprintf(" (%s columns: %s)", rule.Table, cols)
		}
		switch {
		case len(missing) > 0:
			out = append(out, fmt.Sprintf("%s names %s, which the table does not have%s. %s existing columns.", at, strings.Join(missing, " and "), known, effect))
		case unreadJoin:
			out = append(out, fmt.Sprintf("%s names %s.%s, which the table does not have%s. The pattern has no placeholder, so its join column is never read: a user with any row in %s joins the room, and the rule works as written. Name a column the table has: a placeholder added to the pattern later is checked against this column, and with this name every join would be refused.",
				at, rule.Table, rule.JoinCol, known, rule.Table))
		}
	}
	return out
}

// wsRoomRuleWarnings are the check's warnings for the app's ws_rooms rules,
// judged against its sources as the load-reference checks read them (schema,
// migrations/, framework tables). Without a readable schema only the pattern
// is judged.
func wsRoomRuleWarnings(dir string, rules []WSRoomRule) []string {
	if len(rules) == 0 {
		return nil
	}
	var out []string
	for _, wr := range rules {
		if msg := wsRoomUnderscoreWarning(wr.Pattern, wr.Rule); msg != "" {
			out = append(out, msg)
		}
	}
	view, ok := sourceMembershipSchemaView(dir)
	if !ok {
		return out
	}
	return append(out, wsRoomReferenceWarnings(rules, view)...)
}

// sourceMembershipSchemaView is the app's tables and columns as its sources
// declare them, for judging the membership table a ws_rooms or member-of rule
// names. ok is false without a readable schema.
func sourceMembershipSchemaView(dir string) (view wsRoomSchemaView, ok bool) {
	schema := readLoadRefSchema(loadRefSource{dir: dir})
	if schema == nil {
		return view, false
	}
	created := sourceCreatedRelations(dir)
	return wsRoomSchemaView{
		hasTable: func(table string) bool {
			return created[sqliteIdentifierFold(table)] || schema.hasTable(table)
		},
		// The columns of what a migration creates are not the sources' to
		// judge: stay silent rather than guess.
		missingColumn: func(table, column string) bool {
			return !created[sqliteIdentifierFold(table)] && schema.missingColumn(table, column)
		},
		tableList:  schema.tableList,
		columnList: schema.columnList,
	}, true
}

// memberOfReferenceWarnings names each member-of rule of access: whose
// membership table, join column or user column the app's sources do not
// have: the membership query cannot run, so every request the rule gates
// fails. One warning per table and rule, with the operations it is written
// for. The write gate accepts such a file (the table may arrive with the
// next schema write), and until now nothing said so.
func memberOfReferenceWarnings(dir string, access *AccessConfig) []string {
	if access == nil {
		return nil
	}
	view, ok := sourceMembershipSchemaView(dir)
	if !ok {
		return nil
	}
	const effect = "The membership query cannot run, so every request this rule gates fails for everyone but admins until the rule names"
	var out []string
	for _, table := range slices.Sorted(maps.Keys(access.rules)) {
		ops := access.rules[table]
		byMode := map[string][]string{}
		for _, op := range []AccessOp{OpRead, OpWrite, OpUpdate, OpDelete, "all"} {
			if mode, set := ops[op]; set && parseMemberOf(mode) != nil {
				byMode[mode] = append(byMode[mode], string(op))
			}
		}
		for _, mode := range slices.Sorted(maps.Keys(byMode)) {
			rule := parseMemberOf(mode)
			join := rule.JoinCol
			if rule.Parent {
				join += "=id"
			}
			at := "app.yaml: access." + table
			if written := byMode[mode]; !slices.Contains(written, "all") {
				at += " (" + strings.Join(written, ", ") + ")"
			}
			at += fmt.Sprintf(" = member-of:%s(%s, %s)", rule.Table, join, rule.UserCol)
			if !view.hasTable(rule.Table) {
				known := ""
				if view.tableList != "" {
					known = " (tables: " + view.tableList + ")"
				}
				out = append(out, fmt.Sprintf("%s names membership table %s, which the app does not have%s. %s an existing table.", at, rule.Table, known, effect))
				continue
			}
			var missing []string
			for _, col := range []string{rule.JoinCol, rule.UserCol} {
				if view.missingColumn(rule.Table, col) {
					missing = append(missing, rule.Table+"."+col)
				}
			}
			if len(missing) == 0 {
				continue
			}
			known := ""
			if cols := view.columnList(rule.Table); cols != "" {
				known = fmt.Sprintf(" (%s columns: %s)", rule.Table, cols)
			}
			out = append(out, fmt.Sprintf("%s names %s, which the table does not have%s. %s existing columns.", at, strings.Join(missing, " and "), known, effect))
		}
	}
	return out
}

// sourceCreatedRelations are the tables and views (folded names) that the
// app's own SQL creates or renames into place: its migrations/ files, as the
// load-reference checks pick them (a migration the Prisma step generated only
// replays the schema), and schema.sql for an app without schema.prisma.
func sourceCreatedRelations(dir string) map[string]bool {
	out := map[string]bool{}
	add := func(script []byte) {
		for _, name := range sqlCreatedRelations(string(script)) {
			out[sqliteIdentifierFold(name)] = true
		}
	}
	if readAppFileOrNil(dir, "schema.prisma") == nil {
		add(readAppFileOrNil(dir, "schema.sql"))
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "migrations"))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".sql") {
			continue
		}
		body := readAppFileOrNil(dir, filepath.Join("migrations", entry.Name()))
		if generatedPrismaMigration(entry.Name(), string(body)) {
			continue
		}
		add(body)
	}
	return out
}

// sqlCreatedRelations returns the names a SQL script gives a lasting table or
// view: CREATE [VIRTUAL] TABLE, CREATE VIEW and ALTER TABLE ... RENAME TO,
// read from the script's tokens, so text in a comment or a string is not
// DDL. A temporary object is left out: no other connection sees it.
func sqlCreatedRelations(script string) []string {
	var out []string
	for _, st := range sqlTokenStatements(sqlTokenize(script)) {
		word := func(i int, want string) bool {
			return i < len(st) && st[i].kind == sqlTokWord && strings.EqualFold(st[i].text, want)
		}
		// name reads [schema .] name at i.
		name := func(i int) string {
			if i >= len(st) || st[i].kind == sqlTokPunct {
				return ""
			}
			if i+2 < len(st) && st[i+1].kind == sqlTokPunct && st[i+1].text == "." && st[i+2].kind != sqlTokPunct {
				if strings.EqualFold(st[i].text, "temp") {
					return ""
				}
				return st[i+2].text
			}
			return st[i].text
		}
		got := ""
		switch {
		case word(0, "CREATE"):
			i := 1
			if word(i, "VIRTUAL") {
				i++
			}
			if !word(i, "TABLE") && !word(i, "VIEW") {
				continue
			}
			i++
			if word(i, "IF") && word(i+1, "NOT") && word(i+2, "EXISTS") {
				i += 3
			}
			got = name(i)
		case word(0, "ALTER") && word(1, "TABLE"):
			for i := 2; i+2 < len(st) && i < 6; i++ {
				if word(i, "RENAME") && word(i+1, "TO") {
					got = name(i + 2)
				}
			}
		}
		if got != "" {
			out = append(out, got)
		}
	}
	return out
}

// wsRoomLiveFindings is the check's live layer for ws_rooms: the rules of the
// app.yaml in dir whose membership table or column db does not have. Only the
// serving process has db (nil elsewhere, and nothing is reported).
func wsRoomLiveFindings(dir string, db *sql.DB) []CheckFinding {
	if db == nil {
		return nil
	}
	rules := parseWSRooms(readAppFileOrNil(dir, "app.yaml"))
	var out []CheckFinding
	for _, msg := range wsRoomReferenceWarnings(rules, liveWSRoomSchema(db)) {
		out = append(out, CheckFinding{Severity: "warning", Source: "security", File: "app.yaml", Message: msg})
	}
	return out
}

// wsRoomFindingRule is the rule a ws_rooms reference warning is about ("" for
// any other message): the same for the source layer's and the live layer's.
func wsRoomFindingRule(message string) string {
	rule, _, ok := strings.Cut(message, " names ")
	if !ok || !strings.HasPrefix(rule, "app.yaml: ws_rooms.") {
		return ""
	}
	return rule
}

// liveWSRoomSchema reads tables and columns from the database. A lookup that
// fails reports nothing missing: the log must not name a rule it could not
// check.
func liveWSRoomSchema(db rowQuerier) wsRoomSchemaView {
	hasTable := func(table string) bool {
		var n int
		err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?)", table).Scan(&n)
		return err != nil || n > 0
	}
	return wsRoomSchemaView{
		hasTable: hasTable,
		missingColumn: func(table, column string) bool {
			var n int
			err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ? COLLATE NOCASE", table, column).Scan(&n)
			return err == nil && n == 0
		},
		columnList: func(table string) string {
			var cols string
			if db.QueryRow("SELECT COALESCE(group_concat(name, ', '), '') FROM pragma_table_info(?)", table).Scan(&cols) != nil {
				return ""
			}
			return cols
		},
	}
}
