//go:build !cli

package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// App-authored triggers in the revision universe.
//
// Revision enrollment refuses every trigger on an enrolled table that the
// framework did not generate itself (verifyAppMCPDeclaredTriggerClosure): an
// unknown trigger can write tables the revision ledger never sees. A command
// may therefore declare its own triggers, `app_triggers: [{table, name}]`, and
// the declaration is only a pointer. The trigger's SQL is read from the CREATE
// TRIGGER statement in the reviewed migrations (the digested source), the live
// sqlite_schema text must match it, and the tables its body writes join the
// revision universe (or the trigger is refused, as for any _benmore_* or
// non-app table).

type appMCPAppTrigger struct {
	name   string // as written in the migration, which is how SQLite stores it
	table  string // the trigger's ON table
	sql    string // CREATE TRIGGER ... END from the reviewed migration, no trailing ';'
	events []string
	writes []sqlWrite
	reads  []string // tables the WHEN clause and body select from
}

type appMCPMigrationTrigger struct {
	appMCPAppTrigger
	dropped bool
	err     error // why this trigger cannot be admitted; raised only when declared
}

// appMCPDeclaredAppTriggers resolves the declarations of every write command in
// the generation against its captured migrations. A generation without
// declarations returns nil without reading the source.
func appMCPDeclaredAppTriggers(generation *appMCPRuntimeGeneration) ([]appMCPAppTrigger, error) {
	if generation == nil || generation.manifest == nil {
		return nil, nil
	}
	declared := map[string]FlowCommandAppTrigger{}
	for _, tool := range generation.manifest.Tools {
		if tool.Effect != "write" || tool.Handler.Kind != "flow" || tool.Handler.Operation != "command" {
			continue
		}
		flow := appMCPCommandFlowByName(generation, tool.Handler.Flow)
		if flow == nil {
			continue
		}
		for _, trigger := range flow.Command.AppTriggers {
			key := strings.ToLower(trigger.Name)
			if previous, ok := declared[key]; ok && !strings.EqualFold(previous.Table, trigger.Table) {
				return nil, fmt.Errorf("app trigger %q is declared on both %q and %q", trigger.Name, previous.Table, trigger.Table)
			}
			declared[key] = trigger
		}
	}
	if len(declared) == 0 {
		return nil, nil
	}
	source, err := appMCPMigrationTriggers(generation.sourceFiles)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(declared))
	for key := range declared {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]appMCPAppTrigger, 0, len(keys))
	for _, key := range keys {
		decl := declared[key]
		found, ok := source[key]
		if !ok || found.dropped {
			return nil, fmt.Errorf("declared app trigger %q is not created by the reviewed migrations", decl.Name)
		}
		if found.err != nil {
			return nil, fmt.Errorf("declared app trigger %q: %w", decl.Name, found.err)
		}
		if !strings.EqualFold(found.table, decl.Table) {
			return nil, fmt.Errorf("declared app trigger %q is on %q in the reviewed migrations, not %q", decl.Name, found.table, decl.Table)
		}
		out = append(out, found.appMCPAppTrigger)
	}
	return out, nil
}

// appMCPMigrationTriggers returns, per lower-cased trigger name, the last
// CREATE TRIGGER (or DROP TRIGGER) the captured migrations' UP sections hold in
// the order the runtime applies them. Only main-schema triggers count: a TEMP
// trigger never reaches main.sqlite_schema. A name created twice without a DROP
// keeps the database's first body (the second statement is skipped as already
// applied), so the closure check refuses it against this last statement.
func appMCPMigrationTriggers(sources map[string][]byte) (map[string]appMCPMigrationTrigger, error) {
	var names []string
	for path := range sources {
		name, ok := strings.CutPrefix(path, "migrations/")
		if ok && name != "" && !strings.Contains(name, "/") && strings.HasSuffix(name, ".sql") && !strings.HasSuffix(name, ".failed.sql") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := map[string]appMCPMigrationTrigger{}
	for _, name := range names {
		up, _ := extractMigrationSection(string(sources["migrations/"+name]))
		if err := appMCPScanMigrationTriggers(up, out); err != nil {
			return nil, fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return out, nil
}

func appMCPScanMigrationTriggers(up string, out map[string]appMCPMigrationTrigger) error {
	toks := sqlTokenize(up)
	kw := func(i int, words ...string) bool {
		for k, w := range words {
			if !appMCPTokenWord(toks, i+k, w) {
				return false
			}
		}
		return true
	}
	// objectName reads `[main.]name` at i; ok is false for another schema.
	objectName := func(i int) (text string, next int, ok bool) {
		if i >= len(toks) || toks[i].kind == sqlTokPunct || toks[i].text == "" {
			return "", i, false
		}
		if i+2 < len(toks) && toks[i+1].kind == sqlTokPunct && toks[i+1].text == "." {
			return toks[i+2].text, i + 3, strings.EqualFold(toks[i].text, "main")
		}
		return toks[i].text, i + 1, true
	}
	for i := 0; i < len(toks); {
		switch {
		case kw(i, "drop", "trigger"):
			j := i + 2
			if kw(j, "if", "exists") {
				j += 2
			}
			if text, _, ok := objectName(j); ok {
				out[strings.ToLower(text)] = appMCPMigrationTrigger{dropped: true}
			}
		case kw(i, "create", "trigger") || kw(i, "create", "temp", "trigger") || kw(i, "create", "temporary", "trigger"):
			temp := !kw(i, "create", "trigger")
			j := i + 2
			if temp {
				j++
			}
			if kw(j, "if", "not", "exists") {
				j += 3
			}
			text, next, ok := objectName(j)
			end, trigger, err := appMCPParseMigrationTrigger(up, toks, i, next, text)
			if err != nil {
				return err
			}
			if ok && !temp {
				out[strings.ToLower(text)] = trigger
			}
			i = end
			continue
		}
		// Any other statement ends at the next ';' outside a quoting form.
		for i < len(toks) && !(toks[i].kind == sqlTokPunct && toks[i].text == ";") {
			i++
		}
		i++
	}
	return nil
}

// appMCPParseMigrationTrigger reads one CREATE TRIGGER whose statement starts
// at token start and whose name ends before token next. It returns the index
// after the statement's END. Only a statement whose extent cannot be found is
// an error; a trigger that cannot be admitted carries err, which is raised only
// if a command declares it.
func appMCPParseMigrationTrigger(up string, toks []sqlToken, start, next int, name string) (int, appMCPMigrationTrigger, error) {
	begin := -1
	for k := next; k < len(toks); k++ {
		if appMCPTokenWord(toks, k, "begin") {
			begin = k
			break
		}
	}
	end, depth := -1, 0
	for k := begin + 1; begin >= 0 && k < len(toks) && end < 0; k++ {
		switch {
		case appMCPTokenWord(toks, k, "case"):
			depth++
		case appMCPTokenWord(toks, k, "end") && depth > 0:
			depth--
		case appMCPTokenWord(toks, k, "end"):
			end = k
		}
	}
	if end < 0 {
		return 0, appMCPMigrationTrigger{}, fmt.Errorf("trigger %q has no BEGIN ... END body", name)
	}
	trigger := appMCPMigrationTrigger{appMCPAppTrigger: appMCPAppTrigger{name: name, sql: up[toks[start].start:toks[end].end]}}
	trigger.table, trigger.events, trigger.writes, trigger.reads, trigger.err = appMCPTriggerEffects(up, toks, next, begin, end)
	return end + 1, trigger, nil
}

// appMCPTriggerEffects reads the trigger's table and event from its header
// (tokens next..begin), the tables its body (begin..end) writes and the tables
// its WHEN clause and body read. The functions it calls are checked here too:
// the apply authorizer would refuse an unlisted one at the first firing.
func appMCPTriggerEffects(up string, toks []sqlToken, next, begin, end int) (table string, events []string, writes []sqlWrite, reads []string, err error) {
	i := next
	for ; i < begin && !appMCPTokenWord(toks, i, "on"); i++ {
		for _, event := range []string{"insert", "update", "delete"} {
			if appMCPTokenWord(toks, i, event) {
				events = append(events, event)
			}
		}
	}
	if len(events) != 1 || i+1 >= begin || toks[i+1].kind == sqlTokPunct || toks[i+1].text == "" {
		return "", nil, nil, nil, errors.New("header is not a single INSERT, UPDATE or DELETE event ON a table")
	}
	if i+2 < begin && toks[i+2].kind == sqlTokPunct && toks[i+2].text == "." {
		return "", nil, nil, nil, errors.New("the table cannot be schema-qualified")
	}
	table = toks[i+1].text
	if err := appMCPTriggerFunctionError(toks[next : end+1]); err != nil {
		return "", nil, nil, nil, err
	}
	seen := map[string]bool{}
	read := func(query string) error {
		tables, err := commandSQLTableInventory(query)
		for _, name := range tables {
			seen[name] = true
		}
		return err
	}
	for k := i + 2; k < begin; k++ {
		if appMCPTokenWord(toks, k, "when") {
			if err := read("SELECT 1 WHERE " + up[toks[k].end:toks[begin].start]); err != nil {
				return "", nil, nil, nil, fmt.Errorf("WHEN clause: %w", err)
			}
			break
		}
	}
	body := up[toks[begin].end:toks[end].start]
	for _, statement := range sqlTokenStatements(sqlTokenize(body)) {
		upsert := false
		for k := 0; k+1 < len(statement); k++ {
			if appMCPTokenWord(statement, k, "or") && appMCPTokenWord(statement, k+1, "replace") {
				// REPLACE deletes conflicting rows without firing delete triggers,
				// so the ledger would not see those deletions.
				return "", nil, nil, nil, errors.New("OR REPLACE is not admitted in a trigger body")
			}
			upsert = upsert || appMCPTokenWord(statement, k, "on") && appMCPTokenWord(statement, k+1, "conflict")
		}
		if appMCPRevisionStatementVerb(statement) == "REPLACE" {
			return "", nil, nil, nil, errors.New("REPLACE is not admitted in a trigger body")
		}
		if err := read(body[statement[0].start:statement[len(statement)-1].end]); err != nil {
			return "", nil, nil, nil, fmt.Errorf("trigger body: %w", err)
		}
		found, werr := appMCPRevisionHookWrites(body[statement[0].start:statement[len(statement)-1].end])
		if werr != nil {
			return "", nil, nil, nil, werr
		}
		for _, write := range found {
			writes = append(writes, write)
			if write.Action == "insert" && upsert {
				writes = append(writes, sqlWrite{Table: write.Table, Action: "update"})
			}
		}
	}
	for name := range seen {
		reads = append(reads, name)
	}
	sort.Strings(reads)
	return table, events, writes, reads, nil
}

// appMCPTriggerFunctionError refuses a trigger that calls a function the apply
// authorizer would deny: anything outside commandAllowedSQLFunction and
// commandVerifiedTriggerFunction (RAISE, CURRENT_TIMESTAMP, benmore_encrypt).
// A name followed by '(' is a call unless it is a keyword or the column list of
// INSERT INTO t(...); the bare CURRENT_* words are calls too.
func appMCPTriggerFunctionError(toks []sqlToken) error {
	for k, tok := range toks {
		if tok.kind != sqlTokWord && tok.kind != sqlTokIdent {
			continue
		}
		name := strings.ToLower(tok.text)
		call := k+1 < len(toks) && toks[k+1].kind == sqlTokPunct && toks[k+1].text == "(" && !appMCPTriggerNonFunction[name]
		if call {
			p := k - 1
			if p >= 2 && toks[p].kind == sqlTokPunct && toks[p].text == "." {
				p -= 2
			}
			call = !(p >= 0 && p < k && appMCPTokenWord(toks, p, "into"))
		}
		if tok.kind == sqlTokWord && strings.HasPrefix(name, "current_") {
			call = true
		}
		if call && !commandAllowedSQLFunction(name) && !commandVerifiedTriggerFunction(name) {
			return fmt.Errorf("calls function %q, which approved commands cannot run", tok.text)
		}
	}
	return nil
}

var appMCPTriggerNonFunction = map[string]bool{
	"in": true, "values": true, "exists": true, "and": true, "or": true, "not": true, "when": true, "then": true, "else": true,
	"case": true, "select": true, "where": true, "from": true, "join": true, "on": true, "set": true, "as": true, "by": true,
	"using": true, "between": true, "is": true, "conflict": true, "union": true, "intersect": true, "except": true, "all": true,
	"distinct": true, "limit": true, "offset": true, "having": true, "cast": true, "returning": true, "do": true, "update": true,
	"insert": true, "delete": true, "end": true, "of": true, "escape": true,
}

func appMCPTokenWord(toks []sqlToken, i int, w string) bool {
	return i < len(toks) && toks[i].kind == sqlTokWord && strings.EqualFold(toks[i].text, w)
}
