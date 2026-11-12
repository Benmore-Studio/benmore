//go:build !cli

package main

// What `compliance: hipaa` leaves to SQL the app writes itself, reported as
// warnings by `benmore check` and by the check that follows a write.
//
// The hipaa controls cover the generated API. Two things a flow or hook does
// with its own SQL sit outside them, and neither showed anywhere:
//
//   - a write (INSERT/UPDATE/DELETE of an app table) leaves no row in
//     _benmore_audit_log; only the mutation pipeline records one. A job is
//     named when it writes an app table and no step of it inserts an audit row
//     (hipaaUnauditedWriteProblems), a hooks.yaml hook when no hook of the same
//     event and table does (hipaaUnauditedHookProblems).
//   - a SQL step's rows are decrypted for the flow and are not masked for the
//     caller. A respond step is named when it returns a step's rows whole and
//     that step selects `*` from a table with encrypted columns
//     (hipaaWholeRowResponseProblems). The `<col>_blind` HMAC such a query
//     also returns is left out of the response (flows_respond_blind_index.go),
//     so the message names the clear columns only.
//
// Both are warnings and neither is refused: deployed flows do both. The
// written tables come from sqlWriteTargets, the lexer every other SQL check
// uses.

import (
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// auditLogTable is the table a flow inserts its own audit row into.
const auditLogTable = "_benmore_audit_log"

// hipaaFlowFindings reports both checks for a `compliance: hipaa` app: for the
// flow file or hooks.yaml just written, or for every flow file and hooks.yaml
// on a full check and after a write other files depend on (app.yaml is where
// hipaa is switched on). An app without the key gets none.
func hipaaFlowFindings(dir, writtenPath string) []CheckFinding {
	if dir == "" {
		return nil
	}
	flowWrite := writtenPath != "" && (filepath.Base(writtenPath) == "flows.yaml" || isFlowsSubdirFile(writtenPath))
	hooksWrite := writtenPath != "" && strings.EqualFold(appRelativeFile(dir, writtenPath), "hooks.yaml")
	if writtenPath != "" && !flowWrite && !hooksWrite && !writeAffectsOtherFiles(writtenPath) {
		return nil
	}
	appYAML := readAppFileOrNil(dir, "app.yaml")
	if hipaa, err := appYAMLDeclaresHIPAA(appYAML); err != nil || !hipaa {
		return nil
	}
	var findings []CheckFinding
	warn := func(file, problem string) {
		// refusal_docs.go maps the source to the keys that state the two rules.
		findings = append(findings, CheckFinding{Severity: "warning", Source: "compliance", File: file, Message: file + ": " + problem})
	}
	if !hooksWrite {
		files := []string{writtenPath}
		if !flowWrite {
			files = flowFilesFor(dir, "")
		}
		enc := parseEncryptedFieldsConfig(readAppFileOrNil(dir, "encrypted.yaml"), appYAML)
		for _, rel := range files {
			data, err := readFileInRoot(dir, rel)
			// An approved command's writes are recorded by its own sealed
			// operation and audit rows.
			if err != nil || commandDeclarationPresent(string(data)) {
				continue
			}
			var file FlowFileGHA
			if decodeConfigYAML(data, &file) != nil || file.Jobs == nil {
				continue
			}
			name := filepath.ToSlash(rel)
			for _, problem := range hipaaUnauditedWriteProblems(file) {
				warn(name, problem)
			}
			for _, problem := range hipaaWholeRowResponseProblems(file, enc) {
				warn(name, problem)
			}
		}
	}
	if !flowWrite {
		var hooks HooksYAML
		if data := readAppFileOrNil(dir, "hooks.yaml"); data != nil && decodeConfigYAML(data, &hooks) == nil {
			for _, problem := range hipaaUnauditedHookProblems(hooks) {
				warn("hooks.yaml", problem)
			}
		}
	}
	return findings
}

// hipaaUnauditedWriteRule follows the name of the job or hook in both
// unaudited-write messages; what to add follows it.
const hipaaUnauditedWriteRule = "Under compliance: hipaa only writes through the generated API (/api/<table>, batch, ingest, /api/_transaction, workflow transitions) are recorded in the audit log; this write leaves no audit row."

const hipaaAuditRowColumns = "`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, new_values) VALUES (...)`, with the values of encrypted columns left out of new_values"

// hipaaSQLWrites reads one SQL text: the app tables it writes, in order, and
// whether it inserts an audit row.
func hipaaSQLWrites(query string) (tables []string, audited bool) {
	writes, _ := sqlWriteTargets(query)
	for _, w := range writes {
		switch {
		case strings.EqualFold(w.Table, auditLogTable):
			audited = audited || w.Action == "insert"
		case !frameworkOwnedTableName(w.Table):
			tables = append(tables, w.Table)
		}
	}
	return tables, audited
}

// hipaaStepSQL is the text of a `run: sql` or `run: sql_dynamic` step, "" for
// any other step.
func hipaaStepSQL(s FlowStepGHA) string {
	if run := ghaStepRunType(s); run != "sql" && run != "sql_dynamic" {
		return ""
	}
	if q, ok := s.With["query"].(string); ok && q != "" {
		return q
	}
	return s.Query
}

// hipaaUnauditedWriteProblems names each job whose SQL steps write an app
// table while none of them, at any nesting depth, inserts into
// _benmore_audit_log. Jobs in name order.
func hipaaUnauditedWriteProblems(file FlowFileGHA) []string {
	var problems []string
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		var written []string
		audited := false
		var walk func(steps []FlowStepGHA)
		walk = func(steps []FlowStepGHA) {
			for _, s := range steps {
				if query := hipaaStepSQL(s); query != "" {
					tables, insertsAudit := hipaaSQLWrites(query)
					written = appendFoldUnique(written, tables...)
					audited = audited || insertsAudit
				}
				walk(s.Steps)
				walk(s.Else)
				walk(s.OnError)
			}
		}
		walk(file.Jobs[job].Steps)
		if len(written) > 0 && !audited {
			problems = append(problems, fmt.Sprintf("job %q writes %s with its own SQL and inserts no row into %s. %s Add a step to the job that records it: %s.",
				job, strings.Join(written, ", "), auditLogTable, hipaaUnauditedWriteRule, hipaaAuditRowColumns))
		}
	}
	return problems
}

// hipaaUnauditedHookProblems names each hooks.yaml event and table whose
// hooks' SQL writes an app table while none of them inserts into
// _benmore_audit_log. The triggering write itself is recorded by the API; what
// the hook then writes is not.
func hipaaUnauditedHookProblems(hooks HooksYAML) []string {
	var problems []string
	sections := []struct {
		name  string
		hooks map[string][]HookEntryYAML
	}{
		{"before_insert", hooks.BeforeInsert}, {"before_update", hooks.BeforeUpdate}, {"before_delete", hooks.BeforeDelete},
		{"on_insert", hooks.OnInsert}, {"on_update", hooks.OnUpdate}, {"on_delete", hooks.OnDelete},
	}
	for _, section := range sections {
		for _, table := range slices.Sorted(maps.Keys(section.hooks)) {
			var written []string
			audited := false
			for _, hook := range section.hooks[table] {
				tables, insertsAudit := hipaaSQLWrites(hook.SQL)
				written = appendFoldUnique(written, tables...)
				audited = audited || insertsAudit
			}
			if len(written) > 0 && !audited {
				problems = append(problems, fmt.Sprintf("%s hook on %s writes %s with its own SQL and inserts no row into %s. %s Add a `sql:` entry under the same event and table that records it: %s.",
					section.name, table, strings.Join(written, ", "), auditLogTable, hipaaUnauditedWriteRule, hipaaAuditRowColumns))
			}
		}
	}
	return problems
}

// appendFoldUnique appends the names list does not hold yet, compared as
// SQLite compares identifiers.
func appendFoldUnique(list []string, names ...string) []string {
	for _, name := range names {
		if !slices.ContainsFunc(list, func(have string) bool { return strings.EqualFold(have, name) }) {
			list = append(list, name)
		}
	}
	return list
}

// hipaaRowRefRe matches a step-output reference with its whole path, so a
// reference to the rows themselves can be told from one to a column.
var hipaaRowRefRe = regexp.MustCompile(`steps\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs((?:\.[A-Za-z_]\w*|\.\d+|\[\d+\])*)`)

// hipaaWholeRowRef reports whether the path after `.outputs` names rows whole
// (`.first`, `.rows`, `.rows[0]`, an index, or nothing) and not one column.
func hipaaWholeRowRef(tail string) bool {
	tail = strings.TrimPrefix(tail, ".rows")
	tail = strings.TrimPrefix(tail, ".first")
	if tail == "" {
		return true
	}
	// What is left may only be one index: `[0]` or `.0`.
	index := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(tail, "["), "."), "]")
	return index != "" && strings.Trim(index, "0123456789") == ""
}

// hipaaWholeRowResponseProblems names each respond step that returns the rows
// of a SQL step whole when that step's query returns every column of a table
// with encrypted fields (`*`, `t.*` or `RETURNING *`). Jobs in name order,
// each respond step and source step once.
func hipaaWholeRowResponseProblems(file FlowFileGHA, enc *EncryptedFieldConfig) []string {
	if enc == nil || len(enc.Fields) == 0 {
		return nil
	}
	var problems []string
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		// Step id -> the encrypted tables its query returns whole.
		whole := map[string][]string{}
		var collect func(steps []FlowStepGHA)
		collect = func(steps []FlowStepGHA) {
			for _, s := range steps {
				if query := hipaaStepSQL(s); query != "" && s.ID != "" {
					for _, table := range sqlWholeRowTables(query) {
						for _, declared := range slices.Sorted(maps.Keys(enc.Fields)) {
							if strings.EqualFold(declared, table) && len(enc.Fields[declared]) > 0 {
								whole[s.ID] = appendFoldUnique(whole[s.ID], declared)
							}
						}
					}
				}
				collect(s.Steps)
				collect(s.Else)
				collect(s.OnError)
			}
		}
		collect(file.Jobs[job].Steps)
		if len(whole) == 0 {
			continue
		}
		var walk func(path string, steps []FlowStepGHA)
		walk = func(path string, steps []FlowStepGHA) {
			for i, s := range steps {
				here := fmt.Sprintf("%s[%d]", path, i)
				if ghaStepRunType(s) == "respond" {
					reported := map[string]bool{}
					for _, m := range hipaaRowRefRe.FindAllStringSubmatch(flowStepWithText(s.With), -1) {
						tables := whole[m[1]]
						if len(tables) == 0 || reported[m[1]] || !hipaaWholeRowRef(m[2]) {
							continue
						}
						reported[m[1]] = true
						problems = append(problems, hipaaWholeRowProblem(job, here, m[1], tables, enc))
					}
				}
				walk(here+".steps", s.Steps)
				walk(here+".else", s.Else)
				walk(here+".on_error", s.OnError)
			}
		}
		walk("steps", file.Jobs[job].Steps)
	}
	return problems
}

// hipaaWholeRowProblem is the message for one respond step and source step.
func hipaaWholeRowProblem(job, where, step string, tables []string, enc *EncryptedFieldConfig) string {
	var columns []string
	for _, table := range tables {
		for _, def := range enc.Fields[table] {
			columns = appendFoldUnique(columns, def.Column)
		}
	}
	slices.Sort(columns)
	carries := "the encrypted " + pluralWord(len(columns), "column") + " " + strings.Join(columns, ", ") + " in clear"
	return fmt.Sprintf("job %q step %s responds with whole rows of step %q, whose query selects `*` from %s. A flow's SQL result is not masked for the caller: this response carries %s to everyone the flow answers, whatever the unmask roles are. Select the columns the response needs by name.",
		job, where, step, strings.Join(tables, ", "), carries)
}

// pluralWord is word, with an s when n is not one.
func pluralWord(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// --- which tables a statement returns every column of ---

// sqlWholeRowTables returns the tables a SQL text returns every column of: a
// bare `*` in a SELECT's result list covers every table of its FROM clause,
// `t.*` the table (or alias) t, and `RETURNING *` the written table. A `*`
// read through a CTE or a FROM subquery is followed to the tables behind it;
// COUNT(*), a multiplication and a `*` that only feeds a subquery whose outer
// SELECT names its columns are not one. Names are as written.
func sqlWholeRowTables(query string) []string {
	var tables []string
	for _, statement := range sqlTokenStatements(sqlTokenize(query)) {
		tables = appendFoldUnique(tables, sqlStatementWholeRowTables(statement)...)
	}
	return tables
}

func sqlWordIs(toks []sqlToken, i int, word string) bool {
	return i >= 0 && i < len(toks) && toks[i].kind == sqlTokWord && strings.EqualFold(toks[i].text, word)
}

func sqlPunctIs(toks []sqlToken, i int, punct string) bool {
	return i >= 0 && i < len(toks) && toks[i].kind == sqlTokPunct && toks[i].text == punct
}

// sqlCloseParen returns the index of the `)` that closes the `(` at open, or
// len(toks) when it is never closed.
func sqlCloseParen(toks []sqlToken, open int) int {
	depth := 0
	for i := open; i < len(toks); i++ {
		switch {
		case sqlPunctIs(toks, i, "("):
			depth++
		case sqlPunctIs(toks, i, ")"):
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return len(toks)
}

func sqlStatementWholeRowTables(toks []sqlToken) []string {
	if write, ok := sqlStatementWrite(toks); ok {
		depth := 0
		for i := range toks {
			switch {
			case sqlPunctIs(toks, i, "("):
				depth++
			case sqlPunctIs(toks, i, ")"):
				depth--
			case depth == 0 && sqlPunctIs(toks, i, "*") && (sqlWordIs(toks, i-1, "RETURNING") || sqlPunctIs(toks, i-1, ",")) && sqlStatementReturns(toks[:i]):
				return []string{write.Table}
			}
		}
		return nil
	}
	// WITH name [(columns)] AS [[NOT] MATERIALIZED] (select), ...
	ctes := map[string][]string{}
	i := 0
	if sqlWordIs(toks, 0, "WITH") {
		i = 1
		if sqlWordIs(toks, i, "RECURSIVE") {
			i++
		}
		for i < len(toks) && toks[i].kind != sqlTokPunct {
			name := strings.ToLower(toks[i].text)
			i++
			if sqlPunctIs(toks, i, "(") {
				i = sqlCloseParen(toks, i) + 1
			}
			if !sqlWordIs(toks, i, "AS") {
				break
			}
			i++
			if sqlWordIs(toks, i, "NOT") {
				i++
			}
			if sqlWordIs(toks, i, "MATERIALIZED") {
				i++
			}
			if !sqlPunctIs(toks, i, "(") {
				break
			}
			end := sqlCloseParen(toks, i)
			ctes[name] = sqlSelectWholeRowTables(toks[i+1:min(end, len(toks))], ctes)
			i = end + 1
			if !sqlPunctIs(toks, i, ",") {
				break
			}
			i++
		}
	}
	if i > len(toks) {
		return nil
	}
	return sqlSelectWholeRowTables(toks[i:], ctes)
}

// sqlAliasStop are the words that follow a table in a FROM clause and are
// therefore not its alias.
var sqlAliasStop = map[string]bool{
	"ON": true, "USING": true, "WHERE": true, "GROUP": true, "HAVING": true, "WINDOW": true, "ORDER": true, "LIMIT": true,
	"JOIN": true, "LEFT": true, "RIGHT": true, "FULL": true, "INNER": true, "OUTER": true, "CROSS": true, "NATURAL": true,
	"UNION": true, "INTERSECT": true, "EXCEPT": true, "INDEXED": true, "NOT": true, "RETURNING": true,
}

// sqlSelectWholeRowTables reads a SELECT (compound or not) whose CTEs are
// already known: for each of its SELECTs, the tables a `*` of its result list
// stands for.
func sqlSelectWholeRowTables(toks []sqlToken, ctes map[string][]string) []string {
	const (
		other = iota
		resultList
		fromClause
	)
	var out []string
	state, depth := other, 0
	expectSource := false
	bare := false                    // a bare `*` in the current result list
	var qualified []string           // the t of each `t.*`
	sources := map[string][]string{} // table name or alias -> tables behind it
	var all []string                 // every table of the current FROM clause
	flush := func() {
		if bare {
			out = appendFoldUnique(out, all...)
		}
		for _, q := range qualified {
			out = appendFoldUnique(out, sources[q]...)
		}
		bare, qualified, sources, all = false, nil, map[string][]string{}, nil
	}
	// alias reads `[AS] name` at i and returns the name and the last index used.
	alias := func(i int, fallback string) (string, int) {
		j := i
		if sqlWordIs(toks, j, "AS") {
			j++
		}
		if j < len(toks) && (toks[j].kind == sqlTokIdent || toks[j].kind == sqlTokLiteral ||
			(toks[j].kind == sqlTokWord && !sqlAliasStop[strings.ToUpper(toks[j].text)])) {
			return toks[j].text, j
		}
		return fallback, i - 1
	}
	addSource := func(name string, tables []string) {
		if name != "" {
			sources[strings.ToLower(name)] = tables
		}
		all = appendFoldUnique(all, tables...)
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind == sqlTokPunct {
			switch t.text {
			case "(":
				if depth == 0 && state == fromClause && expectSource {
					// A subquery in FROM: its own whole-row tables, under its alias.
					end := sqlCloseParen(toks, i)
					behind := sqlSelectWholeRowTables(toks[i+1:min(end, len(toks))], ctes)
					name, last := alias(end+1, "")
					addSource(name, behind)
					expectSource = false
					i = max(last, end)
					continue
				}
				depth++
			case ")":
				if depth > 0 {
					depth--
				}
			case ",":
				if depth == 0 && state == fromClause {
					expectSource = true
				}
			case "*":
				if depth != 0 || state != resultList {
					break
				}
				switch {
				case sqlPunctIs(toks, i-1, ".") && i >= 2:
					qualified = append(qualified, strings.ToLower(toks[i-2].text))
				case sqlPunctIs(toks, i-1, ","), sqlWordIs(toks, i-1, "SELECT"), sqlWordIs(toks, i-1, "DISTINCT"), sqlWordIs(toks, i-1, "ALL"):
					bare = true
				}
			}
			continue
		}
		if depth != 0 {
			continue
		}
		if t.kind == sqlTokWord {
			switch strings.ToUpper(t.text) {
			case "SELECT":
				state = resultList
				continue
			case "FROM":
				if state == resultList {
					state, expectSource = fromClause, true
				}
				continue
			case "JOIN":
				if state == fromClause {
					expectSource = true
				}
				continue
			case "WHERE", "GROUP", "HAVING", "WINDOW", "ORDER", "LIMIT":
				state = other
				continue
			case "UNION", "INTERSECT", "EXCEPT":
				flush()
				state = other
				continue
			}
		}
		if state == fromClause && expectSource {
			expectSource = false
			name, qualifiedName := t.text, false
			if sqlPunctIs(toks, i+1, ".") && i+2 < len(toks) && toks[i+2].kind != sqlTokPunct {
				name, qualifiedName = toks[i+2].text, true
				i += 2
			}
			tables := []string{name}
			if behind, cte := ctes[strings.ToLower(name)]; cte && !qualifiedName {
				tables = behind
			}
			called, last := alias(i+1, name)
			addSource(name, tables)
			addSource(called, tables)
			i = last
		}
	}
	flush()
	return out
}
