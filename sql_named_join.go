//go:build !cli

package main

// A join that names its columns (`JOIN t USING (col)`, `NATURAL JOIN t`) is the
// one place SQLite reads a table without asking the authorizer: it builds the
// column references of the join itself. Measured on the SQLite this binary
// carries, with an authorizer that denies every read of table d:
//
//   - `SELECT g.x FROM (SELECT 'guess' AS secret, 1 AS x) g JOIN d USING
//     (secret)` compiles and runs with no callback for d at all: the join
//     condition compares d.secret to a chosen value;
//   - `SELECT secret FROM (SELECT NULL AS secret WHERE 0) g FULL JOIN d USING
//     (secret)` returns every d.secret, again with no callback: the result
//     column of a FULL join is coalesce() of both sides.
//
// So an authorizer's answer about a column or a table (deny it, read it as
// NULL, record that it was read) does not hold for a statement with such a
// join. Every guard that depends on that answer for authored SQL asks
// sqlNamedJoinTouches first and refuses the statement, telling its author to
// write the join with ON, where each column reference is resolved by name and
// the authorizer is asked.
//
// The guards and what each protects (grep RegisterAuthorizer for the list):
//
//   - read-only SQL a person writes, and connector read-flow SQL: the framework
//     tables' credential columns, which read as NULL (authorizeReadOnlyQuery);
//   - hook SQL inside an approved connector command: the connector's own
//     stores (authorizeCommandHook);
//   - a page's authored SQL: what the statement read decides the read audit,
//     the hidden columns and the field masks (page_query_reads.go);
//   - computed-field and aggregate SQL at write time: which encrypted column
//     it reads (validators_encrypted_compute.go).
//
// Not asked, because nothing there depends on a read being reported: flow and
// hook SQL (app_sql_guard.go: schema changes and audit rewrites, never reads),
// a hook or workflow `when:` and an aggregate (authorizeWhenQuery admits every
// read), seeds (authorizeAppReset), the migration dry run and the storage
// ceiling. Approved command SQL lists every table of its FROM and JOIN clauses
// from the text and refuses one that is not declared before the statement
// reaches SQLite (commandSQLTableInventory), named joins included. The
// connector's own grant, actor and OAuth reads run fixed framework text.
//
// A view whose own text holds such a join is compiled with the statement that
// reads it, which has no join to find: the guards read the views' texts too
// (see "views" below). Computed-field and aggregate SQL is checked at write
// time, where no view exists yet, by its own text only.

import (
	"context"
	"database/sql"
	"strings"
)

// sqlAuthoredWords returns the text of every bare word, quoted identifier and
// string of a statement, off the shared lexer (comments are not tokens).
// SQLite ends a numbered parameter at its last digit, so `?1natural` is the
// parameter and the keyword; the lexer reads one word there, and the digits
// are dropped.
func sqlAuthoredWords(query string) (words, names []string) {
	toks := sqlTokenize(query)
	for i, tok := range toks {
		switch tok.kind {
		case sqlTokWord:
			text := tok.text
			if i > 0 && toks[i-1].kind == sqlTokPunct && toks[i-1].text == "?" && toks[i-1].end == tok.start {
				text = strings.TrimLeft(text, "0123456789")
			}
			if text != "" {
				words = append(words, text)
				names = append(names, text)
			}
		case sqlTokIdent, sqlTokLiteral:
			// SQLite accepts a string where it expects a table name.
			names = append(names, tok.text)
		}
	}
	return words, names
}

func sqlHasWord(words []string, word string) bool {
	for _, w := range words {
		if strings.EqualFold(w, word) {
			return true
		}
	}
	return false
}

// sqlHasNamedJoin reports a statement that joins by column name. Both
// keywords must be written bare (a quoted join word is an identifier), so a
// word match finds every one; a column or alias called `using` or `natural`
// is a false match, which only refuses more.
func sqlHasNamedJoin(words []string) bool {
	return sqlHasWord(words, "USING") || sqlHasWord(words, "NATURAL")
}

// sqlNamedJoinTouches returns the first name in query that protected accepts,
// when query joins by column name; "" when it has no such join or names no
// protected object. A name is matched wherever it stands in the statement
// (table, alias, column, string), so a false match only refuses more.
func sqlNamedJoinTouches(query string, protected func(name string) bool) string {
	words, names := sqlAuthoredWords(query)
	if !sqlHasNamedJoin(words) {
		return ""
	}
	for _, name := range names {
		if protected(name) {
			return name
		}
	}
	return ""
}

// sqlNamedFullJoin reports a FULL join by column name: the one whose result
// column carries the unreported value itself.
func sqlNamedFullJoin(query string) bool {
	words, _ := sqlAuthoredWords(query)
	return sqlHasWord(words, "FULL") && sqlHasNamedJoin(words)
}

// sqlNamedJoinRefusal words a guard's refusal: who refuses, and which objects
// the statement may not name next to such a join.
func sqlNamedJoinRefusal(who, objects string) string {
	return who + " refuses the words USING and NATURAL in a statement that names " + objects + ": write the join with ON"
}

// sqlNamesFrameworkTable is the protected-name test of the guards over
// framework tables: any name that holds `_benmore_`.
func sqlNamesFrameworkTable(name string) bool {
	return strings.Contains(strings.ToLower(name), "_benmore_")
}

// ---- views ----
//
// SQLite compiles a view's text when a statement reads the view, and a join
// by column name in that text is as unreported as one in the statement
// (TestNamedJoinInsideAViewIsNotReportedToTheAuthorizer). The statement that
// reads the view holds no join to find, so the guards that can read the
// schema judge the statement together with the text of every view it names,
// and every view those name. Only the text that holds the join matters: a
// view that reads a table by name is reported like a subquery, also when the
// statement around it joins the view by column name.

// sqlViewQuerier reads a database's schema: a pinned connection, a
// transaction or the pool.
type sqlViewQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// sqlViewTexts returns the text of every view the connection can read, by
// folded name: the database's and the connection's temporary ones (which a
// statement reaches under the same name).
func sqlViewTexts(ctx context.Context, q sqlViewQuerier) (map[string][]string, error) {
	return sqlViewTextsOf(ctx, q, `SELECT name, sql FROM main.sqlite_master WHERE type = 'view' UNION ALL SELECT name, sql FROM temp.sqlite_master WHERE type = 'view'`)
}

// sqlMainViewTexts is sqlViewTexts without the temporary views, for a scope
// that denies every read of a temporary object.
func sqlMainViewTexts(ctx context.Context, q sqlViewQuerier) (map[string][]string, error) {
	return sqlViewTextsOf(ctx, q, `SELECT name, sql FROM main.sqlite_master WHERE type = 'view'`)
}

func sqlViewTextsOf(ctx context.Context, q sqlViewQuerier, schemaQuery string) (map[string][]string, error) {
	rows, err := q.QueryContext(ctx, schemaQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var views map[string][]string
	for rows.Next() {
		var name string
		var text sql.NullString
		if err := rows.Scan(&name, &text); err != nil {
			return nil, err
		}
		if views == nil {
			views = map[string][]string{}
		}
		folded := sqliteIdentifierFold(name)
		views[folded] = append(views[folded], text.String)
	}
	return views, rows.Err()
}

// sqlTextsRead returns the statement followed by the text of every view it
// names and every view those name. A name is matched wherever it stands, as
// in sqlNamedJoinTouches, so a false match only adds a text.
func sqlTextsRead(query string, views map[string][]string) []string {
	texts := []string{query}
	if len(views) == 0 {
		return texts
	}
	seen := map[string]bool{}
	for i := 0; i < len(texts); i++ {
		_, names := sqlAuthoredWords(texts[i])
		for _, name := range names {
			folded := sqliteIdentifierFold(name)
			if bodies, ok := views[folded]; ok && !seen[folded] {
				seen[folded] = true
				texts = append(texts, bodies...)
			}
		}
	}
	return texts
}

// sqlNamedJoinTouchesIn is sqlNamedJoinTouches over each of texts: the first
// protected name in a text that joins by column name. viaView says the text
// was a view's, not the statement's (texts[0]).
func sqlNamedJoinTouchesIn(texts []string, protected func(name string) bool) (name string, viaView bool) {
	for i, text := range texts {
		if name := sqlNamedJoinTouches(text, protected); name != "" {
			return name, i > 0
		}
	}
	return "", false
}

// sqlNamedFullJoinIn reports a FULL join by column name in any of texts.
func sqlNamedFullJoinIn(texts []string) bool {
	for _, text := range texts {
		if sqlNamedFullJoin(text) {
			return true
		}
	}
	return false
}

// sqlNamedJoinViewRefusal words the refusal of a statement that reads a view
// whose text holds such a join.
func sqlNamedJoinViewRefusal(who, objects string) string {
	return who + " refuses to read a view whose text holds the words USING or NATURAL and names " + objects + ": write the join with ON in the view"
}
