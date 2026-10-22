//go:build !cli

package main

import (
	"fmt"
	"html"
	"log"
	"strings"
)

// Owner scoping for server-rendered queries (<page scope="owner"> and
// frontmatter `scope: owner`). The page's SQL is developer-authored; the
// framework adds `<primary table>.user_id = <session user>` to it.
//
// The clause must bind to the WHOLE query: the page's own WHERE is wrapped in
// parentheses before the owner test is ANDed on, so an OR in it can't widen
// past the owner. Keywords are found only in code at parenthesis depth zero
// (never inside strings, quoted identifiers or comments), and shapes the
// rewrite can't scope with certainty - compound selects, a non-SELECT, no
// FROM table - are refused rather than guessed at.

// sqlWordAt is one bare word of a SQL statement at parenthesis depth zero.
type sqlWordAt struct {
	word string // upper-cased
	pos  int
}

// sqlTopLevelWords lists the words of s that sit in code (not quotes or
// comments) outside every parenthesis. ok is false for unbalanced
// parentheses or a statement the scanner can't classify byte for byte.
func sqlTopLevelWords(s string) (words []sqlWordAt, ok bool) {
	kinds := make([]sqlByteKind, 0, len(s))
	_ = scanSQLBytes(s, func(_ byte, k sqlByteKind) error {
		kinds = append(kinds, k)
		return nil
	})
	if len(kinds) != len(s) {
		return nil, false
	}
	depth := 0
	for i := 0; i < len(s); {
		if kinds[i] != sqlCode {
			i++
			continue
		}
		c := s[i]
		switch {
		case c == '(':
			depth++
			i++
		case c == ')':
			if depth == 0 {
				return nil, false
			}
			depth--
			i++
		case sqlIdentByte(c):
			start := i
			for i < len(s) && kinds[i] == sqlCode && sqlIdentByte(s[i]) {
				i++
			}
			if depth == 0 {
				words = append(words, sqlWordAt{word: strings.ToUpper(s[start:i]), pos: start})
			}
		default:
			i++
		}
	}
	return words, depth == 0
}

// trimTrailingSemicolon drops one statement-ending semicolon in code, so the
// appended clause lands inside the statement.
func trimTrailingSemicolon(s string) string {
	kinds := make([]sqlByteKind, 0, len(s))
	_ = scanSQLBytes(s, func(_ byte, k sqlByteKind) error {
		kinds = append(kinds, k)
		return nil
	})
	if len(kinds) != len(s) {
		return s
	}
	for i := len(s) - 1; i >= 0; i-- {
		if kinds[i] != sqlCode || strings.IndexByte(" \t\n\r\f\v", s[i]) >= 0 {
			continue
		}
		if s[i] == ';' {
			return s[:i] + s[i+1:]
		}
		return s
	}
	return s
}

// ownerScopeAliasStop lists words that end a FROM table without an alias.
var ownerScopeAliasStop = map[string]bool{
	"WHERE": true, "ORDER": true, "GROUP": true, "LIMIT": true, "LEFT": true, "RIGHT": true,
	"INNER": true, "OUTER": true, "JOIN": true, "CROSS": true, "ON": true, "NATURAL": true,
	"FULL": true, "USING": true, "WINDOW": true, "HAVING": true, "INDEXED": true, "NOT": true,
	"UNION": true, "INTERSECT": true, "EXCEPT": true, "OFFSET": true,
}

// ownerScopeQualifier is the primary FROM table's alias (or name) to qualify
// user_id with, so a join can't make the column ambiguous.
func ownerScopeQualifier(afterFrom string) (string, bool) {
	toks := sqlTokenize(afterFrom)
	name := func(t sqlToken) (string, bool) {
		switch t.kind {
		case sqlTokWord:
			return t.text, true
		case sqlTokIdent:
			return quoteIdent(t.text), true
		}
		return "", false
	}
	if len(toks) == 0 {
		return "", false
	}
	table, ok := name(toks[0])
	if !ok {
		return "", false // a subquery or other non-table source
	}
	rest := toks[1:]
	if len(rest) >= 2 && rest[0].kind == sqlTokPunct && rest[0].text == "." {
		if t, ok := name(rest[1]); ok { // schema.table
			table, rest = t, rest[2:]
		}
	}
	if len(rest) == 0 {
		return table, true
	}
	if rest[0].kind == sqlTokWord && strings.EqualFold(rest[0].text, "AS") {
		if len(rest) > 1 {
			if alias, ok := name(rest[1]); ok {
				return alias, true
			}
		}
		return "", false
	}
	if alias, ok := name(rest[0]); ok && !(rest[0].kind == sqlTokWord && ownerScopeAliasStop[strings.ToUpper(rest[0].text)]) {
		return alias, true
	}
	return table, true
}

// injectOwnerScope limits a page query to the signed-in user's rows. userID
// is the server-side session id (never request input), so it is written as
// an integer literal: binding it would reorder placeholders that sit after
// the insertion point (e.g. LIMIT ?). With no session (hasUser false) the
// query is kept but matches nothing.
func injectOwnerScope(sqlText string, userID int64, hasUser bool) (string, error) {
	s := trimTrailingSemicolon(sqlText)
	words, ok := sqlTopLevelWords(s)
	if !ok || len(words) == 0 {
		return "", fmt.Errorf("scope=owner: can't parse the query")
	}
	if words[0].word != "SELECT" && words[0].word != "WITH" {
		return "", fmt.Errorf("scope=owner applies only to SELECT queries")
	}
	from := -1
	for i, w := range words {
		switch w.word {
		case "UNION", "INTERSECT", "EXCEPT":
			return "", fmt.Errorf("scope=owner can't scope a compound (%s) query; scope each part in its own query", w.word)
		case "FROM":
			if from < 0 {
				from = i
			}
		}
	}
	if from < 0 {
		return "", fmt.Errorf("scope=owner: the query has no FROM table")
	}
	// The clause goes before the first trailing clause after FROM.
	ins := len(s)
	where := -1
	for i := from + 1; i < len(words); i++ {
		w := words[i].word
		next := ""
		if i+1 < len(words) {
			next = words[i+1].word
		}
		if w == "WHERE" && where < 0 {
			where = i
			continue
		}
		if (w == "GROUP" || w == "ORDER") && next == "BY" || w == "WINDOW" || w == "LIMIT" {
			ins = words[i].pos
			break
		}
	}
	fromEnd := words[from].pos + len("FROM")
	qualifier, ok := ownerScopeQualifier(s[fromEnd:ins])
	if !ok {
		return "", fmt.Errorf("scope=owner: can't find the query's primary table")
	}
	pred := "0"
	if hasUser {
		pred = fmt.Sprintf("%s.user_id = %d", qualifier, userID)
	}
	if where >= 0 && words[where].pos < ins {
		body := words[where].pos + len("WHERE")
		return s[:body] + " (" + s[body:ins] + "\n) AND " + pred + " " + s[ins:], nil
	}
	return s[:ins] + "\nWHERE " + pred + " " + s[ins:], nil
}

// queryErrorHTML renders a failed <query> in place: full detail in dev mode,
// a generic message (details to the log) in production.
func queryErrorHTML(app *App, q QueryTag, err error) string {
	if app.DevMode {
		return fmt.Sprintf(`<div class="benmore-error"><strong>SQL Error</strong><pre>%s</pre><p>%s</p></div>`,
			html.EscapeString(q.SQL), html.EscapeString(err.Error()))
	}
	log.Printf("ERROR [query] %s: %s", q.SQL, err.Error())
	return `<div class="benmore-error">An error occurred loading this content.</div>`
}
