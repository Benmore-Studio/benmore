//go:build !cli

package main

// ExtractTableRefs pulls table names out of a SQL string. Used by the
// cross-file orphan-ref validator (flows.yaml inline queries) and by
// any future check that wants to know "what tables does this SQL
// touch."
//
// The old approach was a flat regex on `(FROM|INTO|UPDATE|JOIN) <name>`,
// which missed:
//   - CTEs: `WITH active AS (SELECT ...) SELECT * FROM active JOIN users`
//     would flag `active` as an orphan.
//   - Quoted identifiers: `FROM "Note"` or `` FROM `Note` ``.
//   - Subqueries: `SELECT * FROM (SELECT * FROM notes) AS t` should
//     pick up `notes`, not `t`.
//   - Schema-qualified names: `FROM main.notes` should yield `notes`.
//
// The new tokenizer walks the SQL character-by-character, tracks
// string/comment state, identifies the keywords that introduce a
// table reference, and reads the following identifier. CTE names
// declared via `WITH x AS (...)` are collected and excluded from
// the final ref set.

import (
	"strings"
	"unicode"
)

// ExtractTableRefs returns the deduplicated, lowercased set of table
// names referenced in the SQL. CTEs are excluded.
func ExtractTableRefs(sql string) []string {
	tokens := tokenizeSQL(sql)

	cteNames := map[string]bool{}
	refs := map[string]bool{}

	// First pass: collect CTE names from `WITH <name> AS (...)` /
	// `WITH RECURSIVE <name> AS (...)` / `, <name> AS (...)` chains.
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		upper := strings.ToUpper(t)
		if upper == "WITH" {
			// Walk forward picking up name AS pairs until the
			// SELECT/INSERT/etc that begins the actual statement.
			j := i + 1
			if j < len(tokens) && strings.ToUpper(tokens[j]) == "RECURSIVE" {
				j++
			}
			for j < len(tokens) {
				if !isIdentifierToken(tokens[j]) {
					break
				}
				name := unquoteIdent(tokens[j])
				// The next token should be "AS"; if it is, the one
				// after that is a "(" which opens the CTE body.
				if j+1 >= len(tokens) || strings.ToUpper(tokens[j+1]) != "AS" {
					break
				}
				cteNames[strings.ToLower(name)] = true
				j += 2
				// Skip the parenthesized body.
				if j < len(tokens) && tokens[j] == "(" {
					depth := 1
					j++
					for j < len(tokens) && depth > 0 {
						switch tokens[j] {
						case "(":
							depth++
						case ")":
							depth--
						}
						j++
					}
				}
				// After the body we expect either a comma (more CTEs
				// to come) or the main statement.
				if j < len(tokens) && tokens[j] == "," {
					j++
					continue
				}
				break
			}
			i = j - 1
		}
	}

	// Second pass: every FROM/INTO/UPDATE/JOIN/TABLE keyword
	// introduces a table ref. We accept a single identifier after,
	// possibly schema-qualified (`main.notes`). Subqueries `(SELECT ...)`
	// are skipped — they're not a table name.
	tableKeywords := map[string]bool{
		"FROM": true, "INTO": true, "UPDATE": true, "JOIN": true,
		"TABLE": true, // CREATE/DROP/ALTER TABLE
	}
	for i := 0; i < len(tokens); i++ {
		upper := strings.ToUpper(tokens[i])
		if !tableKeywords[upper] {
			continue
		}
		// Look at the next non-whitespace token. We've already
		// filtered whitespace out at tokenize time, so [i+1] works.
		if i+1 >= len(tokens) {
			continue
		}
		next := tokens[i+1]
		// Subquery after FROM/JOIN — skip.
		if next == "(" {
			continue
		}
		// Some FROMs are followed by a temporary/virtual marker
		// (e.g. `INSERT INTO OR REPLACE table`); skip if not an ident.
		if !isIdentifierToken(next) {
			continue
		}
		name := unquoteIdent(next)
		// Schema-qualified: `main.notes` — take the part after the dot.
		if i+2 < len(tokens) && tokens[i+2] == "." && i+3 < len(tokens) && isIdentifierToken(tokens[i+3]) {
			name = unquoteIdent(tokens[i+3])
		}
		nameLower := strings.ToLower(name)
		if cteNames[nameLower] {
			continue
		}
		refs[nameLower] = true
	}

	var out []string
	for r := range refs {
		out = append(out, r)
	}
	return out
}

// tokenizeSQL is a lightweight SQL tokenizer. Output tokens include
// identifiers, keywords, punctuation, and quoted strings. Whitespace
// and `--`/`/* */` comments are dropped. The output is sufficient
// for the table-ref walk above; full SQL parsing (expressions,
// operator precedence) is out of scope.
func tokenizeSQL(sql string) []string {
	var tokens []string
	r := []rune(sql)
	i := 0
	for i < len(r) {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '-' && i+1 < len(r) && r[i+1] == '-':
			// Line comment.
			for i < len(r) && r[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(r) && r[i+1] == '*':
			// Block comment.
			i += 2
			for i+1 < len(r) && !(r[i] == '*' && r[i+1] == '/') {
				i++
			}
			i += 2
		case c == '\'':
			// String literal — gobble.
			start := i
			i++
			for i < len(r) && r[i] != '\'' {
				if r[i] == '\\' && i+1 < len(r) {
					i++
				}
				i++
			}
			i++
			tokens = append(tokens, string(r[start:i]))
		case c == '"' || c == '`':
			// Quoted identifier — preserved with quotes so the
			// caller can recognize it as identifier-shaped.
			quote := c
			start := i
			i++
			for i < len(r) && r[i] != quote {
				i++
			}
			i++
			tokens = append(tokens, string(r[start:i]))
		case c == '(' || c == ')' || c == ',' || c == ';' || c == '.':
			tokens = append(tokens, string(c))
			i++
		case unicode.IsLetter(c) || c == '_':
			// Identifier or keyword.
			start := i
			for i < len(r) && (unicode.IsLetter(r[i]) || unicode.IsDigit(r[i]) || r[i] == '_') {
				i++
			}
			tokens = append(tokens, string(r[start:i]))
		case unicode.IsDigit(c):
			start := i
			for i < len(r) && (unicode.IsDigit(r[i]) || r[i] == '.') {
				i++
			}
			tokens = append(tokens, string(r[start:i]))
		default:
			// Unknown punctuation — emit as its own token so the
			// walk doesn't get stuck.
			tokens = append(tokens, string(c))
			i++
		}
	}
	return tokens
}

// isIdentifierToken returns true if the token looks like a SQL
// identifier (bare or quoted). Excludes keywords, but the caller
// usually doesn't care because the lookup context already requires
// "the thing after FROM" to be an identifier.
func isIdentifierToken(tok string) bool {
	if tok == "" {
		return false
	}
	if tok[0] == '"' || tok[0] == '`' {
		return true
	}
	c := tok[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

// unquoteIdent strips surrounding double-quotes or backticks from an
// identifier token.
func unquoteIdent(tok string) string {
	if len(tok) >= 2 && (tok[0] == '"' || tok[0] == '`') && tok[len(tok)-1] == tok[0] {
		return tok[1 : len(tok)-1]
	}
	return tok
}
