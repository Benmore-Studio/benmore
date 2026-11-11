//go:build !cli

package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Template values in page SQL (<query sql=...> and shorthand where=) are
// always bound as ? arguments, never spliced into the SQL text. Each
// placeholder is classified by where it sits in the statement, using the
// shared SQLite scanner (sql_scan.go):
//
//   - in code: `{{x}}` becomes ? (an empty value becomes NULL, as before);
//     a key that names no value at all stops the page (pageSQLValue), except
//     the ones an ordinary request may lack (pageSQLOptionalKey);
//     `:current_user` becomes ? bound to the session user (NULL without one);
//   - inside a '...' literal: the literal is split around it and rebuilt as a
//     concatenation, so `'%{{q}}%'` becomes `('%' || ? || '%')`;
//   - inside a comment: `{{x}}` is dropped;
//   - inside a quoted identifier: refused, since a value can't be bound as
//     an identifier.
//
// Placeholders are handled in statement order, so arguments always line up
// with their ? markers.

var pageSQLPlaceholderRe = regexp.MustCompile(`\{\{(\w[\w.]*)\}\}|:current_user\b`)

type pageSQLPlaceholder struct {
	start, end  int
	key         string // template key; "" for :current_user
	currentUser bool
}

func bindTemplateSQL(sqlText string, data map[string]any, session *Session) (string, []any, error) {
	if !strings.Contains(sqlText, "{{") && !strings.Contains(sqlText, ":current_user") {
		return sqlText, nil, nil
	}
	kinds := make([]sqlByteKind, 0, len(sqlText))
	_ = scanSQLBytes(sqlText, func(_ byte, k sqlByteKind) error {
		kinds = append(kinds, k)
		return nil
	})
	if len(kinds) != len(sqlText) {
		return "", nil, fmt.Errorf("query: can't classify the SQL text")
	}
	var marks []pageSQLPlaceholder
	for _, m := range pageSQLPlaceholderRe.FindAllStringSubmatchIndex(sqlText, -1) {
		p := pageSQLPlaceholder{start: m[0], end: m[1]}
		if m[2] >= 0 {
			p.key = sqlText[m[2]:m[3]]
		} else {
			p.currentUser = true
		}
		marks = append(marks, p)
	}
	value := func(key string) (string, error) {
		return pageSQLValue(data, key)
	}
	currentUser := func() any {
		if session == nil {
			return nil
		}
		return session.UserID
	}

	var out strings.Builder
	var args []any
	mi := 0
	for i := 0; i < len(sqlText); {
		if kinds[i] == sqlInSingleQuote {
			j := i
			for j < len(sqlText) && kinds[j] == sqlInSingleQuote {
				j++
			}
			var inLit []pageSQLPlaceholder
			for mi < len(marks) && marks[mi].start < j {
				if !marks[mi].currentUser { // :current_user inside a literal is text
					inLit = append(inLit, marks[mi])
				}
				mi++
			}
			lit := sqlText[i:j]
			if len(inLit) == 0 {
				out.WriteString(lit)
				i = j
				continue
			}
			if len(lit) < 2 || lit[0] != '\'' || lit[len(lit)-1] != '\'' {
				return "", nil, fmt.Errorf("query: unterminated string literal")
			}
			out.WriteString("(")
			prev := i + 1
			for _, p := range inLit {
				v, err := value(p.key)
				if err != nil {
					return "", nil, err
				}
				out.WriteString("'" + sqlText[prev:p.start] + "' || ? || ")
				args = append(args, v)
				prev = p.end
			}
			out.WriteString("'" + sqlText[prev:j-1] + "')")
			i = j
			continue
		}
		if mi < len(marks) && marks[mi].start == i {
			p := marks[mi]
			mi++
			switch kinds[i] {
			case sqlCode:
				if p.currentUser {
					out.WriteString("?")
					args = append(args, currentUser())
					break
				}
				v, err := value(p.key)
				if err != nil {
					return "", nil, err
				}
				if v == "" {
					out.WriteString("NULL")
				} else {
					out.WriteString("?")
					args = append(args, v)
				}
			case sqlInLineComment, sqlInBlockComment:
				if p.currentUser {
					out.WriteString(sqlText[p.start:p.end])
				}
			default:
				return "", nil, fmt.Errorf("query: a template value can't be used as a quoted identifier")
			}
			i = p.end
			continue
		}
		out.WriteByte(sqlText[i])
		i++
	}
	if mi != len(marks) {
		return "", nil, fmt.Errorf("query: can't place every template value")
	}
	return out.String(), args, nil
}

// pageSQLValue is the text a page SQL template key binds. A key that names no
// value in the render data is an error, so the page stops (a 500 with the
// request id, like a failed query) instead of binding NULL and rendering its
// empty state as if no rows matched: a misspelled key, `{{id}}` where the URL
// value is `{{param_id}}`, or a nested <query> reading the row of the tag
// around it (tags run innermost first, so that row doesn't exist yet). Keys
// an ordinary request may lack (pageSQLOptionalKey) bind NULL, or the empty
// string inside a quoted literal, as before.
func pageSQLValue(data map[string]any, key string) (string, error) {
	v, found := lookupValueFound(data, key)
	if !found {
		if pageSQLOptionalKey(data, key) {
			return "", nil
		}
		return "", fmt.Errorf("query: nothing binds {{%s}}. Page SQL can read URL query values as {{param_<name>}} (?id=7 is {{param_id}}), the viewer ({{user_id}}, {{user_email}}, {{user_group_id}}, {{user.<column>}}, or :current_user) and the results of <query> tags that have already run; a nested <query> runs before the tag around it, so it can't read that tag's rows (use a JOIN or subquery)", key)
	}
	if v == nil {
		return "", nil
	}
	return valueText(v), nil
}

// pageSQLOptionalKey reports whether a page SQL template key may be absent
// from the render data and bind NULL: a URL query value ({{param_<name>}}, an
// optional filter when the request leaves it out), the viewer's identity keys
// (absent for an anonymous viewer, or a viewer in no tenant), and materialized
// aggregates (absent until computed). gotmpl `queries:` bind :param_<name> and
// the identity names the same way.
func pageSQLOptionalKey(data map[string]any, key string) bool {
	if name, ok := strings.CutPrefix(key, "param_"); ok && name != "" {
		return true
	}
	switch key {
	case "user_id", "user_email", "user_role", "user_roles", "user_group_id", "user_app_role", "logged_in", "notification_count":
		return true
	}
	if strings.HasPrefix(key, "aggregate.") {
		return true
	}
	if strings.HasPrefix(key, "user.") {
		// Every column of a signed-in viewer is present; only an anonymous
		// viewer has no user map. A column the table doesn't have is an
		// error for a signed-in viewer.
		_, signedIn := data["user"].(map[string]any)
		return !signedIn
	}
	return false
}

// lookupValueFound resolves key like lookupValue (an exact key first, then
// dot notation through maps and row lists) and also reports whether the key
// names a value at all. A key that is present with a nil value is found.
func lookupValueFound(data map[string]any, key string) (any, bool) {
	if data == nil {
		return nil, false
	}
	if val, ok := data[key]; ok {
		return val, true
	}
	head, rest, ok := strings.Cut(key, ".")
	if !ok {
		return nil, false
	}
	switch v := data[head].(type) {
	case map[string]any:
		return lookupValueFound(v, rest)
	case []map[string]any:
		idxText, tail, hasTail := strings.Cut(rest, ".")
		idx, err := strconv.Atoi(idxText)
		if err != nil || idx < 0 || idx >= len(v) {
			return nil, false
		}
		if !hasTail {
			return v[idx], true
		}
		return lookupValueFound(v[idx], tail)
	}
	return nil, false
}

// resolveAttrVars fills {{var}} references in a shorthand attribute that the
// query builder validates against the schema or parses as a number (pick,
// hide, owned, sort, limit, offset). where= goes through bindTemplateSQL.
func resolveAttrVars(s string, data map[string]any) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return pageSQLPlaceholderRe.ReplaceAllStringFunc(s, func(match string) string {
		if !strings.HasPrefix(match, "{{") {
			return match
		}
		return valueText(lookupValue(data, match[2:len(match)-2]))
	})
}
