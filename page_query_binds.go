//go:build !cli

package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Template values in page SQL (<query sql=...> and shorthand where=) are
// always bound as ? arguments, never spliced into the SQL text. Each
// placeholder is classified by where it sits in the statement, using the
// shared SQLite scanner (sql_scan.go):
//
//   - in code: `{{x}}` becomes ? (an empty value becomes NULL, as before);
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
	value := func(key string) string {
		return fmt.Sprintf("%v", lookupValue(data, key))
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
				out.WriteString("'" + sqlText[prev:p.start] + "' || ? || ")
				args = append(args, value(p.key))
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
				} else if v := value(p.key); v == "" {
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
		return fmt.Sprintf("%v", lookupValue(data, match[2:len(match)-2]))
	})
}
