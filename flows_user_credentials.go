//go:build !cli

package main

import "strings"

// stripUserCredentialColumns removes the framework's credential columns of
// _benmore_users (password_hash, totp_secret, backup_codes, mfa_*, ...) from
// the rows a flow's SQL step returns when the query reads that table. A
// public flow written `SELECT * FROM _benmore_users` answered every user's
// password hash, TOTP secret and backup codes (live on 2.7.303, no warning
// at push). No flow can use them as values - flows cannot verify bcrypt or
// TOTP - so dropping them breaks nothing that worked; the query itself may
// still read them (`CASE WHEN totp_secret != ” ...`), and a column selected
// under another name is the author's explicit choice.
func stripUserCredentialColumns(app *App, query string, rows []map[string]any) {
	if len(rows) == 0 || !strings.Contains(strings.ToLower(query), "_benmore_users") || !sqlReadsUserTable(query) {
		return
	}
	credential := userCredentialColumnSet(app)
	for _, row := range rows {
		for col := range row {
			if credential[strings.ToLower(col)] {
				delete(row, col)
			}
		}
	}
}

// sqlReadsUserTable reports a query naming _benmore_users outside comments.
// A string literal counts: SQLite reads `FROM '_benmore_users'` as the table,
// and a literal used as a value only drops credential-named columns.
func sqlReadsUserTable(query string) bool {
	for _, tok := range sqlTokenize(query) {
		if (tok.kind == sqlTokWord || tok.kind == sqlTokIdent || tok.kind == sqlTokLiteral) && strings.EqualFold(strings.TrimPrefix(strings.ToLower(tok.text), "main."), "_benmore_users") {
			return true
		}
	}
	return false
}

// userCredentialColumnSet is the set of _benmore_users columns the auth
// responses never expose (isSensitiveUserColumn), from the app's actual
// table, so an app column of another table is never caught by the name
// patterns alone.
func userCredentialColumnSet(app *App) map[string]bool {
	set := map[string]bool{}
	for _, name := range []string{"password_hash", "totp_secret", "backup_codes", "mfa_backup_codes", "recovery_codes"} {
		set[name] = true
	}
	if app == nil || app.DB == nil {
		return set
	}
	if cols, err := GetTableColumns(app.DB, "_benmore_users"); err == nil {
		for _, c := range cols {
			if isSensitiveUserColumn(c.Name) {
				set[strings.ToLower(c.Name)] = true
			}
		}
	}
	return set
}
