//go:build !cli

package main

import "strings"

// Response column visibility - the ONE predicate deciding which columns of an
// app table an API response may carry. Auto-CRUD list/read/cursor/as_of,
// ?fields= projection, ?include= expansion, create read-back, version
// snapshots, /api/_query and the DSAR export all go through it, so a secret
// that is stripped from one surface cannot ride out through another. Before
// this, a `stripe_secret` or `webhook_token` column was dropped from create
// responses and ?fields= but returned verbatim by every SELECT * read.
//
// Hidden:
//   - a blind-index sibling (`<col>_blind` next to its `<col>`): a
//     deterministic HMAC that links equal plaintexts across rows;
//   - a credential-shaped TEXT column (appSecretColumn) - password, salt,
//     session and MFA bookkeeping, credential hashes (`*_hash` whose name
//     names a credential: `password_hash`, `otp_code_hash`, not
//     `content_hash`), `*_secret`, `*_token`,
//     `*_password`, `*_pin`
//     and credential keys (`api_key`, `private_key`, `secret_key`,
//     `access_key`, `signing_key`, also as suffixes) - except names starting
//     `public_` / `publishable_`. Numeric and boolean columns (`secret_id`,
//     `wants_secret`) are never secrets, and a bare `*_key` is usually a
//     lookup key (`playbook_key`, `sort_key`), so neither is hidden. The
//     framework's own _benmore_users keeps the stricter isSensitiveUserColumn.
//
// A column declared in encrypted.yaml WITH unmask roles is not hidden by
// name: the developer stated its visibility explicitly, and
// MaskEncryptedFields enforces it per role. Declared without unmask roles it
// is decrypted for every reader, which states nothing about who may see it,
// so a secret-shaped name keeps it hidden (encrypting `api_secret` must not
// turn it from hidden into returned). Everything else deliberately returned
// (an API key shown once, a share token) belongs in a flow that selects it by
// name.
func apiHiddenColumn(app *App, table, column string) bool {
	if base, ok := strings.CutSuffix(column, blindColSuffix); ok && base != "" {
		if app != nil && (BlindIndexColumnsForTable(app.Encrypted, table)[base] || hasColumn(app, table, base)) {
			return true
		}
	}
	if app != nil && app.Encrypted != nil {
		for _, def := range app.Encrypted.Fields[table] {
			if def.Column == column && len(def.Roles) > 0 {
				return false
			}
		}
	}
	if table == "_benmore_users" {
		return isSensitiveUserColumn(column)
	}
	return appSecretColumn(app, table, column)
}

// appSecretColumn reports whether an app table column is secret-shaped by
// name and holds text.
func appSecretColumn(app *App, table, column string) bool {
	c := strings.ToLower(column)
	if strings.HasPrefix(c, "public_") || strings.HasPrefix(c, "publishable_") {
		return false
	}
	if app != nil {
		for _, t := range app.Tables {
			if t.Name != table {
				continue
			}
			for _, col := range t.Columns {
				if strings.EqualFold(col.Name, column) && !textColumnType(col.Type) {
					return false
				}
			}
		}
	}
	switch c {
	case "password", "password_hash", "salt", "session_id", "csrf_token", "totp_secret",
		"backup_codes", "recovery_codes", "secret", "token",
		"api_key", "private_key", "secret_key", "access_key", "signing_key":
		return true
	}
	if strings.HasPrefix(c, "mfa_") {
		return true
	}
	if stem, ok := strings.CutSuffix(c, "_hash"); ok {
		return credentialHashStem(stem)
	}
	for _, suf := range []string{"_secret", "_token", "_pin",
		"_api_key", "_private_key", "_secret_key", "_access_key", "_signing_key",
		"_password"} {
		if strings.HasSuffix(c, suf) {
			return true
		}
	}
	return false
}

// credentialHashStem reports whether the name before "_hash" says the column
// hashes a credential (password_hash, otp_code_hash). A checksum of content
// (content_hash, payload_hash, commit_hash) is ordinary data.
func credentialHashStem(stem string) bool {
	for _, word := range strings.Split(stem, "_") {
		switch word {
		case "password", "passwd", "pass", "passcode", "pin", "code", "otp", "token", "secret",
			"key", "session", "reset", "recovery", "backup", "verify", "verification",
			"auth", "credential", "credentials", "invite", "magic", "login", "api", "mfa", "totp":
			return true
		}
	}
	return false
}

// textColumnType reports whether a declared SQLite column type can hold a
// string secret (TEXT affinity, or undeclared/BLOB).
func textColumnType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	if t == "" {
		return true
	}
	for _, n := range []string{"INT", "REAL", "FLOA", "DOUB", "BOOL", "NUMERIC", "DECIMAL", "DATE", "TIME"} {
		if strings.Contains(t, n) {
			return false
		}
	}
	return true
}

// hiddenEventKey reports whether a key of a mutation event row (a column, or
// the `old_<col>` change delta update events carry) names a hidden column.
// Audit values and webhook payloads are built from these rows.
func hiddenEventKey(app *App, table, key string) bool {
	if apiHiddenColumn(app, table, key) {
		return true
	}
	base, ok := strings.CutPrefix(key, "old_")
	return ok && apiHiddenColumn(app, table, base)
}

// stripHiddenColumns removes every apiHiddenColumn key from rows in place.
// Keys holding ?include= payloads (a related row or row slice attached by
// ResolveIncludes, already sanitized under its own table) are relation names,
// not columns of this table, and are left alone - a scanned column value is
// always a scalar.
func stripHiddenColumns(app *App, table string, rows []map[string]any) {
	for _, row := range rows {
		for col, v := range row {
			switch v.(type) {
			case map[string]any, []map[string]any:
				continue
			}
			if apiHiddenColumn(app, table, col) {
				delete(row, col)
			}
		}
	}
}

// sanitizeResponseRows is the response-side choke point for app-table rows:
// role-based masking of encrypted columns, then the hidden-column strip.
// Masking runs first because owner unmask reads the row's user_id.
func sanitizeResponseRows(app *App, table string, rows []map[string]any, session *Session) {
	if app == nil {
		return
	}
	MaskEncryptedFields(app, table, rows, session)
	stripHiddenColumns(app, table, rows)
}
