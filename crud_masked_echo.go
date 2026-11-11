//go:build !cli

package main

// Masked encrypted values sent back on update.
//
// A caller outside an encrypted field's unmask roles reads the constant mask
// (encryptedFieldMask) in place of the value. The ordinary edit form reads a
// row, changes a field and sends the whole row back, so the mask came back too
// and was stored as the value: the real value was gone, and on an INTEGER,
// REAL or BOOLEAN column the whole update failed with 422 (`must be an
// integer`). On every update through the canonical pipeline (txUpdateMode:
// PATCH, singleton upsert, batch update, /api/_transaction, version revert and
// the connector's native table update) a submitted value that is exactly the
// mask this caller reads for that column on that row is an unchanged echo: it
// is dropped from the write and the HTTP routes name it in X-Ignored-Fields.
//
// The decision uses only the caller's own masking of the row - the same
// encryptedFieldAccessFor the read path uses, evaluated on the row's owner and
// tenant columns - never the stored value, so the answer cannot confirm a
// guessed plaintext. A caller who reads the column unmasked writes the literal
// text as a value, as before. The decrypt-failure placeholder (decryptFailMask)
// is never a value of an encrypted field, so it is dropped for every caller.

import "slices"

// maskedEchoFields returns, sorted, the submitted keys of data that are an
// echo of what session reads for an encrypted column of row: the constant mask
// on a column it may not unmask on this row, or the decrypt-failure
// placeholder on any encrypted column. row is the current (pre-update) row.
func maskedEchoFields(q rowQuerier, app *App, session *Session, table string, row, data map[string]any) []string {
	if app == nil || app.Encrypted == nil || row == nil || len(data) == 0 {
		return nil
	}
	defs := app.Encrypted.Fields[table]
	if len(defs) == 0 {
		return nil
	}
	var echoed []string
	for key, value := range data {
		text, ok := value.(string)
		if !ok || (text != encryptedFieldMask && text != decryptFailMask) {
			continue
		}
		for _, def := range defs {
			if sqliteIdentifierFold(def.Column) != sqliteIdentifierFold(key) {
				continue
			}
			if text == decryptFailMask || !encryptedFieldAccessFor(app, q, table, def, session).allowsRow(row) {
				echoed = append(echoed, key)
			}
			break
		}
	}
	slices.Sort(echoed)
	return echoed
}

// dropMaskedEchoes returns data without its masked echoes (maskedEchoFields)
// and the names it dropped. data itself is not modified.
func dropMaskedEchoes(q rowQuerier, app *App, session *Session, table string, row, data map[string]any) (map[string]any, []string) {
	echoed := maskedEchoFields(q, app, session, table, row, data)
	if len(echoed) == 0 {
		return data, nil
	}
	kept := make(map[string]any, len(data)-len(echoed))
	for k, v := range data {
		if !slices.Contains(echoed, k) {
			kept[k] = v
		}
	}
	return kept, echoed
}
