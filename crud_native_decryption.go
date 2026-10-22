//go:build !cli

package main

import (
	"context"
	"strings"
)

// nativeRowDecryptor is only for framework-built direct-column projections
// whose source table is known independently of the result labels and values.
// History passes its source table: its fields retain source-table AAD.
// Empty table means no physical encrypted columns (e.g. aggregate results).
// Never use this to infer the provenance of arbitrary authored SQL or aliases.
func nativeRowDecryptor(app *App, table string) rowDecryptFunc {
	var defs []EncryptedFieldDef
	if app != nil && app.Encrypted != nil && table != "" {
		for source, fields := range app.Encrypted.Fields {
			if strings.EqualFold(source, table) {
				table, defs = source, fields
				break
			}
		}
	}
	return func(row map[string]any, key []byte) {
		for _, def := range defs {
			for column, value := range row {
				if !strings.EqualFold(column, def.Column) {
					continue
				}
				text, ok := value.(string)
				if !ok || !cryptoIsEncrypted(text) {
					continue
				}
				// The trusted projection, not the ciphertext's embedded context,
				// determines which source is allowed. v1 has no AAD and retains
				// compatibility; v2 must authenticate this exact table and column.
				plain, sealed, err := appEncryptionRotationOpen(text, key, table, def.Column)
				if err == nil && sealed {
					row[column] = plain
				} else {
					row[column] = decryptFailMask
					logDecryptFailureThrottled(column)
				}
			}
		}
	}
}

func queryNativeRowsWith(q mutationQuerier, app *App, table, query string, args ...any) ([]map[string]any, error) {
	return queryNativeRowsContext(context.Background(), q, app, table, query, args...)
}

func queryNativeRowsContext(ctx context.Context, q mutationQuerier, app *App, table, query string, args ...any) ([]map[string]any, error) {
	var key []byte
	if bound, ok := q.(appMCPContextTx); ok && bound.private {
		var err error
		key, err = cryptoKeyForQuerierMainChecked(q)
		if err != nil {
			return nil, err
		}
	} else {
		key = cryptoKeyForQuerier(q)
	}
	return queryRowsWithKeyContextDecrypt(ctx, q, key, nativeRowDecryptor(app, table), query, args...)
}
