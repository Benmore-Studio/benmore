//go:build !cli

package main

import (
	"fmt"
	"strings"
)

// sealNativeCiphertextLiterals treats encryption-looking API values as ordinary
// plaintext. Storage triggers must remain idempotent for their own updates and
// key rotation, but authentic ciphertext supplied by a client is not trusted
// storage. Run after validation/before-hooks so those gates see the input.
//
// Ordinary inputs retain the existing trigger path. For a prefix literal we
// also supply the framework-owned blind value: the trigger deliberately skips
// already sealed storage, so it cannot derive the original literal itself.
func sealNativeCiphertextLiterals(q mutationQuerier, app *App, table string, fields []string, values []any) ([]string, []any, error) {
	if app == nil || app.Encrypted == nil {
		return fields, values, nil
	}
	if len(fields) != len(values) {
		return nil, nil, fmt.Errorf("encrypted write fields and values differ")
	}
	var key []byte
	var blindKey []byte
	var copied bool
	for i, name := range fields {
		input, ok := values[i].(string)
		if !ok || !cryptoIsEncrypted(input) {
			continue
		}
		var def *EncryptedFieldDef
		sourceTable := table
		for t, defs := range app.Encrypted.Fields {
			if !strings.EqualFold(t, table) {
				continue
			}
			for j := range defs {
				if strings.EqualFold(defs[j].Column, name) {
					copy := defs[j]
					def = &copy
					sourceTable = t
					break
				}
			}
		}
		if def == nil {
			continue
		}
		if !copied {
			fields = append([]string(nil), fields...)
			values = append([]any(nil), values...)
			copied = true
		}
		if key == nil {
			var err error
			if bound, ok := q.(appMCPContextTx); ok && bound.private {
				key, err = cryptoKeyForQuerierMainChecked(q)
			} else {
				key, err = cryptoKeyForQuerierChecked(q)
			}
			if err != nil {
				return nil, nil, err
			}
			if len(key) == 0 {
				return nil, nil, fmt.Errorf("encrypted input requires the owning database key")
			}
		}
		sealed, err := fieldEncryptCtx(key, sourceTable, def.Column, input)
		if err != nil {
			return nil, nil, err
		}
		values[i] = sealed
		if def.BlindIndex {
			if blindKey == nil {
				blindKey, err = DeriveBlindIndexKey(key)
				if err != nil {
					return nil, nil, err
				}
			}
			fields = append(fields, def.Column+blindColSuffix)
			values = append(values, BlindIndexHMACWithKey(blindKey, input))
		}
	}
	return fields, values, nil
}
