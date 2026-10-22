//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	appWebhookJobPayloadLimit = 4 << 20
	appWebhookJobDepthLimit   = 64
	appWebhookJobNodeLimit    = 100000
	appWebhookJobRowLimit     = 10000
	appWebhookJobBytesLimit   = 64 << 20
)

type appWebhookJobSecretRotation struct {
	id                 int64
	originalPayload    string
	replacementPayload string
}

type appWebhookJSONScan struct {
	nodes                  int
	secretStart, secretEnd int
	secretFound            bool
	webhook                map[string]json.RawMessage
	rootRow                json.RawMessage
	rootRowFound           bool
}

func collectAppWebhookJobSecretRotations(ctx context.Context, tx *sql.Tx, oldKey, newKey []byte) ([]appWebhookJobSecretRotation, error) {
	if err := appWebhookJobRotationInputs(ctx, tx, oldKey, newKey); err != nil {
		return nil, err
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return nil, errors.New("webhook rotation requires a clean main connection")
	}
	present, err := validateAppWebhookJobsTable(ctx, tx)
	if err != nil || !present {
		return nil, err
	}
	rs, err := tx.QueryContext(ctx, "SELECT id,typeof(id),typeof(job_type),job_type,typeof(payload),length(CAST(payload AS BLOB)) FROM main._benmore_jobs WHERE job_type COLLATE BINARY='webhook_subscription' COLLATE BINARY ORDER BY id")
	if err != nil {
		return nil, errors.New("cannot read retained webhook jobs")
	}
	defer rs.Close()
	type inventoryRow struct {
		id   int64
		size int64
	}
	inventory := make([]inventoryRow, 0)
	var total int64
	for rs.Next() {
		var id int64
		var idKind, jk, job, pk string
		var size sql.NullInt64
		if err := rs.Scan(&id, &idKind, &jk, &job, &pk, &size); err != nil {
			return nil, errors.New("invalid retained webhook job row")
		}
		if id < 1 || idKind != "integer" || jk != "text" || job != "webhook_subscription" || pk != "text" || !size.Valid || size.Int64 < 0 {
			return nil, errors.New("invalid retained webhook job row")
		}
		if len(inventory) >= appWebhookJobRowLimit {
			return nil, errors.New("retained webhook inventory exceeds supported bound")
		}
		total += size.Int64
		if size.Int64 > appWebhookJobPayloadLimit || total > appWebhookJobBytesLimit {
			return nil, errors.New("retained webhook inventory exceeds supported bound")
		}
		inventory = append(inventory, inventoryRow{id: id, size: size.Int64})
	}
	if err := rs.Err(); err != nil {
		return nil, errors.New("cannot read retained webhook jobs")
	}
	if err := rs.Close(); err != nil {
		return nil, errors.New("cannot close retained webhook inventory")
	}
	out := make([]appWebhookJobSecretRotation, 0)
	for _, item := range inventory {
		var payload string
		var payloadKind string
		var actualSize int64
		if err := tx.QueryRowContext(ctx, "SELECT typeof(payload),length(CAST(payload AS BLOB)),payload FROM main._benmore_jobs WHERE id=? AND job_type COLLATE BINARY='webhook_subscription' COLLATE BINARY", item.id).Scan(&payloadKind, &actualSize, &payload); err != nil || payloadKind != "text" || actualSize != item.size {
			return nil, errors.New("retained webhook job inventory changed")
		}
		replacement, changed, err := appWebhookJobResealPayload(payload, oldKey, newKey)
		if err != nil {
			return nil, errors.New("retained webhook payload is unsupported")
		}
		if changed {
			out = append(out, appWebhookJobSecretRotation{id: item.id, originalPayload: payload, replacementPayload: replacement})
		}
	}
	return out, nil
}

func applyAppWebhookJobSecretRotations(ctx context.Context, tx *sql.Tx, rows []appWebhookJobSecretRotation) (int, error) {
	if ctx == nil || tx == nil {
		return 0, errors.New("invalid webhook rotation transaction")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return 0, errors.New("webhook rotation requires a clean main connection")
	}
	present, err := validateAppWebhookJobsTable(ctx, tx)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if !present {
		return 0, errors.New("webhook jobs table unavailable")
	}
	n := 0
	for i, row := range rows {
		if row.id < 1 || (i > 0 && row.id <= rows[i-1].id) {
			return 0, errors.New("webhook rotation rows must have unique ascending ids")
		}
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := casAppWebhookJobSecretRotation(ctx, tx, row); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

func casAppWebhookJobSecretRotation(ctx context.Context, tx *sql.Tx, row appWebhookJobSecretRotation) error {
	if ctx == nil || tx == nil || row.id < 1 || row.originalPayload == row.replacementPayload {
		return errors.New("invalid webhook rotation row")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, "UPDATE main._benmore_jobs SET payload=? WHERE id=? AND job_type COLLATE BINARY='webhook_subscription' COLLATE BINARY AND typeof(payload)='text' AND payload COLLATE BINARY IS ? COLLATE BINARY", row.replacementPayload, row.id, row.originalPayload)
	if err != nil {
		return errors.New("webhook rotation compare-and-swap failed")
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("webhook rotation source image changed")
	}
	return nil
}

func appWebhookJobRotationInputs(ctx context.Context, tx *sql.Tx, oldKey, newKey []byte) error {
	if ctx == nil || tx == nil || len(oldKey) != 32 || len(newKey) != 32 || bytes.Equal(oldKey, newKey) {
		return errors.New("invalid webhook rotation inputs")
	}
	return ctx.Err()
}

func validateAppWebhookJobsTable(ctx context.Context, tx *sql.Tx) (bool, error) {
	if ctx == nil || tx == nil {
		return false, errors.New("invalid webhook rotation transaction")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var name, kind string
	err := tx.QueryRowContext(ctx, "SELECT name,type FROM main.sqlite_schema WHERE name='_benmore_jobs' COLLATE NOCASE").Scan(&name, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil || kind != "table" {
		return false, errors.New("incompatible webhook jobs schema")
	}
	var typ string
	var wr int
	if err := tx.QueryRowContext(ctx, "SELECT type,wr FROM pragma_table_list WHERE schema='main' AND name=? COLLATE NOCASE", name).Scan(&typ, &wr); err != nil || typ != "table" || wr != 0 {
		return false, errors.New("incompatible webhook jobs schema")
	}
	rs, err := tx.QueryContext(ctx, "PRAGMA main.table_xinfo('_benmore_jobs')")
	if err != nil {
		return false, errors.New("cannot inspect webhook jobs schema")
	}
	type col struct {
		typ                 string
		notnull, pk, hidden int
	}
	cols := map[string]col{}
	pks := 0
	for rs.Next() {
		var cid, nn, pk, hidden int
		var name, decl string
		var dflt any
		if err := rs.Scan(&cid, &name, &decl, &nn, &dflt, &pk, &hidden); err != nil {
			rs.Close()
			return false, errors.New("cannot inspect webhook jobs schema")
		}
		if hidden != 0 {
			rs.Close()
			return false, errors.New("unsupported generated job column")
		}
		cols[name] = col{strings.ToUpper(strings.TrimSpace(decl)), nn, pk, hidden}
		if pk != 0 {
			pks++
		}
	}
	if err := rs.Err(); err != nil {
		rs.Close()
		return false, errors.New("cannot inspect webhook jobs schema")
	}
	if err := rs.Close(); err != nil {
		return false, errors.New("cannot inspect webhook jobs schema")
	}
	id, i := cols["id"]
	jt, j := cols["job_type"]
	payload, p := cols["payload"]
	if !i || id.typ != "INTEGER" || id.pk != 1 || pks != 1 || !j || jt.typ != "TEXT" || jt.notnull != 1 || !p || payload.typ != "TEXT" || payload.notnull != 0 {
		return false, errors.New("incompatible webhook jobs schema")
	}
	var triggers int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type='trigger'").Scan(&triggers); err != nil || triggers != 0 {
		return false, errors.New("webhook rotation requires trigger-free main schema")
	}
	tables, err := tx.QueryContext(ctx, "SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name")
	if err != nil {
		return false, errors.New("cannot inspect webhook job relationships")
	}
	tableNames := make([]string, 0)
	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			tables.Close()
			return false, errors.New("cannot inspect webhook job relationships")
		}
		tableNames = append(tableNames, name)
	}
	if err := tables.Err(); err != nil {
		tables.Close()
		return false, errors.New("cannot inspect webhook job relationships")
	}
	if err := tables.Close(); err != nil {
		return false, errors.New("cannot inspect webhook job relationships")
	}
	for _, name := range tableNames {
		fr, err := tx.QueryContext(ctx, "PRAGMA main.foreign_key_list("+quoteIdent(name)+")")
		if err != nil {
			return false, errors.New("cannot inspect webhook job relationships")
		}
		for fr.Next() {
			var id, seq int
			var table, from, onupdate, ondelete, match string
			var to sql.NullString
			if err := fr.Scan(&id, &seq, &table, &from, &to, &onupdate, &ondelete, &match); err != nil {
				fr.Close()
				return false, errors.New("cannot inspect webhook job relationships")
			}
			if (strings.EqualFold(name, "_benmore_jobs") && strings.EqualFold(from, "payload")) || (strings.EqualFold(table, "_benmore_jobs") && to.Valid && strings.EqualFold(to.String, "payload")) {
				fr.Close()
				return false, errors.New("unsupported webhook payload relationship")
			}
		}
		if err := fr.Err(); err != nil {
			fr.Close()
			return false, errors.New("cannot inspect webhook job relationships")
		}
		if err := fr.Close(); err != nil {
			return false, errors.New("cannot inspect webhook job relationships")
		}
	}
	return true, nil
}

func appWebhookJobResealPayload(payload string, oldKey, newKey []byte) (string, bool, error) {
	if len(payload) > appWebhookJobPayloadLimit || !utf8.ValidString(payload) || !appWebhookValidSurrogates(payload) {
		return "", false, errors.New("invalid payload")
	}
	d := json.NewDecoder(strings.NewReader(payload))
	d.UseNumber()
	var raw json.RawMessage
	if err := d.Decode(&raw); err != nil || len(raw) == 0 || raw[0] != '{' {
		return "", false, errors.New("payload must be one object")
	}
	rawStart := int(d.InputOffset()) - len(raw)
	if rawStart < 0 {
		return "", false, errors.New("invalid payload bounds")
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", false, errors.New("trailing json")
	}
	s := appWebhookJSONScan{secretStart: -1, secretEnd: -1}
	if err := appWebhookScanValue(raw, rawStart, 0, &s); err != nil {
		return "", false, err
	}
	if s.webhook == nil {
		return "", false, errors.New("missing webhook object")
	}
	for _, name := range []string{"url", "event", "table"} {
		var v string
		if b, ok := s.webhook[name]; !ok || len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '"' || json.Unmarshal(b, &v) != nil {
			return "", false, errors.New("invalid webhook field")
		}
	}
	if b, ok := s.webhook["webhook_id"]; ok {
		var v string
		if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '"' || json.Unmarshal(b, &v) != nil {
			return "", false, errors.New("invalid webhook id")
		}
	}
	if s.rootRowFound && len(s.rootRow) > 0 && s.rootRow[0] != '{' && string(s.rootRow) != "null" {
		return "", false, errors.New("invalid webhook row")
	}
	secret, ok := s.webhook["secret"]
	if !ok || !s.secretFound {
		return "", false, errors.New("missing webhook secret")
	}
	if string(secret) == "null" {
		return payload, false, nil
	}
	var value string
	if json.Unmarshal(secret, &value) != nil {
		return "", false, errors.New("invalid webhook secret")
	}
	if value == "" || !cryptoIsEncrypted(value) {
		if strings.HasPrefix(value, "enc:") {
			return "", false, errors.New("unknown encryption version")
		}
		return payload, false, nil
	}
	if strings.HasPrefix(value, encPrefixV2) {
		body := strings.TrimPrefix(value, encPrefixV2)
		sep := strings.IndexByte(body, ':')
		if sep < 0 {
			return "", false, errors.New("malformed v2 envelope")
		}
		aad, e := hex.DecodeString(body[:sep])
		if e != nil || len(aad) != 1 || aad[0] != 0 {
			return "", false, errors.New("unexpected webhook secret AAD")
		}
	}
	plain, err := fieldDecryptCtx(oldKey, "", value)
	if err != nil {
		return "", false, err
	}
	sealed, err := fieldEncryptWithKey(newKey, plain)
	if err != nil {
		return "", false, err
	}
	enc, err := json.Marshal(sealed)
	if err != nil {
		return "", false, err
	}
	if s.secretStart < rawStart || s.secretEnd > rawStart+len(raw) || s.secretEnd > len(payload) {
		return "", false, errors.New("invalid secret span")
	}
	return payload[:s.secretStart] + string(enc) + payload[s.secretEnd:], true, nil
}

func appWebhookScanValue(raw []byte, base, depth int, s *appWebhookJSONScan) error {
	if depth > appWebhookJobDepthLimit {
		return errors.New("json depth limit")
	}
	s.nodes++
	if s.nodes > appWebhookJobNodeLimit {
		return errors.New("json node limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil {
		return err
	}
	switch delim := tok.(type) {
	case json.Delim:
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				kt, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := kt.(string)
				if !ok || seen[key] {
					return errors.New("duplicate json key")
				}
				seen[key] = true
				var v json.RawMessage
				if e = d.Decode(&v); e != nil {
					return e
				}
				end := int(d.InputOffset())
				start := end - len(v)
				if start < 0 || end > len(raw) {
					return errors.New("invalid token bounds")
				}
				handledWebhook := false
				if depth == 0 && key == "_row" {
					s.rootRow = append(json.RawMessage(nil), v...)
					s.rootRowFound = true
				}
				if depth == 0 && key == "_webhook_subscription" && s.webhook == nil {
					if len(v) == 0 || v[0] != '{' {
						return errors.New("invalid webhook object")
					}
					s.webhook = map[string]json.RawMessage{}
					if e = appWebhookScanWebhook(v, base+start, depth+1, s); e != nil {
						return e
					}
					handledWebhook = true
				}
				if !handledWebhook {
					if e = appWebhookScanValue(v, base+start, depth+1, s); e != nil {
						return e
					}
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				var v json.RawMessage
				if err = d.Decode(&v); err != nil {
					return err
				}
				end := int(d.InputOffset())
				if err = appWebhookScanValue(v, base+end-len(v), depth+1, s); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return errors.New("unexpected delimiter")
		}
	}
	return nil
}

func appWebhookScanWebhook(raw []byte, base, depth int, s *appWebhookJSONScan) error {
	if depth > appWebhookJobDepthLimit {
		return errors.New("json depth limit")
	}
	s.nodes++
	if s.nodes > appWebhookJobNodeLimit {
		return errors.New("json node limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("invalid webhook object")
	}
	seen := map[string]bool{}
	for d.More() {
		kt, e := d.Token()
		if e != nil {
			return e
		}
		key, ok := kt.(string)
		if !ok || seen[key] {
			return errors.New("duplicate webhook field")
		}
		seen[key] = true
		var v json.RawMessage
		if e = d.Decode(&v); e != nil {
			return e
		}
		end := int(d.InputOffset())
		start := end - len(v)
		if start < 0 || end > len(raw) {
			return errors.New("invalid webhook token bounds")
		}
		s.webhook[key] = append(json.RawMessage(nil), v...)
		if key == "secret" {
			s.secretStart = base + start
			s.secretEnd = base + end
			s.secretFound = true
		}
		if e = appWebhookScanValue(v, base+start, depth+1, s); e != nil {
			return e
		}
	}
	_, err = d.Token()
	return err
}

func appWebhookValidSurrogates(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		i++
		for i < len(s) && s[i] != '"' {
			if s[i] == '\\' {
				i++
				if i >= len(s) {
					return false
				}
				if s[i] == 'u' {
					if i+4 >= len(s) {
						return false
					}
					v := 0
					for j := 1; j <= 4; j++ {
						c := s[i+j]
						v <<= 4
						switch {
						case c >= '0' && c <= '9':
							v += int(c - '0')
						case c >= 'a' && c <= 'f':
							v += int(c-'a') + 10
						case c >= 'A' && c <= 'F':
							v += int(c-'A') + 10
						default:
							return false
						}
					}
					if v >= 0xD800 && v <= 0xDBFF {
						if i+10 >= len(s) || s[i+5] != '\\' || s[i+6] != 'u' {
							return false
						}
						lo := 0
						for j := 7; j <= 10; j++ {
							c := s[i+j]
							lo <<= 4
							switch {
							case c >= '0' && c <= '9':
								lo += int(c - '0')
							case c >= 'a' && c <= 'f':
								lo += int(c-'a') + 10
							case c >= 'A' && c <= 'F':
								lo += int(c-'A') + 10
							default:
								return false
							}
						}
						if lo < 0xDC00 || lo > 0xDFFF {
							return false
						}
						i += 10
						continue
					}
					if v >= 0xDC00 && v <= 0xDFFF {
						return false
					}
					i += 4
				}
			}
			i++
		}
		if i >= len(s) {
			return false
		}
	}
	return true
}
