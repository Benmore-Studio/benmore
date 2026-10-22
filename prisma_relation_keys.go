//go:build !cli

package main

import (
	"database/sql"
	"strings"
)

// prismaRelationParentKeyStatus deliberately has three outcomes. Ordinary
// rowid PKs and BINARY unique keys without any declared COLLATE are provable
// from existing SQLite metadata. A declared collation needs SQLite's final
// native FK validation; do not guess which column a DDL clause belongs to.
func prismaRelationParentKeyStatus(q mutationQuerier, table, column string) (string, error) {
	rows, err := q.Query(`SELECT name,type,pk FROM pragma_table_xinfo(?)`, table)
	if err != nil {
		return "", err
	}
	pkCount, targetPK := 0, false
	targetType := ""
	for rows.Next() {
		var name, typ string
		var pk int
		if err := rows.Scan(&name, &typ, &pk); err != nil {
			rows.Close()
			return "", err
		}
		if pk > 0 {
			pkCount++
		}
		if strings.EqualFold(name, column) {
			targetPK, targetType = pk > 0, typ
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	rows, err = q.Query(`SELECT name,origin FROM pragma_index_list(?) WHERE "unique"=1 AND partial=0`, table)
	if err != nil {
		return "", err
	}
	var indexes []string
	hasPKIndex := false
	for rows.Next() {
		var name, origin string
		if err := rows.Scan(&name, &origin); err != nil {
			rows.Close()
			return "", err
		}
		indexes = append(indexes, name)
		hasPKIndex = hasPKIndex || origin == "pk"
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if pkCount == 1 && targetPK && strings.EqualFold(targetType, "INTEGER") && !hasPKIndex {
		return "valid", nil // INTEGER PRIMARY KEY aliases the rowid.
	}
	eligible, binary := false, false
	for _, index := range indexes {
		rows, err := q.Query(`SELECT cid,name,coll FROM pragma_index_xinfo(?) WHERE key=1 ORDER BY seqno`, index)
		if err != nil {
			return "", err
		}
		terms, match, binaryTerm := 0, false, false
		for rows.Next() {
			var cid int
			var name, coll sql.NullString
			if err := rows.Scan(&cid, &name, &coll); err != nil {
				rows.Close()
				return "", err
			}
			terms++
			match = cid >= 0 && name.Valid && strings.EqualFold(name.String, column)
			binaryTerm = coll.Valid && strings.EqualFold(coll.String, "BINARY")
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return "", err
		}
		if terms == 1 && match {
			eligible = true
			binary = binary || binaryTerm
		}
	}
	if !eligible {
		return "invalid", nil
	}
	var ddl string
	if err := q.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='table' AND name=? COLLATE NOCASE`, table).Scan(&ddl); err != nil {
		return "", err
	}
	// This is conservative presence detection, not a new DDL parser. Even a
	// COLLATE word in a literal/comment makes this outcome unknown, not valid.
	if strings.Contains(strings.ToUpper(ddl), "COLLATE") {
		return "unknown", nil
	}
	if binary {
		return "valid", nil
	}
	return "invalid", nil // All candidate keys override default BINARY.
}
