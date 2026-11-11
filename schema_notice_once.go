//go:build !cli

package main

// Schema differences a load leaves in place (MigrateResult.Retained: a live
// column the schema no longer declares, a nullability change) are logged by
// the load that first sees them, not by every start. A schema.prisma app that
// once dropped a field logged "DROP habits.legacy_tag - column exists in DB
// but not in schema.sql (use --force to drop)" on every start and reload: the
// wrong file, a flag hosted apps do not have, and the same line forever.
//
// .benmore/schema-notices holds a digest of the list the last load logged. A
// load logs the list again only when it differs (a new difference, one gone,
// a restored database with other columns); a load with nothing to report
// removes the record so a difference that comes back is logged again.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const schemaNoticesStateName = "schema-notices"

// schemaNoticesToLog drops, from what Migrate retained, the undeclared columns
// the framework added itself (a blind-index sibling, a custom field): they are
// never declared in the schema and must not be dropped (frameworkManagedColumn).
func schemaNoticesToLog(db *sql.DB, retained []string) []string {
	if len(retained) == 0 {
		return nil
	}
	customFields, err := customFieldColumns(db)
	if err != nil {
		customFields = nil
	}
	live := map[string]map[string]LiveColumn{}
	var out []string
	for _, notice := range retained {
		if undeclared := parseRetainedUndeclaredColumns([]string{notice}); len(undeclared) == 1 {
			table, col := undeclared[0].Table, undeclared[0].Column
			if live[table] == nil {
				if cols, err := getLiveColumns(db, table); err == nil {
					live[table] = cols
				}
			}
			if frameworkManagedColumn(table, col, live[table], customFields) {
				continue
			}
		}
		out = append(out, notice)
	}
	return out
}

// logSchemaNoticesOnce logs notices unless the last load of dir logged the
// same list. Best effort: when the record cannot be read or written, the
// notices are logged (again next time).
func logSchemaNoticesOnce(dir string, notices []string) {
	path := filepath.Join(dir, ".benmore", schemaNoticesStateName)
	if len(notices) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("  schema: could not clear %s: %v", path, err)
		}
		return
	}
	sorted := slices.Clone(notices)
	slices.Sort(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	digest := hex.EncodeToString(sum[:])
	if previous, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(previous)) == digest {
		return
	}
	for _, notice := range notices {
		log.Printf("  schema kept as it is: %s", notice)
	}
	if err := writeStateFile(dir, schemaNoticesStateName, []byte(digest+"\n")); err != nil {
		log.Printf("  schema: these differences are logged again at the next start (%v)", err)
	}
}
