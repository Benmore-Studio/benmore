//go:build !cli

package main

// Migration files travel between a hosted app's dev and prod instances:
// promote mirrors dev's migrations/ into prod, refresh-dev and seed-dev copy
// prod's into dev. Each instance also generates a migration when it loads a
// schema.prisma its ledger has not applied, numbered after the files in its
// own directory. So after a promote that changed the schema, prod wrote a
// second file for the change dev's file already described (dev's
// 0018_<t1>_x.sql arrived, prod wrote 0019_<t2>_x.sql), then replayed dev's
// file with every statement skipped as already applied. Prod's migrations/
// never again matched dev's, and `benmore sync-status --env prod` reported
// the extra file as drift that pulling or pushing could not settle.
//
// A generated file now names the schema it starts from and the one it
// produces (Schema-From / Schema-To, digests of the parsed models). When an
// instance is about to generate, it first looks for pending files (in
// migrations/ but not in its ledger) whose headers chain from the schema its
// ledger last recorded to the schema it is loading. If they do, it applies
// exactly those files, in name order, in one transaction, records them under
// their own names, and writes nothing. Anything else (no chain, a statement
// that fails, a relation or schema difference left over) rolls back and the
// instance generates its own file as before. The files applied are the ones
// the user-migration runner would have run right after anyway; none is
// skipped and none runs twice.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	migrationSchemaFromHeader = "-- Schema-From: "
	migrationSchemaToHeader   = "-- Schema-To: "
)

// prismaModelsDigest identifies a parsed schema independently of
// formatting, comments and model order.
func prismaModelsDigest(models []PrismaModel) string {
	sorted := append([]PrismaModel{}, models...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Table < sorted[j].Table })
	data, err := json.Marshal(sorted)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// acknowledgedPrismaModels is the schema the ledger last recorded a source
// for. Rows the user-migration runner writes carry no source, so they are
// skipped: they do not change which Prisma schema the database was brought
// to.
func acknowledgedPrismaModels(q mutationQuerier) []PrismaModel {
	var source string
	if err := q.QueryRow(`SELECT source FROM _benmore_migrations WHERE source <> '' ORDER BY id DESC LIMIT 1`).Scan(&source); err != nil || source == "" {
		return nil
	}
	models, err := ParsePrismaSchema(source)
	if err != nil {
		return nil
	}
	return models
}

// prismaNoFileLedgerNames are ledger rows that record a schema source without
// a migration file: a source edit whose diff had no SQL (a @default, type or
// nullability change, a removed field or @unique) and the test boot's row.
var prismaNoFileLedgerNames = []string{"no_schema_change", "test_schema"}

// prismaChainModels is the schema the last migration FILE brought this
// database to: the source of the newest ledger row that names a file. A
// generated file's Schema-From is this schema, and adoption chains from it.
//
// Rows that record a source without a file are skipped. The schema they
// record differs from the last file's only in what the generator does not
// apply, so the database is physically at the last file's schema; and the
// other instance, which receives files and never those rows, is there too.
// Chaining from such a row named a Schema-From prod never reached, so after
// any file-less change on dev, prod wrote its own copy of dev's next file
// (round-2 finding L6).
func prismaChainModels(q mutationQuerier) []PrismaModel {
	var source string
	if err := q.QueryRow(`SELECT source FROM _benmore_migrations WHERE source <> '' AND name NOT IN (?, ?) ORDER BY id DESC LIMIT 1`,
		prismaNoFileLedgerNames[0], prismaNoFileLedgerNames[1]).Scan(&source); err != nil || source == "" {
		return nil
	}
	models, err := ParsePrismaSchema(source)
	if err != nil {
		return nil
	}
	return models
}

// withSchemaChainHeader adds the Schema-From / Schema-To lines to a file
// EmitMigrationSQL produced, after its Migration and Generated lines.
func withSchemaChainHeader(sqlText, from, to string) string {
	header := migrationSchemaFromHeader + from + "\n" + migrationSchemaToHeader + to + "\n"
	if i := strings.Index(sqlText, "\n--\n"); i >= 0 {
		return sqlText[:i+1] + header + sqlText[i+1:]
	}
	return header + sqlText
}

// migrationSchemaChain reads the Schema-From / Schema-To lines from the
// leading comment block of a migration file.
func migrationSchemaChain(content string) (from, to string, ok bool) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "--") {
			break
		}
		if v, found := strings.CutPrefix(line, migrationSchemaFromHeader); found {
			from = strings.TrimSpace(v)
		}
		if v, found := strings.CutPrefix(line, migrationSchemaToHeader); found {
			to = strings.TrimSpace(v)
		}
	}
	return from, to, from != "" && to != ""
}

type pendingChainMigration struct {
	name, content string
}

// pendingSchemaChain returns the pending migration files that carry schema
// headers when, in name order, they lead from ackDigest to wantDigest. Files
// without headers (hand-written, or generated before the headers existed) are
// left to the user-migration runner. Any break in the chain returns nil.
func pendingSchemaChain(q mutationQuerier, migDir, ackDigest, wantDigest string) ([]pendingChainMigration, error) {
	entries, err := os.ReadDir(migDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var chain []pendingChainMigration
	state := ackDigest
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".failed.sql") {
			continue
		}
		var applied int
		if err := q.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
			return nil, err
		}
		if applied > 0 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(migDir, name))
		if err != nil {
			return nil, err
		}
		from, to, ok := migrationSchemaChain(string(data))
		if !ok {
			continue
		}
		if from != state {
			return nil, nil
		}
		chain = append(chain, pendingChainMigration{name: name, content: string(data)})
		state = to
	}
	if len(chain) == 0 || state != wantDigest {
		return nil, nil
	}
	return chain, nil
}

// adoptPendingPrismaMigrations applies a pending chain (see the file comment)
// and records it, returning the adopted names. It returns nil with nothing
// changed when there is no complete chain or the chain does not leave the
// database at the loaded schema; the caller then generates as before. The
// chain starts at the last file's schema (prismaChainModels); ackModels, the
// schema the ledger last recorded, is what the files must finish the job from.
//
// The files are tenant-authored SQL. ctx bounds them: the router's validation
// load passes checkMigrationTimeout, and running out of time fails the load
// (the files stay pending for the app's own boot) instead of generating a
// second file for the same change.
func adoptPendingPrismaMigrations(ctx context.Context, db *sql.DB, dir string, ackModels, currModels []PrismaModel, prismaSrc, hash string, checkOnly bool) ([]string, error) {
	chain, err := pendingSchemaChain(db, filepath.Join(dir, "migrations"), prismaModelsDigest(prismaChainModels(db)), prismaModelsDigest(currModels))
	if err != nil || len(chain) == 0 {
		return nil, err
	}
	// The snapshot the migration runner takes before pending files, and, as
	// the generator requires, a mandatory one when the change drops a table.
	if len(DiffSchemas(ackModels, currModels).TablesDropped) > 0 {
		if bkPath, bkErr := backupDatabase(dir); bkErr != nil {
			return nil, fmt.Errorf("pre-drop backup required before destructive migration %s: %w", chain[len(chain)-1].name, bkErr)
		} else if bkPath == "" {
			return nil, fmt.Errorf("pre-drop backup required before destructive migration %s: no database snapshot created", chain[len(chain)-1].name)
		} else {
			noteLoadSnapshot(ctx, bkPath)
		}
	} else if !(checkOnly && recentPreMigrateBackup(dir, checkBackupMinInterval)) {
		bkPath, err := preparePreMigrationBackup(dir, true)
		if err != nil {
			return nil, err
		}
		noteLoadSnapshot(ctx, bkPath)
	}
	tx, err := db.BeginTx(withLongWriteTx(ctx, "prisma migration adopt"), nil)
	if err != nil {
		return nil, err
	}
	names, abandon, err := applySchemaChainTx(ctx, tx, chain, ackModels, currModels, prismaSrc, hash)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if abandon != "" {
		_ = tx.Rollback()
		log.Printf("migration: not reusing %d pending migration file(s) for this schema (%s); generating one instead", len(chain), abandon)
		return nil, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit adopted migrations: %w", err)
	}
	return names, nil
}

// applySchemaChainTx applies a pending chain in tx and records it. A non-empty
// abandon says the chain cannot stand for this schema (a statement failed, or a
// difference is left over): the caller rolls back and generates instead. err is
// running out of time, which fails the load. The caller ends tx.
func applySchemaChainTx(ctx context.Context, tx *sql.Tx, chain []pendingChainMigration, ackModels, currModels []PrismaModel, prismaSrc, hash string) (applied []string, abandon string, err error) {
	names := make([]string, 0, len(chain))
	for i, m := range chain {
		up, _ := extractMigrationSection(m.content)
		for _, stmt := range splitStatements(up) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" || strings.HasPrefix(stmt, "--") {
				continue
			}
			if err := dropFrameworkIndexesForStatement(tx, stmt); err != nil {
				return nil, fmt.Sprintf("%s: %v", m.name, err), nil
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				if ctx.Err() != nil {
					return nil, "", fmt.Errorf("migration %s did not finish within the validation time limit (it is applied when the app itself starts): %w", m.name, err)
				}
				// The same tolerance the user-migration runner applies to
				// these files: the change is already in place.
				if isBenignMigrationError(err) || isRenameAlreadyApplied(tx, stmt, err) {
					continue
				}
				return nil, fmt.Sprintf("%s: %s: %v", m.name, truncate(stmt, 60), err), nil
			}
		}
		source, sourceHash := "", ""
		if i == len(chain)-1 {
			source, sourceHash = prismaSrc, hash
		}
		if _, err := tx.Exec(`INSERT INTO _benmore_migrations (name, source, source_hash) VALUES (?, ?, ?)`, m.name, source, sourceHash); err != nil {
			return nil, fmt.Sprintf("record %s: %v", m.name, err), nil
		}
		names = append(names, m.name)
	}
	if missing, err := missingPrismaForeignKeys(tx, currModels); err != nil || len(missing) > 0 {
		return nil, "relations still missing after the files", nil
	}
	residual := reconcileDiffAgainstLive(DiffSchemas(ackModels, currModels), tx)
	kept := residual.TablesDropped[:0]
	for _, table := range residual.TablesDropped {
		if dbTableExists(tx, table) {
			kept = append(kept, table)
		}
	}
	residual.TablesDropped = kept
	if !residual.Empty() {
		return nil, "the files do not produce the loaded schema", nil
	}
	return names, "", nil
}
