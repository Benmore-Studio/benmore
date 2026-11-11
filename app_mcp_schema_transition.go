//go:build !cli

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// A reload or start that loads a reviewed mcp.yaml checks the candidate
// routes before migrating, and it cannot project a Prisma migration that
// removes a model (the table would vanish under the connector), so it refuses
// the whole load. Source checks and the write gate passed that state: an app
// that replaced the scaffold's Note model and deployed its new mcp.yaml in the
// same batch had every reload refused, and the only way out was to take the
// connector off, let the migration run and review again. The reload, the
// write gate (through the tenant helper, which can open the database) and
// check all use appMCPPrismaTransitionDrops, so they agree on what is refused.

// errAppMCPPrismaLedger: the migration ledger could not be read.
var errAppMCPPrismaLedger = errors.New("mcp.yaml: cannot inspect Prisma migration ledger")

// appMCPPrismaTransitionDrops returns the tables the schema.prisma source
// prisma drops relative to the newest recorded migration source, as the
// connector's candidate-route check sees it. unparseable reports that either
// schema could not be parsed, which that check refuses as well. A database
// without a migration ledger has nothing to drop.
func appMCPPrismaTransitionDrops(db *sql.DB, prisma []byte) (dropped []string, unparseable bool, err error) {
	var ledger int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND lower(name)='_benmore_migrations'").Scan(&ledger); err != nil {
		return nil, false, errAppMCPPrismaLedger
	}
	if ledger == 0 {
		return nil, false, nil
	}
	var previous string
	err = db.QueryRow("SELECT source FROM _benmore_migrations ORDER BY id DESC LIMIT 1").Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return nil, false, fmt.Errorf("mcp.yaml: cannot inspect Prisma migration source")
	}
	oldModels, oldErr := ParsePrismaSchema(previous)
	newModels, newErr := ParsePrismaSchema(string(prisma))
	if oldErr != nil || newErr != nil {
		return nil, true, nil
	}
	dropped = append(dropped, DiffSchemas(oldModels, newModels).TablesDropped...)
	sort.Strings(dropped)
	return dropped, false, nil
}

// appMCPDestructiveSchemaRecovery is the order that applies such a change:
// the migration runs only while no reviewed mcp.yaml is loaded, and it writes
// a migrations/ file that the next review must cover. Command flows can stay:
// with no mcp.yaml loaded (none on the server, or one reviewed for the old
// schema, which is stale) they load unexposed (loadServedRuntimeConfig).
const appMCPDestructiveSchemaRecovery = "1) keep the reviewed mcp.yaml off the server while the schema change applies: one reviewed for the old schema is stale and already keeps the connector off, and a first connector has none on the server yet; delete one reviewed for the new schema (`benmore delete-file mcp.yaml --app <app> --env <env>`); 2) push schema.prisma (or deploy: its mcp.yaml write is refused and the server reloads the other files) and wait for the reload to migrate (`benmore logs <app> --env <env>`; `benmore check <app> --env <env>` stops reporting this); 3) fetch the migrations/ file the server wrote, which review covers (`benmore push` and `benmore deploy` pull it after the reload; otherwise `benmore pull <app> <dir> --env <env>`); 4) `benmore mcp review <dir> --reviewed`; 5) `benmore deploy <dir> --env <env>`. Command flows can stay: while no mcp.yaml is loaded they load without being exposed, so only mcp.yaml has to be off."

// appMCPDestructiveSchemaError is the reload/start refusal. It keeps its
// historic prefix and names the tables and the recovery order.
func appMCPDestructiveSchemaError(dropped []string) error {
	if len(dropped) == 0 {
		return fmt.Errorf("mcp.yaml: destructive Prisma schema transition is unsupported: schema.prisma or the last applied migration source cannot be parsed for the connector's route check. Fix schema.prisma, then apply it with the connector off: %s", appMCPDestructiveSchemaRecovery)
	}
	return fmt.Errorf("mcp.yaml: destructive Prisma schema transition is unsupported: schema.prisma removes the model of %s, and an app does not migrate a table away while a reviewed mcp.yaml is loaded. Apply it with the connector off, in this order: %s", appMCPTableList(dropped), appMCPDestructiveSchemaRecovery)
}

// appMCPSchemaTransitionReloading is the sentence of the write refusal that
// says the server is reloading the files already written. The CLI keys its
// wait for that reload on it (pushTypesRefresh.refused), so a deploy whose
// final mcp.yaml write is refused still applies the schema change.
const appMCPSchemaTransitionReloading = "the server is reloading the files already written"

// appMCPDestructiveSchemaWriteRefusal is the write gate's answer to an
// mcp.yaml write that the next reload would refuse. A deploy defers its
// reload to its last write, which is mcp.yaml: refused, nothing reloaded the
// schema it had written, and every rerun was refused the same way. When the
// write asked for a reload (reloading), the server still runs it for the
// files already written, without this mcp.yaml.
func appMCPDestructiveSchemaWriteRefusal(dropped []string, reloading bool) string {
	next := "The other files are written, and the next reload applies the schema change without this mcp.yaml."
	if reloading {
		next = "The other files are written, and " + appMCPSchemaTransitionReloading + " without this mcp.yaml, which applies the schema change."
	}
	return fmt.Sprintf("mcp.yaml not written: the server's schema.prisma removes the model of %s, which the app has not migrated yet, and a reload with a reviewed mcp.yaml refuses that migration (every reload would fail until mcp.yaml is removed). %s Its command flows load but are not exposed until mcp.yaml is written (a first connector has no mcp.yaml on the server; one reviewed for the old schema is stale and keeps the connector off). The reload writes a migrations/ file that the review must cover. Then: wait for the reload (`benmore logs <app> --env <env>`), fetch that file (`benmore deploy` and `benmore push` pull it after the reload; otherwise `benmore pull <app> <dir> --env <env>`), run `benmore mcp review <dir> --reviewed`, and deploy again.", appMCPTableList(dropped), next)
}

func appMCPTableList(tables []string) string {
	if len(tables) == 1 {
		return "table " + tables[0]
	}
	return "tables " + strings.Join(tables, ", ")
}

// appMCPSchemaTransitionFindings is check's view of the same refusal. It reads
// the serving app's own open pool (db, from the data channel's check_live) and
// never opens a database itself, so router code cannot reach tenant data
// through it; with db nil it reports nothing and the app load layer reports
// the refusal instead.
func appMCPSchemaTransitionFindings(dir string, db *sql.DB) []CheckFinding {
	if db == nil {
		return nil
	}
	prisma, err := readOptionalConfig(dir, "schema.prisma")
	if err != nil || prisma == nil {
		return nil
	}
	config, err := loadServedRuntimeConfig(dir)
	if err != nil || config.mcp == nil {
		return nil // a withheld (stale) manifest does not block the migration
	}
	dropped, unparseable, err := appMCPPrismaTransitionDrops(db, prisma)
	if err != nil || !unparseable && len(dropped) == 0 {
		return nil
	}
	return []CheckFinding{{Severity: "error", Source: "mcp_connector", File: "mcp.yaml", Message: appMCPDestructiveSchemaError(dropped).Error()}}
}
