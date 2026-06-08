//go:build !cli

package main

import (
	"database/sql"
)

// EnsureContextGraphTables creates the per-app context graph tables in an
// app's database. The context graph is the typed directed graph of
// relationships inside an app — pages ↔ tables, flows ↔ hooks. It's
// available as a context resource describing an app's structure, so a tool
// or LLM can reason about the whole app without scanning files.
//
// Nodes are stored with (type, ref) where ref is a canonical identifier
// like "page:/checkout" or "table:orders" or "document:spec-v2". Edges
// are typed and directional. Metadata JSON allows type-specific fields
// without schema churn.
//
// This lives in the app's own DB because the graph describes the actual
// files/tables/flows present in that branch. Different branches can have
// different graphs — a feature branch may add a new page that doesn't
// exist in prod, and the graph for that branch will contain nodes and
// edges for it.
func EnsureContextGraphTables(db *sql.DB) {
	if db == nil {
		return
	}

	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_context_nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_type TEXT NOT NULL,
		ref TEXT NOT NULL,
		label TEXT DEFAULT '',
		metadata TEXT DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (node_type, ref)
	)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_benmore_context_nodes_type ON _benmore_context_nodes(node_type)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_context_edges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		from_node INTEGER NOT NULL,
		to_node INTEGER NOT NULL,
		edge_type TEXT NOT NULL,
		metadata TEXT DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (from_node) REFERENCES _benmore_context_nodes(id) ON DELETE CASCADE,
		FOREIGN KEY (to_node) REFERENCES _benmore_context_nodes(id) ON DELETE CASCADE
	)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_benmore_context_edges_from ON _benmore_context_edges(from_node)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_benmore_context_edges_to ON _benmore_context_edges(to_node)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_benmore_context_edges_type ON _benmore_context_edges(edge_type)`)
}
