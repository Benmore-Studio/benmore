//go:build !cli

package main

import (
	"os"
	"path/filepath"
)

// readFileInRoot reads name (relative, slash or OS separators) under dir
// through an os.Root, so neither a symlink nor ".." can resolve to a file
// outside dir. The lexical containment check in processIncludesWithReader
// alone followed symlinks: an include of partials/x.html linked to
// /etc/passwd or another tenant's env.yaml was read and rendered.
func readFileInRoot(dir, name string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(filepath.FromSlash(name))
}

// readIncludeSource reads an <include> target for app, relative to
// app.Dir/rootRel: from the captured sources for a reviewed (MCP) app, else
// from disk through an os.Root at that directory.
func (app *App) readIncludeSource(rootRel, name string) ([]byte, error) {
	app.mu.RLock()
	reviewed := app.MCP != nil
	app.mu.RUnlock()
	if reviewed {
		return app.readSourceFile(filepath.Join(rootRel, name))
	}
	return readFileInRoot(filepath.Join(app.Dir, rootRel), name)
}

// readAppInclude reads an <include> target relative to the app dir.
func (app *App) readAppInclude(name string) ([]byte, error) {
	return app.readIncludeSource("", name)
}
