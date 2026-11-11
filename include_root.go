//go:build !cli

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
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
	return readRegularInRoot(root, filepath.FromSlash(name), includeRootMaxBytes)
}

// includeRootMaxBytes bounds one file read by readFileInRoot (a partial, an
// email template, a sourcemap the router's decode_stack reads).
const includeRootMaxBytes = 32 << 20

// readRegularInRoot reads name through root as a regular file: opened without
// blocking, so a FIFO at the name cannot hang the reader (the router reads
// tenant files this way), refused when it is not a regular file (a link to
// /dev/zero) or larger than limit, and read with a cap.
func readRegularInRoot(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s: file is %d bytes, over the %d byte limit", name, st.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: file is over the %d byte limit", name, limit)
	}
	return data, nil
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
