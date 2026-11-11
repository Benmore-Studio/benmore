//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
)

type errorCompileSet struct {
	mu    sync.Mutex
	seen  map[string]bool
	order []string
}

func reportTSXCompileFailure(app *App, entry string, body []byte, contentVersion ...string) {
	const prefix = "throw new Error("
	js := strings.TrimSpace(string(body))
	if !strings.HasPrefix(js, prefix) || !strings.HasSuffix(js, ");") {
		return
	}
	message, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(js, prefix), ");"))
	if err != nil || !strings.HasPrefix(message, "[bm-tsx-compile]") {
		return
	}
	sum := sha256.Sum256(body)
	key := entry + ":" + hex.EncodeToString(sum[:])
	if len(contentVersion) > 0 && contentVersion[0] != "" {
		key = entry + ":" + contentVersion[0]
	}
	c := &app.errorCompiles
	c.mu.Lock()
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[key] {
		c.mu.Unlock()
		return
	}
	if len(c.order) == 256 {
		delete(c.seen, c.order[0])
		c.order = c.order[1:]
	}
	c.seen[key] = true
	c.order = append(c.order, key)
	c.mu.Unlock()
	reportError(app, errorEvent{Source: "server", Kind: "compile", Level: "error", Type: "tsx_compile", Message: message, Route: "/static/" + entry, Handled: true, Mechanism: "generic"})
}
