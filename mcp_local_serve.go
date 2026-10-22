//go:build !cli

package main

// `benmore serve <appdir> --mcp-local [--mcp-writes]` runs an app's reviewed
// MCP connector on this machine, so OAuth, tool listing, prepare → approve →
// _commit → _status and revocation can be exercised before a deploy. Without
// it /api/_mcp and the connector's /.well-known/oauth-* documents answer 404
// locally: the resource must be https unless the app runs in dev mode on
// loopback, and the owner switches are reachable only through a router-minted
// owner token.
//
// The flag only relaxes what is local by nature: the resource is pinned to
// http://localhost:<port>/api/_mcp (validAppMCPResource still refuses any other
// http origin), the listener binds 127.0.0.1 unless the operator set
// BENMORE_LISTEN, the authority directory defaults to a per-app 0700 directory
// in the user's cache dir (outside the app, so restores never copy it), and the
// connector is switched on through the same appMCPConnectorApply path and audit
// row the owner control uses, with subject "local-serve". A manifest that is
// missing or withheld by a stale review is not enabled, and serve then stops
// with an error saying why (see enableMCPLocal and its caller in server.go).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const mcpLocalAuthorityEnv = "BENMORE_MCP_AUTHORITY_DIR"

// prepareMCPLocalAuthority points BENMORE_MCP_AUTHORITY_DIR at a stable
// owner-only directory for dir unless the operator already chose one. It runs
// before loadApp, which binds the app to its authority.
func prepareMCPLocalAuthority(dir string) (string, error) {
	if configured := os.Getenv(mcpLocalAuthorityEnv); configured != "" {
		return configured, nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory for the local connector authority; set %s: %w", mcpLocalAuthorityEnv, err)
	}
	sum := sha256.Sum256([]byte(realPathForContainment(abs)))
	stateDir := filepath.Join(realPathForContainment(cache), "benmore", "mcp-authority", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.Setenv(mcpLocalAuthorityEnv, stateDir); err != nil {
		return "", err
	}
	return stateDir, nil
}

// enableMCPLocal turns the loaded app's connector on (and approved writes,
// when writes is set) exactly as `benmore mcp enable` would on a hosted
// instance, and records the same audit row.
func enableMCPLocal(app *App, writes bool) (appMCPConnectorStatus, error) {
	if appMCPManifestSnapshot(app) == nil {
		return appMCPConnectorStatus{}, errors.New("no reviewed mcp.yaml is loaded (missing, or withheld because the source changed since review: run `benmore mcp check <appdir>`)")
	}
	defer lockAppMCPControl(app.Dir)()
	ctx, cancel := context.WithTimeout(context.Background(), appMCPControlTimeout)
	defer cancel()
	req := appMCPConnectorRequest{Action: "enable", Writes: writes}
	before := appMCPConnectorStatusFor(ctx, app)
	applyErr := appMCPConnectorApply(ctx, app, req)
	after := appMCPConnectorStatusFor(ctx, app)
	auditErr := appMCPConnectorAudit(app, "local-serve", req, before, after, applyErr)
	return after, errors.Join(applyErr, auditErr)
}
