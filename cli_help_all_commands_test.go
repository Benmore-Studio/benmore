//go:build !cli

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// cliHiddenCommands are the commands the binary dispatches that `benmore help
// all` leaves out on purpose, each with the reason. A dispatched command must
// be in the help text or here (TestHelpAllListsEveryDispatchedCommand), so a
// new command cannot go unlisted by accident.
var cliHiddenCommands = map[string]string{
	// Hosted CLI (cloud and platform editions).

	// Creates an account from an email and a password. A platform that signs
	// people in with an emailed code, as benmore.ai does, answers it 403; the
	// listed `benmore login` creates the account in the browser, and help
	// advertises no password sign-in (TestUsageAdvertisesBrowserLogin).
	// `benmore help signup` still prints its usage.
	"signup": "password sign-up: refused (403) by a platform that signs in with an emailed code; `benmore login` creates the account in the browser",
	// Creates or promotes an app admin (--password-stdin, as the listed
	// commands read a password). The listed `benmore users <app> create
	// <email> --password-stdin --role admin` and `users set-password
	// --promote` call the same platform tool, so help names those two.
	"createsuperuser": "an older spelling of `benmore users <app> create --password-stdin --role admin`, which is the listed way",
	// Removed: it ran seeds.sql over SSH on a deploy host the hosted CLI no
	// longer has, so it always failed. For one release it only prints where
	// seeding lives (the listed `benmore reset-seed`, which wipes first);
	// then the dispatch case, its flag spec and this entry go.
	"seed": "removed; for one release it prints a pointer to `benmore reset-seed` and exits 1",

	// Host processes (platform edition): started by the service manager or
	// by another host program with fixed arguments, never typed by a builder.

	"host":          "the single-process multi-app server, started by the host's service manager",
	"router":        "the front-door router process, started by the host's service manager",
	"tenant-helper": "started by scripts/benmore-appctl as an app's own user, never by hand",
	"migrate-media": "one-time operator backfill of local uploads to the media store, run on the host",
}

// switchCaseCommands returns the string cases of the `switch cmd` in fn of
// file: the commands that function dispatches.
func switchCaseCommands(t *testing.T, file, fn string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, decl := range parsed.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Recv != nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if tag, ok := sw.Tag.(*ast.Ident); !ok || tag.Name != "cmd" {
				return true
			}
			for _, stmt := range sw.Body.List {
				for _, e := range stmt.(*ast.CaseClause).List {
					if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						cmd, _ := strconv.Unquote(lit.Value)
						out = append(out, cmd)
					}
				}
			}
			return false
		})
	}
	if len(out) == 0 {
		t.Fatalf("found no `switch cmd` cases in %s %s", file, fn)
	}
	return out
}

// dispatchedCommands are the commands this edition's binary runs: main's own
// switch, the server commands, and by edition the hosted CLI and the host
// commands. Flag spellings of a command (--version, -h) are left out.
func dispatchedCommands(t *testing.T) []string {
	t.Helper()
	// `mcp` is handled in main before its switch (runAppMCPCLI) in every
	// edition; the hosted editions also dispatch its owner switches.
	cmds := []string{"mcp"}
	cmds = append(cmds, switchCaseCommands(t, "main.go", "main")...)
	cmds = append(cmds, switchCaseCommands(t, "main_server.go", "serverDispatch")...)
	if editionName != "framework" {
		cmds = append(cmds, switchCaseCommands(t, "cli_platform_dispatch.go", "dispatchPlatformCLI")...)
	}
	if editionName == "platform" {
		cmds = append(cmds, switchCaseCommands(t, "server_dispatch_platform.go", "dispatchPlatformServer")...)
	}
	seen := map[string]bool{}
	var out []string
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "-") || seen[cmd] {
			continue
		}
		seen[cmd] = true
		out = append(out, cmd)
	}
	sort.Strings(out)
	return out
}

// `benmore help all` is described as every command. signup, createsuperuser
// and seed were dispatched and absent from it, with nothing saying whether
// that was meant. Every dispatched command is now either listed (an alias
// counts through the command it stands for) or in cliHiddenCommands with the
// reason.
func TestHelpAllListsEveryDispatchedCommand(t *testing.T) {
	cmds := dispatchedCommands(t)
	// The parse found the commands: every edition has these.
	for _, known := range []string{"new", "serve", "test", "docs", "version", "help", "mcp"} {
		if !slices.Contains(cmds, known) {
			t.Fatalf("the dispatch parse misses %q: %v", known, cmds)
		}
	}
	if editionName != "framework" && (len(cmds) < 80 || !slices.Contains(cmds, "deploy") || !slices.Contains(cmds, "signup")) {
		t.Fatalf("the dispatch parse found only %d hosted commands: %v", len(cmds), cmds)
	}
	dispatched := map[string]bool{}
	for _, cmd := range cmds {
		dispatched[cmd] = true
		listed := commandUsage(cliCanonicalCommand(cmd)) != ""
		reason, hidden := cliHiddenCommands[cmd]
		switch {
		case listed && hidden:
			t.Errorf("benmore %s is listed in `help all` and in cliHiddenCommands; remove it from the hidden list", cmd)
		case !listed && !hidden:
			t.Errorf("benmore %s is dispatched but `benmore help all` does not list it. Add its line to the usage text, or add it to cliHiddenCommands with the reason it is left out", cmd)
		case hidden && len(strings.Fields(reason)) < 4:
			t.Errorf("cliHiddenCommands[%q] gives no reason", cmd)
		}
	}
	// The platform edition dispatches everything, so there a hidden entry
	// that names no command is stale.
	if editionName == "platform" {
		for cmd := range cliHiddenCommands {
			if !dispatched[cmd] {
				t.Errorf("cliHiddenCommands lists %q, which nothing dispatches; remove it", cmd)
			}
		}
	}
}
