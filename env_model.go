package main

// Dev/prod environment model — the single source of truth for the
// "one logical app, two instances" shape (Model B).
//
//	prod : <sub>.benmore.ai      dir apps/<sub>      unit benmore-app@<sub>
//	dev  : <sub>-dev.benmore.ai   dir apps/<sub>-dev  unit benmore-app@<sub>-dev
//
// A dev instance is, mechanically, "another routed subdomain pointing at a
// second per-app unit" — it reuses the existing provisioning/routing/git/
// migrate machinery wholesale. The ONLY net-new naming rule is the `-dev`
// instance-subdomain suffix, and it lives here so no other file
// hand-concatenates "-dev". (Same single-source-of-truth discipline as
// rowScopeClause for per-row scope — see .claude/rules/security.md.)
//
// This file is intentionally UNTAGGED so every edition links it: the cloud
// CLI threads `--env` through to InstanceSubdomain; the platform host uses
// it for provisioning + routing; the framework edition ignores it. It is
// pure string logic — no systemd, no DB, no I/O — so it is fully unit-
// testable on any platform.
//
// prod is the IDENTITY case (sub -> sub), so when env defaults to prod
// every derived value equals today's value and existing behavior is
// byte-for-byte unchanged. The whole feature stays additive on this seam.

import (
	"fmt"
	"path/filepath"
	"strings"
)

// AppEnv is the environment an app instance runs in.
type AppEnv string

const (
	// EnvProd is the production instance — the canonical app at
	// <sub>.benmore.ai. This is the default everywhere; an empty/absent
	// env string resolves to prod so untouched callers keep today's
	// behavior.
	EnvProd AppEnv = "prod"
	// EnvDev is the development instance — the sibling at
	// <sub>-dev.benmore.ai with its own data.db.
	EnvDev AppEnv = "dev"
)

// devSubdomainSuffix is appended to a logical (prod) subdomain to derive
// its dev sibling's subdomain. The leading hyphen is load-bearing: a prod
// subdomain is always "<base>-<6 char suffix>" (see randomSubdomainSuffix,
// whose alphabet contains no hyphen), so a prod subdomain can NEVER end in
// "-dev". That makes HasSuffix(sub, devSubdomainSuffix) an unambiguous test
// for "is this a dev instance" — there is no logical app whose own
// subdomain ends in -dev.
const devSubdomainSuffix = "-dev"

// Valid reports whether e is a recognized environment.
func (e AppEnv) Valid() bool {
	return e == EnvProd || e == EnvDev
}

// IsDev is a small readability helper.
func (e AppEnv) IsDev() bool { return e == EnvDev }

// String renders the env for logs/labels.
func (e AppEnv) String() string {
	if e == "" {
		return string(EnvProd)
	}
	return string(e)
}

// ParseEnv parses a CLI/MCP env argument. The empty string defaults to
// prod (so existing callers that pass nothing keep production behavior).
// Accepts a few friendly aliases; anything else is an error so a typo
// like "--env prdo" fails loudly instead of silently shipping to the
// wrong instance.
func ParseEnv(s string) (AppEnv, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "prod", "production":
		return EnvProd, nil
	case "dev", "development":
		return EnvDev, nil
	default:
		return "", fmt.Errorf("unknown environment %q (expected \"dev\" or \"prod\")", s)
	}
}

// InstanceSubdomain maps a logical (prod) subdomain + an env to the
// subdomain of the instance that serves it. prod is the identity case;
// dev appends the -dev suffix.
//
// It is idempotent on already-derived input: passing a subdomain that is
// already a dev subdomain together with EnvDev returns it unchanged, and
// any input together with EnvProd returns its logical (de-dev'd) form. So
// callers can pass either the logical subdomain or whatever subdomain they
// happen to hold without double-suffixing.
func InstanceSubdomain(logicalSub string, env AppEnv) string {
	base := LogicalSubdomain(logicalSub)
	if env == EnvDev {
		return base + devSubdomainSuffix
	}
	return base
}

// LogicalSubdomain returns the canonical (prod) subdomain for any instance
// subdomain — i.e. it strips a trailing -dev. The platform_apps row, owner,
// billing, and collaborators are all keyed on this logical subdomain
// regardless of which instance a request names. Identity on a prod
// subdomain.
func LogicalSubdomain(instanceSub string) string {
	return strings.TrimSuffix(instanceSub, devSubdomainSuffix)
}

// IsDevSubdomain reports whether an instance subdomain names the dev
// instance. Relies on the no-hyphen-in-suffix invariant documented on
// devSubdomainSuffix.
func IsDevSubdomain(instanceSub string) bool {
	return strings.HasSuffix(instanceSub, devSubdomainSuffix)
}

// resolveBuildEnv picks the environment for a build-loop operation
// (write_file, edit_file, push, logs, …). An explicitly-requested env always
// wins. With no request, the default is dev for an app that HAS a dev instance
// (devProvisioned), else prod — so existing prod-only apps behave exactly as
// today and a dev-mode app's edit loop defaults to its dev instance (the
// "benmore push -> dev" model). Pure logic so it unit-tests anywhere.
func resolveBuildEnv(requested string, devProvisioned bool) (AppEnv, error) {
	if strings.TrimSpace(requested) != "" {
		return ParseEnv(requested)
	}
	if devProvisioned {
		return EnvDev, nil
	}
	return EnvProd, nil
}

// EnvOfSubdomain returns the environment a given instance subdomain serves.
func EnvOfSubdomain(instanceSub string) AppEnv {
	if IsDevSubdomain(instanceSub) {
		return EnvDev
	}
	return EnvProd
}

// --- instance addressing -------------------------------------------------
//
// These derive the on-disk dir, the systemd unit, and the Linux user for a
// given (logical app, env). They mirror the conventions already hard-coded
// in deploy_systemd.go / mcp_tools_create.go (appDir = appsDir/<sub>; unit =
// "benmore-app@<sub>.service"; user = "benmore-app-<sub>") so that routing,
// reload, and per-app-user logic all stay consistent across both instances.
// Pure path/string logic — no filesystem or systemd I/O — so the host-only
// provisioning code can build a clean API on top and unit tests can run
// anywhere.

// InstanceDir is the on-disk directory for an app instance:
// <appsDir>/<sub> for prod, <appsDir>/<sub>-dev for dev.
func InstanceDir(appsDir, logicalSub string, env AppEnv) string {
	return filepath.Join(appsDir, InstanceSubdomain(logicalSub, env))
}

// systemd template unit prefixes. prod and dev use SEPARATE templates so
// the dev unit's instance specifier can be the LOGICAL subdomain — letting
// the dev template resolve User=benmore-app-%i (= benmore-app-<sub>, prod's
// user) without a separate "-dev" account (which would overflow useradd's
// 32-char cap) and without a runtime drop-in write to /etc/systemd/system.
// The dev template (scripts/benmore-dev@.service) appends "-dev" to all its
// paths (WorkingDirectory=/opt/benmore/apps/%i-dev, etc.) and carries the
// smaller dev resource caps. Both templates are installed once on the host.
const (
	prodUnitPrefix = "benmore-app@"
	devUnitPrefix  = "benmore-dev@"
)

// InstanceUnit is the systemd unit name for an app instance:
//
//	prod : benmore-app@<sub>.service   (instance specifier = <sub>)
//	dev  : benmore-dev@<sub>.service   (instance specifier = LOGICAL <sub>;
//	                                     template appends -dev to paths)
//
// Note the dev unit's instance specifier is the LOGICAL subdomain, NOT
// <sub>-dev — that's what lets the shared template resolve the right user
// and paths. Callers that hold a routing subdomain should pass it through
// LogicalSubdomain (InstanceUnit does this defensively anyway).
func InstanceUnit(logicalSub string, env AppEnv) string {
	base := LogicalSubdomain(logicalSub)
	if env == EnvDev {
		return devUnitPrefix + base + ".service"
	}
	return prodUnitPrefix + base + ".service"
}

// UnitForSubdomain maps a ROUTING subdomain (the ports.json key — either
// <sub> or <sub>-dev) to the systemd unit that serves it. This is the form
// reload/remove paths want: they hold the routing subdomain and need the
// unit. For a prod subdomain it returns exactly "benmore-app@<sub>.service",
// byte-identical to the literal it replaces.
func UnitForSubdomain(routingSub string) string {
	return InstanceUnit(LogicalSubdomain(routingSub), EnvOfSubdomain(routingSub))
}

// PerAppUser is the Linux system user an instance runs as. Per the locked
// 2026-06-03 decision, the DEV instance reuses PROD's user — there is no
// "-dev" user — so this is always derived from the LOGICAL (prod) subdomain
// regardless of env. (A separate dev user would overflow useradd's 32-char
// cap for longer slugs and wreck the fleet migration; see the handoff doc.)
// The dev unit gets there via a systemd drop-in that overrides User=/Group=
// back to this value — see DevUnitDropInOverride.
func PerAppUser(logicalSub string) string {
	return "benmore-app-" + LogicalSubdomain(logicalSub)
}

// Dev resource caps live in the dev systemd template
// (scripts/benmore-dev@.service: MemoryMax=128M, MemoryHigh=96M), NOT in
// generated config — locked decision #2 (dev caps < prod's 256M) is a
// static property of the dev template, so there is nothing to compute at
// provision time.
