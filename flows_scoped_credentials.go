//go:build !cli

package main

// Scoped credentials on flows.
//
// A scoped credential (scopedCredential: an API token or Bearer session
// minted with explicit scopes, a connector grant) is narrowed by auto-CRUD
// table by table. A flow has no table of its own, so the only scope it can
// ask for is the permissions: it declares. A flow that declares none ran for
// a notes:read token as the full account, writes included.
//
// The rule: a scoped credential acts as its user in a flow only through the
// flow's permissions:. An auth-required or role: flow without them refuses it
// (403), a public or auth: optional flow runs for it as for an anonymous
// caller, scheduling refuses such a flow and /_internal/flows.json leaves it
// out. Hosted apps already depend on the old behaviour (a partner API whose
// flow authorizes the client itself), so the rule is advisory until the
// operator sets BENMORE_PLATFORM_SCOPED_FLOWS_REQUIRE_PERMISSIONS=1: until
// then such a call runs as before and the app log names the flow, at most
// once per app and flow every ten minutes, so owners can declare
// permissions: first. Unscoped credentials and ordinary sign-ins are never
// affected.

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// scopedFlowsRequirePermissionsEnv is the operator's switch that enforces
// the rule. BENMORE_PLATFORM_* keys are platform-reserved
// (tenantReservedEnvKey): no app can store one in its environment, the
// router drops them when it writes an app's env file, and env.yaml values
// never reach the process environment. Hosted tenant units receive it from
// tenant.env (scripts/tenant-env.py).
const scopedFlowsRequirePermissionsEnv = "BENMORE_PLATFORM_SCOPED_FLOWS_REQUIRE_PERMISSIONS"

func scopedFlowsRequirePermissions() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(scopedFlowsRequirePermissionsEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// scopedCredentialFlowRefusal is the 403 a scoped credential gets, once the
// rule is enforced, from an auth-required or role: flow that declares no
// permissions: the flow has no scope a narrowed token could have been minted
// for.
const scopedCredentialFlowRefusal = "this credential is limited to the scopes it was issued with, and this flow declares no permissions: a scoped API token or session can call an auth-required flow only when the flow lists on.request.permissions within its scopes. Declare permissions: on the flow, or call it with an unscoped credential"

// scopedFlowUnpermitted reports whether session is a scoped credential
// reaching flow, which declares no permissions:. Callers decide by
// scopedFlowsRequirePermissions whether to refuse it or note it
// (logScopedFlowAdvisory).
func scopedFlowUnpermitted(flow *Flow, session *Session) bool {
	return flow != nil && len(flow.Permissions) == 0 && scopedCredential(session)
}

// scopedFlowAdvisoryLogged throttles logScopedFlowAdvisory per app and flow.
var scopedFlowAdvisoryLogged sync.Map // app dir + "\x00" + flow name -> time.Time

const scopedFlowAdvisoryInterval = 10 * time.Minute

// logScopedFlowAdvisory notes, at most once per app and flow every ten
// minutes, a scoped credential that ran flow as its full account because the
// rule is not enforced yet. anonymousLater is true for a public or optional
// flow, which will run for such a credential as for an anonymous caller.
func logScopedFlowAdvisory(app *App, flow *Flow, session *Session, anonymousLater bool) {
	if app == nil || flow == nil || session == nil {
		return
	}
	key := app.Dir + "\x00" + flow.Name
	now := time.Now()
	if last, ok := scopedFlowAdvisoryLogged.Load(key); ok && now.Sub(last.(time.Time)) < scopedFlowAdvisoryInterval {
		return
	}
	scopedFlowAdvisoryLogged.Store(key, now)
	later := "A later release refuses this (403)"
	if anonymousLater {
		later = "A later release runs it for such a credential as for an anonymous caller (no user_id bound)"
	}
	log.Printf("flow %s [%s]: a scoped API token or session (scopes %q) ran it as its full account, and the flow declares no permissions:. %s: declare on.request.permissions: [<the scopes its callers' tokens carry>] on the flow, or have the integration use an unscoped (*) credential (api(at:\"flows\") permissions)",
		flow.Name, filepath.Base(app.Dir), session.CredentialScopes, later)
}
