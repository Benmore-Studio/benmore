//go:build !cli

package main

// Owner control surface for the connector switches (exposure, approved
// writes). It runs inside the per-app process on purpose: the owner-only
// authority directory is readable and writable only by the process that owns
// it (the one that serves connector calls), and write enablement must verify
// the app's own captured generation and database. The platform router only
// authorizes the owner and forwards here with a short-lived token signed by
// this instance's own server secret (same single-audience shape as the import
// and generated-types tokens, with a distinct tag and purpose key so none
// verifies as another) and bound to the one change it authorizes.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	appMCPControlRoute       = "/api/_internal/mcp/connector"
	appMCPControlTokenHeader = "X-Benmore-MCP-Control-Token"
	appMCPControlTokenTTL    = 30 * time.Second
	// appMCPControlTimeout bounds one action, enrollment included. A caller
	// hanging up must not abandon an enrollment half way, so the action does
	// not inherit the request context.
	appMCPControlTimeout = 90 * time.Second
)

type appMCPConnectorRequest struct {
	Action string `json:"action"` // status, enable or disable
	Writes bool   `json:"writes"`
	// Export and Publication identify which reserved capability switch is
	// being controlled. enable sets selected switches; disable clears them.
	Export      bool `json:"export"`
	Publication bool `json:"publication"`
	// Revoke, with disable, also rotates the read epoch, invalidating every
	// connector grant and token. Plain disable is a pause.
	Revoke bool `json:"revoke"`
	// AutoApprove, with enable --writes, turns grant-consented auto-approval
	// on (with a fresh epoch); with disable it turns only auto-approval off.
	AutoApprove bool `json:"auto_approve,omitempty"`
}

// binding is the exact change a token authorizes. The auto-approve flag is
// appended only when set: a token minted for --writes alone cannot be
// replayed to turn auto-approval on, and a runtime that predates the flag
// computes a shorter binding and refuses such a token.
func (r appMCPConnectorRequest) binding() string {
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	binding := r.Action + ":" + flag(r.Writes) + ":" + flag(r.Revoke) + ":" + flag(r.Export) + ":" + flag(r.Publication)
	if r.AutoApprove {
		binding += ":1"
	}
	return binding
}

// appMCPControlKey derives a purpose key so a control token can never verify
// as any other token signed with the same server secret (import, types, ...).
func appMCPControlKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("benmore-mcp-control-v1"))
	return mac.Sum(nil)
}

// mintAppMCPControlToken signs
// "mcpctl.<exp>.<b64 subject>.<action:writes:revoke>.<app.Dir>", so a captured
// token authorizes only the one change it was minted for.
func mintAppMCPControlToken(appDir string, exp time.Time, secret, subject, binding string) string {
	payload := fmt.Sprintf("mcpctl.%d.%s.%s.%s", exp.Unix(), base64.RawURLEncoding.EncodeToString([]byte(subject)), binding, appDir)
	mac := hmac.New(sha256.New, appMCPControlKey(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyAppMCPControlToken checks MAC (constant time), expiry, the TTL ceiling
// and the audience in that order and returns the minting owner's identity and
// the change the token authorizes.
func verifyAppMCPControlToken(app *App, token string) (subject, binding string, ok bool) {
	if app == nil || serverSecret == "" {
		return "", "", false
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	mac := hmac.New(sha256.New, appMCPControlKey(serverSecret))
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", "", false
	}
	// app.Dir may contain '.', so it is the last field and is never split.
	fields := strings.SplitN(string(payload), ".", 5)
	if len(fields) != 5 || fields[0] != "mcpctl" {
		return "", "", false
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", "", false
	}
	now := time.Now()
	if now.Unix() >= exp || time.Unix(exp, 0).Sub(now) > appMCPControlTokenTTL || fields[4] != app.Dir {
		return "", "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(fields[2])
	if err != nil || len(decoded) == 0 {
		return "", "", false
	}
	return string(decoded), fields[3], true
}

// appMCPConnectorStatus is the owner-visible switch state. It never carries
// the epochs, which are the credentials connector calls compare against.
type appMCPConnectorStatus struct {
	AuthorityConfigured bool `json:"authority_configured"`
	Exposed             bool `json:"exposed"`
	ApprovedWrites      bool `json:"approved_writes"`
	AutoApprove         bool `json:"auto_approve"`
	ExternalExport      bool `json:"external_export"`
	PublicPublication   bool `json:"public_publication"`
	ManifestPresent     bool `json:"manifest_present"`
	ManifestValid       bool `json:"manifest_valid"`
	CommandTools        int  `json:"command_tools"`
	// GrantApprovalTools counts command tools declared approval: grant, the
	// only ones auto-approval can apply.
	GrantApprovalTools int `json:"grant_approval_tools"`
	// Enrollment is none, pending, active, stale (active for an older owner
	// epoch; enable --writes re-enrolls it), retired (ledger removed when the
	// connector was disabled; enable --writes re-enrolls it) or unavailable.
	Enrollment string `json:"revision_enrollment"`
	// ApprovedWritesOffReason is set only while a restart's suspension of
	// approved writes is still recorded and writes did not resume (changed
	// reviewed digests, stale review, unverified enrollment). Fixed phrase.
	ApprovedWritesOffReason string `json:"approved_writes_off_reason,omitempty"`
	// Problem is a fixed phrase, never raw error text or a filesystem path.
	Problem string `json:"problem,omitempty"`
}

func appMCPConnectorStatusFor(ctx context.Context, app *App) (st appMCPConnectorStatus) {
	app.mu.RLock()
	withheld := app.mcpWithheld != ""
	app.mu.RUnlock()
	if withheld {
		defer func() {
			st.ManifestPresent = true
			if st.Problem == "" {
				st.Problem = "mcp.yaml's review does not match the current source, so the connector is off; review the source, run `benmore mcp review <appdir> --reviewed` and push mcp.yaml"
			}
		}()
	}
	st = appMCPConnectorStatus{AuthorityConfigured: os.Getenv("BENMORE_MCP_AUTHORITY_DIR") != "", Enrollment: "unavailable"}
	if generation := snapshotAppMCPGeneration(app); generation != nil && generation.manifest != nil {
		st.ManifestPresent = true
		st.ManifestValid = validateAppMCPWriteManifest(app.Dir, generation.manifest) == nil
		for _, tool := range generation.manifest.Tools {
			if tool.Handler.Kind == "flow" && tool.Handler.Operation == "command" {
				st.CommandTools++
				if tool.Approval == "grant" {
					st.GrantApprovalTools++
				}
			}
		}
	}
	if !st.AuthorityConfigured {
		st.Problem = "connector authority directory is not configured for this instance"
		return st
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if os.IsNotExist(err) {
		st.Enrollment = "none"
		return st
	}
	if err != nil {
		st.Problem = "connector authority state is unreadable"
		return st
	}
	st.Exposed, st.ExternalExport, st.PublicPublication = state.Exposed, state.ExternalExport, state.PublicPublication
	st.ApprovedWrites = state.Version == 2 && state.ApprovedWrites != nil && *state.ApprovedWrites
	st.AutoApprove = st.ApprovedWrites && state.AutoApprove
	_, release, lease, err := acquireAppMCPWritePolicy(ctx, app.Dir)
	if err != nil {
		st.Problem = "revision enrollment state is unreadable"
		return st
	}
	defer release()
	switch enrollment, err := readAppMCPRevisionEnrollment(lease); {
	case os.IsNotExist(err):
		st.Enrollment = "none"
	case err != nil:
		st.Problem = "revision enrollment record is invalid"
	case enrollment.State == "pending":
		st.Enrollment = "pending"
	case enrollment.State == "retired":
		st.Enrollment = "retired"
	case enrollment.OwnerEpoch != state.Epoch:
		st.Enrollment = "stale"
	default:
		st.Enrollment = "active"
	}
	st.ApprovedWritesOffReason = appMCPWritesOffReason(st, state, snapshotAppMCPGeneration(app), withheld)
	return st
}

// appMCPConnectorApply runs one owner switch change. enable turns exposure on
// (and, with writes, enrolls revisions and turns approved writes on); disable
// with writes only turns writes off; disable is a PAUSE: both off, grants and
// tokens survive a later enable; disable with revoke also rotates the read
// epoch, invalidating every connector grant and token, and deletes every
// user's stored external connection credential. Turning writes off
// rotates the write epoch, so an approved but uncommitted operation can never
// run, including after a later re-enable; stored operations, approvals and
// audit rows are left in place.
func appMCPConnectorApply(ctx context.Context, app *App, req appMCPConnectorRequest) error {
	action, writes := req.Action, req.Writes
	if os.Getenv("BENMORE_MCP_AUTHORITY_DIR") == "" {
		return errors.New("connector authority directory is not configured for this instance")
	}
	if req.Revoke && (action != "disable" || writes || req.Export || req.Publication || req.AutoApprove) {
		return errors.New("revoke applies to a full disable only")
	}
	if req.AutoApprove && action == "enable" && !writes {
		return errors.New("auto-approve requires --writes")
	}
	switch {
	case action == "disable" && req.Revoke:
		_, err := updateAppMCPEpochContext(ctx, app.Dir, false, true, false)
		// The upstream credentials users stored for its connections go too,
		// even if the epoch could not rotate: revoke only removes access.
		_, purgeErr := purgeAppMCPConnectionCredentials(ctx, app.DB, nil)
		return errors.Join(appMCPRetireAfterDisable(ctx, app, appMCPNothingToDisable(app, err)), purgeErr)
	case action == "disable" && (req.Export || req.Publication || req.AutoApprove):
		if writes {
			if _, err := setAppMCPApprovedWritesContext(ctx, app.Dir, false); err != nil {
				return err
			}
		}
		_, err := mutateAppMCPEpochContext(ctx, app.Dir, nil, false, false, func(state *appMCPEpochState) error {
			if req.AutoApprove && state.Version == 2 {
				// Rotate even when already off: disabling is always a fresh epoch.
				state.AutoApprove = false
				var rotateErr error
				if state.AutoApproveEpoch, rotateErr = rotateAppMCPCapabilityEpoch(); rotateErr != nil {
					return rotateErr
				}
			}
			if req.Export {
				state.ExternalExport = false
				var rotateErr error
				state.ExternalExportEpoch, rotateErr = rotateAppMCPCapabilityEpoch()
				if rotateErr != nil {
					return rotateErr
				}
			}
			if req.Publication {
				state.PublicPublication = false
				var rotateErr error
				state.PublicPublicationEpoch, rotateErr = rotateAppMCPCapabilityEpoch()
				if rotateErr != nil {
					return rotateErr
				}
			}
			return nil
		})
		return appMCPNothingToDisable(app, err)
	case action == "disable" && writes:
		_, err := setAppMCPApprovedWritesContext(ctx, app.Dir, false)
		return appMCPNothingToDisable(app, err)
	case action == "disable":
		_, err := updateAppMCPEpochContext(ctx, app.Dir, false, false, false)
		return appMCPRetireAfterDisable(ctx, app, appMCPNothingToDisable(app, err))
	case action != "enable":
		return fmt.Errorf("unknown action %q", action)
	}
	generation := snapshotAppMCPGeneration(app)
	if generation == nil || generation.manifest == nil {
		app.mu.RLock()
		withheld := app.mcpWithheld != ""
		app.mu.RUnlock()
		if withheld {
			return errors.New("mcp.yaml's review does not match the current source, so the connector is off; review the source, run `benmore mcp review <appdir> --reviewed` and push mcp.yaml before enabling")
		}
		return errors.New("no reviewed mcp.yaml is loaded; nothing to expose")
	}
	if !writes {
		exposed := true
		_, err := mutateAppMCPEpochContext(ctx, app.Dir, &exposed, false, true, func(state *appMCPEpochState) error {
			if req.Export {
				state.ExternalExport = true
				var rotateErr error
				state.ExternalExportEpoch, rotateErr = rotateAppMCPCapabilityEpoch()
				if rotateErr != nil {
					return rotateErr
				}
			}
			if req.Publication {
				state.PublicPublication = true
				var rotateErr error
				state.PublicPublicationEpoch, rotateErr = rotateAppMCPCapabilityEpoch()
				if rotateErr != nil {
					return rotateErr
				}
			}
			return nil
		})
		return err
	}
	if err := validateAppMCPWriteManifest(app.Dir, generation.manifest); err != nil {
		return fmt.Errorf("manifest check failed: %w", err)
	}
	commands, grantTools := 0, 0
	for _, tool := range generation.manifest.Tools {
		if tool.Handler.Kind == "flow" && tool.Handler.Operation == "command" {
			commands++
			if tool.Approval == "grant" {
				grantTools++
			}
		}
	}
	if commands == 0 {
		return errors.New("manifest declares no command tools; approved writes stay off")
	}
	if req.AutoApprove && grantTools == 0 {
		return errors.New("manifest declares no command tool with approval: grant; nothing to auto-approve, so no switch changed")
	}
	wasExposed := false
	if state, err := currentAppMCPEpoch(app.Dir); err == nil {
		wasExposed = state.Exposed
	} else if !os.IsNotExist(err) {
		return err
	}
	exposed := true
	if _, err := mutateAppMCPEpochContext(ctx, app.Dir, &exposed, false, true, func(state *appMCPEpochState) error {
		if req.Export {
			state.ExternalExport = true
			var rotateErr error
			state.ExternalExportEpoch, rotateErr = rotateAppMCPCapabilityEpoch()
			if rotateErr != nil {
				return rotateErr
			}
		}
		if req.Publication {
			state.PublicPublication = true
			var rotateErr error
			state.PublicPublicationEpoch, rotateErr = rotateAppMCPCapabilityEpoch()
			if rotateErr != nil {
				return rotateErr
			}
		}
		return nil
	}); err != nil {
		return err
	}
	err := appMCPEnrollAndEnableWrites(ctx, app, generation)
	if err == nil && req.AutoApprove {
		// After writes are on: enabling writes rotates the write epoch, which
		// ends auto-approval. The new switch always gets a fresh epoch.
		if _, autoErr := setAppMCPAutoApproveContext(ctx, app.Dir, true); autoErr != nil {
			return fmt.Errorf("approved writes are on, auto-approval stays off: %w", autoErr)
		}
	}
	if err != nil && !wasExposed {
		// Refusing must not leave a read-only connector live that the owner
		// did not ask for. The caller's deadline may be what failed, so the
		// rollback gets its own.
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, rollback := updateAppMCPEpochContext(rollbackCtx, app.Dir, false, false, false); rollback != nil {
			err = errors.Join(err, errors.New("could not restore exposure off"))
		}
	}
	return err
}

// appMCPRetireAfterDisable removes the revision ledger once exposure is off
// (retireAppMCPRevisionLedger). The disable has already applied, so a failure
// is logged, not returned; start-up retries it.
func appMCPRetireAfterDisable(ctx context.Context, app *App, disableErr error) error {
	if disableErr != nil {
		return disableErr
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := retireAppMCPRevisionLedger(ctx, app, generation != nil && generation.manifest != nil); err != nil {
		log.Printf("MCP revision ledger: could not remove the ledger after disable: %v", err)
	}
	return nil
}

// appMCPNothingToDisable turns an update failure into success ONLY when the
// authority root is present and valid and just this app's state file is
// missing (nothing was ever enabled, so no grant can exist). A missing or
// unusable root is a failure: a revoke must never report success unchecked.
func appMCPNothingToDisable(app *App, err error) error {
	if err == nil || !os.IsNotExist(err) {
		return err
	}
	root, key, rootErr := appMCPAuthorityRoot(app.Dir)
	if rootErr != nil {
		return errors.New("connector authority is unavailable")
	}
	defer root.Close()
	if _, statErr := root.Lstat(key + ".json"); os.IsNotExist(statErr) {
		return nil
	}
	return err
}

// Each helper acquires and releases its own policy lease; they cannot nest.
// An enrollment recorded for an older owner epoch (after a revoke or a
// restore) is re-enrolled; one stuck pending needs an operator.
func appMCPEnrollAndEnableWrites(ctx context.Context, app *App, generation *appMCPRuntimeGeneration) error {
	_, release, lease, err := acquireAppMCPWritePolicy(ctx, app.Dir)
	if err != nil {
		return err
	}
	state, stateErr := lease.read()
	enrollment, readErr := readAppMCPRevisionEnrollment(lease)
	release()
	if stateErr != nil {
		return errors.New("connector authority state is unreadable")
	}
	switch {
	case os.IsNotExist(readErr):
		if _, err := initializeAppMCPRevisionEnrollment(ctx, app, generation); err != nil {
			return fmt.Errorf("revision enrollment failed: %w", err)
		}
	case readErr != nil:
		return errors.New("revision enrollment record is unusable; an operator must repair it before approved writes can be enabled")
	case enrollment.State == "pending":
		return errors.New("revision enrollment is pending from an interrupted attempt; an operator must repair it before approved writes can be enabled")
	case enrollment.State == "retired" || enrollment.OwnerEpoch != state.Epoch:
		if _, err := repairAppMCPRevisionEnrollment(ctx, app, generation); err != nil {
			return fmt.Errorf("revision re-enrollment failed: %w", err)
		}
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(ctx, app, generation); err != nil {
		return fmt.Errorf("approved writes stay off: %w", err)
	}
	return nil
}

var appMCPControlLocks sync.Map // canonical app path -> *sync.Mutex

// lockAppMCPControl serializes enable and disable (apply plus audit) per app,
// keyed like the policy gate, so concurrent requests cannot interleave a
// rollback with another change however the app directory is spelled.
func lockAppMCPControl(dir string) (unlock func()) {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	mu, _ := appMCPControlLocks.LoadOrStore(canonicalDBPath(dir), &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	return mu.(*sync.Mutex).Unlock
}

var appMCPControlPathText = regexp.MustCompile(`\S*/\S*|\d{1,3}(\.\d{1,3}){3}\S*`)

// appMCPControlText is error text safe to return: any token containing a
// slash (filesystem paths, URLs) or starting with an IPv4 address (a loopback
// host:port) is removed.
func appMCPControlText(err error) string {
	return appMCPControlPathText.ReplaceAllString(err.Error(), "<path>")
}

// appMCPConnectorAudit records who changed which switch from what to what.
// Only booleans are recorded, never an epoch.
func appMCPConnectorAudit(app *App, subject string, req appMCPConnectorRequest, before, after appMCPConnectorStatus, applyErr error) error {
	view := func(st appMCPConnectorStatus) map[string]any {
		return map[string]any{"exposed": st.Exposed, "approved_writes": st.ApprovedWrites, "auto_approve": st.AutoApprove, "external_export": st.ExternalExport, "public_publication": st.PublicPublication}
	}
	oldValues, newValues := view(before), view(after)
	newValues["action"], newValues["writes_flag"], newValues["export_flag"], newValues["publication_flag"], newValues["revoke"] = req.Action, req.Writes, req.Export, req.Publication, req.Revoke
	newValues["auto_approve_flag"] = req.AutoApprove
	if applyErr != nil {
		newValues["refused"] = appMCPControlText(applyErr)
	}
	oldJSON, _ := json.Marshal(oldValues)
	newJSON, _ := json.Marshal(newValues)
	return insertAuditRowChecked(app.DB, "mcp_connector_switch", "mcp_connector", "", &Session{Email: subject}, string(oldJSON), string(newJSON))
}

// registerAppMCPConnectorControl mounts the owner-only control endpoint. It
// accepts only the router-minted owner token, bound to the requested change:
// no cookie, API token or in-app admin session reaches it.
func registerAppMCPConnectorControl(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("POST "+appMCPControlRoute, func(w http.ResponseWriter, r *http.Request) {
		subject, binding, ok := verifyAppMCPControlToken(app, r.Header.Get(appMCPControlTokenHeader))
		if !ok {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "owner token required"})
			return
		}
		var req appMCPConnectorRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		if !hmac.Equal([]byte(binding), []byte(req.binding())) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "owner token does not authorize this change"})
			return
		}
		if req.Action != "status" && req.Action != "enable" && req.Action != "disable" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "action must be status, enable or disable"})
			return
		}
		if req.Action == "status" && (req.Writes || req.Export || req.Publication || req.Revoke || req.AutoApprove) {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "status does not accept switch flags"})
			return
		}
		if req.Action != "status" {
			// Take the lock before the deadline starts, so waiting behind
			// another change does not spend this one's budget.
			defer lockAppMCPControl(app.Dir)()
		}
		ctx, cancel := context.WithTimeout(context.Background(), appMCPControlTimeout)
		defer cancel()
		if req.Action == "status" {
			httpJSON(w, http.StatusOK, map[string]any{"status": appMCPConnectorStatusFor(ctx, app)})
			return
		}
		before := appMCPConnectorStatusFor(ctx, app)
		applyErr := appMCPConnectorApply(ctx, app, req)
		after := appMCPConnectorStatusFor(ctx, app)
		out := map[string]any{"status": after, "before": before}
		if applyErr != nil {
			out["error"] = appMCPControlText(applyErr)
		}
		auditErr := appMCPConnectorAudit(app, subject, req, before, after, applyErr)
		switch {
		case auditErr != nil && applyErr == nil:
			// The switch HAS changed; say so, so the caller does not retry blind.
			out["applied"] = true
			out["error"] = "applied; audit failed: " + appMCPControlText(auditErr)
			id := recordRequestError(r, "[_mcp connector control] audit failed: "+appMCPControlText(auditErr))
			w.Header().Set(requestIDHeader, id)
			out["request_id"] = id
			httpJSON(w, http.StatusInternalServerError, out)
		case applyErr != nil:
			if auditErr != nil {
				out["audit_error"] = appMCPControlText(auditErr)
			}
			httpJSON(w, http.StatusConflict, out)
		default:
			httpJSON(w, http.StatusOK, out)
		}
	})
}
