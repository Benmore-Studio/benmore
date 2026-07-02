//go:build !cli

package main

import (
	"database/sql"
	"log"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// App holds the entire application state.
type App struct {
	Dir      string
	DB       *sql.DB
	Pages    map[string]*Page
	Tables   []Table
	Design   *DesignConfig
	Partials map[string]string
	Sessions *SessionStore
	Hooks    *HookConfig
	Flows    []Flow
	// Scopes lets app.yaml declare per-table override SQL fragments
	// for the auto-CRUD's read filter. Keyed by table name. The most
	// common use is `public_read_when: "status = 'published'"` so a
	// "publish a story" use case doesn't require writing a custom
	// flow with raw SQL - the auto-CRUD GET endpoint returns the
	// public rows for anonymous + non-owner sessions while still
	// scoping write paths by user_id.
	Scopes map[string]ScopeConfig
	Access *AccessConfig
	// WSRooms (v2.7.164) binds WebSocket room-name patterns to
	// membership tables (app.yaml `ws_rooms:`), so joining
	// "room-:id"-shaped rooms requires a membership row - the same
	// EXISTS semantics as the member-of: access mode. Rooms matching
	// no pattern keep the historical any-authed-user behavior.
	WSRooms         []WSRoomRule
	Workflows       *WorkflowConfig
	Computed        *ComputedFieldConfig
	Encrypted       *EncryptedFieldConfig
	Cron            *CronConfig
	JoinMap         JoinMap
	UUIDTables      map[string]bool // tables with TEXT PRIMARY KEY (UUID)
	Group           *GroupConfig
	Roles           *RolesConfig
	Paths           *AuthPaths
	Validators      *ValidatorConfig
	Admin           *AdminConfig  // admin.yaml - Django-ModelAdmin-style auto-admin customisation
	SessionDuration time.Duration // per-app session lifetime (no global race in multi-tenant)
	AppID           string        // auto-generated UUID for this app (persisted in .benmore/app_id)
	ExternalID      string        // optional external system ID from app.yaml (e.g., project tracker ID)
	DevMode         bool
	// Optional hosting metadata, populated by the platform layer when present
	// (all zero/empty in a self-hosted build). Drives the "Built with Benmore"
	// badge when set.
	OwnerPlan    string    // hosting plan name, if any
	BuildSeconds int       // accumulated build time, if tracked
	PublishedAt  time.Time // first publish timestamp, if tracked
	// Stop is closed when the app is being unloaded. Background workers
	// (locks cleanup, pub/sub pollers, etc.) must select on this to exit
	// cleanly before App.DB is closed, otherwise they leak goroutines that
	// keep ticking against a closed DB handle.
	Stop chan struct{}
	// CronStop is closed on every hot reload (SIGHUP) BEFORE a fresh
	// cron scheduler is spawned. v2.7.40 fix: pre-fix, the cron ticker
	// listened only on app.Stop (process exit), so every SIGHUP
	// silently leaked a goroutine. Each leaked goroutine held its own
	// stale `lastFire` snapshot and would re-fire `every 15m` jobs on
	// its independent 60s cadence - the agent-visible bug was "every
	// time I edit a file, the cron jobs fire again." This channel is
	// the per-scheduler-instance stop signal; reloadAppConfig closes
	// it, StartCronScheduler creates a fresh one.
	CronStop chan struct{}
	// ServerPort is the bound port of the running HTTP server. Set at
	// StartServer time so subsystems that need to dial localhost (e.g.
	// to render a page back into a different request context) can find
	// the right port. Zero when no server is running (CLI subcommands,
	// MCP context).
	ServerPort int
	// walShippedOffset is maintained by the optional platform WAL shipper.
	// WAL maintenance may only TRUNCATE when this offset has caught up to
	// the current data.db-wal size; otherwise it runs PASSIVE so frames are
	// checkpointed without being discarded before S3 shipping sees them.
	walShippedOffset atomic.Int64
	// walCheckpointMu serializes the two in-process checkpointers - the WAL
	// maintenance loop (db.go) and the WAL shipper's base snapshot
	// (wal_shipper.go) - so a maintenance checkpoint can't write data.db while
	// the shipper is taking its base snapshot.
	walCheckpointMu sync.Mutex
	mu              sync.RWMutex
}

// Shutdown signals background workers to stop and closes the DB.
// Safe to call multiple times.
//
// Runs `PRAGMA wal_checkpoint(TRUNCATE)` before close so the next
// process opens with a clean WAL - no partially-written frames left
// behind, no chance of "file is not a database" / "disk I/O error"
// on next boot from a torn WAL header. Pre-2.7.32 the close path
// relied on SQLite's autocheckpoint, which doesn't run during the
// final connection close, so any frames that hadn't been
// auto-checkpointed during the process's lifetime sat in the WAL at
// shutdown - fine on a clean SQLite reload, but if the next process
// race-failed to open them (e.g. permission glitch, mid-deploy file
// swap), auto-recovery would replace data.db with the most recent
// pre-migrate backup and lose every uncheckpointed write.
//
// The checkpoint is best-effort: a busy-step error is logged but
// shouldn't block the close path (we still want to release the file
// handle). Apps with very long-running queries during shutdown may
// see "database is locked" here - that's OK, the WAL still survives
// for the next process.
func (app *App) Shutdown() {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.Stop != nil {
		select {
		case <-app.Stop:
			// already closed
		default:
			close(app.Stop)
		}
	}
	if app.DB != nil {
		// Force a final WAL checkpoint so the next process opens with
		// a clean WAL. Ignore errors - we still need to close the DB
		// regardless, and the comment above describes why a failure
		// here is survivable.
		if _, err := app.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			log.Printf("shutdown: wal_checkpoint: %v", err)
		}
		app.DB.Close()
	}
}

// FeatureEnabled returns whether a named feature is enabled for this app.
// Each feature has its own default - admin/sse/ws/docs/analytics default
// to true, testing defaults to false (opt-in). Delegates to
// FeaturesConfig.IsEnabled so the same defaults apply whether Design is
// nil or fully populated. Previously this returned true for EVERY
// feature when Design was nil, which silently auto-enabled the testing
// banner on every fresh `benmore serve` app even with no `features:` block.
func (app *App) FeatureEnabled(name string) bool {
	if app.Design == nil {
		return (*FeaturesConfig)(nil).IsEnabled(name)
	}
	return app.Design.Features.IsEnabled(name)
}

// FeedbackWidgetEnabled reports whether the visitor feedback widget + its
// read/write API should be active. True when testing mode is on (drafts /
// QA preview) OR when features.feedback is explicitly opted in. The latter
// keeps the widget on a PUBLISHED prod app - `publish` only flips
// features.testing, never features.feedback - so clients who want live
// feedback set features.feedback: true and it survives going live. The
// amber "testing" banner + the demo password gate stay gated on
// features.testing alone; prod feedback is silent.
func (app *App) FeedbackWidgetEnabled() bool {
	return app.FeatureEnabled("testing") || app.FeatureEnabled("feedback")
}

// IsUUIDTable returns true if the table uses TEXT PRIMARY KEY (UUID) instead of INTEGER AUTOINCREMENT.
func (app *App) IsUUIDTable(table string) bool {
	return app.UUIDTables != nil && app.UUIDTables[table]
}

// AuthPaths holds discovered URL paths for auth routes.
// Paths are discovered from page type="" attributes at load time.
// Falls back to conventional defaults if no typed page exists.
type AuthPaths struct {
	Login          string // discovered from type="login", default: /login
	Signup         string // discovered from type="signup", default: /signup
	Logout         string // POST-only, default: /logout
	ForgotPassword string // discovered from type="forgot-password", default: /forgot-password
	ResetPassword  string // discovered from type="reset-password", default: /reset-password
	VerifyEmail    string // GET-only, default: /verify-email
	VerifyOTP      string // discovered from type="verify-otp", default: /verify-otp
	VerifyMFA      string // discovered from type="verify-mfa", default: /verify-mfa
	Settings       string // discovered from type="settings", default: /settings
}

// DiscoverAuthPaths scans pages for type="" attributes and builds auth paths.
// Falls back to conventional defaults for any type not declared by the developer.
// Also falls back if a page exists at the conventional path without a type attribute
// (backwards compatibility).
func DiscoverAuthPaths(pages map[string]*Page) *AuthPaths {
	paths := &AuthPaths{
		Login:          "/login",
		Signup:         "/signup",
		Logout:         "/logout",
		ForgotPassword: "/forgot-password",
		ResetPassword:  "/reset-password",
		VerifyEmail:    "/verify-email",
		VerifyOTP:      "/verify-otp",
		VerifyMFA:      "/verify-mfa",
		Settings:       "/settings",
	}
	// Deterministic assignment. Two pages can legitimately (or by
	// mistake) declare the same type="..." - e.g. both login.html AND
	// a cli-auth.html marked type="login". Ranging a Go map is
	// UNORDERED, so the naive "last write wins" made app.Paths.Login
	// flaky: on one boot it resolved to /login, on another to
	// /cli-auth, and POST /login then 404'd nondeterministically.
	//
	// Rule, applied over routes in sorted order:
	//   1. A page whose route already equals the conventional default
	//      (/login, /signup, …) always wins - that's unambiguously the
	//      real auth page.
	//   2. Otherwise the lexicographically-first matching route wins
	//      (stable because we sort), so the result is identical on
	//      every boot regardless of map iteration order.
	routes := make([]string, 0, len(pages))
	for r := range pages {
		routes = append(routes, r)
	}
	sort.Strings(routes)

	// assign sets *cur from route unless *cur already holds a non-default
	// match (then only the conventional default may override it).
	assign := func(cur *string, def, route string) {
		if route == def { // the canonical page - always wins
			*cur = route
			return
		}
		if *cur == def { // still untouched default → take first candidate
			*cur = route
		}
		// else: *cur already holds an earlier (sorted) non-default
		// candidate - keep it for stability.
	}

	for _, route := range routes {
		switch pages[route].Type {
		case "login":
			assign(&paths.Login, "/login", route)
		case "signup":
			assign(&paths.Signup, "/signup", route)
		case "forgot-password":
			assign(&paths.ForgotPassword, "/forgot-password", route)
		case "reset-password":
			assign(&paths.ResetPassword, "/reset-password", route)
		case "verify-otp":
			assign(&paths.VerifyOTP, "/verify-otp", route)
		case "verify-mfa":
			assign(&paths.VerifyMFA, "/verify-mfa", route)
		case "settings":
			assign(&paths.Settings, "/settings", route)
		}
	}
	return paths
}

// RolesConfig holds developer-defined role → scope mappings from app.yaml.
type RolesConfig struct {
	Roles map[string]RoleDef
}

// RoleDef defines a single role: its own scopes plus the parents it
// inherits from. Inherited scopes are unioned at resolve time (see
// ResolveRoleScopes), so `editor: { scopes: posts:write, inherits: [viewer] }`
// effectively grants posts:read + posts:write.
//
// `Inherits` is allowed to be a single string ("inherits: viewer") OR
// a list ("inherits: [viewer, commenter]"). LoadRolesConfig normalises
// both to []string.
type RoleDef struct {
	Scopes   string   `yaml:"scopes"`
	Inherits []string `yaml:"inherits"`
}

// GroupConfig defines organization-level data scoping from app.yaml.
type GroupConfig struct {
	Table     string `yaml:"table"`      // membership table (e.g., "user_roles")
	Key       string `yaml:"key"`        // group-level foreign key column (e.g., "district_id")
	UserField string `yaml:"user_field"` // how to look up user in the membership table (e.g., "email")

	// RoleField (v2.7.164) names a membership-table column holding the
	// member's IN-TENANT role (e.g. member_role on company_members).
	// When set, the value joins session.Roles at session load, so
	// `role:company_admin` access modes resolve against the membership
	// table - tenant roles get real enforcement without a parallel
	// grant in _benmore_user_roles.
	RoleField string `yaml:"role_field"`

	// Bootstrap (v2.7.164) enables POST /api/_groups/create - the
	// atomic "create my org + my founding membership" primitive every
	// multi-tenant app previously had to hand-roll as a flow (the
	// group key is correctly stripped from client bodies, so a
	// groupless user couldn't found a tenant through plain CRUD).
	Bootstrap *GroupBootstrapConfig `yaml:"bootstrap"`
}

// GroupBootstrapConfig configures the founding-moment endpoint.
type GroupBootstrapConfig struct {
	OrgTable     string `yaml:"org_table"`     // the org/company table the group key points at
	FoundingRole string `yaml:"founding_role"` // written to groups.role_field on the founding membership (optional)
}

// WorkflowConfig holds all workflow state machine definitions for the app.
type WorkflowConfig struct {
	Workflows map[string]*Workflow
}

// Workflow defines a state machine for a single entity table.
type Workflow struct {
	Name         string
	Table        string
	Field        string
	Initial      string
	States       []string
	Transitions  map[string]map[string]Transition // from_state → to_state → rule
	OnTransition map[string][]Hook                // state_entered → hooks to fire
	Timeouts     map[string]WorkflowTimeout       // state → auto-transition
}

// Transition defines a single allowed state change.
type Transition struct {
	Role string // required role (empty = anyone)
	When string // optional condition
}

// WorkflowTimeout defines auto-transition after a duration in a state.
type WorkflowTimeout struct {
	After time.Duration
	To    string
}

// Page represents a single HTML page/route.
type Page struct {
	Route       string
	File        string
	RawHTML     string
	Auth        string // "required", "none", "" (default = none)
	Scope       string // "owner", ""
	Layout      string // "none" to skip sidebar wrapper
	Title       string
	Description string // meta description + OG description
	Image       string // OG image URL
	Robots      string // "noindex", "nofollow", etc.
	Require     string // generic user field gating: "plan:pro,enterprise verified:1"
	Type        string // page type: "login", "signup", "forgot-password", "reset-password", "verify-otp", "verify-mfa", "settings"
	Redirect    string // role-based redirect: "admin:/admin,user:/dashboard"
	Engine      string // frontmatter engine: "" (mustache default), "gotmpl", "raw"
}

// Table represents a database table discovered from schema.sql.
type Table struct {
	Name    string
	Columns []Column
	// FullText is the list of column-set indexes declared via
	// `@@fulltext([...])` in schema.prisma. Each entry becomes a
	// SQLite FTS5 virtual table (<Name>_fts) + sync triggers, and
	// /api/<Name>?q=... routes through it.
	FullText [][]string
}

// Column represents a table column.
type Column struct {
	Name    string
	Type    string
	NotNull bool
	Default string
	PK      bool
}

// ForeignKey represents a foreign key relationship.
type ForeignKey struct {
	Table  string
	Column string
}

// QueryTag represents a <query sql="..." as="..."> or <query from="..." pick="..."> in a template.
type QueryTag struct {
	SQL   string
	As    string
	From  string            // shorthand mode: table name
	Attrs map[string]string // all attributes for shorthand expansion
	Start int
	End   int
	Inner string
}

// FeaturesConfig holds opt-in/opt-out flags for framework features.
// All features default to enabled (true) for backwards compatibility.
type FeaturesConfig struct {
	Admin *bool `yaml:"admin"` // /admin panel (default: true)
	// Search removed - opinionated feature, not a framework concern
	SSE       *bool `yaml:"sse"`       // /sse/events endpoint (default: true)
	WS        *bool `yaml:"ws"`        // /ws WebSocket endpoint (default: true)
	Docs      *bool `yaml:"docs"`      // /api/_docs + /docs endpoints (default: true)
	Testing   *bool `yaml:"testing"`   // testing/QA mode: password gate, feedback widget, session banner (default: false, opt-in)
	Feedback  *bool `yaml:"feedback"`  // visitor feedback widget + API WITHOUT the testing posture (no banner/gate); survives publish so live apps can collect feedback (default: false, opt-in)
	Analytics *bool `yaml:"analytics"` // per-app analytics beacon + cookie tracking (default: true)

	// WSAnonymous, when true, drops the auth gate on /ws and /sse/events.
	// Default false - authed apps require a session as before. Opt-in for
	// chat rooms, real-time dashboards, transport tests, anything that
	// wants public broadcast. Same-origin + connection-cap checks still
	// apply; only the session gate is lifted.
	WSAnonymous *bool `yaml:"ws_anonymous"`

	// DocsVisibility controls access to /api/_docs, /docs, /llms.txt.
	// "public" (default) = accessible to anyone; "auth" = requires login.
	DocsVisibility string `yaml:"-"`
}

// IsEnabled returns whether a feature is enabled for this config. Each
// feature has its own default (see the switch). Nil receiver gets the
// same defaults as a zero struct, so callers don't have to nil-check.
func (f *FeaturesConfig) IsEnabled(name string) bool {
	switch name {
	case "testing", "feedback":
		// Opt-in: stays off unless explicitly enabled. Critical that
		// `benmore serve` on a fresh app doesn't auto-render the orange
		// "Testing Mode" banner over the user's UI.
		if f == nil {
			return false
		}
		if name == "testing" {
			return f.Testing != nil && *f.Testing
		}
		return f.Feedback != nil && *f.Feedback // feedback: explicit opt-in (independent of testing)
	case "admin":
		return f == nil || f.Admin == nil || *f.Admin
	case "sse":
		return f == nil || f.SSE == nil || *f.SSE
	case "ws":
		return f == nil || f.WS == nil || *f.WS
	case "docs":
		return f == nil || f.Docs == nil || *f.Docs
	case "analytics":
		return f == nil || f.Analytics == nil || *f.Analytics
	default:
		return true
	}
}

// DocsRequireAuth returns true if docs endpoints require authentication.
// Configured via features.docs: "auth" in app.yaml.
func (f *FeaturesConfig) DocsRequireAuth() bool {
	if f == nil {
		return false
	}
	return f.DocsVisibility == "auth"
}

// DesignConfig represents app.yaml tokens.
// ScopeConfig carries per-table read-filter overrides. Read from
// app.yaml's `scopes:` section:
//
//	scopes:
//	  stories:
//	    public_read_when: "status = 'published'"
//	  comments:
//	    public_read_when: "1=1"  # all comments are public-readable
//
// Only `public_read_when` is supported today. The SQL fragment is
// inserted into the auto-CRUD read query AND-OR'd with the standard
// owner/group/ACL filter so an owner sees their own rows PLUS public
// rows from anyone else.
type ScopeConfig struct {
	PublicReadWhen string `yaml:"public_read_when"`
}

// AutoMembershipConfig declares "every active user is automatically a
// member of every row in <parent>". An earlier app build's #1 schema
// boilerplate: on creating a public channel, hand-write an `on_insert`
// hook that bulk-INSERTs membership rows for every active user. Same
// shape comes up for rooms, projects, workspaces, broadcast-feeds -
// anything with a parent + a join table for "who can see this."
//
// Declared in app.yaml:
//
//	auto_memberships:
//	  channels:
//	    table: channel_members      # join table (default: <parent>_members)
//	    parent: channel_id          # FK to parent.id (default: <parent_singular>_id)
//	    members: all_users          # default; or a SQL WHERE fragment
//
// Synthesized at load time as a real on_insert hook so the same
// fan-out + audit + SSE pipeline runs.
type AutoMembershipConfig struct {
	Table     string `yaml:"table"`      // join table
	Parent    string `yaml:"parent"`     // FK column on the join table → parent.id
	UserField string `yaml:"user_field"` // FK column for user_id (default: user_id)
	Members   string `yaml:"members"`    // "all_users" | SQL WHERE fragment over _benmore_users
}

type DesignConfig struct {
	CSS             string                          // "default", "tailwind", "both", "none"
	Colors          map[string]string               `yaml:"colors"`
	Typography      map[string]string               `yaml:"typography"`
	Spacing         map[string]string               `yaml:"spacing"`
	Radius          string                          `yaml:"radius"`
	Shadow          string                          `yaml:"shadow"`
	Nav             map[string]string               `yaml:"nav"`
	Table           map[string]any                  `yaml:"table"`
	SEO             map[string]string               // site_name, description, image, url, favicon
	CSP             map[string]string               // per-directive CSP allowlist extensions - keys: script_src, style_src, img_src, font_src, connect_src, frame_src
	Auth            map[string]string               // domain, otp, redirect
	PWA             map[string]string               // name, short_name, icon, theme_color, offline
	Recording       map[string]string               // enabled, production, mask_inputs
	Features        *FeaturesConfig                 // opt-in/opt-out for admin, search, sse, docs
	AutoMemberships map[string]AutoMembershipConfig `yaml:"auto_memberships"`
}

// SessionStore manages user sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// Session represents an authenticated user session.
type Session struct {
	ID     string
	UserID int64
	Email  string
	// GroupID is the tenant key from the configured `groups:` table.
	// Originally INTEGER-only; v2.5.10 widened to string so UUID /
	// slug / opaque-ID tenants work natively. SQLite's dynamic typing
	// stores both numeric and TEXT values in the same column -
	// _benmore_sessions.group_id still has INTEGER affinity, but a
	// string value lands fine and round-trips cleanly. Pre-existing
	// INTEGER values stringify to their decimal form ("0", "1", …).
	GroupID string
	Role    string // PRIMARY role from _benmore_users.role - back-compat field used by getSession callers and `role: "admin"` shortcut checks
	// Roles is the FULL set of roles the user holds (v2.7.54+):
	// _benmore_users.role + every active row in _benmore_user_roles,
	// expanded transitively through `inherits:` declared in the
	// RolesConfig. Always non-empty for a valid session (at minimum
	// equals []string{Role}). The access mode `role:editor` checks
	// membership in this slice; `role:editor,reviewer` checks any-of.
	Roles []string
	// Permissions is the union of scope tokens granted by every role
	// in Roles (and their inherited parents). Computed once at session
	// load and used by the `perm:<scope>` access mode. Empty when no
	// RolesConfig is declared (the session falls back to Scopes for
	// scope checks in that case).
	Permissions []string
	Scopes      string // OAuth2-style space-separated: "contacts:read deals:write". Empty = full access.
	Verified    bool   // from _benmore_users.verified - loaded at session resolution
	// ActingAsGroup is the platform-admin "step-in" tenant. Non-empty
	// means an admin has explicitly scoped this session to one group
	// via POST /api/_auth/act_as. While set, the framework applies
	// per-tenant scoping to the admin as if they were a regular member
	// of that group: reads filter to the group, writes auto-inject the
	// group_key, and the admin-bypass shortcut at access.Allowed and
	// in crud.go's WHERE-builders is disabled. The session's Role
	// stays "admin" so admin-only endpoints (e.g. the /_admin panel) still
	// work - only the data-scoping rule changes.
	ActingAsGroup string

	// GlobalAdmin is true ONLY when the session's admin status comes from
	// a platform-global source: the _benmore_users.role column (== "admin")
	// or a globally-scoped (group_id IS NULL) admin grant in
	// _benmore_user_roles. It is set at session-load time from trusted
	// data and is the SOLE input to the cross-tenant admin bypass.
	//
	// Membership roles (groups.role_field, e.g. member_role) and
	// GROUP-SCOPED admin grants also land in Roles and still satisfy
	// in-tenant `role:` access modes (via HasAnyRole) - but they must
	// NEVER set GlobalAdmin, because the membership-role column is
	// client-writable: a member could PATCH their own row to
	// member_role="admin" and, if that fed the bypass, read/write every
	// other tenant's data. Keeping the bypass on GlobalAdmin only is what
	// makes the documented "tenant-scoped grants can't leak cross-tenant"
	// guarantee actually hold.
	GlobalAdmin bool
}

// HasGroup reports whether the session has a non-empty tenant key.
// Replaces the old `session.GroupID > 0` integer-truthy check from
// when GroupID was int64 - empty string AND literal "0" both count
// as "no group" (back-compat with apps that stored 0 as the default).
//
// NOTE: this is the user's NATIVE tenant membership. Most scoping
// callers should use EffectiveHasGroup instead - that one also
// covers the admin-step-in case.
func (s *Session) HasGroup() bool {
	return s != nil && s.GroupID != "" && s.GroupID != "0"
}

// EffectiveGroupID returns the tenant key the framework should use
// for THIS request when scoping rows. For ordinary users it is their
// session GroupID. For admins who have stepped into a tenant via
// /api/_auth/act_as it is the acting-as target - overrides the
// admin's native (usually empty) GroupID for the duration of step-in.
func (s *Session) EffectiveGroupID() string {
	if s == nil {
		return ""
	}
	if s.ActingAsGroup != "" && s.ActingAsGroup != "0" {
		return s.ActingAsGroup
	}
	return s.GroupID
}

// EffectiveHasGroup is HasGroup, but observes act-as.
func (s *Session) EffectiveHasGroup() bool {
	if s == nil {
		return false
	}
	gid := s.EffectiveGroupID()
	return gid != "" && gid != "0"
}

// IsAdminBypass reports whether this session should bypass tenant
// scoping. Only TRUE for actual platform admins who have NOT stepped
// into a tenant. A stepped-in admin keeps admin authority (so admin-
// only endpoints stay reachable) but loses the row-level bypass for
// the duration of step-in - that's the whole point of step-in: see
// the world as that tenant sees it.
//
// Honors multi-role (v2.7.56+): a user holding `admin` via
// _benmore_user_roles bypasses scoping the same way as one whose
// _benmore_users.role column is 'admin'. Without this the join-table
// grant of admin was a "dead parallel store" - the role showed up in
// session.Roles but no framework gate respected it.
func (s *Session) IsAdminBypass() bool {
	return s.IsAdmin() && s.ActingAsGroup == ""
}

// IsAdmin reports whether the session holds the admin role via ANY
// path: the primary _benmore_users.role column OR a grant in
// _benmore_user_roles (loaded into session.Roles at session resolve).
//
// This is the single source of truth for "is this caller an admin"
// in framework code. Every gate that previously read
// `session.Role == "admin"` should call this instead - otherwise an
// admin grant via the join table silently fails to elevate.
//
// nil-safe: returns false for a nil receiver (matches the previous
// `session != nil && session.Role == "admin"` idiom).
func (s *Session) IsAdmin() bool {
	if s == nil {
		return false
	}
	// Global platform admin ONLY: the primary _benmore_users.role column
	// or a globally-scoped (group_id IS NULL) admin grant, captured in
	// GlobalAdmin at session load. We deliberately DO NOT scan s.Roles for
	// "admin" here: that slice also carries client-writable membership
	// roles and group-scoped grants, and counting those would let a tenant
	// member self-escalate to a cross-tenant superuser. In-tenant
	// `role:admin` enforcement runs through HasAnyRole, which still matches
	// "admin" in s.Roles - so legitimate tenant admins are unaffected.
	return s.Role == "admin" || s.GlobalAdmin
}

// RenderContext holds data for template rendering.
type RenderContext struct {
	Data       map[string]any
	User       *Session
	Request    *http.Request
	App        *App
	Page       *Page
	QueryCount int      // N+1 detection: number of queries executed during render
	QueryLog   []string // N+1 detection: SQL of each query (dev mode only, truncated to 200 chars)
}

// CheckResult represents a validation finding.
type CheckResult struct {
	Level   string `json:"level"` // "error", "warning", "info"
	File    string `json:"file"`
	Line    int    `json:"line"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// StatusOutput represents the app introspection snapshot.
type StatusOutput struct {
	Tables        map[string][]string `json:"tables"`
	Routes        []RouteInfo         `json:"routes"`
	API           []string            `json:"api"`
	Relationships []string            `json:"relationships"`
}

// RouteInfo describes a discovered route.
type RouteInfo struct {
	Path string `json:"path"`
	File string `json:"file"`
	Auth string `json:"auth"`
}
