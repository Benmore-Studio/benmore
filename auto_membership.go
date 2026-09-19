//go:build !cli

package main

// Auto-membership: declarative shorthand for the "every active user is
// automatically a member of every row in <parent>" pattern. The chat
// session's #1 schema boilerplate was hand-writing this same hooks.yaml
// stanza for public channels:
//
//   on_insert:
//     channels:
//       - sql: |
//           INSERT INTO channel_members (user_id, channel_id)
//           SELECT id, {{id}} FROM _benmore_users
//           WHERE deactivated_at IS NULL OR deactivated_at = ''
//
// Open social spaces (channels, rooms, projects, workspaces, broadcast
// feeds) ~always want this. Pre-2.7.35 every agent wrote it from
// scratch and tripped on the same things - wrong column name, missing
// deactivated filter, no creator-admin distinction, race against the
// client-side membership POST that also writes the creator row.
//
// Now you declare it in app.yaml:
//
//   auto_memberships:
//     channels:
//       table: channel_members      # default: <parent>_members
//       parent: channel_id          # default: <parent_singular>_id
//       members: all_users          # default; or a WHERE fragment
//                                   # over _benmore_users
//
// At app-load time, synthesizeAutoMembershipHooks adds the equivalent
// on_insert hook. Same code path as a user-written hook - SSE fan-out,
// audit log, webhook subscriptions, all run automatically.

import (
	"fmt"
	"log"
	"strings"
)

// synthesizeAutoMembershipHooks reads app.Design.AutoMemberships and
// appends the equivalent on_insert hooks to app.Hooks. Idempotent on
// re-runs (e.g. hot-reload): the synthesized hooks all carry the
// `[auto_membership]` marker in their SQL so we can recognise + skip
// re-adding them.
//
// No-op when AutoMemberships is empty / nil.
func synthesizeAutoMembershipHooks(app *App) {
	if app == nil || app.Design == nil || len(app.Design.AutoMemberships) == 0 {
		return
	}
	if app.Hooks == nil {
		app.Hooks = &HookConfig{
			OnInsert:     map[string][]Hook{},
			OnUpdate:     map[string][]Hook{},
			OnDelete:     map[string][]Hook{},
			BeforeInsert: map[string][]Hook{},
			BeforeUpdate: map[string][]Hook{},
			BeforeDelete: map[string][]Hook{},
		}
	}
	if app.Hooks.OnInsert == nil {
		app.Hooks.OnInsert = map[string][]Hook{}
	}

	for parent, cfg := range app.Design.AutoMemberships {
		hook := buildAutoMembershipHook(parent, cfg)
		if hook.SQL == "" {
			log.Printf("auto_memberships: %s: skipped (invalid config)", parent)
			continue
		}
		// Idempotent: if a hook with the same marker is already present
		// for this parent, skip - hot-reload re-runs this function and
		// we don't want N copies after N hot-reloads.
		marker := autoMembershipMarker(parent)
		alreadyPresent := false
		for _, h := range app.Hooks.OnInsert[parent] {
			if strings.Contains(h.SQL, marker) {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			app.Hooks.OnInsert[parent] = append(app.Hooks.OnInsert[parent], hook)
			log.Printf("auto_memberships: %s → %s (auto-enrol active users on insert)",
				parent, fillMembershipDefaults(parent, cfg).Table)
		}
	}
}

// buildAutoMembershipHook produces the synthesized Hook for one parent
// entry. Empty SQL is the sentinel for "invalid config, skip."
func buildAutoMembershipHook(parent string, cfg AutoMembershipConfig) Hook {
	cfg = fillMembershipDefaults(parent, cfg)
	if cfg.Table == "" || cfg.Parent == "" || cfg.UserField == "" {
		return Hook{}
	}

	// Default WHERE: every active _benmore_users row. SQLite's empty-
	// string-vs-NULL on deactivated_at requires both branches.
	whereClause := "deactivated_at IS NULL OR deactivated_at = ''"
	if cfg.Members != "" && cfg.Members != "all_users" {
		// Custom SQL fragment - agent's responsibility to keep it
		// quoted-correctly. We don't try to parse it.
		whereClause = cfg.Members
	}

	// ON CONFLICT DO NOTHING so the synthesized hook coexists with a
	// client-side membership POST that may have written the creator's
	// row before the hook fires. UNIQUE(user_id, <parent>) on the
	// memberships table is the agent's responsibility - it's the
	// canonical shape every chat schema has.
	sql := fmt.Sprintf(
		"%s INSERT INTO %s (%s, %s) SELECT id, {{id}} FROM _benmore_users WHERE %s ON CONFLICT DO NOTHING",
		autoMembershipMarker(parent), cfg.Table, cfg.UserField, cfg.Parent, whereClause,
	)
	return Hook{SQL: sql}
}

// fillMembershipDefaults returns cfg with sensible defaults applied:
//
//	table:      <parent>_members
//	parent:     <parent_singular>_id     (channels → channel_id)
//	user_field: user_id
//	members:    all_users
//
// Singularization is rough: "channels" → "channel" (drop trailing 's').
// Sufficient for the canonical English-pluralized table names; agents
// with irregular plurals (`people`) can specify `parent:` explicitly.
func fillMembershipDefaults(parent string, cfg AutoMembershipConfig) AutoMembershipConfig {
	if cfg.Table == "" {
		cfg.Table = parent + "_members"
	}
	if cfg.Parent == "" {
		singular := strings.TrimSuffix(parent, "s")
		if singular == parent {
			// not pluralized - fall back to raw name + _id
			cfg.Parent = parent + "_id"
		} else {
			cfg.Parent = singular + "_id"
		}
	}
	if cfg.UserField == "" {
		cfg.UserField = "user_id"
	}
	if cfg.Members == "" {
		cfg.Members = "all_users"
	}
	return cfg
}

func autoMembershipMarker(parent string) string {
	return "/*auto_membership:" + parent + "*/"
}
