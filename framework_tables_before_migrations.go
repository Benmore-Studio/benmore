//go:build !cli

package main

// Framework tables exist before the app's migration files run.
//
// A file in migrations/ may put a trigger of the app's own on a framework
// table, write its rows or read it (authorizeMigration). The start created
// most of those tables later, when it registered routes, so a file that named
// one ran on every database that already had the table and failed with `no
// such table` on a new one: the copy `benmore test` runs on, a dev database
// built again, a first promote. The app could not start from an empty
// database at all.
//
// So a start and a reload create them before the first file, through the
// same functions route registration calls (which then find them in place):
//   - for every app: the audit log, notifications, upload ownership,
//     sharing grants, jobs, webhook subscriptions and custom field
//     definitions;
//   - for an app that has sign-in (NeedsAuth, as route registration decides
//     it): users with their MFA columns and the columns auth.signup_fields
//     and page `require=` declare, sessions, sign-in attempts, role grants,
//     reset and verification links and API tokens.
//
// An app without sign-in still has no sign-in tables after its start, so a
// file of its that names one keeps failing, here as on every database.
//
// Left to route registration and first use, because they hold the
// framework's own working state and no row an app's migration has a reason
// to name: idempotency keys, record locks, the request log, the context
// graph, import sessions, analytics, push devices, saved views, scheduling,
// aggregates, cron state, presence, broadcast, read audit, usage, cluster
// events and rate limits, passkeys, OAuth tokens and the OAuth provider's
// tables, email changes and the connector's tables. A statement that names
// one of those on a database that lacks it is never skipped
// (migrationReservedName), so it fails the file where the table is missing.

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
)

// frameworkTablesForEveryApp and frameworkTablesForSignIn name what
// ensureFrameworkTablesBeforeMigrations creates, for the dry run of a start
// or reload (frameworkTableBeforeMigrations): that run cannot create them,
// and a test holds the names to what the functions create.
var (
	frameworkTablesForEveryApp = []string{
		"_benmore_audit_log", "_benmore_notifications", "_benmore_upload_owners", "_benmore_public_upload_owners",
		"_benmore_permissions", "_benmore_jobs", "_benmore_webhooks", "_benmore_custom_fields",
	}
	frameworkTablesForSignIn = []string{
		"_benmore_users", "_benmore_sessions", "_benmore_login_attempts", "_benmore_user_roles",
		"_benmore_password_resets", "_benmore_api_tokens",
		// Created with the users table.
		"_benmore_signin_challenges", "_benmore_otp",
	}
)

// frameworkTableBeforeMigrations reports whether a start or reload of an app
// creates table before its migration files. table is compared as SQLite
// compares identifiers; signIn is NeedsAuth for the app's source.
func frameworkTableBeforeMigrations(table string, signIn bool) bool {
	name := sqliteIdentifierFold(table)
	for _, known := range frameworkTablesForEveryApp {
		if name == known {
			return true
		}
	}
	if !signIn {
		return false
	}
	for _, known := range frameworkTablesForSignIn {
		if name == known {
			return true
		}
	}
	return false
}

// ensureSignInTables creates the tables of an app that has sign-in: the
// calls RegisterAuthRoutes makes, in its order. That file keeps its own
// calls, which find the tables in place.
func ensureSignInTables(db *sql.DB) error {
	var errs []error
	if err := EnsureUsersTable(db); err != nil {
		errs = append(errs, fmt.Errorf("users: %w", err))
	}
	EnsureSessionsTable(db)
	EnsureLoginAttemptsTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		errs = append(errs, fmt.Errorf("role grants: %w", err))
	}
	EnsurePasswordResetsTable(db)
	EnsureAPITokensTable(db)
	EnsureAuditLogTable(db)
	return errors.Join(errs...)
}

// ensureFrameworkTablesBeforeMigrations creates the framework tables a
// migration file may name (see the top of this file). design and pages are
// the configuration being loaded; signIn is NeedsAuth for it. Every function
// called here is called again by route registration and changes nothing the
// second time.
//
// The notifications table is the one whose failure fails the load, as it did
// when it was the only table created here. Any other table that cannot be
// created is logged and not an error, as when route registration creates it:
// a file that names it then fails with `no such table`, which says what is
// wrong.
func ensureFrameworkTablesBeforeMigrations(db *sql.DB, design *DesignConfig, pages map[string]*Page, signIn bool) error {
	if err := EnsureNotificationsTableChecked(db); err != nil {
		return err
	}
	EnsureAuditLogTable(db)
	if err := EnsureUploadOwnersTable(db); err != nil {
		log.Printf("  WARNING: upload ownership table before migrations: %v", err)
	}
	EnsurePermissionsTable(db)
	EnsureJobsTable(db)
	EnsureWebhooksTable(db)
	EnsureCustomFieldsTable(db)
	if !signIn {
		return nil
	}
	if err := ensureSignInTables(db); err != nil {
		log.Printf("  WARNING: sign-in tables before migrations: %v", err)
	}
	EnsureMFAColumns(db)
	EnsureRequiredUserFields(db, pages)
	if design != nil {
		EnsureSignupFieldColumns(db, design.Auth["signup_fields"])
	}
	return nil
}

// signInConfigured is NeedsAuth for a configuration that is not published
// yet: pages is the page set it will serve.
func signInConfigured(design *DesignConfig, pages map[string]*Page) bool {
	return NeedsAuth(&App{Design: design, Pages: pages})
}
