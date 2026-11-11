//go:build !cli

package main

// Command failures that repeating the same operation cannot get past.
//
// Most apply failures are reported as unavailable_provider and recorded as a
// failed attempt that _commit may retry, which is right for an outage. Two are
// deterministic instead:
//
//   - constraint_failed: the command's own apply SQL hit a FOREIGN KEY, UNIQUE
//     (or PRIMARY KEY), NOT NULL or CHECK constraint. The business transaction
//     rolled back, so the outcome is a known failure, never unknown.
//   - invalid_declaration: the reviewed declaration cannot run against this
//     database (a dependency query that does not return exactly one id column,
//     command SQL that calls a function outside the command allowlist, or
//     command SQL that names a function or a column the database does not have).
//
// Both reach the caller with their own code and a message that holds no SQL
// text and no row values, _status reports retryable false, and _commit refuses
// another attempt of that operation with the same code: prepare a new one.

import (
	"errors"
	"strings"

	"github.com/mattn/go-sqlite3"
)

const (
	appMCPConstraintFailedCode     = "constraint_failed"
	appMCPInvalidDeclarationCode   = "invalid_declaration"
	appMCPConstraintRetryAdvice    = " Retrying this operation fails the same way; change the data or prepare a different operation."
	appMCPDeclarationRetryAdvice   = " The app's command declaration must be fixed and reviewed again; retrying cannot succeed."
	appMCPRepeatedFinalFailureText = "An earlier attempt of this operation failed this way and was rolled back; committing it again cannot succeed. Prepare a new operation."
)

// appMCPCommandFinalError is a deterministic command failure. Message is safe
// for the client; cause is kept for the operator log only.
type appMCPCommandFinalError struct {
	Code, Message string
	cause         error
}

func (e *appMCPCommandFinalError) Error() string {
	if e.cause != nil {
		return e.Code + ": " + e.cause.Error()
	}
	return e.Code + ": " + e.Message
}
func (e *appMCPCommandFinalError) Unwrap() error { return e.cause }

// appMCPFinalErrorClass reports whether a recorded attempt class ends the
// operation's retries.
func appMCPFinalErrorClass(class string) bool {
	return class == appMCPConstraintFailedCode || class == appMCPInvalidDeclarationCode
}

// appMCPRepeatedFinalFailure is _commit's answer after an attempt already
// failed with a final class.
func appMCPRepeatedFinalFailure(class string) error {
	return &appMCPCommandFinalError{Code: class, Message: appMCPRepeatedFinalFailureText}
}

// appMCPCommandConstraintFailure classifies an error from the command's own
// apply SQL. Only the four declarative constraint kinds qualify: a trigger's
// RAISE (the framework's revision and integrity guards) and every other error
// keep their class, and so does a hook error, which has its own. A UNIQUE or
// NOT NULL failure that names a framework table is a framework fault, not the
// command's, and stays an operational failure.
func appMCPCommandConstraintFailure(err error) error {
	if err == nil {
		return nil
	}
	var hook *appMCPCommandHookError
	var final *appMCPCommandFinalError
	if errors.As(err, &hook) || errors.As(err, &final) {
		return err
	}
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) || sqliteErr.Code != sqlite3.ErrConstraint {
		return err
	}
	var reason string
	switch sqliteErr.ExtendedCode {
	case sqlite3.ErrConstraintForeignKey:
		reason = "a foreign key constraint failed: the change would reference a record that does not exist, or remove or change a record that other records still reference."
	case sqlite3.ErrConstraintUnique, sqlite3.ErrConstraintPrimaryKey:
		reason = "a uniqueness constraint failed: a record with the same unique value already exists."
	case sqlite3.ErrConstraintNotNull:
		reason = "a NOT NULL constraint failed: a required value is missing."
	case sqlite3.ErrConstraintCheck:
		reason = "a CHECK constraint failed: a value is not allowed."
	default:
		return err
	}
	if appMCPConstraintNamesFrameworkTable(sqliteErr.Error()) {
		return err
	}
	return &appMCPCommandFinalError{Code: appMCPConstraintFailedCode, Message: "The change was rolled back because " + reason + appMCPConstraintRetryAdvice, cause: err}
}

// appMCPConstraintNamesFrameworkTable reads the "<kind> constraint failed:
// table.column, ..." list SQLite reports for UNIQUE, PRIMARY KEY and NOT NULL.
func appMCPConstraintNamesFrameworkTable(message string) bool {
	_, list, ok := strings.Cut(message, "constraint failed: ")
	if !ok {
		return false
	}
	for _, target := range strings.Split(list, ",") {
		table, _, _ := strings.Cut(strings.TrimSpace(target), ".")
		lower := strings.ToLower(table)
		if strings.HasPrefix(lower, "_benmore_") || strings.HasPrefix(lower, "sqlite_") {
			return true
		}
	}
	return false
}
