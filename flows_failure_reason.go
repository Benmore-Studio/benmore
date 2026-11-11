//go:build !cli

package main

import (
	"context"
	"errors"
	"strings"
)

// flowFailureReason is the reason a failed flow's answer gives every caller:
// a fixed phrase chosen from the step type and the kind of error, never the
// error's own text. SQLite's messages name tables, columns and sometimes
// values, and an api or compute error can quote upstream or request data, so
// production answers carry only this class; the error itself is in the
// request log and journal under the request id (and in the answer where
// flowFailureDetailVisible allows). The constraint phrases match the ones
// auto-CRUD already answers (publicConstraintMessage).
func flowFailureReason(stepType string, err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "the step timed out"
	}
	msg := strings.ToLower(err.Error())
	has := func(parts ...string) bool {
		for _, p := range parts {
			if strings.Contains(msg, p) {
				return true
			}
		}
		return false
	}
	if has("unresolved template reference") {
		return "a ${{ }} reference in the step had no value when it ran"
	}
	switch stepType {
	case "sql", "sql_dynamic", "":
		switch {
		case has("expect_rows assertion failed"):
			return "the statement returned or changed a different number of rows than expect_rows allows"
		case has("expect_rows"):
			return "the step's expect_rows cannot be checked"
		case has("no sql statement"):
			return "the step has no SQL statement"
		case has("with.params does not define"):
			return "a :name the statement binds had no value; the request did not send it"
		case has("request-sourced value"):
			return "the statement reads request input as raw SQL text"
		case has("no such table"):
			return "the statement names a table that does not exist"
		case has("no such column"):
			return "the statement names a column that does not exist"
		case has("no such function"):
			return "the statement calls a function that does not exist"
		case has("syntax error", "incomplete input", "unrecognized token"):
			return "the statement has a syntax error"
		case has("unique constraint failed", "primary key must be unique"):
			return "a record with the same unique value already exists"
		case has("foreign key constraint failed"):
			return "a referenced record does not exist"
		case has("not null constraint failed"):
			return "a required value is missing"
		case has("check constraint failed"):
			return "a value is not allowed"
		case has("datatype mismatch"):
			return "a value has the wrong type for its column"
		case has("malformed json"):
			return "a value passed to a JSON function is not valid JSON"
		case has("database is locked", "database table is locked", "sqlite_busy"):
			return "the database was busy"
		case has("readonly", "read-only"):
			return "the database refused the write"
		case has("interrupted"):
			return "the statement was interrupted"
		case stepType == "":
			return "the flow failed outside a step"
		}
		return "the statement failed"
	case "api", "webhook":
		switch {
		case has("paginate:"):
			return "the step's paginate block cannot be run as written"
		case has("ssrf", "private", "blocked"):
			return "the outbound URL was refused"
		case has("success_when"):
			return "the response did not meet success_when"
		case has("timeout", "deadline exceeded"):
			return "the outbound call timed out"
		case has("returned 4", "returned 5", "status 4", "status 5"):
			return "the upstream service answered with an error status"
		}
		return "the outbound call failed"
	case "parse":
		return "the request body could not be parsed"
	case "compute":
		return "the compute module failed"
	case "proxy":
		switch {
		case has("ssrf", "private", "blocked", "scheme or host", "path segment"):
			return "the outbound URL was refused"
		case has("could not resolve"):
			return "the upstream host could not be resolved"
		case has("url's own origin"):
			return "the upstream redirected outside the URL's own origin"
		case has("redirected"):
			return "the upstream redirect could not be followed"
		case has("csrf"):
			return "an upstream POST cannot run in a GET flow"
		case has("content-type"):
			return "the upstream answered a media type the step does not serve"
		case has("max_bytes"):
			return "the upstream body is larger than the step allows"
		case has("aborted"):
			return "the response was aborted while streaming"
		case has("timeout", "deadline exceeded", "time ran out"):
			return "the outbound call timed out"
		case has("answered"):
			return "the upstream service answered with an error status"
		case has("first byte"):
			return "the upstream failed before sending the body"
		}
		return "the outbound call failed"
	case "for_each":
		if has("not a list") {
			return "the loop's source is not a list"
		}
		if has("loop variable") {
			return "the loop variable's name is one the runtime owns, so the loop was not run"
		}
	case "respond", "redirect", "serve_file":
		return "the response could not be written"
	case "purge_current_user":
		if has("last active admin") {
			return "the account is the app's last active admin; make another account an admin first"
		}
	case "email":
		if has("attachment") {
			return "an attachment could not be built, so nothing was sent"
		}
		return "the email could not be sent"
	case "sms":
		return "the text message could not be sent"
	case "notify":
		// One phrase for every cause: a request-chosen recipient must not
		// learn which user ids exist.
		return "the notification could not be created"
	}
	return "the " + stepType + " step failed"
}
