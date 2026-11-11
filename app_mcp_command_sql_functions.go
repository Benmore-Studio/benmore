//go:build !cli

package main

// SQL functions in command SQL: one rule for review and for commit.
//
// When SQLite compiles a command statement, the command authorizer admits only
// the functions in commandAllowedSQLFunctions (commandPhaseSQLFunctionAllowed).
// The command compiler checks a statement's text, bindings and tables but not
// the functions it calls, so a command whose apply SQL called
// hex(randomblob(8)) passed `benmore mcp review`, `mcp check` and the push
// write gate, was prepared and approved, and then failed at _commit as a
// retryable outage although no attempt could ever succeed.
//
// Two things close that:
//
//   - Review. Every SQL statement of a command (its dependency queries and the
//     SQL steps of prepare, apply and readback) is compiled against an empty
//     in-memory database built from the app's schema source, with an authorizer
//     that asks the commit-time authorizer's own question. The statement is
//     never stepped and the database holds no app data. A statement the schema
//     files alone cannot compile (a table or column only a migration adds) is
//     left to the runtime.
//   - Commit. A statement the authorizer refuses over a function is reported
//     as invalid_declaration, which is final, instead of unavailable_provider.
//
// Both read commandAllowedSQLFunctions through commandPhaseSQLFunctionAllowed:
// there is no second list.
//
// A name the database does not have is the same kind of failure: SQLite cannot
// compile a statement that calls a function it has no definition of
// (`datetim('now')`) or that names a missing column, and it fails that way on
// every attempt.
//
//   - A function SQLite does not have is refused at review like a function off
//     the list: the review connection is the framework driver the app runs on,
//     so it has every function a commit has, and no schema makes one exist.
//   - A column is not judged at review. The schema files do not show the
//     columns a migration, a custom field or the framework adds, so "no such
//     column" there says nothing about the app's database.
//   - Commit reports both as invalid_declaration (commandUnresolvedNameFailure).

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/mattn/go-sqlite3"
)

// commandSQLFunctionName is what a refusal may repeat to the caller: SQLite
// reports the registered function's own name, which is always an identifier.
var commandSQLFunctionName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// commandRefusedFunctionError is the final failure for command SQL that calls
// a function approved commands cannot run. where names the SQL ("apply SQL",
// "dependency query"); the message holds no SQL text and no row values.
func commandRefusedFunctionError(where, name string, cause error) *appMCPCommandFinalError {
	called := "a SQL function"
	if commandSQLFunctionName.MatchString(name) {
		called = fmt.Sprintf("the SQL function %q", strings.ToLower(name))
	}
	return &appMCPCommandFinalError{Code: appMCPInvalidDeclarationCode,
		Message: fmt.Sprintf("The command's %s calls %s, which approved commands cannot run.%s", where, called, appMCPDeclarationRetryAdvice), cause: cause}
}

func (g *appMCPCommandExecution) noteRefusedFunction(name string) {
	g.policyMu.Lock()
	g.refusedFunction = name
	g.policyMu.Unlock()
}

func (g *appMCPCommandExecution) takeRefusedFunction() string {
	g.policyMu.Lock()
	name := g.refusedFunction
	g.refusedFunction = ""
	g.policyMu.Unlock()
	return name
}

// forgetRefusedFunction clears the guard's note before a command statement
// runs, so a refusal is only ever attributed to the statement that caused it.
func (cap *appMCPCommandCapability) forgetRefusedFunction() {
	if cap != nil && cap.guard != nil {
		cap.guard.takeRefusedFunction()
	}
}

// refusedFunctionFailure classifies the error of one command statement. It
// qualifies only when SQLite itself failed the statement and the authorizer
// noted a function it refused while that statement was compiled: a refused
// function fails the compile every time, whatever else the statement does.
// SQLite reports that failure as a plain SQLITE_ERROR ("not authorized to use
// function: <name>"), not SQLITE_AUTH, so the note, not the result code, is
// the signal. Every other error keeps its class.
func (cap *appMCPCommandCapability) refusedFunctionFailure(err error, where string) error {
	if err == nil || cap == nil || cap.guard == nil {
		return err
	}
	name := cap.guard.takeRefusedFunction()
	var sqliteErr sqlite3.Error
	if name == "" || !errors.As(err, &sqliteErr) {
		return err
	}
	return commandRefusedFunctionError(where, name, err)
}

// SQLite's compile errors for a name the database does not have. An INSERT or
// upsert column list reports a missing column in its own words.
const (
	sqliteNoSuchFunction = "no such function: "
	sqliteNoSuchColumn   = "no such column: "
)

var sqliteTableHasNoColumn = regexp.MustCompile(`^table .+ has no column named .+$`)

// sqliteUnknownFunction names the function SQLite could not find when it
// compiled a statement, or "".
func sqliteUnknownFunction(err error) string {
	var sqliteErr sqlite3.Error
	if err == nil || !errors.As(err, &sqliteErr) || sqliteErr.Code != sqlite3.ErrError {
		return ""
	}
	if name, found := strings.CutPrefix(sqliteErr.Error(), sqliteNoSuchFunction); found {
		return name
	}
	return ""
}

// commandUnresolvedNameFailure classifies the error SQLite returned for one of
// the command's own statements (a dependency query, or the SQL of a phase
// step) when the statement names a function or a column the database does not
// have. SQLite reports both while it compiles the statement, before anything
// runs, and compiles it the same way on every attempt, so the failure is the
// final invalid_declaration, not an outage. It is called only where the
// command's own statement is handed to SQLite: an error of a hook or of the
// framework's own bookkeeping keeps its class. The message names a function
// (as a refused function is named) and never a column, a table or SQL text;
// the cause, kept for the operator log, has SQLite's own message.
func commandUnresolvedNameFailure(err error, where string) error {
	var final *appMCPCommandFinalError
	var sqliteErr sqlite3.Error
	if err == nil || errors.As(err, &final) || !errors.As(err, &sqliteErr) || sqliteErr.Code != sqlite3.ErrError {
		return err
	}
	if name := sqliteUnknownFunction(err); name != "" {
		return commandRefusedFunctionError(where, name, err)
	}
	if message := sqliteErr.Error(); strings.HasPrefix(message, sqliteNoSuchColumn) || sqliteTableHasNoColumn.MatchString(message) {
		return &appMCPCommandFinalError{Code: appMCPInvalidDeclarationCode,
			Message: fmt.Sprintf("The command's %s names a column the app's database does not have.%s", where, appMCPDeclarationRetryAdvice), cause: err}
	}
	return err
}

// commandSQLStatement is one SQL statement of a command with the phase whose
// authorizer policy compiles it at run time.
type commandSQLStatement struct{ phase, where, query string }

// commandSQLStatements lists every SQL statement a command can run:
// dependency queries (compiled under the prepare policy) and the SQL steps of
// the three phases, nested branches and loop bodies included.
func commandSQLStatements(command *FlowCommand) []commandSQLStatement {
	if command == nil {
		return nil
	}
	var out []commandSQLStatement
	for _, dependency := range command.Dependencies {
		out = append(out, commandSQLStatement{"prepare", fmt.Sprintf("dependency %q query", dependency.Name), dependency.Query})
	}
	var walk func(phase string, steps []FlowStep)
	walk = func(phase string, steps []FlowStep) {
		for i := range steps {
			step := &steps[i]
			if step.Type == "sql" && step.SQL != "" {
				where := phase + " SQL"
				if step.Name != "" {
					where = fmt.Sprintf("%s SQL (step %q)", phase, step.Name)
				}
				out = append(out, commandSQLStatement{phase, where, step.SQL})
			}
			walk(phase, step.Steps)
			walk(phase, step.ElseSteps)
		}
	}
	walk("prepare", command.Prepare.Steps)
	walk("apply", command.Apply.Steps)
	walk("readback", command.Readback.Steps)
	return out
}

// commandSQLFunctionRefusal is the review-time refusal text: the tool (when a
// manifest binds the command), the flow file, the statement, the function,
// and the list of functions command SQL may call.
func commandSQLFunctionRefusal(manifest *AppMCPManifest, flow Flow, where, name string) error {
	source := flow.Source
	if source == "" {
		source = fmt.Sprintf("command %q", flow.Name)
	}
	if manifest != nil {
		for _, tool := range manifest.Tools {
			if tool.Handler.Operation == "command" && tool.Handler.Flow == flow.Name {
				source = fmt.Sprintf("mcp.yaml: tool %q: %s", tool.Name, source)
				break
			}
		}
	}
	allowed := append([]string(nil), commandAllowedSQLFunctions...)
	sort.Strings(allowed)
	hint := ""
	switch strings.ToLower(name) {
	case "random", "randomblob":
		hint = " For a server-made random value, declare it under the command's `generated:` and bind `${{ params.generated.<name> }}` in apply SQL."
	case "current_timestamp", "current_date", "current_time":
		hint = " For the current time use datetime('now'), date('now') or time('now')."
	}
	return fmt.Errorf("%s: %s calls function %q, which approved commands cannot run: it would fail every time it runs. Command SQL may call only: %s.%s",
		source, where, strings.ToLower(name), strings.Join(allowed, ", "), hint)
}

// appMCPCheckCommandSQLFunctions refuses the first command statement that
// calls a function the command authorizer would refuse when the statement
// runs. A schema that cannot be read or emitted is reported by the command
// table inventory itself, so it is not judged again here.
func appMCPCheckCommandSQLFunctions(readSource func(string) ([]byte, error), flows []Flow, manifest *AppMCPManifest) error {
	var commands []Flow
	for _, flow := range flows {
		if flow.Command != nil {
			commands = append(commands, flow)
		}
	}
	if len(commands) == 0 {
		return nil
	}
	// The text rule the runtime applies before a phase starts: a trigger-only
	// function (RAISE, benmore_encrypt, ...) may not be called by name.
	for _, flow := range commands {
		for _, statement := range commandSQLStatements(flow.Command) {
			if name := commandTriggerOnlyCall(statement.query); name != "" {
				return commandSQLFunctionRefusal(manifest, flow, statement.where, name)
			}
		}
	}
	ddl, err := appMCPSchemaDDLWithReader(readSource)
	if err != nil || strings.TrimSpace(ddl) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), appMCPDependencyShapeBudget)
	defer cancel()
	db := appMCPDependencyShapeDB(ctx, ddl)
	if db == nil {
		return nil
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil
	}
	defer conn.Close()
	// phase and refused are read and written only on this goroutine: SQLite
	// calls the authorizer synchronously while it compiles the statement.
	phase, refused := "", []string(nil)
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := sqliteConnOf(raw)
		if !ok {
			return errors.New("not a SQLite connection")
		}
		sqliteConn.RegisterAuthorizer(func(action int, _, name, _ string) int {
			if action == sqlite3.SQLITE_FUNCTION && !commandPhaseSQLFunctionAllowed(phase, name) {
				refused = append(refused, name)
			}
			// Never deny here: compilation continues, so every refused function
			// of the statement is seen, and nothing is ever stepped.
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		return nil
	}
	defer conn.Raw(func(raw any) error {
		if sqliteConn, ok := sqliteConnOf(raw); ok {
			restoreConnAuthorizer(sqliteConn)
		}
		return nil
	})
	for _, flow := range commands {
		for _, statement := range commandSQLStatements(flow.Command) {
			query, runnable := sqlRunnableText(statement.query)
			if !runnable {
				continue
			}
			phase, refused = statement.phase, nil
			// Compiled only. A statement that does not compile against the
			// schema files is not judged unless SQLite already reported a
			// refused function while resolving it, or stopped at a function
			// it does not have: this connection has every function a commit
			// has, so that statement can never run.
			if stmt, err := conn.PrepareContext(ctx, query); err == nil {
				_ = stmt.Close()
			} else if name := sqliteUnknownFunction(err); name != "" {
				refused = append(refused, name)
			}
			if len(refused) > 0 {
				return commandSQLFunctionRefusal(manifest, flow, statement.where, refused[0])
			}
			if ctx.Err() != nil {
				return nil
			}
		}
	}
	return nil
}

// commandTriggerOnlyCall names the first trigger-only function (RAISE,
// benmore_encrypt, ...) a statement calls by name, or "". It is the one text
// rule behind validateCommandAuthoredSQLFunctions, which the runtime applies
// before a phase starts and again before each statement.
func commandTriggerOnlyCall(query string) string {
	tokens := sqlTokenize(stripSQLComments(query))
	for i := 0; i+1 < len(tokens); i++ {
		if (tokens[i].kind == sqlTokWord || tokens[i].kind == sqlTokIdent) && tokens[i+1].kind == sqlTokPunct && tokens[i+1].text == "(" && commandVerifiedTriggerFunction(tokens[i].text) {
			return tokens[i].text
		}
	}
	return ""
}
