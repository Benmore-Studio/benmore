//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
)

type appMCPPrivateFlowKey struct{}
type appMCPPrivateFlow struct {
	app                                             *App
	origin                                          *App
	generation                                      *appMCPRuntimeGeneration
	manifest                                        *AppMCPManifest
	flow                                            *Flow
	actor                                           *Session
	environment                                     map[string]string // immutable per-execution private snapshot
	request                                         *http.Request
	credential, resource, tool, method, path, query string
}

func appMCPFlowSnapshot(app *App, name string) *Flow {
	app.mu.RLock()
	defer app.mu.RUnlock()
	var found *Flow
	for i := range app.Flows {
		if app.Flows[i].Name == name {
			if found != nil {
				return nil
			}
			found = &app.Flows[i]
		}
	}
	return found
}
func appMCPReadFlowPolicy(flow *Flow) error {
	if flow != nil && (flow.Command != nil || flow.Trigger.Type == "command") {
		return fmt.Errorf("command declarations are not callable read flows")
	}
	if flow == nil || flow.Trigger.Type != "http" || flow.Async || flow.Verify != "" || flow.VerifyConfig != nil {
		return fmt.Errorf("connector requires a synchronous native read flow")
	}
	if err := flowValidateParallelTx(flow); err != nil {
		return err
	}
	var check func([]FlowStep) error
	check = func(steps []FlowStep) error {
		for _, step := range steps {
			switch step.Type {
			case "sql":
				if !isReadOnlyQuery(step.SQL) {
					return fmt.Errorf("connector flow SQL must be one read-only statement")
				}
			case "sql_dynamic", "compute", "set", "parse", "respond", "if", "for_each":
			default:
				return fmt.Errorf("connector read flow contains unsupported effect %q", step.Type)
			}
			for _, nested := range [][]FlowStep{step.Steps, step.ElseSteps, step.OnError} {
				if err := check(nested); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return check(flow.Steps)
}
func appMCPToolAllowed(app *App, tool *AppMCPTool, actor *Session) bool {
	if tool == nil || actor == nil || (tool.Handler.Kind != "native" && tool.Handler.Kind != "file") || tool.Effect != "read" || !scopesWithin(actor.Scopes, strings.Join(tool.Permissions, " ")) {
		return false
	}
	if tool.Handler.Kind == "file" {
		return (tool.Handler.Operation == "ingest" || tool.Handler.Operation == "verify") && SessionCanAccessTable(app, tool.Handler.Table, OpRead, actor) && scopesWithin(actor.Scopes, tool.Handler.Table+":read")
	}
	switch tool.Handler.Operation {
	case "table.list", "table.read":
		return SessionCanAccessTable(app, tool.Handler.Table, OpRead, actor)
	case "flow.call":
		flow := appMCPFlowSnapshot(app, tool.Handler.Flow)
		return appMCPReadFlowPolicy(flow) == nil && (flow.Role == "" || HasAnyRole(actor, []string{flow.Role})) && len(flow.Permissions) > 0 && scopesWithin(actor.Scopes, strings.Join(flow.Permissions, " "))
	}
	return false
}
func appMCPFlowPrivateSession(app *App, r *http.Request) (*Session, bool) {
	identity, present := r.Context().Value(appMCPPrivateFlowKey{}).(*appMCPPrivateFlow)
	if !present {
		return nil, false
	}
	if identity == nil || identity.flow == nil || identity.app != app || identity.request != r || !appMCPGenerationCurrent(identity.origin, identity.generation) || r.Context().Err() != nil || r.Method != identity.method || r.URL.Path != identity.path || r.URL.RawQuery != identity.query || identity.generation.manifest != identity.manifest || appMCPFlowSnapshot(app, identity.flow.Name) != identity.flow {
		return nil, true
	}
	_, actor, err := resolveAppMCPAccessForGeneration(r.Context(), identity.origin, identity.generation, identity.credential, identity.resource, time.Now())
	tool := appMCPReadTool(app, identity.tool)
	if err != nil || !appMCPAuthorityUnchanged(identity.actor, actor) || !appMCPToolAllowed(app, tool, actor) {
		return nil, true
	}
	return actor, true
}
func appMCPFlowStepGuard(ctx *FlowContext, step *FlowStep) error {
	if ctx.Request == nil {
		return nil
	}
	identity, present := ctx.Request.Context().Value(appMCPPrivateFlowKey{}).(*appMCPPrivateFlow)
	if !present {
		return nil
	}
	// No effects may run under the read snapshot. Current grant authority is
	// re-resolved at entry and after the pinned connection has been released.
	if identity == nil || identity.flow == nil || identity.request != ctx.Request || !appMCPGenerationCurrent(identity.origin, identity.generation) || ctx.Request.Context().Err() != nil || identity.app != ctx.App || ctx.Request.Method != identity.method || ctx.Request.URL.Path != identity.path || ctx.Request.URL.RawQuery != identity.query || identity.generation.manifest != identity.manifest || appMCPFlowSnapshot(ctx.App, identity.flow.Name) != identity.flow || !appMCPAuthorityUnchanged(identity.actor, ctx.Session) {
		return errAppMCPGrantDenied
	}
	return appMCPReadFlowPolicy(&Flow{Trigger: FlowTrigger{Type: "http"}, Steps: []FlowStep{*step}})
}

// Transaction control belongs to the canonical flow lifecycle. Authored SQL
// still passes the shared single-statement SELECT gate before driver execution.
func authorizeAppMCPReadFlow(action int, arg1, arg2, database string) int {
	if action == sqlite3.SQLITE_TRANSACTION {
		return sqlite3.SQLITE_OK
	}
	return authorizeReadOnlyQuery(action, arg1, arg2, database)
}
func startAppMCPReadFlow(ctx *FlowContext) (func(), error) {
	conn, key, closeConn, err := openReadOnlyQueryConn(ctx.Request.Context(), ctx.App.DB)
	if err != nil {
		return nil, err
	}
	if err = conn.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(authorizeAppMCPReadFlow); return nil }); err != nil {
		closeConn()
		return nil, err
	}
	ctx.mcpReadConn, ctx.mcpReadKey = conn, key
	return func() {
		rollbackAppMCPReadConn(conn)
		closeConn()
	}, nil
}

func runAppMCPReadFlow(ctx context.Context, app *App, raw, resource string, tool *AppMCPTool, args map[string]any) (*appMCPReadResult, error) {
	return runAppMCPReadFlowGeneration(ctx, app, snapshotAppMCPGeneration(app), raw, resource, tool, args)
}

func runAppMCPReadFlowGeneration(ctx context.Context, origin *App, generation *appMCPRuntimeGeneration, raw, resource string, tool *AppMCPTool, args map[string]any) (*appMCPReadResult, error) {
	if generation == nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	app := generation.view
	manifest := generation.manifest
	if tool == nil {
		return nil, appMCPResultFailure("denied")
	}
	tool = appMCPReadTool(app, tool.Name)
	if tool == nil || tool.Handler.Operation != "flow.call" {
		return nil, appMCPResultFailure("denied")
	}
	_, actor, err := resolveAppMCPAccessForGeneration(ctx, origin, generation, raw, resource, time.Now())
	flow := appMCPFlowSnapshot(app, tool.Handler.Flow)
	if err != nil || !appMCPToolAllowed(app, tool, actor) || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	payload, err := json.Marshal(args)
	if err != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	parts := strings.Split(flow.Trigger.Path, "/")
	for i, part := range parts {
		name := ""
		if strings.HasPrefix(part, ":") {
			name = strings.TrimPrefix(part, ":")
		} else if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name = strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
		}
		if name == "" {
			continue
		}
		value, ok := args[name]
		if !ok || value == nil {
			return nil, appMCPResultFailure("invalid_input")
		}
		segment := ""
		switch value.(type) {
		case string, json.Number, bool:
			segment = fmt.Sprint(value)
		default:
			return nil, appMCPResultFailure("invalid_input")
		}
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "/\\\x00") {
			return nil, appMCPResultFailure("invalid_input")
		}
		parts[i] = url.PathEscape(segment)
	}
	ctx, cancel := context.WithTimeout(ctx, readOnlyQueryTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, flow.Trigger.Method, strings.Join(parts, "/"), bytes.NewReader(payload))
	if err != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	// Reload publishes configuration and merged env under this same lock.
	// Credentials stay private and are excluded from reviewed source digests.
	if !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	environment := appEnvSnapshot(app.Dir, generation.environment)
	identity := &appMCPPrivateFlow{app: app, origin: origin, generation: generation, manifest: manifest, flow: flow, actor: actor, environment: environment, credential: raw, resource: resource, tool: tool.Name, method: request.Method, path: request.URL.Path, query: request.URL.RawQuery}
	request = request.WithContext(context.WithValue(request.Context(), appMCPPrivateFlowKey{}, identity))
	identity.request = request
	request.Header = make(http.Header)
	request.Header.Set("Content-Type", "application/json")
	capture := &appMCPReadCapture{header: make(http.Header)}
	err = executeFlowHTTP(app, flow, capture, request)
	if current, _ := appMCPFlowPrivateSession(app, request); current == nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	if err != nil || capture.overflow || capture.status < 200 || capture.status >= 300 {
		return nil, appMCPResultFailure("incomplete_result")
	}
	decoder := json.NewDecoder(bytes.NewReader(capture.Bytes()))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil || value == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, appMCPResultFailure("incomplete_result")
	}
	data, err := appMCPProjectRow(tool, value)
	if err != nil {
		return nil, err
	}
	result := &appMCPReadResult{Data: data, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceRevisions: map[string]string{"contract": manifest.ContractDigest, "execution": manifest.ExecutionDigest}, Completeness: appMCPCompleteness{State: "indeterminate", Basis: "declared_output"}, Freshness: "observed", Warnings: []string{"data_revision_unavailable", "flow_completeness_not_declared"}}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > appMCPResultLimit {
		return nil, appMCPResultFailure("incomplete_result")
	}
	if current, _ := appMCPFlowPrivateSession(app, request); current == nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	return result, nil
}

// Retain the canonical flow's snapshot without holding a writer transaction.
func appMCPReadFlowTransaction(ctx *FlowContext, statement string) error {
	callContext := ctx.Request.Context()
	if statement == "ROLLBACK" {
		callContext = context.Background()
	}
	_, err := ctx.mcpReadConn.ExecContext(callContext, statement)
	return err
}

// Goja consumes IEEE-754 numbers. Preserve JSON numeric semantics and reject
// a number whose JSON value would change at that boundary; SQL keeps exact IDs.
func appMCPComputeArgs(value any) (any, error) {
	switch v := value.(type) {
	case json.Number, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		before, ok := appMCPExactNumber(v)
		if !ok {
			return nil, fmt.Errorf("connector compute number cannot be represented exactly")
		}
		n, _ := before.Float64()
		after, valid := appMCPExactNumber(n)
		if !valid || before.Cmp(after) != 0 {
			return nil, fmt.Errorf("connector compute number cannot be represented exactly")
		}
		return n, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			converted, err := appMCPComputeArgs(item)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case []map[string]any:
		out := make([]any, len(v))
		for i, item := range v {
			converted, err := appMCPComputeArgs(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			converted, err := appMCPComputeArgs(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	default:
		return value, nil
	}
}

// Cleanup outlives request cancellation. An unclosed read transaction is never
// returned to the app pool; shared lease cleanup restores the authorizer.
func rollbackAppMCPReadConn(conn *sql.Conn) {
	_ = conn.Raw(func(raw any) error {
		sqlite := raw.(*sqlite3.SQLiteConn)
		if !sqlite.AutoCommit() {
			if _, err := sqlite.Exec("ROLLBACK", nil); err != nil {
				return driver.ErrBadConn
			}
		}
		return nil
	})
}
