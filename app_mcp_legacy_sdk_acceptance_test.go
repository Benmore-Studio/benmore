//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type appMCPLegacyWireRequest struct {
	method string
	header http.Header
	body   []byte
	status int
}

type appMCPLegacyCapture struct {
	mu       sync.Mutex
	requests []appMCPLegacyWireRequest
}

type appMCPLegacyCaptureWriter struct {
	http.ResponseWriter
	status int
}

func (w *appMCPLegacyCaptureWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (c *appMCPLegacyCapture) handler(app *App, resource string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		cw := &appMCPLegacyCaptureWriter{ResponseWriter: w}
		serveAppMCP(cw, r, app, resource)
		if cw.status == 0 {
			cw.status = http.StatusOK
		}
		c.mu.Lock()
		c.requests = append(c.requests, appMCPLegacyWireRequest{method: r.Method, header: r.Header.Clone(), body: append([]byte(nil), body...), status: cw.status})
		c.mu.Unlock()
	})
}

func (c *appMCPLegacyCapture) snapshot() []appMCPLegacyWireRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]appMCPLegacyWireRequest(nil), c.requests...)
}

// This runs a separate child module pinned to the last SDK release before
// modern discovery negotiation. The child uses the SDK's default initialize
// path over real TLS; no MCP wire messages are rewritten by this fixture.
func TestAppMCPRealSDKTLSLegacyNegotiationAndRevocation(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	manifest := strings.Replace(appMCPManifestFixture(), "resources: []", `  - name: list_projects
    description: Read project IDs
    handler: {kind: native, operation: table.list, table: projects}
    input_schema: {type: object, additionalProperties: false}
    output_schema:
      type: object
      additionalProperties: false
      properties:
        id: {type: integer}
    permissions: [projects:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id]}
    component: none
resources: []`, 1)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, org_id TEXT);\nCREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT);\n")
	writeTestFile(t, app.Dir, "mcp.yaml", manifest)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	// auditApp's physical notes table predates this fixture's tenant-scoped
	// schema.sql rewrite; that rewrite does not migrate the existing SQLite DB.
	if _, err := app.DB.Exec("ALTER TABLE notes ADD COLUMN org_id TEXT"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT)"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"notes", "projects"} {
		columns, err := GetTableColumns(app.DB, table)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for i := range app.Tables {
			if app.Tables[i].Name == table {
				app.Tables[i].Columns = columns
				found = true
			}
		}
		if !found {
			app.Tables = append(app.Tables, Table{Name: table, Columns: columns})
		}
	}
	app.Access.rules["notes"] = map[AccessOp]string{"read": "group"}
	app.Access.rules["projects"] = map[AccessOp]string{"read": "group"}
	app.Roles.Roles["project_reader"] = RoleDef{Scopes: "projects:read"}
	if _, err := app.DB.Exec("INSERT INTO _benmore_user_roles(user_id,role,group_id) VALUES (?,'project_reader','29')", uid); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("INSERT INTO notes(id,user_id,title,org_id) VALUES (1,?,'tenant 17','17'),(2,?,'tenant 29','29'),(3,?,'foreign tenant decoy','99')", uid, uid, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("INSERT INTO projects(id,org_id) VALUES (17,'17'),(29,'29'),(99,'99')"); err != nil {
		t.Fatal(err)
	}

	// The TLS server starts handlers before its URL and grants are available.
	// The race gate caught an unsynchronized resource read; publish all setup
	// through this channel before any handler touches those values.
	ready := make(chan struct{})
	var resource string
	capture := &appMCPLegacyCapture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/_mcp", func(w http.ResponseWriter, r *http.Request) {
		<-ready
		capture.handler(app, resource).ServeHTTP(w, r)
	})
	controlSecret := generateToken(32)
	var pair17, pair29 *appMCPTokenPair
	mux.HandleFunc("/test/revoke-17", func(w http.ResponseWriter, r *http.Request) {
		<-ready
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+controlSecret {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		result, err := app.DB.Exec("UPDATE _benmore_mcp_grants SET revoked=1 WHERE id=? AND user_id=? AND tenant='17' AND revoked=0", pair17.GrantID, uid)
		if err != nil {
			http.Error(w, "revoke failed", http.StatusInternalServerError)
			return
		}
		changed, _ := result.RowsAffected()
		if changed != 1 {
			http.Error(w, "unexpected grant count", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	resource = server.URL + "/api/_mcp"
	var grantErr error
	pair17, grantErr = createAppMCPGrant(app, uid, "17", "legacy-tenant-17", resource, "notes:read", time.Now())
	if grantErr != nil {
		t.Fatal(grantErr)
	}
	pair29, grantErr = createAppMCPGrant(app, uid, "29", "legacy-tenant-29", resource, "notes:read projects:read", time.Now())
	if grantErr != nil {
		t.Fatal(grantErr)
	}
	if pair17.AccessToken == pair29.AccessToken {
		t.Fatal("tenant grants unexpectedly share a bearer token")
	}
	close(ready)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if len(certPEM) == 0 {
		t.Fatal("could not encode test TLS certificate")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not trust test TLS certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	childDir := filepath.Join("testdata", "mcp-legacy-sdk")
	cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "test", "-count=1", "-run", "^TestLegacyClientProtocolAndTenantRevocation$", "-v", ".")
	cmd.Dir = childDir
	cmd.Env = append(os.Environ(),
		"GOTOOLCHAIN=local",
		"MCP_LEGACY_ENDPOINT="+resource,
		"MCP_LEGACY_RESOURCE="+resource,
		"MCP_LEGACY_TOKEN_17="+pair17.AccessToken,
		"MCP_LEGACY_TOKEN_29="+pair29.AccessToken,
		"MCP_LEGACY_EXPECTED_ID_17=1",
		"MCP_LEGACY_EXPECTED_ID_29=2",
		"MCP_LEGACY_CA_CERT="+string(certPEM),
		"MCP_LEGACY_REVOKE_ENDPOINT="+server.URL+"/test/revoke-17",
		"MCP_LEGACY_REVOKE_SECRET="+controlSecret,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official legacy SDK child failed: %v\n%s", err, out)
	}
	t.Logf("official legacy SDK child:\n%s", out)
	assertAppMCP313LegacySDKWire(t, capture.snapshot(), pair17.AccessToken, pair29.AccessToken)

	var revoked bool
	if err := app.DB.QueryRow("SELECT revoked FROM _benmore_mcp_grants WHERE id=?", pair17.GrantID).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("test control did not revoke tenant 17 grant: revoked=%v err=%v", revoked, err)
	}
}

func assertAppMCP313LegacySDKWire(t *testing.T, captured []appMCPLegacyWireRequest, token17, token29 string) {
	t.Helper()
	const version = "2025-11-25"
	var initialize, initialized, list, call int
	methodsByToken := map[string]map[string]int{}
	unauthorizedByBearerAndMethod := map[string]map[string]int{}
	for _, request := range captured {
		if request.method != http.MethodPost || len(request.body) == 0 {
			continue
		}
		var message struct {
			Method string `json:"method"`
			Params struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"params"`
		}
		if err := json.Unmarshal(request.body, &message); err != nil {
			t.Fatalf("captured SDK POST body is invalid JSON: %v", err)
		}
		bearer := request.header.Get("Authorization")
		switch message.Method {
		case "initialize":
			initialize++
			if message.Params.ProtocolVersion != version {
				t.Errorf("legacy SDK initialize protocolVersion=%q want %q", message.Params.ProtocolVersion, version)
			}
		case "notifications/initialized":
			initialized++
		case "tools/list":
			list++
		case "tools/call":
			call++
		}
		if bearer == "Bearer "+token17 || bearer == "Bearer "+token29 {
			if methodsByToken[bearer] == nil {
				methodsByToken[bearer] = map[string]int{}
			}
			methodsByToken[bearer][message.Method]++
		} else {
			t.Errorf("legacy SDK request used unexpected bearer identity %q", bearer)
		}
		if request.status == http.StatusUnauthorized {
			if unauthorizedByBearerAndMethod[bearer] == nil {
				unauthorizedByBearerAndMethod[bearer] = map[string]int{}
			}
			unauthorizedByBearerAndMethod[bearer][message.Method]++
		}
		protocolHeader := request.header.Get("Mcp-Protocol-Version")
		if message.Method == "initialize" {
			if protocolHeader != "" && protocolHeader != version {
				t.Errorf("initialize request used unexpected protocol header %q", protocolHeader)
			}
			if request.status != http.StatusOK {
				t.Errorf("initialize returned HTTP %d, want 200", request.status)
			}
		} else if protocolHeader != version {
			t.Errorf("legacy %s request protocol header %q, want %q", message.Method, protocolHeader, version)
		}
		if protocolHeader != "" && protocolHeader != version {
			t.Errorf("SDK sent unexpected protocol header %q", request.header.Get("Mcp-Protocol-Version"))
		}
	}
	if initialize != 3 || initialized != 3 || list < 3 || call < 6 {
		t.Errorf("captured methods initialize=%d initialized=%d tools/list=%d tools/call=%d", initialize, initialized, list, call)
	}
	for label, token := range map[string]string{"tenant17": "Bearer " + token17, "tenant29": "Bearer " + token29} {
		for _, method := range []string{"initialize", "notifications/initialized", "tools/list", "tools/call"} {
			if methodsByToken[token][method] == 0 {
				t.Errorf("%s SDK traffic did not capture method %s", label, method)
			}
		}
	}
	for _, method := range []string{"tools/list", "tools/call"} {
		if unauthorizedByBearerAndMethod["Bearer "+token17][method] == 0 {
			t.Errorf("did not capture tenant 17 legacy-protocol HTTP 401 for %s after revocation", method)
		}
	}
}
