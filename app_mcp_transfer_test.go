//go:build !cli

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const transferPushOpenAPI = `openapi: 3.0.3
info: {title: Transfer fixture, version: '1'}
paths:
  /files:
    post:
      operationId: pushFile
      requestBody:
        required: true
        content:
          application/json:
            schema: {type: object, additionalProperties: false, required: [content_base64, idempotency_key], properties: {content_base64: {type: string}, idempotency_key: {type: string}}}
      responses:
        '200': {description: ok, content: {application/json: {schema: {type: object, additionalProperties: false, required: [id, sha256], properties: {id: {type: string}, sha256: {type: string}}}}}}
  /files/by-key:
    get:
      operationId: findFileByKey
      parameters: [{name: key, in: query, required: true, schema: {type: string}}]
      responses:
        '200': {description: ok, content: {application/json: {schema: {type: object, additionalProperties: false, required: [id, sha256], properties: {id: {type: string}, sha256: {type: string}}}}}}
`

const transferPullOpenAPI = `openapi: 3.0.3
info: {title: Pull fixture, version: '1'}
paths:
  /files/{id}:
    get:
      operationId: pullFile
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {type: object, additionalProperties: false, required: [content, mime, revision, checksum], properties: {content: {type: string}, mime: {type: string}, revision: {type: string}, checksum: {type: string}}}
`

func newTransferPullFixture(t *testing.T) (*App, string, int64, *appMCPTokenPair, *appMCPRuntimeGeneration) {
	t.Helper()
	flow := strings.Replace(commandTaskFlowFixture, "required: [id, project_id]", "required: [id, project_id, file_id, record_id]", 1)
	flow = strings.Replace(flow, "project_id: {type: integer, minimum: 1, maximum: 9007199254740991}", "project_id: {type: integer, minimum: 1, maximum: 9007199254740991}\n      file_id: {type: string, minLength: 1, maxLength: 128}\n      record_id: {type: string, minLength: 1, maxLength: 128}", 1)
	flow = strings.Replace(flow, "arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}'}", "arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}', file_id: '${{ params.arguments.file_id }}', record_id: '${{ params.arguments.record_id }}'}", 1)
	app, sessionID, actorID := newUnenrolledCommandProviderTaskFixtureWithManifest(t, flow, "", func(manifest *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "schema.sql", `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, user_id INTEGER NOT NULL);
CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, org_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, completed_by INTEGER, completed_at TEXT, evidence_file TEXT);
CREATE TABLE activities (id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, actor_user_id INTEGER NOT NULL, actor_email TEXT NOT NULL, event TEXT NOT NULL);
`)
		writeTestFile(t, dir, "openapi/transfers.yaml", transferPullOpenAPI)
		args := manifest.Tools[0].InputSchema.Properties["arguments"]
		args.Properties["file_id"] = &AppMCPSchema{Type: "string", MinLength: intPointer(1), MaxLength: intPointer(128)}
		args.Properties["record_id"] = &AppMCPSchema{Type: "string", MinLength: intPointer(1), MaxLength: intPointer(128)}
		args.Required = append(args.Required, "file_id", "record_id")
		manifest.Tools[0].Transfer = &AppMCPTransfer{Kind: "pull", Connection: "files", OperationID: "pullFile", SelectorIntentPath: "arguments.file_id", SelectorParameter: "path.id",
			ContentField: "content", MIMEField: "mime", ExpectedMIME: "application/pdf", RevisionField: "revision", ChecksumField: "checksum",
			AttachTool: "attach_evidence", RecordIDIntentPath: "arguments.record_id", FileColumn: "evidence_file"}
		manifest.Tools = append(manifest.Tools, pullAttachTool())
		manifest.Connections = []AppMCPConnection{{Name: "files", BaseURL: "https://files.example.invalid/v1", Auth: AppMCPConnectionAuth{Kind: "none"}, OpenAPI: "openapi/transfers.yaml"}}
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	generation = snapshotAppMCPGeneration(app)
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "transfer-pull-fixture", grantFixtureResource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ensureCommandAuditFixture(t, app)
	EnsureJobsTable(app.DB)
	EnsureLocksTable(app.DB)
	return app, sessionID, actorID, pair, generation
}

func pullAttachTool() AppMCPTool {
	closed := false
	file := &AppMCPSchema{Type: "string", MaxLength: intPointer(512)}
	return AppMCPTool{Name: "attach_evidence", Description: "Attach a pulled private file to a task.",
		Handler: AppMCPHandler{Kind: "native", Operation: "table.update", Table: "tasks"},
		InputSchema: &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: []string{"id", "data"}, Properties: map[string]*AppMCPSchema{
			"id":   {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
			"data": {Type: "object", AdditionalProperties: &closed, Required: []string{"evidence_file"}, Properties: map[string]*AppMCPSchema{"evidence_file": file}},
		}},
		OutputSchema: &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: []string{"id", "evidence_file"}, Properties: map[string]*AppMCPSchema{
			"id": {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))}, "evidence_file": file,
		}}, Permissions: []string{"tasks:write"}, Effect: "write", Approval: "first_party", Idempotency: "operation", Reconciliation: "authoritative_readback",
		Output: AppMCPProjection{Include: []string{"id", "evidence_file"}}, Component: "none"}
}

func newTransferPushFixture(t *testing.T) (*App, string, int64, *appMCPTokenPair, *appMCPRuntimeGeneration) {
	t.Helper()
	flow := strings.Replace(commandTaskFlowFixture, "required: [id, project_id]", "required: [id, project_id, artifact_id]", 1)
	flow = strings.Replace(flow, "project_id: {type: integer, minimum: 1, maximum: 9007199254740991}", "project_id: {type: integer, minimum: 1, maximum: 9007199254740991}\n      artifact_id: {type: string, minLength: 1, maxLength: 128}", 1)
	flow = strings.Replace(flow, "arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}'}", "arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}', artifact_id: '${{ params.arguments.artifact_id }}'}", 1)
	app, sessionID, actorID := newUnenrolledCommandProviderTaskFixtureWithManifest(t, flow, "", func(manifest *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "openapi/transfers.yaml", transferPushOpenAPI)
		args := manifest.Tools[0].InputSchema.Properties["arguments"]
		args.Properties["artifact_id"] = &AppMCPSchema{Type: "string", MinLength: intPointer(1), MaxLength: intPointer(128)}
		args.Required = append(args.Required, "artifact_id")
		manifest.Tools[0].Transfer = &AppMCPTransfer{Kind: "push", Connection: "files", OperationID: "pushFile", ArtifactIntentPath: "arguments.artifact_id",
			RequestContentField: "content_base64", RequestIdempotencyField: "idempotency_key", ReconcileOperationID: "findFileByKey", ReconcileParameter: "query.key", ResultIDField: "id", ResultChecksumField: "sha256"}
		manifest.Connections = []AppMCPConnection{{Name: "files", BaseURL: "https://files.example.invalid/v1", Auth: AppMCPConnectionAuth{Kind: "none"}, OpenAPI: "openapi/transfers.yaml"}}
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := mutateAppMCPEpochContext(context.Background(), app.Dir, nil, false, false, func(state *appMCPEpochState) error {
		state.ExternalExport = true
		state.ExternalExportEpoch, _ = rotateAppMCPCapabilityEpoch()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	generation = snapshotAppMCPGeneration(app)
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "transfer-fixture", grantFixtureResource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ensureCommandAuditFixture(t, app)
	EnsureJobsTable(app.DB)
	return app, sessionID, actorID, pair, generation
}

func installPipeUpstream(t *testing.T, handler func(*http.Request) (int, string, bool)) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "files.example.invalid"}, DNSNames: []string{"files.example.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	previous := appMCPExternalTransport
	appMCPExternalTransport = func() *http.Transport {
		return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					conn := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
					defer conn.Close()
					if conn.Handshake() != nil {
						return
					}
					req, err := http.ReadRequest(bufio.NewReader(conn))
					if err != nil {
						return
					}
					defer req.Body.Close()
					status, body, drop := handler(req)
					if drop {
						return
					}
					_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
				}()
				return client, nil
			}}
	}
	t.Cleanup(func() { appMCPExternalTransport = previous })
}

func TestAppMCPTransferPushCoordinatorWorkerAndLaterReadOnlyReconcile(t *testing.T) {
	app, sessionID, actorID, pair, generation := newTransferPushFixture(t)
	artifact := newTestMCPArtifact(t, app, actorID, []byte("approved transfer artifact"))
	var fixtureCount int
	if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_mcp_artifacts WHERE id=?`, artifact.ID).Scan(&fixtureCount); err != nil || fixtureCount != 1 {
		t.Fatalf("artifact fixture missing before command: id=%s count=%d err=%v", artifact.ID, fixtureCount, err)
	}
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := appMCPConnectorOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
	prepared, err := appMCPPrepareOperation(context.Background(), request, map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7, "artifact_id": artifact.ID}})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if got := prepared.Preview["external_transfer"].(map[string]any)["artifact_id"]; got != artifact.ID {
		t.Fatalf("prepare did not disclose exact artifact: %#v", prepared.Preview)
	}
	approve := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
	if _, err := appMCPReviewOperation(context.Background(), approve, prepared.ID, "fixture-approved"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	commit, err := appMCPCommitOperation(context.Background(), request, prepared.ID)
	if err != nil || commit.Outcome != "applied" {
		t.Fatalf("commit: view=%+v err=%v", commit, err)
	}
	var posts, gets atomic.Int32
	upstreamID, checksum := "upstream-file-1", artifact.SHA256
	installPipeUpstream(t, func(req *http.Request) (int, string, bool) {
		if req.Method == http.MethodPost {
			posts.Add(1)
			return 0, "", true // accepted or rejected cannot be inferred after this drop
		}
		if req.Method != http.MethodGet || req.URL.Query().Get("key") == "" {
			return http.StatusBadRequest, `{}`, false
		}
		if gets.Add(1) == 1 {
			return http.StatusNotFound, `{}`, false // worker's immediate readback cannot prove the POST
		}
		body, _ := json.Marshal(map[string]string{"id": upstreamID, "sha256": checksum})
		return http.StatusOK, string(body), false
	})
	if !processNextJob(app) {
		t.Fatal("worker did not process the transfer job")
	}
	var jobStatus, phase string
	if err := app.DB.QueryRow(`SELECT j.status,s.phase FROM main._benmore_jobs j JOIN main._benmore_mcp_transfer_state s ON s.job_id=j.id WHERE j.job_type=?`, appMCPTransferJobType).Scan(&jobStatus, &phase); err != nil || jobStatus != "failed" || phase != "unknown" {
		t.Fatalf("lost response was not durably unknown: job=%q phase=%q err=%v", jobStatus, phase, err)
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("initial attempt methods: POST=%d GET=%d", posts.Load(), gets.Load())
	}
	statusOrigin, err := appMCPConnectorStatusOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	statusRequest := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: statusOrigin, readOnlyStatus: true, now: time.Now().UTC()}
	statusView, err := appMCPStatusOperation(context.Background(), statusRequest, prepared.ID)
	if err != nil {
		t.Fatalf("read-only status reconcile: %v", err)
	}
	var state, phaseStatus string
	if err := app.DB.QueryRow(`SELECT j.status,s.phase FROM main._benmore_jobs j JOIN main._benmore_mcp_transfer_state s ON s.job_id=j.id WHERE j.job_type=?`, appMCPTransferJobType).Scan(&state, &phaseStatus); err != nil || state != "failed" || phaseStatus != "pushed" {
		t.Fatalf("later GET did not persist confirmed outcome: job=%q phase=%q err=%v", state, phaseStatus, err)
	}
	effects, _ := statusView.Effects["items"].([]any)
	if len(effects) != 1 || effects[0].(map[string]any)["status"] != appMCPEffectDelivered || effects[0].(map[string]any)["phase"] != "pushed" {
		t.Fatalf("reconciled effect view did not expose durable delivered phase: %#v", statusView.Effects)
	}
	if posts.Load() != 1 || gets.Load() != 2 {
		t.Fatalf("status replayed push or skipped GET: POST=%d GET=%d", posts.Load(), gets.Load())
	}
}

func TestAppMCPTransferTamperedEffectStampBlocksBeforeProviderEgress(t *testing.T) {
	app, sessionID, actorID, pair, generation := newTransferPushFixture(t)
	artifact := newTestMCPArtifact(t, app, actorID, []byte("tamper test artifact"))
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := appMCPConnectorOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
	prepared, err := appMCPPrepareOperation(context.Background(), request, map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7, "artifact_id": artifact.ID}})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	approve := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
	if _, err := appMCPReviewOperation(context.Background(), approve, prepared.ID, "fixture-approved"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := appMCPCommitOperation(context.Background(), request, prepared.ID); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var payload string
	if err := app.DB.QueryRow(`SELECT payload FROM main._benmore_jobs WHERE job_type=?`, appMCPTransferJobType).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var job map[string]any
	if err := json.Unmarshal([]byte(payload), &job); err != nil {
		t.Fatal(err)
	}
	stamp := job[appMCPEffectKey].(map[string]any)
	stamp["grant_id"] = strings.Repeat("f", 64)
	tampered, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE main._benmore_jobs SET payload=? WHERE job_type=?`, string(tampered), appMCPTransferJobType); err != nil {
		t.Fatal(err)
	}
	var egress atomic.Int32
	installPipeUpstream(t, func(*http.Request) (int, string, bool) {
		egress.Add(1)
		return http.StatusInternalServerError, `{}`, false
	})
	if !processNextJob(app) {
		t.Fatal("worker did not claim tampered transfer")
	}
	var status, jobError string
	if err := app.DB.QueryRow(`SELECT status,COALESCE(error,'') FROM main._benmore_jobs WHERE job_type=?`, appMCPTransferJobType).Scan(&status, &jobError); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.HasPrefix(jobError, appMCPEffectBlockedPrefix) || egress.Load() != 0 {
		t.Fatalf("tampered transfer was not blocked before egress: status=%q error=%q egress=%d", status, jobError, egress.Load())
	}
	statusOrigin, err := appMCPConnectorStatusOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	statusRequest := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: statusOrigin, readOnlyStatus: true, now: time.Now().UTC()}
	statusView, err := appMCPStatusOperation(context.Background(), statusRequest, prepared.ID)
	if err != nil {
		t.Fatalf("status for blocked tampered transfer: %v", err)
	}
	effects, _ := statusView.Effects["items"].([]any)
	var effectStatus any
	if len(effects) == 1 {
		effectStatus = effects[0].(map[string]any)["status"]
	}
	if len(effects) != 1 || effectStatus != appMCPEffectUnknown && effectStatus != appMCPEffectBlocked {
		t.Fatalf("blocked tampered transfer was misreported as pending or delivered: %#v", statusView.Effects)
	}
}

func TestAppMCPTransferPullWorkerStoresProvenanceAndCanonicallyAttaches(t *testing.T) {
	app, sessionID, _, pair, generation := newTransferPullFixture(t)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := appMCPConnectorOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
	input := map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7, "file_id": "upstream-file-99", "record_id": "1"}}
	prepared, err := appMCPPrepareOperation(context.Background(), request, input)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	disclosure, _ := prepared.Preview["external_transfer"].(map[string]any)
	if disclosure["selected_source_id"] != "upstream-file-99" || disclosure["target_table"] != "tasks" || disclosure["target_record_id"] != "1" || disclosure["target_file_column"] != "evidence_file" {
		t.Fatalf("pull review did not disclose exact source and target: %#v", prepared.Preview)
	}
	approve := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
	if _, err := appMCPReviewOperation(context.Background(), approve, prepared.ID, "fixture-approved"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := appMCPCommitOperation(context.Background(), request, prepared.ID); err != nil {
		t.Fatalf("commit: %v", err)
	}
	content := []byte("%PDF-1.7\nprivate transfer fixture\n")
	response, _ := json.Marshal(map[string]string{"content": "JVBERi0xLjcKcHJpdmF0ZSB0cmFuc2ZlciBmaXh0dXJlCg==", "mime": "application/pdf", "revision": "rev-42", "checksum": hashBytesSHA256(content)})
	var gets atomic.Int32
	var transferPayload string
	if err := app.DB.QueryRow(`SELECT payload FROM main._benmore_jobs WHERE job_type=?`, appMCPTransferJobType).Scan(&transferPayload); err != nil {
		t.Fatal(err)
	}
	var transferEnvelope map[string]any
	if err := json.Unmarshal([]byte(transferPayload), &transferEnvelope); err != nil {
		t.Fatal(err)
	}
	job, err := appMCPDecodeTransferJob(transferEnvelope[appMCPTransferPayloadKey])
	if err != nil {
		t.Fatal(err)
	}
	workerActor, err := appMCPGrantActorForGeneration(context.Background(), app, generation, grant, time.Now())
	if err != nil {
		t.Fatalf("worker grant actor: %v", err)
	}
	if err := appMCPTransferPullAuthorize(context.Background(), app, generation, workerActor, generation.manifest.Tools[0].Transfer, job.RecordID, job.RowDigest); err != nil {
		t.Fatalf("pull target authorization before worker: %v", err)
	}
	installPipeUpstream(t, func(req *http.Request) (int, string, bool) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/files/upstream-file-99" {
			return http.StatusBadRequest, `{}`, false
		}
		gets.Add(1)
		return http.StatusOK, string(response), false
	})
	if !processNextJob(app) {
		t.Fatal("worker did not process pull job")
	}
	var status, phase, path, hash string
	if err := app.DB.QueryRow(`SELECT j.status,s.phase,s.recovery_ref,s.content_sha256 FROM main._benmore_jobs j JOIN main._benmore_mcp_transfer_state s ON s.job_id=j.id WHERE j.job_type=?`, appMCPTransferJobType).Scan(&status, &phase, &path, &hash); err != nil || status != "completed" || phase != "attached" || hash != hashBytesSHA256(content) {
		t.Fatalf("pull did not finish with durable attached provenance: job=%q phase=%q path=%q hash=%q err=%v", status, phase, path, hash, err)
	}
	var attached string
	if err := app.DB.QueryRow(`SELECT evidence_file FROM main.tasks WHERE id=1`).Scan(&attached); err != nil || attached != path {
		t.Fatalf("canonical attach did not update the target: got=%q want=%q err=%v", attached, path, err)
	}
	var ownerID int64
	logical := strings.TrimPrefix(path, "uploads/")
	if err := app.DB.QueryRow(`SELECT user_id FROM main._benmore_upload_owners WHERE path=?`, logical).Scan(&ownerID); err != nil || ownerID <= 0 {
		t.Fatalf("private upload owner missing: user=%d err=%v", ownerID, err)
	}
	var source, upstreamID, revision string
	if err := app.DB.QueryRow(`SELECT source_connection,source_file_id,source_revision FROM main._benmore_mcp_file_processings WHERE file_id=?`, strings.TrimPrefix(path, "uploads/")).Scan(&source, &upstreamID, &revision); err != nil || source != "files" || upstreamID != "upstream-file-99" || revision != "rev-42" {
		t.Fatalf("external file provenance missing: source=%q id=%q revision=%q err=%v", source, upstreamID, revision, err)
	}
	if gets.Load() != 1 {
		t.Fatalf("pull download count = %d, want one", gets.Load())
	}
	if err := appMCPTransferPullAuthorize(context.Background(), app, generation, workerActor, generation.manifest.Tools[0].Transfer, job.RecordID, job.RowDigest); err == nil {
		t.Fatal("pull accepted a stale target revision after canonical attachment")
	}
}

func TestAppMCPTransferDecodeJSONRejectsTrailingDocuments(t *testing.T) {
	closed := false
	operation := &appMCPExternalOperation{Output: &AppMCPSchema{Type: "object", AdditionalProperties: &closed,
		Required: []string{"id"}, Properties: map[string]*AppMCPSchema{"id": {Type: "string"}}}}
	header := http.Header{"Content-Type": []string{"application/json"}}
	if _, err := appMCPTransferDecodeJSON(header, []byte(`{"id":"one"}`), operation); err != nil {
		t.Fatalf("single JSON object rejected: %v", err)
	}
	if _, err := appMCPTransferDecodeJSON(header, []byte(`{"id":"one"} {"id":"two"}`), operation); err == nil {
		t.Fatal("trailing JSON document accepted")
	}
}

func TestAppMCPTransferRequestUsesTransferWireBound(t *testing.T) {
	closed := false
	operation := &appMCPExternalOperation{Method: "POST", Path: "/files", Input: &AppMCPSchema{Type: "object", AdditionalProperties: &closed,
		Required: []string{"body"}, Properties: map[string]*AppMCPSchema{"body": {Type: "object", AdditionalProperties: &closed,
			Required: []string{"content"}, Properties: map[string]*AppMCPSchema{"content": {Type: "string"}}}}}}
	base, _ := url.Parse("https://example.invalid")
	connection := &AppMCPConnection{Auth: AppMCPConnectionAuth{Kind: "none"}}
	input := map[string]any{"body": map[string]any{"content": strings.Repeat("x", 5<<20)}}
	if _, _, _, err := buildAppMCPExternalRequest(base, connection, operation, input, ""); err == nil {
		t.Fatal("ordinary external request exceeded its P9 input cap")
	}
	if _, _, body, err := buildAppMCPExternalRequestLimit(base, connection, operation, input, "", int(appMCPTransferWireLimit)); err != nil || len(body) <= appMCPInputLimit {
		t.Fatalf("transfer request did not use its bounded transfer cap: body=%d err=%v", len(body), err)
	}
}

func TestAppMCPTransferPullRequiresPinnedMIMEAndSafeContent(t *testing.T) {
	transfer := &AppMCPTransfer{ContentField: "content", MIMEField: "mime", RevisionField: "revision", ChecksumField: "checksum", ExpectedMIME: "application/pdf"}
	content := []byte("%PDF-1.7\nfile")
	result := map[string]any{"content": "JVBERi0xLjcKZmlsZQ==", "mime": "application/pdf", "revision": "r1", "checksum": hashBytesSHA256(content)}
	decoded, media, revision, err := appMCPDecodePulledFile(result, transfer)
	if err != nil || string(decoded) != string(content) || media != "application/pdf" || revision != "r1" {
		t.Fatalf("valid pulled file rejected: media=%q revision=%q err=%v", media, revision, err)
	}
	result["mime"] = "text/html"
	if _, _, _, err := appMCPDecodePulledFile(result, transfer); err == nil {
		t.Fatal("unapproved response MIME accepted")
	}
	if extension := appMCPTransferExtension(transfer.ExpectedMIME); extension != ".pdf" {
		t.Fatalf("P6b parser extension = %q, want .pdf", extension)
	}
}

func TestAppMCPCommandPreviewSchemaDisclosesTransfer(t *testing.T) {
	closed := false
	base := &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: []string{"summary"}, Properties: map[string]*AppMCPSchema{"summary": {Type: "string"}}}
	transfer := &AppMCPTransfer{Kind: "push", Connection: "records", OperationID: "createFile"}
	schema := appMCPCommandPreviewOutputSchema(base, transfer)
	properties := schema["properties"].(map[string]any)
	required := schema["required"].([]any)
	if _, ok := properties["external_transfer"]; !ok {
		t.Fatal("SDK prepare schema omitted transfer disclosure")
	}
	found := false
	for _, field := range required {
		found = found || field == "external_transfer"
	}
	if !found {
		t.Fatal("SDK prepare schema does not require transfer disclosure")
	}
}

func TestAppMCPPushOnceReconcilesLostResponseWithoutReplay(t *testing.T) {
	closed := false
	output := &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: []string{"id", "sha"}, Properties: map[string]*AppMCPSchema{
		"id": {Type: "string"}, "sha": {Type: "string"},
	}}
	post := &appMCPExternalOperation{Method: "POST", Output: output}
	get := &appMCPExternalOperation{Method: "GET", Output: output}
	operations := &appMCPTransferOperations{Operation: post, Reconcile: get}
	transfer := &AppMCPTransfer{RequestContentField: "content", RequestIdempotencyField: "key", ReconcileParameter: "query.key", ResultIDField: "id", ResultChecksumField: "sha"}
	key, checksum := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var methods []string
	var gotKey string
	call := func(input map[string]any, operation *appMCPExternalOperation, _ int64) (int, http.Header, []byte, error) {
		methods = append(methods, operation.Method)
		header := http.Header{"Content-Type": []string{"application/json"}}
		if operation == post {
			body := input["body"].(map[string]any)
			gotKey, _ = body["key"].(string)
			return 0, nil, nil, http.ErrHandlerTimeout // simulate response lost after POST
		}
		gotKey, _ = input["query"].(map[string]any)["key"].(string)
		result, _ := json.Marshal(map[string]any{"id": "upstream-file-1", "sha": checksum})
		return http.StatusOK, header, result, nil
	}
	id, confirmed := appMCPPushOnce(transfer, operations, key, checksum, "YmFzZTY0", call)
	if !confirmed || id != "upstream-file-1" || gotKey != key || !reflect.DeepEqual(methods, []string{"POST", "GET"}) {
		t.Fatalf("lost POST response was not reconciled once: id=%q confirmed=%v key=%q methods=%v", id, confirmed, gotKey, methods)
	}
	methods = nil
	id, confirmed = appMCPPushOnce(transfer, operations, key, checksum, "YmFzZTY0", func(input map[string]any, operation *appMCPExternalOperation, limit int64) (int, http.Header, []byte, error) {
		methods = append(methods, operation.Method)
		return 0, nil, nil, http.ErrHandlerTimeout
	})
	if confirmed || id != "" || !reflect.DeepEqual(methods, []string{"POST", "GET"}) {
		t.Fatalf("unconfirmed outcome was retried or reported successful: id=%q confirmed=%v methods=%v", id, confirmed, methods)
	}
}

func TestAppMCPReadOnlyPushReconcileNeverPosts(t *testing.T) {
	closed := false
	operation := &appMCPExternalOperation{Method: "GET", Output: &AppMCPSchema{Type: "object", AdditionalProperties: &closed,
		Required: []string{"id", "sha"}, Properties: map[string]*AppMCPSchema{"id": {Type: "string"}, "sha": {Type: "string"}}}}
	transfer := &AppMCPTransfer{ReconcileParameter: "query.key", ResultIDField: "id", ResultChecksumField: "sha"}
	key, checksum := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var methods []string
	id, confirmed := appMCPReconcilePushByKey(transfer, operation, key, checksum, func(input map[string]any, op *appMCPExternalOperation, _ int64) (int, http.Header, []byte, error) {
		methods = append(methods, op.Method)
		if input["query"].(map[string]any)["key"] != key {
			t.Fatalf("reconcile key was not server-derived: %#v", input)
		}
		body, _ := json.Marshal(map[string]any{"id": "upstream-file-1", "sha": checksum})
		return http.StatusOK, http.Header{"Content-Type": []string{"application/json"}}, body, nil
	})
	if !confirmed || id != "upstream-file-1" || !reflect.DeepEqual(methods, []string{"GET"}) {
		t.Fatalf("later reconciliation was not GET-only: id=%q confirmed=%v methods=%v", id, confirmed, methods)
	}
}

func TestAppMCPStorePulledFilePersistsPrivateOwnershipAndProvenance(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(func() { _ = db.Close() })
	path := "uploads/private/mcp/" + strings.Repeat("a", 64) + ".pdf"
	content := []byte("%PDF-1.7\nprivate transfer")
	checksum := hashBytesSHA256(content)
	if err := appMCPStorePulledFile(app, Session{UserID: 42}, path, content, "application/pdf", checksum, "source_drive", "selected-17", "rev-9"); err != nil {
		t.Fatal(err)
	}
	var ownerID int64
	if err := db.QueryRow(`SELECT user_id FROM _benmore_upload_owners WHERE path=?`, strings.TrimPrefix(path, "uploads/")).Scan(&ownerID); err != nil || ownerID != 42 {
		t.Fatalf("private upload ownership was not recorded: owner=%d err=%v", ownerID, err)
	}
	var gotPath, gotHash, origin, connection, sourceID, revision string
	if err := db.QueryRow(`SELECT file_id,file_sha256,origin,source_connection,source_file_id,source_revision FROM _benmore_mcp_file_processings`).Scan(&gotPath, &gotHash, &origin, &connection, &sourceID, &revision); err != nil {
		t.Fatalf("pull provenance was not persisted: %v", err)
	}
	if gotPath != strings.TrimPrefix(path, "uploads/") || gotHash != checksum || origin != "external_transfer" || connection != "source_drive" || sourceID != "selected-17" || revision != "rev-9" {
		t.Fatalf("unexpected transfer provenance: %q %q %q %q %q %q", gotPath, gotHash, origin, connection, sourceID, revision)
	}
}

func TestAppMCPStatusOriginAllowsReadOnlyReconcileAfterExportOff(t *testing.T) {
	app, _, actorID := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, "")
	ensureCommandAuditFixture(t, app)
	resource := "https://connector.example.invalid/api/_mcp"
	if _, err := setAppMCPApprovedWrites(app.Dir, true); err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "client-status", resource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	tool := &AppMCPTool{Name: "push", Transfer: &AppMCPTransfer{Kind: "push"}, Permissions: []string{"files:write"}}
	if _, err := appMCPConnectorOrigin(app, nil, grant, tool, pair.AccessToken, resource); err == nil {
		t.Fatal("write-capable push origin remained available with export disabled")
	}
	if _, err := appMCPConnectorStatusOrigin(app, nil, grant, tool, pair.AccessToken, resource); err != nil {
		t.Fatalf("read-only reconciliation origin denied with export disabled: %v", err)
	}
}

func TestAppMCPEffectGateBlocksQueuedPushAfterExportDisableAndReenable(t *testing.T) {
	app, _, actorID := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, "")
	ensureCommandAuditFixture(t, app)
	resource := "https://connector.example.invalid/api/_mcp"
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "client-status", resource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	setExport := func(enabled bool) {
		t.Helper()
		_, err := mutateAppMCPEpochContext(context.Background(), app.Dir, nil, false, false, func(state *appMCPEpochState) error {
			state.ExternalExport = enabled
			epoch, err := rotateAppMCPCapabilityEpoch()
			state.ExternalExportEpoch = epoch
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	setExport(true)
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	stamp := appMCPEffectGrant{OperationID: strings.Repeat("a", 64), GrantID: grant.ID, ActorID: grant.UserID,
		ActorCreated: grant.UserCreated, Tenant: grant.Tenant, Client: grant.Client, Resource: grant.Resource,
		OwnerEpoch: state.Epoch, WriteEpoch: state.ApprovedWriteEpoch, ExternalExportEpoch: state.ExternalExportEpoch,
		TransferKind: "push", PayloadDigest: strings.Repeat("b", 64), Permissions: strings.Fields(grant.Scopes)}
	setExport(false)
	setExport(true)
	if err := appMCPEffectGate(app, map[string]any{appMCPEffectKey: stamp}); err == nil || !strings.HasPrefix(err.Error(), appMCPEffectBlockedPrefix) {
		t.Fatalf("queued export survived disable/re-enable: %v", err)
	}
}
