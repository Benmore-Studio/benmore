//go:build linux && (amd64 || arm64) && !cli

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivatePDFFlowStepsRenderThroughAuthorizedHTTPExecutor(t *testing.T) {
	if !appMCPPDFIsolationAvailable(t.TempDir()) {
		t.Skip("native PDF worker isolation is unavailable")
	}
	app, cleanup := newTestApp(t)
	defer cleanup()
	privateDir := filepath.Join(app.Dir, "uploads", "private")
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := stampFixturePDF()
	if err := os.WriteFile(filepath.Join(privateDir, "source.pdf"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := png.Encode(&signature, image.NewNRGBA(image.Rect(0, 0, 20, 10))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(privateDir, "signature.png"), signature.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceSum := sha256.Sum256(source)
	signatureSum := sha256.Sum256(signature.Bytes())
	placements, err := json.Marshal([]authoredPDFPlacement{{Page: 2, Rect: pdfStampRect{X: .2, Y: .2, Width: .5, Height: .3}, SignaturePath: "uploads/private/signature.png", SignatureSHA: hex.EncodeToString(signatureSum[:])}})
	if err != nil {
		t.Fatal(err)
	}
	flow := &Flow{
		Name:    "render-private-pdf",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/render-private-pdf"},
		Steps: []FlowStep{
			{Name: "inspect", Type: "inspect_private_upload", InspectPrivateUpload: &FlowInspectPrivateUpload{SourcePath: "uploads/private/source.pdf", Kind: "pdf"}},
			{Name: "render", Type: "render_pdf_signatures", RenderPDFSignatures: &FlowRenderPDFSignatures{SourcePath: "uploads/private/source.pdf", SourceSHA256: hex.EncodeToString(sourceSum[:]), PlacementsJSON: string(placements)}},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"path": "{{render.outputs.path}}", "sha256": "{{render.outputs.sha256}}", "input_sha256": "{{render.outputs.input_sha256}}", "page_count": "{{render.outputs.page_count}}"}}},
		},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/render-private-pdf", nil)
	recorder := httptest.NewRecorder()
	if err := executeFlowHTTP(app, flow, recorder, request); err != nil {
		t.Fatalf("HTTP flow failed: %v body=%s", err, recorder.Body.String())
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Path        string `json:"path"`
		SHA256      string `json:"sha256"`
		InputSHA256 string `json:"input_sha256"`
		PageCount   any    `json:"page_count"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("parse response %q: %v", recorder.Body.String(), err)
	}
	if !strings.HasPrefix(response.Path, "uploads/private/__pdf_stamp__/") || !validSHA256(response.SHA256) || !validSHA256(response.InputSHA256) || response.PageCount == nil {
		t.Fatalf("invalid HTTP flow output: %+v", response)
	}
	stored, _, err := readAppPrivateStorage(&FlowContext{App: app}, response.Path, pdfStampMaxOutputBytes)
	if err != nil {
		t.Fatalf("private output is not readable through the app backend: %v", err)
	}
	storedSum := sha256.Sum256(stored)
	if hex.EncodeToString(storedSum[:]) != response.SHA256 || bytes.Equal(stored, source) {
		t.Fatal("stored output hash mismatch or source was returned unchanged")
	}
	unchanged, err := os.ReadFile(filepath.Join(privateDir, "source.pdf"))
	if err != nil || string(unchanged) != string(source) {
		t.Fatalf("original source was modified: %v", err)
	}
}
