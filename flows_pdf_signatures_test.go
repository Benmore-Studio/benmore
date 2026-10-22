//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPDFStorageReadsShareOneStepDeadline(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) == 1 {
			time.Sleep(80 * time.Millisecond)
			_, _ = w.Write([]byte("first"))
			return
		}
		select {
		case <-time.After(time.Second):
			_, _ = w.Write([]byte("second"))
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	store := &S3Storage{Bucket: "bucket", Endpoint: server.URL}
	stepCtx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	first, _, err := readAppS3Object(stepCtx, store, "uploads/private/source.pdf", 32)
	if err != nil || string(first) != "first" {
		t.Fatalf("first bounded read failed: data=%q err=%v", first, err)
	}
	started := time.Now()
	if _, _, err := readAppS3Object(stepCtx, store, "uploads/private/signature.png", 32); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second read did not inherit remaining step deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("canceled storage read exceeded step deadline by too long: %v", elapsed)
	}
}

func TestPrivateUploadInspectWorkerContract(t *testing.T) {
	pdf, err := encodePrivateUploadInspectWorkerRequest("pdf", stampFixturePDF())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runPDFInspectWorker(bytes.NewReader(pdf), &out); err != nil {
		t.Fatal(err)
	}
	var inspected privateUploadInspection
	if err := json.Unmarshal(out.Bytes(), &inspected); err != nil || inspected.Kind != "pdf" || inspected.PageCount != 4 || len(inspected.Pages) != 4 {
		t.Fatalf("bad PDF inspection: %+v err=%v", inspected, err)
	}
	var imageBytes bytes.Buffer
	if err := png.Encode(&imageBytes, image.NewNRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	frame, err := encodePrivateUploadInspectWorkerRequest("png", imageBytes.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runPDFInspectWorker(bytes.NewReader(frame), &out); err != nil {
		t.Fatal(err)
	}
	inspected = privateUploadInspection{}
	if err := json.Unmarshal(out.Bytes(), &inspected); err != nil || inspected.Kind != "png" || inspected.Width != 1 || inspected.Height != 1 || inspected.PageCount != 0 {
		t.Fatalf("bad PNG inspection: %+v err=%v", inspected, err)
	}
	if _, err := encodePrivateUploadInspectWorkerRequest("jpeg", imageBytes.Bytes()); err == nil {
		t.Fatal("inspection accepted an unsupported content kind")
	}
	invalidPNG, err := encodePrivateUploadInspectWorkerRequest("png", []byte("not a png"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runPDFInspectWorker(bytes.NewReader(invalidPNG), &out); err == nil {
		t.Fatal("isolated inspection worker accepted a malformed PNG")
	}
}

func TestDecodeAuthoredPDFPlacementsStrictAndBounded(t *testing.T) {
	good := `[{"page":1,"rect":{"x":0.1,"y":0.2,"width":0.3,"height":0.2},"signature_path":"uploads/private/sign.png","signature_sha256":"` + strings.Repeat("a", 64) + `"}]`
	placements, err := decodeAuthoredPDFPlacements(good)
	if err != nil || len(placements) != 1 || placements[0].Page != 1 {
		t.Fatalf("valid placement refused: %+v %v", placements, err)
	}
	for _, raw := range []string{
		`[{"page":1,"rect":{"x":0.9,"y":0.2,"width":0.3,"height":0.2},"signature_path":"uploads/private/sign.png","signature_sha256":"` + strings.Repeat("a", 64) + `"}]`,
		`[{"page":1,"rect":{"x":0.1,"y":0.2,"width":0.3,"height":0.2},"signature_path":"https://elsewhere.invalid/sign.png","signature_sha256":"` + strings.Repeat("a", 64) + `","extra":true}]`,
		"[]",
		"[] {}",
	} {
		if _, err := decodeAuthoredPDFPlacements(raw); err == nil {
			t.Errorf("accepted malformed placement JSON: %s", raw)
		}
	}
}

func TestPDFStampImageBudgetIsReservedBeforeRetainingPlacements(t *testing.T) {
	total, err := reservePDFStampImageBytes(0, pdfStampMaxImagesBytes)
	if err != nil || total != uint64(pdfStampMaxImagesBytes) {
		t.Fatalf("exact aggregate image limit refused: total=%d err=%v", total, err)
	}
	if _, err := reservePDFStampImageBytes(total, 1); err == nil {
		t.Fatal("aggregate image budget accepted bytes past its cap")
	}
	if _, err := reservePDFStampImageBytes(^uint64(0), 1); err == nil {
		t.Fatal("aggregate image budget accepted an overflowing prior total")
	}
}

func TestPDFStampSaveUnknownOutcomeUsesBoundedHashReadback(t *testing.T) {
	pdf := []byte("%PDF-synthetic-output")
	sum := sha256.Sum256(pdf)
	wantSHA := hex.EncodeToString(sum[:])
	var durable []byte
	stored, path, err := persistPDFStampOutput(
		func() error {
			durable = append([]byte(nil), pdf...)
			return errors.New("synthetic lost PUT response")
		},
		func() ([]byte, string, error) { return durable, "uploads/private/output.pdf", nil },
		pdf,
		wantSHA,
	)
	if err != nil || path != "uploads/private/output.pdf" || !bytes.Equal(stored, pdf) {
		t.Fatalf("matching durable readback did not recover the save: path=%q err=%v", path, err)
	}
	if _, _, err := persistPDFStampOutput(
		func() error { return errors.New("synthetic failed PUT") },
		func() ([]byte, string, error) { return []byte("wrong object"), "uploads/private/output.pdf", nil },
		pdf,
		wantSHA,
	); err == nil {
		t.Fatal("unknown save outcome accepted a mismatching readback hash")
	}
}

func TestPrivatePDFFlowStepsParseOnlyDeclaredConfiguration(t *testing.T) {
	steps := convertGHASteps([]FlowStepGHA{
		{ID: "inspect", Run: "inspect_private_upload", With: map[string]any{"source_path": "uploads/private/source.pdf", "kind": "pdf"}},
		{ID: "render", Run: "render_pdf_signatures", With: map[string]any{"source_path": "uploads/private/source.pdf", "source_sha256": strings.Repeat("a", 64), "placements_json": "[]"}},
	})
	if len(steps) != 2 || steps[0].Type != "inspect_private_upload" || steps[0].InspectPrivateUpload == nil || steps[0].InspectPrivateUpload.Kind != "pdf" || steps[1].Type != "render_pdf_signatures" || steps[1].RenderPDFSignatures == nil {
		t.Fatalf("private PDF steps did not parse: %+v", steps)
	}
	if !flowRunTypes["inspect_private_upload"] || !flowRunTypes["render_pdf_signatures"] {
		t.Fatal("private PDF run types were not registered")
	}
}

func TestReadAppPrivateStorageIsAppScopedBoundedAndSymlinkSafe(t *testing.T) {
	base := t.TempDir()
	appA := &App{Dir: filepath.Join(base, "a")}
	appB := &App{Dir: filepath.Join(base, "b")}
	for _, app := range []*App{appA, appB} {
		if err := os.MkdirAll(filepath.Join(app.Dir, "uploads", "private"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	content := []byte("A-local-private-pdf")
	if err := os.WriteFile(filepath.Join(appA.Dir, "uploads", "private", "source.pdf"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	ctxA := &FlowContext{App: appA, Data: map[string]any{}, Params: map[string]string{}}
	got, path, err := readAppPrivatePDF(ctxA, "uploads/private/source.pdf")
	if err != nil || path != "uploads/private/source.pdf" || !bytes.Equal(got, content) {
		t.Fatalf("own private file read failed: path=%q err=%v", path, err)
	}
	ctxB := &FlowContext{App: appB, Data: map[string]any{}, Params: map[string]string{}}
	if _, _, err := readAppPrivatePDF(ctxB, "uploads/private/source.pdf"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign app file was visible: %v", err)
	}
	if _, _, err := readAppPrivateStorage(ctxA, "../b/uploads/private/source.pdf", 100); err == nil {
		t.Fatal("storage reader accepted traversal")
	}
	if _, _, err := readAppPrivateStorage(ctxA, "https://example.invalid/uploads/private/source.pdf", 100); err == nil {
		t.Fatal("storage reader accepted arbitrary URL")
	}
	if _, _, err := readAppPrivateStorage(ctxA, "uploads/private/source.pdf", int64(len(content)-1)); !errors.Is(err, ErrIngestTooLarge) {
		t.Fatalf("bounded reader did not refuse oversize data: %v", err)
	}
	outside := filepath.Join(base, "outside.pdf")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(appA.Dir, "uploads", "private", "linked.pdf")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readAppPrivateStorage(ctxA, "uploads/private/linked.pdf", 100); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("storage reader followed symlink outside uploads: %v", err)
	}
}
