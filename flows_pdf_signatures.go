//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	pdfStampInspectStepTimeout = 90 * time.Second
	pdfStampRenderStepTimeout  = 120 * time.Second
)

type authoredPDFPlacement struct {
	Page          int          `json:"page"`
	Rect          pdfStampRect `json:"rect"`
	SignaturePath string       `json:"signature_path"`
	SignatureSHA  string       `json:"signature_sha256"`
}

type pdfPlacementFingerprint struct {
	Page         int          `json:"page"`
	Rect         pdfStampRect `json:"rect"`
	SignatureSHA string       `json:"signature_sha256"`
}

func execStepInspectPrivateUpload(ctx *FlowContext, step *FlowStep) error {
	if ctx == nil || ctx.App == nil || step.InspectPrivateUpload == nil {
		return errors.New("inspect_private_upload requires an app, source_path and kind")
	}
	stepCtx, cancel := context.WithTimeout(flowStepContext(ctx), pdfStampInspectStepTimeout)
	defer cancel()
	path := strings.TrimSpace(interpolateCtx(step.InspectPrivateUpload.SourcePath, ctx))
	kind := step.InspectPrivateUpload.Kind
	if kind != "pdf" && kind != "png" {
		return errors.New("inspect_private_upload kind must be pdf or png")
	}
	data, logical, err := readAppPrivateStorageContext(ctx, stepCtx, path, pdfStampMaxInputBytes)
	if err != nil {
		return err
	}
	if (kind == "pdf" && strings.ToLower(filepath.Ext(logical)) != ".pdf") || (kind == "png" && strings.ToLower(filepath.Ext(logical)) != ".png") {
		return errors.New("inspect_private_upload kind does not match the private file extension")
	}
	inspection, err := appMCPInspectPrivateUpload(stepCtx, ctx.App.Dir, kind, data)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	result := map[string]any{"kind": kind, "source_path": logical, "source_sha256": hex.EncodeToString(sum[:])}
	if kind == "pdf" {
		result["page_count"] = inspection.PageCount
		result["pages"] = inspection.Pages
	} else {
		result["width"] = inspection.Width
		result["height"] = inspection.Height
	}
	publishPDFStepOutput(ctx, step.Name, result)
	return nil
}

func execStepRenderPDFSignatures(ctx *FlowContext, step *FlowStep) error {
	if ctx == nil || ctx.App == nil || step.RenderPDFSignatures == nil {
		return errors.New("render_pdf_signatures requires an app and render configuration")
	}
	stepCtx, cancel := context.WithTimeout(flowStepContext(ctx), pdfStampRenderStepTimeout)
	defer cancel()
	config := step.RenderPDFSignatures
	source, sourcePath, err := readAppPrivatePDFContext(ctx, stepCtx, strings.TrimSpace(interpolateCtx(config.SourcePath, ctx)))
	if err != nil {
		return err
	}
	sourceSum := sha256.Sum256(source)
	sourceSHA := hex.EncodeToString(sourceSum[:])
	expectedSourceSHA := strings.ToLower(strings.TrimSpace(interpolateCtx(config.SourceSHA256, ctx)))
	if !validSHA256(expectedSourceSHA) || expectedSourceSHA != sourceSHA {
		return errors.New("render_pdf_signatures source hash does not match the approved source snapshot")
	}
	geometry, err := appMCPInspectPrivateUpload(stepCtx, ctx.App.Dir, "pdf", source)
	if err != nil {
		return err
	}
	placements, err := decodeAuthoredPDFPlacements(interpolateCtx(config.PlacementsJSON, ctx))
	if err != nil {
		return err
	}
	workerPlacements := make([]pdfStampPlacement, len(placements))
	fingerprintPlacements := make([]pdfPlacementFingerprint, len(placements))
	var totalSignatureBytes uint64
	for i, placement := range placements {
		if placement.Page > geometry.PageCount {
			return fmt.Errorf("signature placement %d references page %d in a %d-page PDF", i+1, placement.Page, geometry.PageCount)
		}
		signature, _, err := readAppPrivateSignatureContext(ctx, stepCtx, placement.SignaturePath)
		if err != nil {
			return fmt.Errorf("signature placement %d: %w", i+1, err)
		}
		totalSignatureBytes, err = reservePDFStampImageBytes(totalSignatureBytes, len(signature))
		if err != nil {
			return errors.New("signature images exceed the aggregate size limit")
		}
		sum := sha256.Sum256(signature)
		actualSHA := hex.EncodeToString(sum[:])
		wantSHA := strings.ToLower(strings.TrimSpace(placement.SignatureSHA))
		if !validSHA256(wantSHA) || wantSHA != actualSHA {
			return fmt.Errorf("signature placement %d does not match the approved image snapshot", i+1)
		}
		workerPlacements[i] = pdfStampPlacement{Page: placement.Page, Rect: placement.Rect, Signature: signature}
		fingerprintPlacements[i] = pdfPlacementFingerprint{Page: placement.Page, Rect: placement.Rect, SignatureSHA: actualSHA}
	}
	canonical, err := json.Marshal(struct {
		SourceSHA  string                    `json:"source_sha256"`
		Placements []pdfPlacementFingerprint `json:"placements"`
	}{SourceSHA: sourceSHA, Placements: fingerprintPlacements})
	if err != nil {
		return err
	}
	inputSum := sha256.Sum256(canonical)
	inputSHA := hex.EncodeToString(inputSum[:])
	result, err := appMCPPDFStamp(stepCtx, ctx.App.Dir, source, workerPlacements)
	if err != nil {
		return err
	}
	// Key each uploaded artifact by its canonical input fingerprint and the
	// actual output hash. Rendering is not byte-deterministic, so app-level
	// durable job CAS chooses the winning completion; losing artifacts remain
	// private for reconciliation. An existing exact-hash object is safe to reuse.
	key := "uploads/private/__pdf_stamp__/" + inputSHA + "/" + result.SHA256 + ".pdf"
	backend := storageBackendForApp(ctx.App)
	if backend == nil {
		return errors.New("PDF output storage is unavailable")
	}
	if existing, _, readErr := readAppPrivateStorageContext(ctx, stepCtx, key, pdfStampMaxOutputBytes); readErr == nil {
		sum := sha256.Sum256(existing)
		if hex.EncodeToString(sum[:]) != result.SHA256 {
			return errors.New("content-addressed PDF output already exists with different bytes")
		}
		publishPDFStepOutput(ctx, step.Name, pdfStampOutput(sourcePath, key, result.SHA256, inputSHA, geometry.PageCount))
		return nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("check existing PDF output: %w", readErr)
	}
	_, storedPath, err := persistPDFStampOutput(
		func() error {
			if err := stepCtx.Err(); err != nil {
				return err
			}
			_, err := backend.Save(key, bytes.NewReader(result.PDF))
			return err
		},
		func() ([]byte, string, error) {
			return readAppPrivateStorageContext(ctx, stepCtx, key, pdfStampMaxOutputBytes)
		},
		result.PDF,
		result.SHA256,
	)
	if err != nil {
		return fmt.Errorf("persist stamped PDF: %w", err)
	}
	publishPDFStepOutput(ctx, step.Name, pdfStampOutput(sourcePath, storedPath, result.SHA256, inputSHA, geometry.PageCount))
	return nil
}

func reservePDFStampImageBytes(total uint64, next int) (uint64, error) {
	if next <= 0 || total > uint64(pdfStampMaxImagesBytes) || uint64(next) > uint64(pdfStampMaxImagesBytes)-total {
		return total, errors.New("aggregate signature image limit exceeded")
	}
	return total + uint64(next), nil
}

func persistPDFStampOutput(save func() error, readback func() ([]byte, string, error), expected []byte, expectedSHA string) ([]byte, string, error) {
	saveErr := save()
	stored, path, readErr := readback()
	if readErr != nil {
		if saveErr != nil {
			return nil, "", fmt.Errorf("save failed: %v; bounded readback failed: %w", saveErr, readErr)
		}
		return nil, "", fmt.Errorf("bounded readback failed: %w", readErr)
	}
	sum := sha256.Sum256(stored)
	if hex.EncodeToString(sum[:]) != expectedSHA || (saveErr == nil && !bytes.Equal(stored, expected)) {
		return nil, "", errors.New("stored PDF output failed exact hash readback")
	}
	return stored, path, nil
}

func publishPDFStepOutput(ctx *FlowContext, name string, result map[string]any) {
	ctx.DataMu.Lock()
	ctx.Data[name] = result
	ctx.Data[name+".outputs"] = result
	ctx.DataMu.Unlock()
	ctx.flatCache.invalidate()
}

func pdfStampOutput(sourcePath, outputPath, outputSHA, inputSHA string, pageCount int) map[string]any {
	return map[string]any{"source_path": sourcePath, "path": outputPath, "sha256": outputSHA, "input_sha256": inputSHA, "page_count": pageCount}
}

func decodeAuthoredPDFPlacements(raw string) ([]authoredPDFPlacement, error) {
	if len(raw) == 0 || len(raw) > pdfStampWorkerHeaderMaxBytes {
		return nil, errors.New("placements_json is missing or too large")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var placements []authoredPDFPlacement
	if err := decoder.Decode(&placements); err != nil {
		return nil, fmt.Errorf("invalid placements_json: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("placements_json contains trailing data")
	}
	if len(placements) == 0 || len(placements) > pdfStampMaxPlacements {
		return nil, errors.New("placements_json count is outside the supported range")
	}
	for i, placement := range placements {
		if placement.Page < 1 || validatePDFStampRect(placement.Rect) != nil || !validSHA256(strings.ToLower(strings.TrimSpace(placement.SignatureSHA))) {
			return nil, fmt.Errorf("placement %d has invalid page, rectangle or signature hash", i+1)
		}
	}
	return placements, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func readAppPrivatePDF(ctx *FlowContext, raw string) ([]byte, string, error) {
	return readAppPrivatePDFContext(ctx, flowStepContext(ctx), raw)
}

func readAppPrivatePDFContext(ctx *FlowContext, requestCtx context.Context, raw string) ([]byte, string, error) {
	data, logical, err := readAppPrivateStorageContext(ctx, requestCtx, raw, pdfStampMaxInputBytes)
	if err != nil {
		return nil, "", err
	}
	if strings.ToLower(filepath.Ext(logical)) != ".pdf" {
		return nil, "", errors.New("source_path must reference a private PDF")
	}
	return data, logical, nil
}

func readAppPrivateSignature(ctx *FlowContext, raw string) ([]byte, string, error) {
	return readAppPrivateSignatureContext(ctx, flowStepContext(ctx), raw)
}

func readAppPrivateSignatureContext(ctx *FlowContext, requestCtx context.Context, raw string) ([]byte, string, error) {
	data, logical, err := readAppPrivateStorageContext(ctx, requestCtx, raw, pdfStampMaxImageBytes)
	if err != nil {
		return nil, "", err
	}
	if strings.ToLower(filepath.Ext(logical)) != ".png" {
		return nil, "", errors.New("signature_path must reference a private PNG")
	}
	return data, logical, nil
}

func readAppPrivateStorage(ctx *FlowContext, raw string, maxBytes int64) ([]byte, string, error) {
	return readAppPrivateStorageContext(ctx, flowStepContext(ctx), raw, maxBytes)
}

func readAppPrivateStorageContext(ctx *FlowContext, requestCtx context.Context, raw string, maxBytes int64) ([]byte, string, error) {
	if ctx == nil || ctx.App == nil || raw == "" || maxBytes <= 0 || appMCPArtifactStorageReference(raw) {
		return nil, "", errors.New("private storage reference is invalid")
	}
	if requestCtx == nil {
		return nil, "", errors.New("private storage read requires a context")
	}
	if err := requestCtx.Err(); err != nil {
		return nil, "", err
	}
	backend := storageBackendForApp(ctx.App)
	if backend == nil {
		return nil, "", errors.New("private storage is unavailable")
	}
	logical, err := privateUploadPath(ctx.App, backend, raw)
	if err != nil {
		return nil, "", fmt.Errorf("private storage reference refused: %w", err)
	}
	if local, ok := backend.(*LocalStorage); ok {
		root := filepath.Join(local.Dir, "uploads")
		target := filepath.Join(local.Dir, filepath.FromSlash(logical))
		file, ok := openServableFile(root, target)
		if !ok {
			return nil, logical, os.ErrNotExist
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
		if err != nil {
			return nil, logical, err
		}
		if int64(len(data)) > maxBytes {
			return nil, logical, ErrIngestTooLarge
		}
		if err := requestCtx.Err(); err != nil {
			return nil, logical, err
		}
		return data, logical, nil
	}
	if s3, ok := backend.(*S3Storage); ok {
		return readAppS3Object(requestCtx, s3, logical, maxBytes)
	}
	if cdn, ok := backend.(*CDNStorage); ok {
		return readAppCDNObject(requestCtx, ctx.App, cdn, logical, maxBytes)
	}
	return nil, logical, errors.New("configured private storage backend does not support bounded reads")
}

func readAppS3Object(requestCtx context.Context, store *S3Storage, key string, maxBytes int64) ([]byte, string, error) {
	response, err := store.FetchContext(requestCtx, key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, key, os.ErrNotExist
		}
		return nil, key, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, key, fmt.Errorf("private object read returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, key, err
	}
	if int64(len(data)) > maxBytes {
		return nil, key, ErrIngestTooLarge
	}
	return data, key, nil
}

func flowStepContext(ctx *FlowContext) context.Context {
	if ctx != nil && ctx.Request != nil {
		return ctx.Request.Context()
	}
	return context.Background()
}

func readAppCDNObject(requestCtx context.Context, app *App, _ *CDNStorage, logical string, maxBytes int64) ([]byte, string, error) {
	data, _, err := appMCPReadPrivateUpload(requestCtx, app, logical, maxBytes)
	if err != nil {
		return nil, logical, err
	}
	return data, logical, nil
}

// extractTextOutputBytes caps the text one `run: extract_text` step puts in
// the flow context; the parser's own cap (64 MiB) is far above what a step
// output, a job row or a response should carry.
const extractTextOutputBytes = 1 << 20

// extractTextErrorCode maps a read or parser failure to a fixed code. Parser
// and tool text never reaches the flow error.
func extractTextErrorCode(err error) string {
	switch {
	case errors.Is(err, errAppMCPPDFUnavailable):
		return "unavailable_provider"
	case errors.Is(err, ErrIngestEncrypted):
		return "encrypted_pdf"
	case errors.Is(err, ErrIngestLimit), errors.Is(err, ErrIngestTooLarge):
		return "limit_exceeded"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	}
	return "unsupported_file" // ErrIngestUnsupported, ErrIngestCorrupt and any other tool failure
}

// extractTextSlots holds one slot per app: a PDF extraction is a CPU-heavy
// child for up to 10 minutes, so an app runs one at a time.
var extractTextSlots sync.Map // app dir -> chan struct{}

// extractTextReadTimeout bounds the private read that precedes the cache
// lookup and the slot wait.
const extractTextReadTimeout = 2 * time.Minute

// execStepExtractText is `run: extract_text`: the text of a private PDF, page
// by page, from the connector's isolated Poppler/Tesseract extractor. It runs
// only in a background run (job, scheduled, data event), never inside a
// `transaction: true` flow, and always names the row that owns the file
// (`with.record`): that row must reference the file and the uploader must own
// it (flowPrivateUploadOwnerRefusal); when a request chose the reference, the
// signed-in caller must also be able to read the row: the table's read mode,
// the credential's read scope and the per-row scope (flowCallerCanReadRecord).
// Results are cached by file hash and each user has an extraction-time budget
// (flows_extract_text_limits.go).
func execStepExtractText(ctx *FlowContext, step *FlowStep) error {
	cfg := step.ExtractText
	if ctx == nil || ctx.App == nil || cfg == nil || cfg.SourcePath == "" {
		return errors.New("extract_text requires an app and source_path")
	}
	if !ctx.backgroundRun {
		return errors.New("extract_text runs only in an async, enqueued or scheduled flow, not in a synchronous request flow")
	}
	// A job or cron transaction holds the app's write lock (BEGIN IMMEDIATE)
	// for as long as the step waits for its slot and extracts: up to 20
	// minutes in which no other write could commit.
	if ctx.Tx != nil {
		return errors.New(extractTextTransactionMessage)
	}
	record := step.UploadRecord
	if record == nil {
		return errors.New("extract_text: name the row that owns the file with `with.record: {table, id}`")
	}
	path := strings.TrimSpace(interpolateCtx(cfg.SourcePath, ctx))
	tainted := ctx.taintedRef(cfg.SourcePath) != ""
	backend := storageBackendForApp(ctx.App)
	logical, err := privateUploadPath(ctx.App, backend, path)
	if err != nil {
		return fmt.Errorf("extract_text: %s", extractTextErrorCode(err))
	}
	recordID := strings.TrimSpace(interpolateCtx(record.ID, ctx))
	if why := flowPrivateUploadOwnerRefusal(ctx, record, recordID, backend, logical); why != "" {
		return fmt.Errorf("extract_text refused: %s", why)
	}
	// The record vouches for the file, but a request chose which record: the
	// caller must be allowed to read that row (table read mode, credential
	// scope and row scope: flowCallerCanReadRecord), or naming a victim's row
	// and its file_url would pass.
	if tainted && !flowCallerCanReadRecord(ctx, record.Table, recordID) {
		return errors.New("extract_text refused: the signed-in caller cannot read the `record:` row")
	}
	ocr := cfg.OCR == nil || *cfg.OCR
	readCtx, readCancel := context.WithTimeout(flowStepContext(ctx), extractTextReadTimeout)
	data, logical, err := readAppPrivateStorageContext(ctx, readCtx, path, DefaultIngestLimits().MaxFileBytes)
	readCancel()
	if err != nil {
		return fmt.Errorf("extract_text: %s", extractTextErrorCode(err))
	}
	sum := sha256.Sum256(data)
	cacheKey := extractTextCacheKey(ctx.App.Dir, hex.EncodeToString(sum[:]), ocr)
	if hit, ok := extractTextCacheGet(cacheKey, time.Now()); ok {
		publishExtractTextOutput(ctx, step.Name, logical, hit)
		return nil
	}
	// The budget is per signed-in user; scheduled runs and jobs without an
	// actor are the author's own work (and repeats of the same file are free).
	budgetKey := ""
	if ctx.Session != nil && ctx.Session.UserID != 0 {
		budgetKey = extractTextBudgetKey(ctx.App.Dir, ctx.Session.UserID)
		if !extractTextBudgetAllows(budgetKey, time.Now()) {
			return errors.New("extract_text: limit_exceeded")
		}
	}
	waitCtx, waitCancel := context.WithTimeout(flowStepContext(ctx), appMCPPDFTotalTimeout)
	defer waitCancel()
	slot, _ := extractTextSlots.LoadOrStore(ctx.App.Dir, make(chan struct{}, 1))
	select {
	case slot.(chan struct{}) <- struct{}{}:
		defer func() { <-slot.(chan struct{}) }()
	case <-waitCtx.Done():
		return errors.New("extract_text: limit_exceeded")
	}
	// Another run may have extracted the same file while this one waited.
	if hit, ok := extractTextCacheGet(cacheKey, time.Now()); ok {
		publishExtractTextOutput(ctx, step.Name, logical, hit)
		return nil
	}
	stepCtx, cancel := context.WithTimeout(flowStepContext(ctx), appMCPPDFTotalTimeout+time.Minute)
	defer cancel()
	started := time.Now()
	parsed, err := appMCPPDFExtractOCR(stepCtx, ctx.App.Dir, data, ocr)
	if budgetKey != "" {
		extractTextBudgetSpend(budgetKey, started, time.Since(started))
	}
	if err != nil {
		return fmt.Errorf("extract_text: %s", extractTextErrorCode(err))
	}
	result := newExtractTextResult(parsed)
	extractTextCachePut(cacheKey, result, time.Now())
	publishExtractTextOutput(ctx, step.Name, logical, result)
	return nil
}

// extractTextTransactionMessage refuses the step in a `transaction: true`
// flow, at write time and when it runs.
const extractTextTransactionMessage = "`run: extract_text` can't run in a `transaction: true` flow: the job or schedule holds the app's write lock for the whole transaction, and extraction can wait 10 minutes for its slot and take 10 more, so every other write would wait (the write-transaction watchdog ends it first). Extract in a flow without `transaction: true` and write the text with a following `run: sql`; if the write must be atomic with other writes, `run: enqueue` a transactional flow and pass it the text."

// newExtractTextResult turns the extractor's blocks into the step's per-page
// text, capped at extractTextOutputBytes in total.
func newExtractTextResult(parsed appMCPPDFResult) extractTextResult {
	lines := make([][]string, parsed.PageCount)
	for _, block := range parsed.Blocks {
		if block.Page >= 1 && block.Page <= len(lines) {
			lines[block.Page-1] = append(lines[block.Page-1], block.Value)
		}
	}
	result := extractTextResult{
		sha256: parsed.SHA256, parserVersion: parsed.ParserVersion, complete: parsed.Complete,
		quality: slices.Clone(parsed.Quality), pages: make([]string, parsed.PageCount),
	}
	budget := extractTextOutputBytes
	for i := range result.pages {
		text := strings.Join(lines[i], "\n")
		if len(text) > budget {
			text, result.truncated = strings.ToValidUTF8(text[:budget], ""), true
		}
		budget -= len(text)
		result.pages[i] = text
	}
	return result
}

// publishExtractTextOutput writes a fresh output map (a cached result is
// shared, the maps a flow reads are not) and taints it: the text is the
// uploader's content, not the author's, so it stays out of sql_dynamic text.
func publishExtractTextOutput(ctx *FlowContext, name, logical string, r extractTextResult) {
	pages := make([]map[string]any, len(r.pages))
	for i, text := range r.pages {
		pages[i] = map[string]any{"page": i + 1, "text": text}
	}
	quality := slices.Clone(r.quality)
	if quality == nil {
		quality = []string{}
	}
	publishPDFStepOutput(ctx, name, map[string]any{
		"source_path": logical, "source_sha256": r.sha256, "parser_version": r.parserVersion,
		"complete": r.complete, "quality_flags": quality, "page_count": len(r.pages),
		"pages": pages, "truncated": r.truncated,
	})
	ctx.markTainted(name)
}
