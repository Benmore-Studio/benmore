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
	"strings"
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
