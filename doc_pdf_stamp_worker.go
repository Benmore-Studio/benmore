//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	pdfStampWorkerHeaderMaxBytes    = 64 << 10
	pdfStampWorkerTimeout           = 75 * time.Second
	pdfStampWorkerMemoryLimit       = 768 << 20 // Go GC target, not a hard RSS cap.
	pdfStampWorkerAddressSpaceLimit = 2 << 30
)

var errPDFStampWorkerRequest = errors.New("invalid PDF stamp worker request")

type pdfStampWorkerHeader struct {
	SourceBytes uint64                    `json:"source_bytes"`
	Placements  []pdfStampWorkerPlacement `json:"placements"`
}

type pdfInspectWorkerHeader struct {
	SourceBytes uint64 `json:"source_bytes"`
	Kind        string `json:"kind"`
}

type privateUploadInspection struct {
	Kind      string            `json:"kind"`
	PageCount int               `json:"page_count,omitempty"`
	Pages     []pdfPageGeometry `json:"pages,omitempty"`
	Width     int               `json:"width,omitempty"`
	Height    int               `json:"height,omitempty"`
}

func encodePrivateUploadInspectWorkerRequest(kind string, source []byte) ([]byte, error) {
	if (kind != "pdf" && kind != "png") || len(source) == 0 || len(source) > pdfStampMaxInputBytes {
		return nil, errPDFStampWorkerRequest
	}
	header, err := json.Marshal(pdfInspectWorkerHeader{SourceBytes: uint64(len(source)), Kind: kind})
	if err != nil || len(header) == 0 || len(header) > pdfStampWorkerHeaderMaxBytes {
		return nil, errPDFStampWorkerRequest
	}
	request := make([]byte, 4+len(header)+len(source))
	binary.BigEndian.PutUint32(request[:4], uint32(len(header)))
	copy(request[4:], header)
	copy(request[4+len(header):], source)
	return request, nil
}

func runPDFInspectWorker(input io.Reader, output io.Writer) error {
	var prefix [4]byte
	if _, err := io.ReadFull(input, prefix[:]); err != nil {
		return errPDFStampWorkerRequest
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > pdfStampWorkerHeaderMaxBytes {
		return errPDFStampWorkerRequest
	}
	headerBytes := make([]byte, int(n))
	if _, err := io.ReadFull(input, headerBytes); err != nil {
		return errPDFStampWorkerRequest
	}
	var header pdfInspectWorkerHeader
	dec := json.NewDecoder(bytes.NewReader(headerBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&header); err != nil || header.SourceBytes == 0 || header.SourceBytes > pdfStampMaxInputBytes || (header.Kind != "pdf" && header.Kind != "png") {
		return errPDFStampWorkerRequest
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(canonical, headerBytes) {
		return errPDFStampWorkerRequest
	}
	source := make([]byte, int(header.SourceBytes))
	if _, err := io.ReadFull(input, source); err != nil {
		return errPDFStampWorkerRequest
	}
	var trailing [1]byte
	if got, err := io.ReadFull(input, trailing[:]); got != 0 || !errors.Is(err, io.EOF) {
		return errPDFStampWorkerRequest
	}
	inspection := privateUploadInspection{Kind: header.Kind}
	if header.Kind == "pdf" {
		pdfInfo, err := inspectPDF(source)
		if err != nil {
			return fmt.Errorf("inspect PDF: %w", err)
		}
		inspection.PageCount, inspection.Pages = pdfInfo.PageCount, pdfInfo.Pages
	} else {
		width, height, err := pdfStampPNGSize(source)
		if err != nil {
			return fmt.Errorf("inspect PNG: %w", err)
		}
		inspection.Width, inspection.Height = width, height
	}
	encoded, err := json.Marshal(inspection)
	if err != nil || len(encoded) > pdfStampWorkerHeaderMaxBytes {
		return errPDFStampWorkerRequest
	}
	_, err = output.Write(encoded)
	return err
}

type pdfStampWorkerPlacement struct {
	Page           int          `json:"page"`
	Rect           pdfStampRect `json:"rect"`
	SignatureBytes uint64       `json:"signature_bytes"`
}

// encodePDFStampWorkerRequest writes a length-prefixed JSON header followed by
// the source PDF and each PNG in header order. Payload bytes are never encoded
// into JSON, command arguments, or temporary files.
func encodePDFStampWorkerRequest(source []byte, placements []pdfStampPlacement) ([]byte, error) {
	if len(source) == 0 || len(source) > pdfStampMaxInputBytes || len(placements) == 0 || len(placements) > pdfStampMaxPlacements {
		return nil, errPDFStampWorkerRequest
	}
	header := pdfStampWorkerHeader{SourceBytes: uint64(len(source)), Placements: make([]pdfStampWorkerPlacement, len(placements))}
	var totalImages uint64
	for i, placement := range placements {
		if len(placement.Signature) == 0 || len(placement.Signature) > pdfStampMaxImageBytes || uint64(len(placement.Signature)) > uint64(pdfStampMaxImagesBytes)-totalImages {
			return nil, errPDFStampWorkerRequest
		}
		if placement.Page < 1 || validatePDFStampRect(placement.Rect) != nil {
			return nil, errPDFStampWorkerRequest
		}
		totalImages += uint64(len(placement.Signature))
		header.Placements[i] = pdfStampWorkerPlacement{Page: placement.Page, Rect: placement.Rect, SignatureBytes: uint64(len(placement.Signature))}
	}
	headerBytes, err := json.Marshal(header)
	if err != nil || len(headerBytes) == 0 || len(headerBytes) > pdfStampWorkerHeaderMaxBytes {
		return nil, errPDFStampWorkerRequest
	}
	request := make([]byte, 4+len(headerBytes)+len(source)+int(totalImages))
	binary.BigEndian.PutUint32(request[:4], uint32(len(headerBytes)))
	copy(request[4:], headerBytes)
	pos := 4 + len(headerBytes)
	copy(request[pos:], source)
	pos += len(source)
	for _, placement := range placements {
		copy(request[pos:], placement.Signature)
		pos += len(placement.Signature)
	}
	return request, nil
}

// decodePDFStampWorkerRequest validates all declared lengths before allocating
// the corresponding buffers, and rejects trailing bytes after the final PNG.
func decodePDFStampWorkerRequest(reader io.Reader) ([]byte, []pdfStampPlacement, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, nil, errPDFStampWorkerRequest
	}
	headerLength := binary.BigEndian.Uint32(prefix[:])
	if headerLength == 0 || headerLength > pdfStampWorkerHeaderMaxBytes {
		return nil, nil, errPDFStampWorkerRequest
	}
	headerBytes := make([]byte, int(headerLength))
	if _, err := io.ReadFull(reader, headerBytes); err != nil {
		return nil, nil, errPDFStampWorkerRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(headerBytes))
	decoder.DisallowUnknownFields()
	var header pdfStampWorkerHeader
	if err := decoder.Decode(&header); err != nil {
		return nil, nil, errPDFStampWorkerRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, errPDFStampWorkerRequest
	}
	canonicalHeader, err := json.Marshal(header)
	if err != nil || !bytes.Equal(headerBytes, canonicalHeader) {
		return nil, nil, errPDFStampWorkerRequest
	}
	if header.SourceBytes == 0 || header.SourceBytes > pdfStampMaxInputBytes || len(header.Placements) == 0 || len(header.Placements) > pdfStampMaxPlacements {
		return nil, nil, errPDFStampWorkerRequest
	}
	var totalImages uint64
	for _, placement := range header.Placements {
		if placement.Page < 1 || placement.SignatureBytes == 0 || placement.SignatureBytes > pdfStampMaxImageBytes || placement.SignatureBytes > uint64(pdfStampMaxImagesBytes)-totalImages || validatePDFStampRect(placement.Rect) != nil {
			return nil, nil, errPDFStampWorkerRequest
		}
		totalImages += placement.SignatureBytes
	}
	source := make([]byte, int(header.SourceBytes))
	if _, err := io.ReadFull(reader, source); err != nil {
		return nil, nil, errPDFStampWorkerRequest
	}
	placements := make([]pdfStampPlacement, len(header.Placements))
	for i, headerPlacement := range header.Placements {
		image := make([]byte, int(headerPlacement.SignatureBytes))
		if _, err := io.ReadFull(reader, image); err != nil {
			return nil, nil, errPDFStampWorkerRequest
		}
		placements[i] = pdfStampPlacement{Page: headerPlacement.Page, Rect: headerPlacement.Rect, Signature: image}
	}
	var extra [1]byte
	if n, err := io.ReadFull(reader, extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return nil, nil, errPDFStampWorkerRequest
	}
	return source, placements, nil
}

func runPDFStampWorker(input io.Reader, output io.Writer) error {
	source, placements, err := decodePDFStampWorkerRequest(input)
	if err != nil {
		return err
	}
	result, err := stampPDFSignatures(context.Background(), source, placements)
	if err != nil {
		return fmt.Errorf("stamp PDF: %w", err)
	}
	if len(result.PDF) == 0 || len(result.PDF) > pdfStampMaxOutputBytes || !bytes.HasPrefix(result.PDF, []byte("%PDF-")) {
		return errPDFStampLimit
	}
	if _, err := io.Copy(output, bytes.NewReader(result.PDF)); err != nil {
		return err
	}
	return nil
}

// appMCPPDFStamp runs the fixed, isolated worker. It returns a hash of the
// exact PDF bytes received from the child; stdout contains only the PDF.
func appMCPPDFStamp(ctx context.Context, appDir string, source []byte, placements []pdfStampPlacement) (pdfStampResult, error) {
	if ctx == nil || ctx.Err() != nil || appDir == "" || len(source) == 0 || len(source) > pdfStampMaxInputBytes {
		return pdfStampResult{}, errAppMCPPDFUnavailable
	}
	request, err := encodePDFStampWorkerRequest(source, placements)
	if err != nil {
		return pdfStampResult{}, err
	}
	if !appMCPPDFIsolationAvailable(appDir) {
		return pdfStampResult{}, errAppMCPPDFUnavailable
	}
	runDir, err := appMCPPDFCreateTempRunDir()
	if err != nil {
		return pdfStampResult{}, errAppMCPPDFUnavailable
	}
	defer func() { _ = removePDFStampRunDir(runDir) }()
	workerCtx, cancel := context.WithTimeout(ctx, pdfStampWorkerTimeout)
	defer cancel()
	cmd, err := appMCPPDFStampRestrictedCommand(workerCtx, runDir, appDir)
	if err != nil {
		return pdfStampResult{}, errAppMCPPDFUnavailable
	}
	cmd.Stdin = bytes.NewReader(request)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = pdfStampMaxOutputBytes, 64<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if workerCtx.Err() != nil {
			return pdfStampResult{}, workerCtx.Err()
		}
		if stdout.overflow || stderr.overflow {
			return pdfStampResult{}, errPDFStampLimit
		}
		return pdfStampResult{}, errAppMCPPDFUnavailable
	}
	if stdout.overflow || len(stdout.Bytes()) == 0 || len(stdout.Bytes()) > pdfStampMaxOutputBytes || !bytes.HasPrefix(stdout.Bytes(), []byte("%PDF-")) {
		return pdfStampResult{}, errPDFStampLimit
	}
	data := append([]byte(nil), stdout.Bytes()...)
	sum := sha256.Sum256(data)
	return pdfStampResult{PDF: data, SHA256: hex.EncodeToString(sum[:])}, nil
}

func appMCPInspectPrivateUpload(ctx context.Context, appDir, kind string, source []byte) (privateUploadInspection, error) {
	if ctx == nil || ctx.Err() != nil || appDir == "" || len(source) == 0 || len(source) > pdfStampMaxInputBytes || !appMCPPDFIsolationAvailable(appDir) {
		return privateUploadInspection{}, errAppMCPPDFUnavailable
	}
	request, err := encodePrivateUploadInspectWorkerRequest(kind, source)
	if err != nil {
		return privateUploadInspection{}, err
	}
	runDir, err := appMCPPDFCreateTempRunDir()
	if err != nil {
		return privateUploadInspection{}, errAppMCPPDFUnavailable
	}
	defer func() { _ = removePDFStampRunDir(runDir) }()
	workerCtx, cancel := context.WithTimeout(ctx, pdfStampWorkerTimeout)
	defer cancel()
	cmd, err := appMCPPDFInspectRestrictedCommand(workerCtx, runDir, appDir)
	if err != nil {
		return privateUploadInspection{}, errAppMCPPDFUnavailable
	}
	cmd.Stdin = bytes.NewReader(request)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = pdfStampWorkerHeaderMaxBytes, 64<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil || stdout.overflow || len(stdout.Bytes()) == 0 {
		if workerCtx.Err() != nil {
			return privateUploadInspection{}, workerCtx.Err()
		}
		return privateUploadInspection{}, errAppMCPPDFUnavailable
	}
	var result privateUploadInspection
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil || result.Kind != kind ||
		(kind == "pdf" && (result.PageCount < 1 || result.PageCount > pdfStampMaxPages || len(result.Pages) != result.PageCount)) ||
		(kind == "png" && (result.Width < 1 || result.Height < 1 || result.Width > pdfStampMaxImageSide || result.Height > pdfStampMaxImageSide || result.Width > pdfStampMaxImagePixels/result.Height)) {
		return privateUploadInspection{}, errAppMCPPDFUnavailable
	}
	return result, nil
}

func removePDFStampRunDir(path string) error {
	// Keep cleanup inside the private temporary root even if a caller passes a
	// malformed value due to a programming error.
	if path == "" || path != filepath.Clean(path) || filepath.Dir(path) != appMCPPDFTempRootPath {
		return errPDFStampWorkerRequest
	}
	return os.RemoveAll(path)
}
