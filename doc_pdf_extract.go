//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// These PDF extraction limits are a connector contract. Keep resource caps
// here rather than inheriting app-configurable ingest limits.
const (
	appMCPPDFMaxPages          = 200
	appMCPPDFMaxPixelsPerPage  = 40_000_000
	appMCPPDFPageTimeout       = 60 * time.Second
	appMCPPDFPageMemoryBytes   = 512 << 20
	appMCPPDFMaxTempBytes      = 512 << 20
	appMCPPDFTotalTimeout      = 10 * time.Minute
	appMCPPDFMaxExtractedBytes = 64 << 20
	appMCPPDFMaxBlocks         = 100_000
	appMCPPDFRenderMaxSide     = 6324 // 6324² is below 40 MP.
)

const (
	appMCPPDFTextPath      = "/usr/bin/pdftotext"
	appMCPPDFRenderPath    = "/usr/bin/pdftoppm"
	appMCPPDFOCRPath       = "/usr/bin/tesseract"
	appMCPPDFInfoPath      = "/usr/bin/pdfinfo"
	appMCPPDFEnglishData   = "/usr/share/tesseract-ocr/5/tessdata/eng.traineddata"
	appMCPPDFTempRootPath  = "/tmp/benmore-document-ingest"
	appMCPPDFParserVersion = "poppler-tesseract-v1"
	appMCPPDFWorkerMarker  = "--benmore-internal-pdf-worker"
)

var errAppMCPPDFUnavailable = errors.New("pdf extraction tools unavailable")

type appMCPPDFBox struct {
	XMin float64 `json:"x_min"`
	YMin float64 `json:"y_min"`
	XMax float64 `json:"x_max"`
	YMax float64 `json:"y_max"`
}

type appMCPPDFBlock struct {
	Page       int          `json:"page"`
	Ref        string       `json:"ref"`
	BBox       appMCPPDFBox `json:"bbox"`
	BBoxUnit   string       `json:"bbox_unit"`
	Value      string       `json:"value"`
	Confidence *float64     `json:"confidence,omitempty"`
	Quality    []string     `json:"quality,omitempty"`
}

type appMCPPDFResult struct {
	Blocks        []appMCPPDFBlock `json:"blocks"`
	Complete      bool             `json:"complete"`
	ParserVersion string           `json:"parser_version"`
	SHA256        string           `json:"sha256"`
	Quality       []string         `json:"quality_flags"`
}

// pdfExtractionAvailable reports whether the fixed tools are installed and a
// parser child can run confined away from appDir (see appMCPPDFIsolationAvailable).
func pdfExtractionAvailable(appDir string) bool {
	for _, path := range []string{appMCPPDFTextPath, appMCPPDFRenderPath, appMCPPDFOCRPath, appMCPPDFInfoPath, appMCPPDFEnglishData} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		if strings.HasSuffix(path, ".traineddata") {
			continue
		}
		if info.Mode()&0111 == 0 {
			return false
		}
	}
	return appMCPPDFIsolationAvailable(appDir)
}

func appMCPPDFTempBytes(inputBytes int64) int64 {
	if inputBytes < 0 || inputBytes >= appMCPPDFMaxTempBytes {
		return 0
	}
	return appMCPPDFMaxTempBytes - inputBytes
}

func appMCPPDFWorkerArgs(tempBytes int64, tempDir, binary string, args []string) []string {
	if tempBytes < 1 || tempBytes > appMCPPDFMaxTempBytes || tempDir == "" || (binary != appMCPPDFTextPath && binary != appMCPPDFInfoPath && binary != appMCPPDFRenderPath && binary != appMCPPDFOCRPath) {
		return nil
	}
	argv := []string{strconv.FormatInt(tempBytes, 10), tempDir, binary}
	return append(argv, args...)
}

func appMCPPDFWorkerInvocationArgs(executable string, workerArgs []string) []string {
	if strings.HasSuffix(filepath.Base(executable), ".test") {
		args := []string{"-test.run=^$", "--", appMCPPDFWorkerMarker}
		return append(args, workerArgs...)
	}
	args := []string{appMCPPDFWorkerMarker}
	return append(args, workerArgs...)
}

func appMCPPDFTextArgs(inputPath string) []string {
	return []string{"-bbox-layout", "-f", "1", "-l", strconv.Itoa(appMCPPDFMaxPages + 1), inputPath, "-"}
}

func appMCPPDFRenderArgs(inputPath, outputPrefix string, page int) []string {
	return []string{"-f", strconv.Itoa(page), "-l", strconv.Itoa(page), "-singlefile", "-scale-to", strconv.Itoa(appMCPPDFRenderMaxSide), "-png", inputPath, outputPrefix}
}

func appMCPPDFOCRArgs(imagePath string) []string {
	return []string{imagePath, "stdout", "-l", "eng", "--tessdata-dir", filepath.Dir(appMCPPDFEnglishData), "-c", "tessedit_create_tsv=1"}
}

func appMCPPDFEncryptedOutput(out []byte) (bool, error) {
	var found *bool
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Encrypted:") {
			continue
		}
		if found != nil {
			return false, ErrIngestCorrupt
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "Encrypted:" {
			return false, ErrIngestCorrupt
		}
		value := strings.EqualFold(fields[1], "yes")
		if !value && !strings.EqualFold(fields[1], "no") {
			return false, ErrIngestCorrupt
		}
		found = &value
	}
	if found == nil {
		return false, ErrIngestCorrupt
	}
	return *found, nil
}

func appMCPPDFInfoArgs(inputPath string) []string { return []string{inputPath} }

func appMCPPDFCheckEncrypted(ctx context.Context, inputPath string, tempBytes int64, tempDir string) (bool, error) {
	out, _, err := appMCPPDFRun(ctx, appMCPPDFInfoPath, appMCPPDFInfoArgs(inputPath), tempBytes, 64<<10, tempDir)
	if err != nil {
		return false, err
	}
	return appMCPPDFEncryptedOutput(out)
}

func appMCPPDFRun(ctx context.Context, binary string, args []string, tempBytes int64, outputLimit int64, tempDir string) ([]byte, []byte, error) {
	if ctx == nil || ctx.Err() != nil || tempBytes < 1 || outputLimit < 1 || tempDir == "" {
		return nil, nil, errAppMCPPDFUnavailable
	}
	cmd, err := appMCPPDFRestrictedCommand(ctx, binary, args, tempBytes, tempDir)
	if err != nil {
		return nil, nil, errAppMCPPDFUnavailable
	}
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = outputLimit, 64<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if stdout.overflow || stderr.overflow {
		return nil, nil, ErrIngestLimit
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if appMCPPDFWorkerFailure(err) {
			return nil, nil, errAppMCPPDFUnavailable
		}
		message := strings.ToLower(stderr.String())
		if strings.Contains(message, "password") || strings.Contains(message, "encrypted") {
			return nil, stderr.Bytes(), ErrIngestEncrypted
		}
		return nil, stderr.Bytes(), fmt.Errorf("pdf tool failed")
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	max      int64
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.max - int64(b.Len())
	if remaining <= 0 {
		b.overflow = true
		return 0, ErrIngestLimit
	}
	if int64(len(p)) > remaining {
		n, _ := b.Buffer.Write(p[:remaining])
		b.overflow = true
		return n, ErrIngestLimit
	}
	return b.Buffer.Write(p)
}

type appMCPPDFXML struct {
	Pages [][]appMCPPDFBlock
}

func appMCPPDFParseBBox(data []byte) ([][]appMCPPDFBlock, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	var pages [][]appMCPPDFBlock
	page := 0
	word := false
	var current appMCPPDFBlock
	var text strings.Builder
	count := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrIngestCorrupt
		}
		switch token := token.(type) {
		case xml.StartElement:
			switch token.Name.Local {
			case "page":
				page++
				if page > appMCPPDFMaxPages+1 {
					return nil, ErrIngestLimit
				}
				pages = append(pages, nil)
			case "word":
				if page == 0 || word {
					return nil, ErrIngestCorrupt
				}
				var coords [4]float64
				seen := [4]bool{}
				for _, attr := range token.Attr {
					idx := -1
					switch attr.Name.Local {
					case "xMin":
						idx = 0
					case "yMin":
						idx = 1
					case "xMax":
						idx = 2
					case "yMax":
						idx = 3
					}
					if idx < 0 {
						continue
					}
					if seen[idx] {
						return nil, ErrIngestCorrupt
					}
					seen[idx] = true
					coords[idx], err = strconv.ParseFloat(attr.Value, 64)
					if err != nil {
						return nil, ErrIngestCorrupt
					}
				}
				for _, required := range seen {
					if !required {
						return nil, ErrIngestCorrupt
					}
				}
				if !appMCPPDFValidBox(coords[0], coords[1], coords[2], coords[3]) {
					return nil, ErrIngestCorrupt
				}
				current = appMCPPDFBlock{Page: page, Ref: fmt.Sprintf("p%dw%d", page, len(pages[page-1])+1), BBox: appMCPPDFBox{XMin: coords[0], YMin: coords[1], XMax: coords[2], YMax: coords[3]}, BBoxUnit: "points"}
				text.Reset()
				word = true
			}
		case xml.CharData:
			if word {
				_, _ = text.Write(token)
			}
		case xml.EndElement:
			if token.Name.Local == "word" {
				if !word {
					return nil, ErrIngestCorrupt
				}
				current.Value = strings.TrimSpace(text.String())
				word = false
				if current.Value != "" {
					count++
					if count > appMCPPDFMaxBlocks {
						return nil, ErrIngestLimit
					}
					pages[page-1] = append(pages[page-1], current)
				}
			}
		}
	}
	if page == 0 || word {
		return nil, ErrIngestCorrupt
	}
	return pages, nil
}

func appMCPPDFNativePageQuality(blocks []appMCPPDFBlock) []string {
	if len(blocks) == 0 {
		return nil
	}
	return []string{"native_text_only_pages"}
}

func appMCPPDFFailureResult(result appMCPPDFResult) appMCPPDFResult {
	return appMCPPDFResult{ParserVersion: result.ParserVersion, SHA256: result.SHA256}
}

func appMCPPDFValidBox(xMin, yMin, xMax, yMax float64) bool {
	return !math.IsNaN(xMin) && !math.IsNaN(yMin) && !math.IsNaN(xMax) && !math.IsNaN(yMax) && !math.IsInf(xMin, 0) && !math.IsInf(yMin, 0) && !math.IsInf(xMax, 0) && !math.IsInf(yMax, 0) && xMin >= 0 && yMin >= 0 && xMax >= xMin && yMax >= yMin
}

func appMCPPDFParseTSV(data []byte, page int) ([]appMCPPDFBlock, error) {
	if page < 1 || page > appMCPPDFMaxPages || len(data) > appMCPPDFMaxExtractedBytes {
		return nil, ErrIngestLimit
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) == 0 || string(lines[0]) != "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext" {
		return nil, ErrIngestCorrupt
	}
	blocks := make([]appMCPPDFBlock, 0)
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		fields := strings.SplitN(string(line), "\t", 12)
		if len(fields) != 12 {
			return nil, ErrIngestCorrupt
		}
		if fields[0] != "5" {
			continue
		}
		pageNum, err := strconv.Atoi(fields[1])
		if err != nil || pageNum != 1 {
			return nil, ErrIngestCorrupt
		}
		value := strings.TrimSpace(fields[11])
		if value == "" {
			continue
		}
		coords := [4]int{}
		for i, idx := range []int{6, 7, 8, 9} {
			v, err := strconv.Atoi(fields[idx])
			if err != nil || v < 0 {
				return nil, ErrIngestCorrupt
			}
			coords[i] = v
		}
		confidence, err := strconv.ParseFloat(fields[10], 64)
		maxInt := int(^uint(0) >> 1)
		if err != nil || math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0 || confidence > 100 || coords[2] == 0 || coords[3] == 0 || coords[0] > maxInt-coords[2] || coords[1] > maxInt-coords[3] {
			return nil, ErrIngestCorrupt
		}
		c := confidence
		blocks = append(blocks, appMCPPDFBlock{Page: page, Ref: fmt.Sprintf("p%dw%d", page, len(blocks)+1), BBox: appMCPPDFBox{XMin: float64(coords[0]), YMin: float64(coords[1]), XMax: float64(coords[0] + coords[2]), YMax: float64(coords[1] + coords[3])}, BBoxUnit: "pixels", Value: value, Confidence: &c, Quality: []string{"ocr"}})
		if len(blocks) > appMCPPDFMaxBlocks {
			return nil, ErrIngestLimit
		}
	}
	return blocks, nil
}

func appMCPPDFPNGDimensions(r io.Reader) (int64, int64, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil || !bytes.Equal(header[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) || string(header[12:16]) != "IHDR" {
		return 0, 0, ErrIngestCorrupt
	}
	w, h := int64(binaryBigEndianUint32(header[16:20])), int64(binaryBigEndianUint32(header[20:24]))
	if w < 1 || h < 1 || w > appMCPPDFMaxPixelsPerPage || h > appMCPPDFMaxPixelsPerPage || w > appMCPPDFMaxPixelsPerPage/h {
		return 0, 0, ErrIngestLimit
	}
	return w, h, nil
}

func binaryBigEndianUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func appMCPPDFExtract(ctx context.Context, appDir string, data []byte) (appMCPPDFResult, error) {
	result := appMCPPDFResult{ParserVersion: appMCPPDFParserVersion, Complete: false}
	if !bytes.HasPrefix(data, []byte("%PDF-")) || len(data) == 0 {
		return result, ErrIngestUnsupported
	}
	sum := sha256.Sum256(data)
	result.SHA256 = hex.EncodeToString(sum[:])
	failureResult := func() appMCPPDFResult { return appMCPPDFFailureResult(result) }
	if int64(len(data)) >= appMCPPDFMaxTempBytes || !pdfExtractionAvailable(appDir) {
		return failureResult(), errAppMCPPDFUnavailable
	}
	dir, err := appMCPPDFCreateTempRunDir()
	if err != nil {
		return result, errAppMCPPDFUnavailable
	}
	defer os.RemoveAll(dir)
	inputPath := filepath.Join(dir, "input.pdf")
	if err := os.WriteFile(inputPath, data, 0600); err != nil {
		return result, errAppMCPPDFUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, appMCPPDFTotalTimeout)
	defer cancel()
	checkCtx, checkCancel := context.WithTimeout(ctx, appMCPPDFPageTimeout)
	encrypted, err := appMCPPDFCheckEncrypted(checkCtx, inputPath, appMCPPDFTempBytes(int64(len(data))), dir)
	checkCancel()
	if err != nil {
		return result, err
	}
	if encrypted {
		return result, ErrIngestEncrypted
	}
	pageCtx, pageCancel := context.WithTimeout(ctx, appMCPPDFPageTimeout)
	bbox, _, err := appMCPPDFRun(pageCtx, appMCPPDFTextPath, appMCPPDFTextArgs(inputPath), appMCPPDFTempBytes(int64(len(data))), appMCPPDFMaxExtractedBytes, dir)
	pageCancel()
	if err != nil {
		return result, err
	}
	pages, err := appMCPPDFParseBBox(bbox)
	if err != nil {
		return result, err
	}
	if len(pages) > appMCPPDFMaxPages {
		return result, ErrIngestLimit
	}
	extractedBytes := int64(0)
	for pageIdx, blocks := range pages {
		if ctx.Err() != nil {
			return failureResult(), ctx.Err()
		}
		if len(blocks) == 0 {
			prefix := filepath.Join(dir, "page")
			pageCtx, pageCancel = context.WithTimeout(ctx, appMCPPDFPageTimeout)
			_, _, err = appMCPPDFRun(pageCtx, appMCPPDFRenderPath, appMCPPDFRenderArgs(inputPath, prefix, pageIdx+1), appMCPPDFTempBytes(int64(len(data))), 1, dir)
			pageCancel()
			if err != nil {
				return failureResult(), err
			}
			imagePath := prefix + ".png"
			imageFile, openErr := os.Open(imagePath)
			if openErr != nil {
				return failureResult(), ErrIngestCorrupt
			}
			_, _, sizeErr := appMCPPDFPNGDimensions(imageFile)
			stat, statErr := imageFile.Stat()
			closeErr := imageFile.Close()
			if sizeErr != nil || statErr != nil || closeErr != nil || stat.Size() > appMCPPDFTempBytes(int64(len(data))) {
				return failureResult(), ErrIngestLimit
			}
			remaining := appMCPPDFMaxExtractedBytes - extractedBytes
			if remaining <= 0 {
				_ = os.Remove(imagePath)
				return failureResult(), ErrIngestLimit
			}
			pageCtx, pageCancel = context.WithTimeout(ctx, appMCPPDFPageTimeout)
			tsv, _, ocrErr := appMCPPDFRun(pageCtx, appMCPPDFOCRPath, appMCPPDFOCRArgs(imagePath), appMCPPDFTempBytes(int64(len(data))), remaining, dir)
			pageCancel()
			_ = os.Remove(imagePath)
			if ocrErr != nil {
				return failureResult(), ocrErr
			}
			blocks, err = appMCPPDFParseTSV(tsv, pageIdx+1)
			if err != nil {
				return failureResult(), err
			}
			if len(blocks) > 0 {
				result.Quality = append(result.Quality, "ocr")
			}
		} else {
			for _, quality := range appMCPPDFNativePageQuality(blocks) {
				if !slices.Contains(result.Quality, quality) {
					result.Quality = append(result.Quality, quality)
				}
			}
		}
		for _, block := range blocks {
			extractedBytes += int64(len(block.Value))
			if extractedBytes > appMCPPDFMaxExtractedBytes {
				return failureResult(), ErrIngestLimit
			}
		}
		result.Blocks = append(result.Blocks, blocks...)
		if len(result.Blocks) > appMCPPDFMaxBlocks {
			return failureResult(), ErrIngestLimit
		}
	}
	result.Complete = true
	return result, nil
}
