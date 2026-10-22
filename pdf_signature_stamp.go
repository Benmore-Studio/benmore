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
	"image/png"
	"math"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const (
	pdfStampMaxInputBytes     = 20 << 20
	pdfStampMaxOutputBytes    = 32 << 20
	pdfStampMaxImageBytes     = 2 << 20
	pdfStampMaxImagesBytes    = 8 << 20
	pdfStampMaxImagePixels    = 4_000_000
	pdfStampMaxImageSide      = 4096
	pdfStampMaxPages          = 200
	pdfStampMaxPlacements     = 400
	pdfStampMaxPageSidePoints = 20_000
)

var errPDFStampLimit = errors.New("PDF signature stamping limit exceeded")

// pdfStampRect is normalized to the displayed CropBox: origin at top-left,
// width and height are fractions of the visible page dimensions.
type pdfStampRect struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type pdfStampPlacement struct {
	Page      int
	Rect      pdfStampRect
	Signature []byte
}

type pdfStampResult struct {
	PDF       []byte
	SHA256    string
	PageCount int
}

type pdfPageGeometry struct {
	Page       int     `json:"page"`
	Width      float64 `json:"width"`       // displayed CropBox dimensions, points
	Height     float64 `json:"height"`      // displayed CropBox dimensions, points
	CropX      float64 `json:"crop_x"`      // unrotated PDF user-space points
	CropY      float64 `json:"crop_y"`      // unrotated PDF user-space points
	CropWidth  float64 `json:"crop_width"`  // unrotated PDF user-space points
	CropHeight float64 `json:"crop_height"` // unrotated PDF user-space points
	Rotation   int     `json:"rotation"`    // normalized clockwise degrees
}

type pdfInspection struct {
	PageCount int               `json:"page_count"`
	Pages     []pdfPageGeometry `json:"pages"`
}

func inspectPDF(source []byte) (pdfInspection, error) {
	pdf, err := readPDFStampSource(source)
	if err != nil {
		return pdfInspection{}, err
	}
	pages := make([]pdfPageGeometry, 0, pdf.PageCount)
	for pageNo := 1; pageNo <= pdf.PageCount; pageNo++ {
		_, _, attrs, err := pdf.PageDict(context.Background(), pageNo, false)
		if err != nil {
			return pdfInspection{}, fmt.Errorf("read page %d geometry: %w", pageNo, err)
		}
		box := attrs.MediaBox
		if attrs.CropBox != nil {
			box = attrs.CropBox
		}
		width, height, err := pdfStampViewport(attrs)
		if err != nil {
			return pdfInspection{}, fmt.Errorf("page %d: %w", pageNo, err)
		}
		rotation := attrs.Rotate % 360
		if rotation < 0 {
			rotation += 360
		}
		pages = append(pages, pdfPageGeometry{Page: pageNo, Width: width, Height: height,
			CropX: box.LL.X, CropY: box.LL.Y, CropWidth: box.Width(), CropHeight: box.Height(), Rotation: rotation})
	}
	return pdfInspection{PageCount: pdf.PageCount, Pages: pages}, nil
}

func readPDFStampSource(source []byte) (*model.Context, error) {
	if len(source) == 0 || len(source) > pdfStampMaxInputBytes {
		return nil, errPDFStampLimit
	}
	conf := pdfStampConfiguration()
	pdf, err := api.ReadValidateAndOptimize(context.Background(), bytes.NewReader(source), conf, nil)
	if err != nil {
		return nil, fmt.Errorf("read and validate source PDF: %w", err)
	}
	if pdf.Encrypt != nil {
		return nil, errors.New("encrypted source PDFs are not supported")
	}
	if len(pdf.Signatures) > 0 || pdf.SignatureExist || pdf.AppendOnly {
		return nil, errors.New("PDFs with existing cryptographic signatures are not supported")
	}
	if pdf.PageCount < 1 || pdf.PageCount > pdfStampMaxPages {
		return nil, errPDFStampLimit
	}
	return pdf, nil
}

func pdfStampConfiguration() *model.Configuration {
	conf := model.NewDefaultConfiguration()
	conf.WriteObjectStream = false
	conf.Limits.MaxInputBytes = pdfStampMaxInputBytes
	conf.Limits.MaxObjectBytes = 2 << 20
	conf.Limits.MaxStreamBytes = pdfStampMaxInputBytes
	conf.Limits.MaxDecodeBytes = 64 << 20
	conf.Limits.MaxImagePixels = 40_000_000
	conf.Limits.MaxImageBytes = 32 << 20
	conf.Limits.MaxObjectCount = 250_000
	conf.Limits.MaxObjectStreamCount = 250_000
	conf.Limits.MaxObjectStreamFirst = 2 << 20
	conf.Limits.MaxXRefEntries = 250_000
	conf.Limits.MaxRecursionDepth = 100
	return conf
}

type pdfStampLimitWriter struct {
	buf bytes.Buffer
	max int
}

func (w *pdfStampLimitWriter) Write(p []byte) (int, error) {
	if len(p) > w.max-w.buf.Len() {
		return 0, errPDFStampLimit
	}
	return w.buf.Write(p)
}

func validatePDFStampRect(r pdfStampRect) error {
	if math.IsNaN(r.X) || math.IsInf(r.X, 0) || math.IsNaN(r.Y) || math.IsInf(r.Y, 0) ||
		math.IsNaN(r.Width) || math.IsInf(r.Width, 0) || math.IsNaN(r.Height) || math.IsInf(r.Height, 0) {
		return errors.New("signature rectangle must contain finite coordinates")
	}
	if r.X < 0 || r.Y < 0 || r.Width <= 0 || r.Height <= 0 || r.Width > 1 || r.Height > 1 || r.X+r.Width > 1 || r.Y+r.Height > 1 {
		return errors.New("signature rectangle must be a positive box inside the visible page")
	}
	return nil
}

func pdfStampPNGSize(data []byte) (int, int, error) {
	if len(data) == 0 || len(data) > pdfStampMaxImageBytes {
		return 0, 0, errPDFStampLimit
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0, fmt.Errorf("signature image must be a valid PNG: %w", err)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > pdfStampMaxImageSide || cfg.Height > pdfStampMaxImageSide || cfg.Width > pdfStampMaxImagePixels/cfg.Height {
		return 0, 0, errPDFStampLimit
	}
	return cfg.Width, cfg.Height, nil
}

func pdfStampViewport(attrs *model.InheritedPageAttrs) (float64, float64, error) {
	if attrs == nil {
		return 0, 0, errors.New("missing PDF page attributes")
	}
	box := attrs.MediaBox
	if attrs.CropBox != nil {
		box = attrs.CropBox
	}
	if box == nil {
		return 0, 0, errors.New("PDF page has no effective CropBox or MediaBox")
	}
	w, h := box.Width(), box.Height()
	if !isFinitePDFStamp(w) || !isFinitePDFStamp(h) || w <= 0 || h <= 0 || w > pdfStampMaxPageSidePoints || h > pdfStampMaxPageSidePoints ||
		!isFinitePDFStamp(box.LL.X) || !isFinitePDFStamp(box.LL.Y) || !isFinitePDFStamp(box.UR.X) || !isFinitePDFStamp(box.UR.Y) ||
		math.Abs(box.LL.X) > pdfStampMaxPageSidePoints || math.Abs(box.LL.Y) > pdfStampMaxPageSidePoints ||
		math.Abs(box.UR.X) > pdfStampMaxPageSidePoints || math.Abs(box.UR.Y) > pdfStampMaxPageSidePoints {
		return 0, 0, errors.New("PDF page has unsupported dimensions")
	}
	switch attrs.Rotate {
	case 0, 180, -180, 360, -360:
		return w, h, nil
	case 90, -90, 270, -270:
		return h, w, nil
	default:
		return 0, 0, errors.New("PDF page rotation must be a multiple of 90 degrees")
	}
}

func isFinitePDFStamp(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

// stampPDFSignatures adds PNG signature images to a new PDF byte slice. It
// never writes into source and returns the hash of the exact generated bytes.
func stampPDFSignatures(ctx context.Context, source []byte, placements []pdfStampPlacement) (pdfStampResult, error) {
	if len(source) == 0 || len(source) > pdfStampMaxInputBytes {
		return pdfStampResult{}, errPDFStampLimit
	}
	if len(placements) == 0 || len(placements) > pdfStampMaxPlacements {
		return pdfStampResult{}, errors.New("signature placement count is outside the supported range")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var totalImageBytes int
	imageSizes := make([][2]int, len(placements))
	for i, p := range placements {
		if p.Page < 1 {
			return pdfStampResult{}, errors.New("signature page numbers start at 1")
		}
		if err := validatePDFStampRect(p.Rect); err != nil {
			return pdfStampResult{}, fmt.Errorf("placement %d: %w", i+1, err)
		}
		w, h, err := pdfStampPNGSize(p.Signature)
		if err != nil {
			return pdfStampResult{}, fmt.Errorf("placement %d: %w", i+1, err)
		}
		if len(p.Signature) > pdfStampMaxImagesBytes-totalImageBytes {
			return pdfStampResult{}, errPDFStampLimit
		}
		totalImageBytes += len(p.Signature)
		imageSizes[i] = [2]int{w, h}
	}

	pdf, err := readPDFStampSource(source)
	if err != nil {
		return pdfStampResult{}, err
	}
	conf := pdfStampConfiguration()

	watermarks := make(map[int][]*model.Watermark, len(placements))
	for i, p := range placements {
		if p.Page > pdf.PageCount {
			return pdfStampResult{}, fmt.Errorf("placement %d references page %d in a %d-page PDF", i+1, p.Page, pdf.PageCount)
		}
		_, _, attrs, err := pdf.PageDict(ctx, p.Page, false)
		if err != nil {
			return pdfStampResult{}, fmt.Errorf("read page %d geometry: %w", p.Page, err)
		}
		pageWidth, pageHeight, err := pdfStampViewport(attrs)
		if err != nil {
			return pdfStampResult{}, fmt.Errorf("page %d: %w", p.Page, err)
		}
		maxWidth := p.Rect.Width * pageWidth
		maxHeight := p.Rect.Height * pageHeight
		imgWidth, imgHeight := float64(imageSizes[i][0]), float64(imageSizes[i][1])
		scale := math.Min(maxWidth/imgWidth, maxHeight/imgHeight)
		stampWidth, stampHeight := imgWidth*scale, imgHeight*scale
		x := p.Rect.X*pageWidth + (maxWidth-stampWidth)/2
		y := (1-p.Rect.Y-p.Rect.Height)*pageHeight + (maxHeight-stampHeight)/2
		wm, err := api.ImageWatermarkForReader(ctx, bytes.NewReader(p.Signature), "", true, false, types.POINTS)
		if err != nil {
			return pdfStampResult{}, fmt.Errorf("placement %d: prepare PNG watermark: %w", i+1, err)
		}
		wm.ScaleAbs = true
		wm.Scale = scale
		wm.Pos = types.BottomLeft
		wm.Diagonal = model.NoDiagonal
		wm.Rotation = 0
		wm.Dx = x
		wm.Dy = y
		wm.Opacity = 1
		watermarks[p.Page] = append(watermarks[p.Page], wm)
	}
	identity := sha256.New()
	_, _ = identity.Write(source)
	for _, placement := range placements {
		geometry, _ := json.Marshal(struct {
			Page int          `json:"page"`
			Rect pdfStampRect `json:"rect"`
		}{placement.Page, placement.Rect})
		_, _ = identity.Write(geometry)
		imageHash := sha256.Sum256(placement.Signature)
		_, _ = identity.Write(imageHash[:])
	}
	stableID := hex.EncodeToString(identity.Sum(nil)[:16])
	pdf.ID = types.Array{types.HexLiteral(stableID), types.HexLiteral(stableID)}

	if err := pdfcpu.AddWatermarksSliceMap(ctx, pdf, watermarks); err != nil {
		return pdfStampResult{}, fmt.Errorf("apply signature images: %w", err)
	}
	// pdfcpu otherwise inserts the wall clock into PDF metadata during Write.
	// A fixed metadata dictionary makes retries with identical inputs produce
	// the same output bytes; the app records the actual completion time.
	if pdf.Info == nil {
		info := types.NewDict()
		info.InsertString("Producer", "Benmore PDF signature renderer")
		info.InsertString("CreationDate", "D:19700101000000Z")
		info.InsertString("ModDate", "D:19700101000000Z")
		infoRef, err := pdf.IndRefForNewObject(info)
		if err != nil {
			return pdfStampResult{}, fmt.Errorf("prepare deterministic PDF metadata: %w", err)
		}
		pdf.Info = infoRef
	}
	pdf.PreserveInfoDict = true
	limited := &pdfStampLimitWriter{max: pdfStampMaxOutputBytes}
	if err := api.Write(ctx, pdf, limited, conf); err != nil {
		return pdfStampResult{}, fmt.Errorf("write stamped PDF: %w", err)
	}
	result := append([]byte(nil), limited.buf.Bytes()...)
	if len(result) == 0 || len(result) > pdfStampMaxOutputBytes || !bytes.HasPrefix(result, []byte("%PDF-")) {
		return pdfStampResult{}, errors.New("PDF writer returned an invalid output")
	}
	if err := canonicalizePDFTrailerID(result); err != nil {
		return pdfStampResult{}, err
	}
	sum := sha256.Sum256(result)
	return pdfStampResult{PDF: result, SHA256: hex.EncodeToString(sum[:]), PageCount: pdf.PageCount}, nil
}

func canonicalizePDFTrailerID(data []byte) error {
	startXRef := bytes.LastIndex(data, []byte("startxref"))
	if startXRef < 0 {
		return errors.New("PDF writer returned a missing xref")
	}
	id := bytes.LastIndex(data[:startXRef], []byte("/ID"))
	if id < 0 {
		return errors.New("PDF writer returned a missing file identifier")
	}
	pos := id + len("/ID")
	for pos < startXRef && (data[pos] == ' ' || data[pos] == '\n' || data[pos] == '\r' || data[pos] == '\t') {
		pos++
	}
	if pos >= startXRef || data[pos] != '[' {
		return errors.New("PDF writer returned a malformed file identifier")
	}
	pos++
	for pos < startXRef && (data[pos] == ' ' || data[pos] == '\n' || data[pos] == '\r' || data[pos] == '\t') {
		pos++
	}
	if pos >= startXRef || data[pos] != '<' {
		return errors.New("PDF writer returned a malformed file identifier")
	}
	firstStart := pos + 1
	firstEnd := bytes.IndexByte(data[firstStart:startXRef], '>')
	if firstEnd != 32 {
		return errors.New("PDF writer returned an unexpected file identifier width")
	}
	firstEnd += firstStart
	pos = firstEnd + 1
	for pos < startXRef && (data[pos] == ' ' || data[pos] == '\n' || data[pos] == '\r' || data[pos] == '\t') {
		pos++
	}
	if pos >= startXRef || data[pos] != '<' {
		return errors.New("PDF writer returned a malformed second file identifier")
	}
	secondStart := pos + 1
	secondEnd := bytes.IndexByte(data[secondStart:startXRef], '>')
	if secondEnd != 32 {
		return errors.New("PDF writer returned an unexpected second file identifier width")
	}
	secondEnd += secondStart
	copy(data[secondStart:secondEnd], data[firstStart:firstEnd])
	return nil
}
