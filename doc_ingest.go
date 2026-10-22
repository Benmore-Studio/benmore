//go:build !cli

package main

// Bounded document ingest core (epic #313, F06.3-F06.5): CSV and XLSX/XLSM
// readers that turn a file into immutable "source blocks" carrying sheet and
// cell coordinates, the extracted value, its type and quality flags.
//
// Internal library, not yet exposed through any route, tool or manifest.
//
// Contract highlights:
//   - Pure parsing: standard library only, in memory, no disk writes, no goroutines.
//   - Never executes macros, formulas or external links; cached formula results
//     are labelled and flagged as possibly stale.
//   - Never truncates: any limit overflow, corrupt, encrypted or unsupported
//     input returns an error and an IngestResult with Complete == false and no
//     blocks. Complete is true only when every cell of every worksheet was read.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// IngestParserVersion is recorded on every result so a stored block can be
// traced to the parser that produced it. Bump it when extraction semantics change.
const IngestParserVersion = "doc-ingest/1"

// Formats reported in IngestResult.Format.
const (
	IngestFormatCSV  = "csv"
	IngestFormatXLSX = "xlsx"
	IngestFormatXLSM = "xlsm"
)

// SourceBlock kinds. Only cell blocks are produced today.
const BlockKindCell = "cell"

// SourceBlock value types.
const (
	CellTypeString = "string"
	CellTypeNumber = "number"
	CellTypeBool   = "bool"
	CellTypeDate   = "date"
	CellTypeError  = "error"
	CellTypeEmpty  = "empty"
)

// Quality flags. Block-level flags describe one value; result-level flags
// (IngestResult.Quality) describe the whole file.
const (
	QualityCachedFormulaResult   = "cached_formula_result"
	QualityFreshnessNotVerified  = "freshness_not_verified"
	QualityFormulaNoCachedValue  = "formula_no_cached_value"
	QualityUnparseableNumber     = "unparseable_number"
	QualityUnknownCellType       = "unknown_cell_type"
	QualityInvalidBool           = "invalid_bool"
	QualityDateOutOfRange        = "date_out_of_range"
	QualityDate1900LeapBug       = "date_1900_leap_year_bug"
	QualityMacrosNotExecuted     = "macros_present_not_executed"
	QualityExternalLinksNotFetch = "external_links_present_not_resolved"
)

// IngestLimits bounds every resource a parse may use. The zero value is NOT
// usable; start from DefaultIngestLimits(). A non-positive field is treated as
// "use the default" by normalize so a partially filled struct cannot disable a guard.
type IngestLimits struct {
	// MaxFileBytes is the largest accepted input (compressed size for XLSX).
	MaxFileBytes int64
	// MaxCells is the most cells a file may contain, empty ones included
	// (CSV fields, XLSX <c> elements), summed over all sheets.
	MaxCells int
	// MaxDecompressedBytes bounds the declared total of all ZIP entries and the
	// bytes actually inflated while reading.
	MaxDecompressedBytes int64
	// MaxEntryBytes bounds one ZIP entry, declared and actually inflated.
	MaxEntryBytes int64
	// MaxZipEntries bounds the archive entry count.
	MaxZipEntries int
	// MaxCompressionRatio rejects an entry whose declared uncompressed size is
	// over 1 MiB and more than this many times its compressed size (zip bomb).
	MaxCompressionRatio int64
	// MaxSharedStrings bounds the shared string table.
	MaxSharedStrings int
	// MaxSheets bounds the workbook sheet count.
	MaxSheets int
	// MaxXMLDepth bounds element nesting inside any XML part.
	MaxXMLDepth int
	// MaxXMLTokens bounds tokens per XML part.
	MaxXMLTokens int
	// MaxCSVRows bounds CSV records.
	MaxCSVRows int
	// MaxFieldBytes bounds one CSV field or spreadsheet cell value (Excel's own
	// cell ceiling is 32767 characters).
	MaxFieldBytes int
	// MaxExtractedBytes bounds the sum of all extracted values, so a shared
	// string referenced by every cell cannot amplify memory.
	MaxExtractedBytes int64
}

// DefaultIngestLimits returns the frozen defaults. Later packets advertise these
// values; changing one is a contract change.
func DefaultIngestLimits() IngestLimits {
	return IngestLimits{
		MaxFileBytes:         25 << 20,
		MaxCells:             100_000,
		MaxDecompressedBytes: 200 << 20,
		MaxEntryBytes:        64 << 20,
		MaxZipEntries:        2_000,
		MaxCompressionRatio:  200,
		MaxSharedStrings:     100_000,
		MaxSheets:            256,
		MaxXMLDepth:          64,
		MaxXMLTokens:         10_000_000,
		MaxCSVRows:           100_000,
		MaxFieldBytes:        32 << 10,
		MaxExtractedBytes:    64 << 20,
	}
}

func (l IngestLimits) normalize() IngestLimits {
	d := DefaultIngestLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxCells <= 0 {
		l.MaxCells = d.MaxCells
	}
	if l.MaxDecompressedBytes <= 0 {
		l.MaxDecompressedBytes = d.MaxDecompressedBytes
	}
	if l.MaxEntryBytes <= 0 {
		l.MaxEntryBytes = d.MaxEntryBytes
	}
	if l.MaxZipEntries <= 0 {
		l.MaxZipEntries = d.MaxZipEntries
	}
	if l.MaxCompressionRatio <= 0 {
		l.MaxCompressionRatio = d.MaxCompressionRatio
	}
	if l.MaxSharedStrings <= 0 {
		l.MaxSharedStrings = d.MaxSharedStrings
	}
	if l.MaxSheets <= 0 {
		l.MaxSheets = d.MaxSheets
	}
	if l.MaxXMLDepth <= 0 {
		l.MaxXMLDepth = d.MaxXMLDepth
	}
	if l.MaxXMLTokens <= 0 {
		l.MaxXMLTokens = d.MaxXMLTokens
	}
	if l.MaxCSVRows <= 0 {
		l.MaxCSVRows = d.MaxCSVRows
	}
	if l.MaxFieldBytes <= 0 {
		l.MaxFieldBytes = d.MaxFieldBytes
	}
	if l.MaxExtractedBytes <= 0 {
		l.MaxExtractedBytes = d.MaxExtractedBytes
	}
	return l
}

// Typed sentinel errors. Match with errors.Is.
var (
	ErrIngestTooLarge    = errors.New("ingest: file too large")
	ErrIngestEncrypted   = errors.New("ingest: encrypted or password-protected file")
	ErrIngestCorrupt     = errors.New("ingest: corrupt file")
	ErrIngestUnsupported = errors.New("ingest: unsupported content")
	ErrIngestLimit       = errors.New("ingest: limit exceeded")
)

// IngestLimitError names the limit that was exceeded; errors.Is(err, ErrIngestLimit)
// is true for it. Limit is the IngestLimits field name.
type IngestLimitError struct {
	Limit string
	Max   int64
	Got   int64 // observed value when the limit tripped (may be a lower bound)
}

func (e *IngestLimitError) Error() string {
	return fmt.Sprintf("ingest: limit exceeded: %s (max %d, got %d)", e.Limit, e.Max, e.Got)
}

func (e *IngestLimitError) Is(target error) bool { return target == ErrIngestLimit }

func ingestLimit(name string, max, got int64) error {
	return &IngestLimitError{Limit: name, Max: max, Got: got}
}

// SourceBlock is one extracted value with its provenance. Ref is the canonical
// A1 reference ("B12"); for CSV, Sheet is "csv" and Row is the 1-based record
// ordinal (blank lines are not records).
type SourceBlock struct {
	Kind   string `json:"kind"`
	Sheet  string `json:"sheet"`
	Ref    string `json:"ref"`
	Row    int    `json:"row"`
	Col    int    `json:"col"`
	Value  string `json:"value"`
	Type   string `json:"type"`
	NumFmt string `json:"num_fmt,omitempty"` // declared number format (unit/percent/currency), when not General
	// Formula marks a cell that holds a formula. Its Value is the cached result
	// stored in the file; the formula is never evaluated and the result may be stale.
	Formula       bool     `json:"formula,omitempty"`
	CachedFormula bool     `json:"cached_formula,omitempty"`
	Quality       []string `json:"quality,omitempty"`
}

// SheetInfo describes one worksheet. Cells counts extracted (non-empty) blocks.
type SheetInfo struct {
	Name   string `json:"name"`
	State  string `json:"state,omitempty"` // "hidden" / "veryHidden"; empty when visible
	Cells  int    `json:"cells"`
	MaxRow int    `json:"max_row"`
	MaxCol int    `json:"max_col"`
}

// IngestResult is what a successful ingest returns. On any error the readers
// return a result with Complete == false, no blocks and the error alongside.
type IngestResult struct {
	Format        string        `json:"format"`
	Sheets        []SheetInfo   `json:"sheets"`
	Blocks        []SourceBlock `json:"blocks"`
	Complete      bool          `json:"complete"`
	ParserVersion string        `json:"parser_version"`
	SHA256        string        `json:"sha256"`
	Quality       []string      `json:"quality,omitempty"` // file-level flags
	Warnings      []string      `json:"warnings,omitempty"`
}

// VerifySpan reports whether the (complete) result holds a block at sheet/ref
// whose value is exactly expected. It is how an attributed claim is checked
// against the extracted blocks; it never normalizes either side.
func VerifySpan(res IngestResult, sheet, ref, expected string) bool {
	if !res.Complete {
		return false
	}
	for i := range res.Blocks {
		b := &res.Blocks[i]
		if b.Sheet == sheet && b.Ref == ref {
			return b.Value == expected
		}
	}
	return false
}

// failedIngest is the result shape for every error path.
func failedIngest(format string) IngestResult {
	return IngestResult{Format: format, ParserVersion: IngestParserVersion}
}

// ingestAcc enforces the cell and extracted-bytes limits while blocks accrue.
type ingestAcc struct {
	lim   IngestLimits
	cells int
	bytes int64
}

func (a *ingestAcc) countCell() error {
	a.cells++
	if a.cells > a.lim.MaxCells {
		return ingestLimit("MaxCells", int64(a.lim.MaxCells), int64(a.cells))
	}
	return nil
}

func (a *ingestAcc) addValue(v string) error {
	if len(v) > a.lim.MaxFieldBytes {
		return ingestLimit("MaxFieldBytes", int64(a.lim.MaxFieldBytes), int64(len(v)))
	}
	a.bytes += int64(len(v))
	if a.bytes > a.lim.MaxExtractedBytes {
		return ingestLimit("MaxExtractedBytes", a.lim.MaxExtractedBytes, a.bytes)
	}
	return nil
}

// ingestSHA256 hashes a ReaderAt of known size in streaming fashion.
func ingestSHA256(r io.ReaderAt, size int64) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(r, 0, size)); err != nil {
		return "", fmt.Errorf("%w: reading input: %v", ErrIngestCorrupt, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
