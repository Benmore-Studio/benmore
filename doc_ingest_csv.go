//go:build !cli

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// ingestCSVSheet is the pseudo-sheet name CSV blocks carry.
const ingestCSVSheet = "csv"

// IngestCSV reads comma-separated text into cell blocks. Every value stays a
// string (no type inference, so "00123" is never altered). The input must be
// valid UTF-8 (a UTF-8 BOM is stripped and noted); UTF-16 and binary input are
// rejected as unsupported rather than guessed at.
func IngestCSV(r io.Reader, limits IngestLimits) (IngestResult, error) {
	lim := limits.normalize()
	fail := func(err error) (IngestResult, error) { return failedIngest(IngestFormatCSV), err }

	data, err := io.ReadAll(io.LimitReader(r, lim.MaxFileBytes+1))
	if err != nil {
		return fail(fmt.Errorf("%w: reading input: %v", ErrIngestCorrupt, err))
	}
	if int64(len(data)) > lim.MaxFileBytes {
		return fail(fmt.Errorf("%w: more than %d bytes", ErrIngestTooLarge, lim.MaxFileBytes))
	}
	sum := sha256.Sum256(data)
	res := failedIngest(IngestFormatCSV)
	res.SHA256 = hex.EncodeToString(sum[:])

	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}), bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		return res, fmt.Errorf("%w: UTF-16 text; convert to UTF-8", ErrIngestUnsupported)
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		data = data[3:]
		res.Warnings = append(res.Warnings, "utf8_bom_stripped")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return res, fmt.Errorf("%w: empty file", ErrIngestCorrupt)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return res, fmt.Errorf("%w: binary data (NUL byte)", ErrIngestUnsupported)
	}
	if !utf8.Valid(data) {
		return res, fmt.Errorf("%w: not valid UTF-8; convert the encoding", ErrIngestUnsupported)
	}
	// encoding/csv materializes every field of a record before returning it,
	// about 40 bytes of bookkeeping per field, so a single line of commas the
	// size of the file limit would allocate gigabytes before the per-cell
	// check below could refuse it. Count first; a record that alone exceeds
	// the cell limit can never succeed.
	if n := ingestCSVWidestRecord(data, lim.MaxCells); n > lim.MaxCells {
		return res, ingestLimit("MaxCells", int64(lim.MaxCells), int64(n))
	}

	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true

	acc := &ingestAcc{lim: lim}
	sheet := SheetInfo{Name: ingestCSVSheet}
	var blocks []SourceBlock // assigned to res only on success: errors never carry partial blocks
	ragged := false
	firstWidth := -1
	for row := 1; ; row++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, fmt.Errorf("%w: %v", ErrIngestCorrupt, err)
		}
		if row > lim.MaxCSVRows {
			return res, ingestLimit("MaxCSVRows", int64(lim.MaxCSVRows), int64(row))
		}
		if firstWidth < 0 {
			firstWidth = len(rec)
		} else if len(rec) != firstWidth {
			ragged = true
		}
		sheet.MaxRow = row
		if len(rec) > sheet.MaxCol {
			sheet.MaxCol = len(rec)
		}
		for i, f := range rec {
			if err := acc.countCell(); err != nil {
				return res, err
			}
			if f == "" {
				continue
			}
			if err := acc.addValue(f); err != nil {
				return res, err
			}
			col := i + 1
			blocks = append(blocks, SourceBlock{
				Kind: BlockKindCell, Sheet: ingestCSVSheet,
				Ref: colLetter(i) + strconv.Itoa(row), Row: row, Col: col,
				Value: f, Type: CellTypeString,
			})
			sheet.Cells++
		}
	}
	if ragged {
		res.Warnings = append(res.Warnings, "ragged_rows")
	}
	res.Blocks = blocks
	res.Sheets = []SheetInfo{sheet}
	res.Complete = true
	return res, nil
}

// ingestCSVWidestRecord returns the largest number of fields encoding/csv
// (comma ',', strict quotes, no comment character) builds for one record of
// data, counting without allocating and returning as soon as a record exceeds
// stop. It follows the reader's grammar: physical lines end at '\n' with a
// "\r\n" pair treated as one newline and a final '\r' dropped, empty lines are
// skipped, and a quoted field may span lines. At the first input the reader
// rejects (a bare or unterminated quote) it stops, counting the fields that
// record had reached, because the reader fails there too.
func ingestCSVWidestRecord(data []byte, stop int) int {
	nextLine := func() ([]byte, bool) {
		if len(data) == 0 {
			return nil, false
		}
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
			line = bytes.TrimSuffix(line, []byte{'\r'})
		} else {
			line, data = data, nil
			line = bytes.TrimSuffix(line, []byte{'\r'})
		}
		return line, true
	}
	widest := 0
	for {
		line, ok := nextLine()
		if !ok {
			return widest
		}
		if len(line) == 0 {
			continue
		}
		fields := 0
		count := func() bool {
			fields++
			if fields > widest {
				widest = fields
			}
			return fields > stop
		}
	record:
		for {
			if len(line) == 0 || line[0] != '"' {
				i := bytes.IndexByte(line, ',')
				field := line
				if i >= 0 {
					field = line[:i]
				}
				if bytes.IndexByte(field, '"') >= 0 {
					return widest // bare quote: the reader fails on this record
				}
				if count() {
					return widest
				}
				if i < 0 {
					break record
				}
				line = line[i+1:]
				continue record
			}
			line = line[1:]
			for {
				i := bytes.IndexByte(line, '"')
				if i < 0 {
					if line, ok = nextLine(); !ok {
						return widest // unterminated quote
					}
					continue
				}
				line = line[i+1:]
				switch {
				case len(line) > 0 && line[0] == '"':
					line = line[1:]
				case len(line) > 0 && line[0] == ',':
					if count() {
						return widest
					}
					line = line[1:]
					continue record
				case len(line) == 0:
					if count() {
						return widest
					}
					break record
				default:
					return widest // text after a closing quote
				}
			}
		}
	}
}
