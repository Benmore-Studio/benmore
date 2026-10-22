//go:build !cli

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestPDFStampWorkerRequestRoundTripAndStrictLengths(t *testing.T) {
	source := stampFixturePDF()
	image := stampFixturePNG(t, 5, 3)
	placements := []pdfStampPlacement{{Page: 2, Rect: pdfStampRect{X: .1, Y: .2, Width: .3, Height: .4}, Signature: image}}
	request, err := encodePDFStampWorkerRequest(source, placements)
	if err != nil {
		t.Fatal(err)
	}
	gotSource, gotPlacements, err := decodePDFStampWorkerRequest(bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSource, source) || len(gotPlacements) != 1 || gotPlacements[0].Page != placements[0].Page || gotPlacements[0].Rect != placements[0].Rect || !bytes.Equal(gotPlacements[0].Signature, image) {
		t.Fatal("worker frame did not preserve exact source, geometry, and image bytes")
	}
	if _, _, err := decodePDFStampWorkerRequest(bytes.NewReader(append(append([]byte(nil), request...), 0))); err == nil {
		t.Fatal("worker frame accepted trailing bytes")
	}

	badHeader, err := json.Marshal(pdfStampWorkerHeader{SourceBytes: uint64(pdfStampMaxInputBytes + 1), Placements: []pdfStampWorkerPlacement{{Page: 1, Rect: pdfStampRect{X: .1, Y: .1, Width: .2, Height: .2}, SignatureBytes: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	badFrame := make([]byte, 4+len(badHeader))
	binary.BigEndian.PutUint32(badFrame[:4], uint32(len(badHeader)))
	copy(badFrame[4:], badHeader)
	if _, _, err := decodePDFStampWorkerRequest(bytes.NewReader(badFrame)); err == nil {
		t.Fatal("worker frame accepted oversized declared PDF before reading payload")
	}
	if _, err := encodePDFStampWorkerRequest(source, []pdfStampPlacement{{Page: 1, Rect: pdfStampRect{X: .9, Y: .1, Width: .2, Height: .2}, Signature: image}}); err == nil {
		t.Fatal("request encoder accepted out-of-page geometry")
	}
}
