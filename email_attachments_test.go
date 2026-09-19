//go:build !cli

package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// TestBuildRawMIMEMessage_Attachment verifies the raw-MIME builder produces a
// parseable multipart/mixed message whose attachment round-trips byte-for-byte.
func TestBuildRawMIMEMessage_Attachment(t *testing.T) {
	fileBytes := []byte("%PDF-1.4 fake pdf bytes\x00\x01\x02")
	atts := []EmailAttachment{{
		Filename:    "report.pdf",
		ContentType: "application/pdf",
		Content:     base64.StdEncoding.EncodeToString(fileBytes),
	}}

	raw, err := buildRawMIMEMessage(
		"GO-180 <no-reply@go180.ai>", "vet@example.com", "Your report",
		"", "https://go180.ai/unsub", "", "<p>hi</p>", "hi", atts,
	)
	if err != nil {
		t.Fatalf("buildRawMIMEMessage: %v", err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	if got := msg.Header.Get("List-Unsubscribe"); got != "<https://go180.ai/unsub>" {
		t.Errorf("List-Unsubscribe = %q", got)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("top content-type = %q (%v)", mediaType, err)
	}

	var sawAlternative bool
	var gotAttachment []byte
	var gotFilename string
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("next part: %v", err)
		}
		ct, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if ct == "multipart/alternative" {
			sawAlternative = true
			continue
		}
		if cd := part.Header.Get("Content-Disposition"); strings.HasPrefix(cd, "attachment") {
			_, dp, _ := mime.ParseMediaType(cd)
			gotFilename = dp["filename"]
			body, _ := io.ReadAll(part)
			// Body is base64 (Content-Transfer-Encoding: base64).
			decoded, derr := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(body)), "\r\n", ""))
			if derr != nil {
				t.Fatalf("decode attachment: %v", derr)
			}
			gotAttachment = decoded
		}
	}
	if !sawAlternative {
		t.Error("missing multipart/alternative body part")
	}
	if gotFilename != "report.pdf" {
		t.Errorf("attachment filename = %q", gotFilename)
	}
	if !bytes.Equal(gotAttachment, fileBytes) {
		t.Errorf("attachment bytes did not round-trip: got %q", gotAttachment)
	}
}

// TestWithToEmail_ParsesAttachments verifies the GHA flow parser reads the
// attachments key off a `run: email` step's with-map.
func TestWithToEmail_ParsesAttachments(t *testing.T) {
	e := withToEmail(map[string]any{
		"to":      "v@example.com",
		"subject": "s",
		"html":    "<p>b</p>",
		"attachments": []any{
			map[string]any{"filename": "a.pdf", "content_type": "application/pdf", "content": "aGVsbG8="},
			map[string]any{"filename": "skip-me"}, // no content → dropped
			"not-an-object",                       // non-object → skipped
		},
	})
	if len(e.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(e.Attachments))
	}
	if e.Attachments[0].Filename != "a.pdf" || e.Attachments[0].Content != "aGVsbG8=" {
		t.Errorf("bad attachment: %+v", e.Attachments[0])
	}
}
