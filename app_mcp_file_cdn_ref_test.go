//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// A private upload on the platform media CDN is stored as the URL
// /api/_upload returned. The file tools accept that stored reference (it
// normalizes to the same logical path) and still refuse every other URL.
func TestAppMCPFileToolAcceptsOwnStoredPrivateCDNReference(t *testing.T) {
	app, pair := appMCPFileRuntimeFixture(t)
	app.DB.SetMaxOpenConns(1)
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	prefix := appMediaPrefix(app)
	stored := "https://" + cfg.CDNDomain + "/private/" + prefix + "/uploads/private/source.csv"
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, stored); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	run := func(name string, input map[string]any) (*appMCPReadResult, error) {
		return runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, name, input)
	}
	ingested, err := run("ingest_file", map[string]any{"file_ref": stored, "record_id": "1", "per_page": json.Number("100")})
	if err != nil {
		t.Fatalf("stored private CDN reference refused: %#v", err)
	}
	data, _ := ingested.Data.(map[string]any)
	if data["complete"] != true || len(ingested.ProcessingID) != 32 {
		t.Fatalf("ingest output = %#v", ingested)
	}
	// The processing is keyed by the logical path, so either spelling of the
	// same reference verifies it.
	for _, ref := range []string{stored, "uploads/private/source.csv"} {
		verified, err := run("verify_file", map[string]any{"file_ref": ref, "record_id": "1", "processing_id": ingested.ProcessingID, "sheet": "csv", "ref": "B2", "expected": "42"})
		if err != nil || verified.Data.(map[string]any)["valid"] != true {
			t.Fatalf("verify with %q = %#v, %v", ref, verified, err)
		}
	}

	refused := map[string]string{
		"other app's prefix":       "https://" + cfg.CDNDomain + "/private/other-app/uploads/private/source.csv",
		"public tier":              "https://" + cfg.CDNDomain + "/public/" + prefix + "/uploads/private/source.csv",
		"public upload path":       "https://" + cfg.CDNDomain + "/private/" + prefix + "/uploads/source.csv",
		"other host":               "https://media.example.invalid/private/" + prefix + "/uploads/private/source.csv",
		"host with port":           "https://" + cfg.CDNDomain + ":443/private/" + prefix + "/uploads/private/source.csv",
		"plain http":               "http://" + cfg.CDNDomain + "/private/" + prefix + "/uploads/private/source.csv",
		"userinfo":                 "https://user@" + cfg.CDNDomain + "/private/" + prefix + "/uploads/private/source.csv",
		"query":                    stored + "?Signature=x",
		"fragment":                 stored + "#x",
		"encoded traversal":        "https://" + cfg.CDNDomain + "/private/" + prefix + "/uploads/private/%2e%2e/source.csv",
		"dot segment":              "https://" + cfg.CDNDomain + "/private/" + prefix + "/uploads/private/../private/source.csv",
		"traversal into other app": "https://" + cfg.CDNDomain + "/private/" + prefix + "/../other-app/uploads/private/source.csv",
		"empty segment":            "https://" + cfg.CDNDomain + "/private/" + prefix + "//uploads/private/source.csv",
	}
	for label, ref := range refused {
		_, err := run("ingest_file", map[string]any{"file_ref": ref, "record_id": "1"})
		var failure *appMCPResultError
		if !errors.As(err, &failure) || failure.Code != "invalid_input" {
			t.Errorf("%s: %q = %v, want invalid_input", label, ref, err)
		}
	}
}

// Without the platform media CDN the app's backend is local storage, which
// has no URL form, so a CDN-shaped reference stays refused.
func TestAppMCPFileToolRefusesCDNReferenceWithoutMediaCDN(t *testing.T) {
	app, pair := appMCPFileRuntimeFixture(t)
	app.DB.SetMaxOpenConns(1)
	withPlatformMedia(t, nil)
	generation := snapshotAppMCPGeneration(app)
	ref := "https://cdn.example.test/private/" + appMediaPrefix(app) + "/uploads/private/source.csv"
	_, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": ref, "record_id": "1"})
	var failure *appMCPResultError
	if !errors.As(err, &failure) || failure.Code != "invalid_input" {
		t.Fatalf("CDN reference without a media CDN = %v, want invalid_input", err)
	}
}
