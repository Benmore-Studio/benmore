//go:build !cli

package main

import "context"

// queryMetadataRows is for framework-built reads of ordinary system metadata.
// Display names, browser labels, task titles and similar values are plaintext
// even when they resemble encrypted envelopes. Built-in sealed credentials
// must be decoded explicitly, once, by the caller that owns that protocol.
// This is not the decoder for app columns or arbitrary authored SQL.
func queryMetadataRows(q mutationQuerier, query string, args ...any) ([]map[string]any, error) {
	return queryRowsWithKeyContextDecrypt(context.Background(), q, nil, func(map[string]any, []byte) {}, query, args...)
}
