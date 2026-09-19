//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Route + credential isolate cache entries. Input and current permissions must
// match before replay. The insert and response cache commit in one transaction.
func createIdempotencyIdentity(r *http.Request, table string, session *Session, key string) (string, string) {
	identity, _ := json.Marshal([]any{"create-v2", table, session.UserID, session.ID, key})
	values := make(url.Values)
	for k, v := range r.Form {
		if k != csrfTokenName {
			values[k] = v
		}
	}
	request, _ := json.Marshal([]any{values.Encode(), isHTMX(r), sessionSecurityFingerprint(session)})
	return fmt.Sprintf("v2:%x", sha256.Sum256(identity)), fmt.Sprintf("%x", sha256.Sum256(request))
}
