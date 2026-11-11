//go:build !cli

package main

import (
	"fmt"
	"strings"
)

// apiRequestHostProblem is the write gate's and `benmore check`'s refusal of
// a `run: api` step in a request flow whose URL lets request input choose the
// scheme or host while the call carries the app's credentials
// (apiCallCarriesSecrets: an auth value, a header other than a literal
// Content-Type/Accept/Accept-Language/User-Agent, a signer, or any env
// reference). The runtime refuses every such call (renderOutboundURL), so the
// step could never work: the flow failed with only "the outbound call failed"
// at run time, while the write gate and check passed it.
func apiRequestHostProblem(with map[string]any) string {
	api := withToAPI(with)
	if !apiCallCarriesSecrets(api) {
		return ""
	}
	ref := outboundURLAuthorityRequestRef(api.URL)
	if ref == "" {
		return ""
	}
	note := flowUserProfileInputNote(flowUserProfileRef(strings.TrimSuffix(strings.TrimPrefix(ref, "${{ "), " }}")))
	return fmt.Sprintf("`run: api` url: request input %s%s would choose the scheme or host of a call that carries the app's credentials (an `auth:` value, a header other than a literal Content-Type, Accept, Accept-Language or User-Agent, a signer, or an env value). The runtime refuses that call every time, so the step can never run. Keep the host literal or in env (`url: \"https://api.example.com/v1/items/${{ params.id }}\"`, or `url: \"${{ env.API_BASE }}/v1/items\"`) and pass request values in the path or query.", ref, note)
}

// outboundURLAuthorityRequestRef returns the first request-input reference
// (`${{ params.X }}` or a caller-written profile value `${{ user.X }}`
// (flowUserProfileRef), a single reference without `||`) that lands in the
// scheme or host of a URL template, as the runtime places values
// (flowURLScanner), or "" when there is none. Only a definite case counts:
// any other reference before the path (an env base URL, a step output) can
// carry its own path, so the position of what follows it is unknown.
func outboundURLAuthorityRequestRef(template string) string {
	var s flowURLScanner
	for i := 0; i < len(template) && s.region == flowURLAuthority; {
		if strings.HasPrefix(template[i:], "{{") {
			end := strings.Index(template[i+2:], "}}")
			if end < 0 {
				return ""
			}
			expr := strings.TrimSpace(template[i+2 : i+2+end])
			if !strings.Contains(expr, "||") && (strings.HasPrefix(ghaRefBase(expr), "params.") || flowUserProfileRef(expr) != "") {
				return "${{ " + expr + " }}"
			}
			return ""
		}
		s.writeByte(template[i])
		i++
	}
	return ""
}
