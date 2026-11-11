//go:build !cli

package main

import (
	"testing"
)

// A whole-value ref is emitted as its native JSON type ("respond JSON emits
// native types", api(at:"flows")). A ref ending in a pipe that counts
// (`| length`, `| count`) or converts to whole cents (`| cents`) produces a
// number, so it is a JSON number too: `n: ${{ steps.x.outputs.rows | length }}`
// used to answer "n": "3" while a bare numeric ref answered a number. Text
// pipes, refs embedded in text and `||` fallbacks keep rendering as text.
func TestRespondJSONNumericPipeIsNumber(t *testing.T) {
	steps := `      - id: x
        query: "SELECT 1 AS id UNION ALL SELECT 2 UNION ALL SELECT 3"
      - run: respond
        with:
          body:
            n: '${{ steps.x.outputs.rows | length }}'
            c: '${{ steps.x.outputs.rows | count }}'
            spaced: '  ${{ steps.x.outputs.rows | length }}  '
            cents: '${{ params.price | cents }}'
            nested:
              n: '${{ steps.x.outputs.rows | length }}'
            list:
              - '${{ steps.x.outputs.rows | length }}'
            text: 'total: ${{ steps.x.outputs.rows | length }}'
            upper: '${{ params.name | upper }}'
            digits: '${{ params.zip | digits }}'
            formatted: '${{ params.price | number }}'
            chained: '${{ steps.x.outputs.rows | length | default:0 }}'
            fallback: '${{ params.missing | length || ''none'' }}'
            bare_text: '${{ params.zip }}'
`
	app := expectRowsApp(t)
	rr, _, err := runStepValueFlow(t, app, responseValueFlow("", steps), "?price=19.99&name=bob&zip=02134", nil)
	if err != nil || rr.Code != 200 {
		t.Fatalf("flow: %d %v %s", rr.Code, err, rr.Body.String())
	}
	want := `{
		"n": 3, "c": 3, "spaced": 3, "cents": 1999,
		"nested": {"n": 3}, "list": [3],
		"text": "total: 3", "upper": "BOB", "digits": "02134", "formatted": "19.99",
		"chained": "3", "fallback": "none", "bare_text": "02134"
	}`
	if !jsonEqual(t, rr.Body.String(), want) {
		t.Fatalf("respond body:\n got %s\nwant %s", rr.Body.String(), want)
	}
}

// The api step's json: body resolves exactly like a respond body, so it
// sends the same number.
func TestAPIJSONNumericPipeIsNumber(t *testing.T) {
	steps := `      - id: x
        query: "SELECT 1 AS id UNION ALL SELECT 2"
      - id: send
        run: api
        with:
          url: https://8.8.8.8/count
          method: POST
          json:
            n: '${{ steps.x.outputs.rows | length }}'
            label: 'rows: ${{ steps.x.outputs.rows | length }}'
      - run: respond
        with: { status: 200, body: { ok: true } }
`
	app := expectRowsApp(t)
	rr, sent, err := runStepValueFlow(t, app, responseValueFlow("", steps), "", nil)
	if err != nil || rr.Code != 200 || len(sent) != 1 {
		t.Fatalf("flow: %d %v %d sent %s", rr.Code, err, len(sent), rr.Body.String())
	}
	if !jsonEqual(t, sent[0].body, `{"n": 2, "label": "rows: 2"}`) {
		t.Fatalf("api body: %s", sent[0].body)
	}
}
