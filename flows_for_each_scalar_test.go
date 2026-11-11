//go:build !cli

package main

import "testing"

// A loop over a list of strings or numbers runs once per element. Scalars
// used to be skipped, so it ran zero times and the flow answered 200.
func TestForEachIteratesScalarItems(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE invites (email TEXT NOT NULL, seat INTEGER)`)
	flow := `on:
  request:
    method: POST
    path: /api/invite
jobs:
  invite:
    steps:
      - for_each: ${{ params.emails }}
        as: email
        steps:
          - run: sql
            with:
              query: "INSERT INTO invites (email) VALUES (:e)"
              params:
                e: '${{ email }}'
      - for_each: ${{ params.seats }}
        as: seat
        steps:
          - run: sql
            with:
              query: "INSERT INTO invites (email, seat) VALUES ('seat', :s)"
              params:
                s: '${{ seat }}'
      - run: respond
        with:
          status: 200
          json: { ok: true }
`
	rr := runProbeGHAFlow(t, app, flow, `{"emails":["a@example.com","b@example.com"],"seats":[1,2,3]}`)
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var emails, seats int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM invites WHERE email LIKE '%@%'`).Scan(&emails); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM invites WHERE seat IN (1, 2, 3)`).Scan(&seats); err != nil {
		t.Fatal(err)
	}
	if emails != 2 || seats != 3 {
		t.Fatalf("iterated %d emails and %d seats, want 2 and 3", emails, seats)
	}
}
