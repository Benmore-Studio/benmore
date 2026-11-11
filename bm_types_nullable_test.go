//go:build !cli

package main

import (
	"strings"
	"testing"
)

// A nullable column comes back from the API as `"venue_id": null`, but
// bm.d.ts declared it `venue_id?: number`, so `e.venue_id === null` looked
// impossible to the editor and `number | undefined` code compiled against a
// value that is never undefined. Every nullable column is now `T | null`;
// create/update take Partial<Row>, so they still accept omitting it or
// sending null.
func TestBMTypesNullableColumnsAreNullNotOptional(t *testing.T) {
	app := &App{Tables: []Table{
		{
			Name: "events",
			Columns: []Column{
				{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
				{Name: "title", Type: "TEXT", NotNull: true},
				{Name: "venue_id", Type: "INTEGER"},
				{Name: "summary", Type: "TEXT"},
				{Name: "published", Type: "BOOLEAN"},
				{Name: "starts_at", Type: "DATETIME"},
				{Name: "price", Type: "REAL"},
				{Name: "meta", Type: "JSON"},
				// Secret-shaped: never returned by a read, accepted on write.
				{Name: "api_secret", Type: "TEXT"},
				{Name: "webhook_token", Type: "TEXT", NotNull: true},
			},
		},
		{
			Name: "_benmore_users",
			Columns: []Column{
				{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
				{Name: "email", Type: "TEXT", NotNull: true},
				{Name: "first_name", Type: "TEXT"},
				{Name: "role", Type: "TEXT", NotNull: true},
			},
		},
	}}
	out := GenerateBMTypes(app)
	for _, want := range []string{
		"  id: number;\n",
		"  title: string;\n",
		"  venue_id: number | null;\n",
		"  summary: string | null;\n",
		"  published: boolean | null;\n",
		"  starts_at: string | null;\n",
		"  price: number | null;\n",
		"  meta: Record<string, unknown> | unknown[] | null;\n",
		"  api_secret?: string | null;\n",
		"  webhook_token?: string;\n",
		"  first_name: string | null;\n",
		"  email: string;\n",
		"create(body: Partial<Row>): Promise<Row>;",
		"update(id: number | string, body: Partial<Row>): Promise<UpdateReceipt>;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("bm.d.ts missing %q", want)
		}
	}
	for _, stale := range []string{"venue_id?:", "summary?:", "first_name?:", "starts_at?:"} {
		if strings.Contains(out, stale) {
			t.Errorf("bm.d.ts still declares %q optional instead of nullable", stale)
		}
	}
}
