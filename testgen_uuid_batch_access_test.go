//go:build !cli

package main

import (
	"net/http"
	"testing"
)

func TestGeneratedUUIDBatchRespectsWriteAccess(t *testing.T) {
	for _, tc := range []struct {
		name, read, write string
		wantBatch         bool
	}{
		{"owner", "self", "self", true},
		{"authenticated", "everyone", "everyone", true},
		{"public", "anon", "anon", true},
		{"write-only", "off", "self", true},
		{"hidden", "off", "off", false},
		{"read-only", "self", "off", false},
		{"admin-write", "self", "admin", false},
		{"role-write", "self", "role:staff", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Required scalar IDs make this a nonempty batch fixture, but do
			// not grant the synthetic framework user permission to submit it.
			app, server := generatedScalarFixture(t, `model UserBadge {
 id String @id @default(uuid())
 userId Int
 staffProfileId String @map("staff_profile_id")
 badgeId String @map("badge_id")
 @@map("user_badges")
}`)
			app.Access.rules["user_badges"] = map[AccessOp]string{"read": tc.read, "write": tc.write}
			file := generateUUIDTests(app)
			batch, generated := file.Tests["uuid_batch_user_badges"]
			if generated != tc.wantBatch {
				t.Fatalf("UUID batch generated=%v for write=%q, want %v", generated, tc.write, tc.wantBatch)
			}
			// The UUID journeys need a row: a table the plain user may not
			// write gets none, and create_<table> asserts the refusal instead.
			_, created := file.Tests["uuid_create_user_badges"]
			writable := tc.write == "self" || tc.write == "everyone" || tc.write == "anon"
			if created != writable {
				t.Fatalf("uuid_create generated=%v for write=%q, want %v", created, tc.write, writable)
			}
			if !writable {
				refusal := generateCRUDTests(app).Tests["create_user_badges"]
				// `off` answers like a missing route; any other refused
				// write on a table the user may read answers 403.
				want := http.StatusNotFound
				if tc.write != "off" && tc.read != "off" {
					want = http.StatusForbidden
				}
				if len(refusal.Steps) != 1 || refusal.Steps[0].Expect.Status != want {
					t.Fatalf("create_user_badges must assert the declared refusal: %+v", refusal.Steps)
				}
				if result := runSingleTest(app, server.URL, "_framework_crud", "create_user_badges", refusal); !result.Pass {
					t.Fatalf("declared refusal not observed: %+v", result)
				}
			}
			if !generated {
				return
			}
			if len(batch.Steps) != 1 || batch.Steps[0].Expect.Status != http.StatusOK || len(batch.Steps[0].Expect.StatusIn) != 0 {
				t.Fatal("writable UUID batch must retain a strict success assertion")
			}
			result := runSingleTest(app, server.URL, file.Name, "uuid_batch_user_badges", batch)
			if !result.Pass {
				t.Fatalf("writable UUID batch failed: %+v", result)
			}
			var rows, distinctIDs int
			if err := app.DB.QueryRow(`SELECT count(*),count(DISTINCT id) FROM user_badges WHERE typeof(id)='text' AND length(id)=36`).Scan(&rows, &distinctIDs); err != nil || rows != 2 || distinctIDs != 2 {
				t.Fatalf("UUID batch effect: rows=%d distinct IDs=%d err=%v", rows, distinctIDs, err)
			}
		})
	}
}
