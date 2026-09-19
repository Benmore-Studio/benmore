//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Synthetic payloads and indexes exercise snapshot/verification I/O without
// copying a tenant database. Run with -benchtime=1x for cold-start comparisons.
func BenchmarkUnchangedStartup(b *testing.B) {
	for _, size := range []struct {
		name string
		rows int
	}{{"16MiB", 4096}, {"128MiB", 32768}} {
		b.Run(size.name, func(b *testing.B) {
			dir := b.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "schema.sql"), []byte(`CREATE TABLE items (
  id INTEGER PRIMARY KEY,
  category INTEGER,
  payload BLOB
);
CREATE INDEX items_category ON items(category);`), 0600); err != nil {
				b.Fatal(err)
			}
			app, err := loadApp(dir)
			if err != nil {
				b.Fatal(err)
			}
			_, err = app.DB.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < ?)
INSERT INTO items SELECT x, x % 97, zeroblob(4096) FROM n`, size.rows)
			if err != nil {
				b.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "migrations"), 0700); err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "migrations", "001_index.sql"), []byte("CREATE INDEX IF NOT EXISTS items_category ON items(category);"), 0600); err != nil {
				b.Fatal(err)
			}
			if err := RunMigrations(app.DB, dir); err != nil {
				b.Fatal(err)
			}
			app.Shutdown()
			info, err := os.Stat(filepath.Join(dir, "data.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(info.Size())
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				app, err := loadApp(dir)
				if err != nil {
					b.Fatal(err)
				}
				app.Shutdown()
			}
		})
	}
}
