//go:build !cli

package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// prefixRetentionStore is a bucket the sweep can list one instance prefix at
// a time; a "flooded" prefix cannot be listed whole, a "broken" one not at all.
type prefixRetentionStore struct {
	objects map[string][]S3Object // top-level prefix ("shop/") -> objects
	flooded map[string]bool
	broken  map[string]error
	deleted []string
	paged   []string
	failDel map[string]bool
}

func (s *prefixRetentionStore) ListPrefixes(prefix string) ([]string, error) {
	if prefix != "" {
		return nil, errors.New("only the top level is listed")
	}
	var out []string
	for p := range s.objects {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (s *prefixRetentionStore) List(prefix string) ([]S3Object, error) {
	if s.flooded[prefix] {
		return nil, errS3ListBudget
	}
	if err := s.broken[prefix]; err != nil {
		return nil, err
	}
	if prefix == "" {
		return nil, errors.New("the whole bucket was listed")
	}
	return s.objects[prefix], nil
}

func (s *prefixRetentionStore) ListPages(prefix string, fn func([]S3Object) error) error {
	s.paged = append(s.paged, prefix)
	top, _, _ := strings.Cut(prefix, "/")
	var page []S3Object
	for _, o := range s.objects[top+"/"] {
		if !strings.HasPrefix(o.Key, prefix) {
			continue
		}
		page = append(page, o)
		if len(page) == 2 {
			if err := fn(page); err != nil {
				return err
			}
			page = nil
		}
	}
	if page != nil {
		return fn(page)
	}
	return nil
}

func (s *prefixRetentionStore) Delete(key string) error {
	if s.failDel[key] {
		return errors.New("synthetic delete failure")
	}
	s.deleted = append(s.deleted, key)
	return nil
}

// Retention lists and prunes one instance prefix at a time: a prefix that is
// too large to list whole, or that fails to list, blocks only itself; junk a
// WAL session left under litestream/ is cleared once older than the PITR
// window, even from a prefix too large to list whole.
func TestRetentionSweepsEachPrefixAlone(t *testing.T) {
	t.Setenv("BENMORE_RETENTION_DRYRUN", "0")
	now := time.Now().UTC()
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	hour := now.Add(-time.Hour).Format("2006-01-02-15")
	oldGen := now.Add(-20 * 24 * time.Hour).Format("20060102T150405Z")
	newGen := now.Add(-time.Hour).Format("20060102T150405Z")
	store := &prefixRetentionStore{
		objects: map[string][]S3Object{
			"shop/": {
				{Key: "shop/2000-01-01-00.db.gz", LastModified: at(0)},
				{Key: "shop/" + hour + ".db.gz", LastModified: at(time.Hour)},
				{Key: "shop/litestream/" + oldGen + "/snapshot.db.gz", LastModified: at(20 * 24 * time.Hour)},
				{Key: "shop/litestream/" + newGen + "/snapshot.db.gz", LastModified: at(time.Hour)},
				{Key: "shop/litestream/junk.bin", LastModified: at(30 * 24 * time.Hour)},
				{Key: "shop/litestream/fresh-junk.bin", LastModified: at(time.Hour)},
				{Key: "shop/broker-check.bin", LastModified: at(30 * 24 * time.Hour)},
			},
			"flood/": {
				{Key: "flood/litestream/x/y/z", LastModified: at(30 * 24 * time.Hour)},
				{Key: "flood/litestream/" + oldGen + "/snapshot.db.gz", LastModified: at(20 * 24 * time.Hour)},
				{Key: "flood/litestream/a", LastModified: at(9 * 24 * time.Hour)},
				{Key: "flood/litestream/b", LastModified: at(time.Hour)},
				{Key: "flood/2000-01-01-00.db.gz", LastModified: at(0)},
			},
			"broken/":    {{Key: "broken/2000-01-01-00.db.gz"}},
			"_platform/": {{Key: "_platform/2000-01-01-00.db.gz"}, {Key: "_platform/" + hour + ".db.gz"}},
		},
		flooded: map[string]bool{"flood/": true},
		broken:  map[string]error{"broken/": errors.New("synthetic listing failure")},
	}
	reads := 0
	n, err := runRetentionSweep(store, func() (map[string]bool, error) {
		reads++
		return map[string]bool{"shop": true, "flood": true, "broken": true, "_platform": true}, nil
	})
	want := []string{
		"_platform/2000-01-01-00.db.gz",
		"flood/litestream/a", "flood/litestream/x/y/z",
		"shop/2000-01-01-00.db.gz", "shop/litestream/" + oldGen + "/snapshot.db.gz", "shop/litestream/junk.bin",
	}
	sort.Strings(store.deleted)
	if !slices.Equal(store.deleted, want) || n != len(want) {
		t.Fatalf("deleted %d %q, want %q", n, store.deleted, want)
	}
	if err == nil || !strings.Contains(err.Error(), "flood: too many objects") || !strings.Contains(err.Error(), "broken: synthetic listing failure") ||
		strings.Contains(err.Error(), "shop") || !errors.Is(err, errS3ListBudget) {
		t.Fatalf("sweep error: %v", err)
	}
	if !slices.Equal(store.paged, []string{"flood/litestream/"}) {
		t.Fatalf("paged %q", store.paged)
	}
	// The inventory is read once before and again after each complete
	// listing (_platform/ and shop/; the other two never listed whole).
	if reads != 3 {
		t.Fatalf("inventory read %d times", reads)
	}
	// A failing inventory recheck stops the sweep instead of guessing.
	store.deleted = nil
	reads = 0
	failure := errors.New("synthetic inventory failure")
	if _, err := runRetentionSweep(store, func() (map[string]bool, error) {
		reads++
		if reads > 1 {
			return nil, failure
		}
		return map[string]bool{"shop": true}, nil
	}); !errors.Is(err, failure) {
		t.Fatalf("inventory failure: %v", err)
	}
	for _, k := range store.deleted {
		if !strings.Contains(k, "/litestream/") {
			t.Fatalf("deleted %s without an inventory", k)
		}
	}
}

func TestLitestreamJunkKeys(t *testing.T) {
	t.Setenv("BENMORE_PITR_RETENTION_HOURS", "24")
	now := time.Now().UTC()
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	gen := now.Add(-72 * time.Hour).Format("20060102T150405Z")
	got := litestreamJunkKeys([]S3Object{
		{Key: "shop/litestream/junk", LastModified: at(48 * time.Hour)},
		{Key: "shop/litestream/fresh", LastModified: at(time.Hour)},
		{Key: "shop/litestream/undated", LastModified: "yesterday"},
		{Key: "shop/litestream/" + gen + "/snapshot.db.gz", LastModified: at(72 * time.Hour)},
		{Key: "shop/litestream/" + gen + "/wal/0-1-" + gen + ".wal.gz", LastModified: at(72 * time.Hour)},
		{Key: "shop/2000-01-01-00.db.gz", LastModified: at(72 * time.Hour)},
		{Key: "shop/other/litestream", LastModified: at(72 * time.Hour)},
	}, now)
	if !slices.Equal(got, []string{"shop/litestream/junk"}) {
		t.Fatalf("junk %q", got)
	}
}

// S3Storage lists the bucket's top-level prefixes (delimiter "/") and
// refuses one that is not under the asked prefix.
func TestS3ListPrefixes(t *testing.T) {
	// A key starting with "/" makes S3 list the common prefix "/": skipped
	// (and logged), never a failure of the whole listing.
	body := `<ListBucketResult><IsTruncated>false</IsTruncated><CommonPrefixes><Prefix>/</Prefix></CommonPrefixes><CommonPrefixes><Prefix>blog/</Prefix></CommonPrefixes><CommonPrefixes><Prefix>shop/</Prefix></CommonPrefixes></ListBucketResult>`
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	store := &S3Storage{Bucket: "bucket", Endpoint: server.URL, Key: "fixture", Secret: "secret"}
	got, err := store.ListPrefixes("")
	if err != nil || !slices.Equal(got, []string{"blog/", "shop/"}) || !strings.Contains(query, "delimiter=%2F") {
		t.Fatalf("prefixes %q %v (query %s)", got, err, query)
	}
	body = `<ListBucketResult><IsTruncated>false</IsTruncated><CommonPrefixes><Prefix>other/x/</Prefix></CommonPrefixes></ListBucketResult>`
	if _, err := store.ListPrefixes("shop/"); err == nil {
		t.Fatal("a foreign common prefix was accepted")
	}
	// ListPages hands every page over; the whole listing is not kept.
	body = `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>shop/a</Key><Size>1</Size></Contents></ListBucketResult>`
	var seen []string
	if err := store.ListPages("shop/", func(page []S3Object) error {
		for _, o := range page {
			seen = append(seen, o.Key)
		}
		return nil
	}); err != nil || !slices.Equal(seen, []string{"shop/a"}) {
		t.Fatalf("pages %q %v", seen, err)
	}
}

// Junk under litestream/ is deleted in its own call: a junk delete that
// fails (or is refused) never holds up the snapshots and generations.
func TestRetentionJunkNeverBlocksPruning(t *testing.T) {
	t.Setenv("BENMORE_RETENTION_DRYRUN", "0")
	now := time.Now().UTC()
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	hour := now.Add(-time.Hour).Format("2006-01-02-15")
	store := &prefixRetentionStore{
		objects: map[string][]S3Object{"shop/": {
			{Key: "shop/litestream/aaa-junk", LastModified: at(30 * 24 * time.Hour)},
			{Key: "shop/2000-01-01-00.db.gz", LastModified: at(0)},
			{Key: "shop/" + hour + ".db.gz", LastModified: at(time.Hour)},
		}},
		failDel: map[string]bool{"shop/litestream/aaa-junk": true},
	}
	n, err := runRetentionSweep(store, func() (map[string]bool, error) { return map[string]bool{"shop": true}, nil })
	if !slices.Equal(store.deleted, []string{"shop/2000-01-01-00.db.gz"}) || n != 1 {
		t.Fatalf("deleted %d %q", n, store.deleted)
	}
	if err == nil || !strings.Contains(err.Error(), "shop litestream/ cleanup") {
		t.Fatalf("junk failure not reported: %v", err)
	}
}
