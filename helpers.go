//go:build !cli

package main

// Small utility helpers used across the runtime.

import "strings"

// extractTableFromSQL pulls the first table name after FROM in a SQL
// statement. Returns "" if no FROM clause is found. Used to attribute
// queries to a table for caching invalidation and dev-mode warnings.
func extractTableFromSQL(sql string) string {
	upper := strings.ToUpper(sql)
	idx := strings.Index(upper, "FROM ")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(sql[idx+5:])
	parts := strings.Fields(rest)
	if len(parts) > 0 {
		return strings.Trim(parts[0], "\"'`")
	}
	return ""
}

// levenshtein computes the edit distance between two strings.
// Used to suggest "did you mean?" for typos in column names etc.
func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min3(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	return matrix[len(a)][len(b)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
