//go:build !platform && !cloud

package main

// Open-source framework edition: app runtime + serve/new only, no cloud client,
// no fleet engine. Built with `-tags sqlite_fts5`. This is what the public
// repo (Benmore-Studio/benmore) ships and what `export-public.sh` exports.
const platformBuild = false
const editionName = "framework"
