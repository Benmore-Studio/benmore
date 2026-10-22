#!/usr/bin/env node
// Release-time only (not shipped: package.json "files" omits scripts/).
// Reads the release's checksums.txt - which release-cli.yml has already
// verified against its Sigstore bundle - and writes bin/checksums.json with the
// SHA-256 of every platform archive the launcher can download. The launcher
// then trusts only these values, which travel inside the npm tarball published
// through npm trusted publishing; a later edit to the GitHub release cannot
// change them.
//
// Usage: node scripts/embed-checksums.js <checksums.txt> <version>
'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Every OS/arch pair bin/benmore.js supports (goreleaser-cloud.yaml builds).
const PLATFORMS = [
  ['darwin', 'amd64', 'tar.gz'],
  ['darwin', 'arm64', 'tar.gz'],
  ['linux', 'amd64', 'tar.gz'],
  ['linux', 'arm64', 'tar.gz'],
  ['windows', 'amd64', 'zip'],
];

function die(msg) {
  process.stderr.write('embed-checksums: ' + msg + '\n');
  process.exit(1);
}

const [sumsPath, version] = process.argv.slice(2);
if (!sumsPath || !version) die('usage: embed-checksums.js <checksums.txt> <version>');
if (!/^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/.test(version)) die('invalid version ' + version);

const listed = new Map();
for (const line of fs.readFileSync(sumsPath, 'utf8').split('\n')) {
  const m = line.trim().match(/^([0-9a-fA-F]{64})\s+\*?(\S+)$/);
  if (m) listed.set(m[2], m[1].toLowerCase());
}

const archives = {};
for (const [os, arch, ext] of PLATFORMS) {
  const name = 'benmore_' + version + '_' + os + '_' + arch + '.' + ext;
  const sum = listed.get(name);
  if (!sum) die('checksums.txt has no entry for ' + name);
  archives[name] = sum;
}

const out = path.join(__dirname, '..', 'bin', 'checksums.json');
fs.writeFileSync(out, JSON.stringify({ version, archives }, null, 2) + '\n');
process.stdout.write('wrote ' + Object.keys(archives).length + ' archive checksums for ' + version + ' to bin/checksums.json\n');
