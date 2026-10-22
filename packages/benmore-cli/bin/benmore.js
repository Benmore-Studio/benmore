#!/usr/bin/env node
// Thin launcher for the Benmore CLI. On first run it downloads the release
// archive for this platform from the public Benmore-Studio/benmore-cli GitHub
// release matching this package's version, checks its SHA-256 against the
// value embedded in this package (bin/checksums.json, written at publish time
// from the Sigstore-verified release checksums), caches the binary and runs
// it. Later runs use the cache. No install scripts, so it works with
// `npx benmore` and with --ignore-scripts. The Homebrew cask
// (brew install benmore-studio/benmore/benmore) remains the preferred install
// on macOS.
'use strict';

const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const VERSION = require('../package.json').version;
const REPO = 'https://github.com/Benmore-Studio/benmore-cli/releases/download/v' + VERSION + '/';
const OS = { darwin: 'darwin', linux: 'linux', win32: 'windows' }[process.platform];
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];

function fail(msg) {
  process.stderr.write('benmore (npm launcher): ' + msg + '\n');
  process.exit(1);
}

// The trusted SHA-256 values ship inside the npm tarball. The release's own
// checksums.txt is deliberately NOT consulted: anyone able to edit the GitHub
// release could replace an archive and its checksums.txt line together.
function pinnedChecksum(archive) {
  let pinned;
  try {
    pinned = require('./checksums.json');
  } catch (_) {
    fail('this package has no embedded checksums (bin/checksums.json); refusing to download an unverifiable binary');
  }
  if (!pinned || pinned.version !== VERSION || !pinned.archives) {
    fail('embedded checksums do not match package version ' + VERSION + '; refusing to download');
  }
  const want = pinned.archives[archive];
  if (typeof want !== 'string' || !/^[0-9a-f]{64}$/.test(want)) {
    fail('no embedded checksum for ' + archive + '; refusing to download');
  }
  return want;
}

function cacheDir() {
  const base = process.env.BENMORE_NPM_CACHE ||
    (process.platform === 'win32'
      ? path.join(process.env.LOCALAPPDATA || os.homedir(), 'benmore', 'npm')
      : path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'benmore', 'npm'));
  return path.join(base, VERSION);
}

async function download(url) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) fail('download failed: HTTP ' + res.status + ' ' + url);
  return Buffer.from(await res.arrayBuffer());
}

async function install(binPath) {
  if (!OS || !ARCH || (OS === 'windows' && ARCH === 'arm64')) {
    fail('no prebuilt CLI for ' + process.platform + '/' + process.arch + '. See https://benmore.ai/cli');
  }
  const archive = 'benmore_' + VERSION + '_' + OS + '_' + ARCH + (OS === 'windows' ? '.zip' : '.tar.gz');
  const want = pinnedChecksum(archive);
  process.stderr.write('Downloading Benmore CLI ' + VERSION + ' (' + OS + '/' + ARCH + ')...\n');
  const data = await download(REPO + archive);
  const got = crypto.createHash('sha256').update(data).digest('hex');
  if (got !== want) fail('checksum mismatch for ' + archive + ' (expected ' + want + ', got ' + got + '); nothing was installed');

  const dir = path.dirname(binPath);
  fs.mkdirSync(dir, { recursive: true });
  const work = fs.mkdtempSync(path.join(dir, '.tmp-'));
  try {
    const file = path.join(work, archive);
    fs.writeFileSync(file, data);
    // tar ships with macOS, Linux and Windows 10+ (bsdtar, which also reads zip).
    const res = spawnSync('tar', ['-xf', file, '-C', work], { stdio: 'inherit' });
    if (res.status !== 0) fail('could not extract ' + archive + ' (is tar installed?)');
    const exe = OS === 'windows' ? 'benmore.exe' : 'benmore';
    const extracted = path.join(work, exe);
    if (!fs.existsSync(extracted)) fail(archive + ' did not contain ' + exe);
    fs.chmodSync(extracted, 0o755);
    fs.renameSync(extracted, binPath);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

async function main() {
  const binPath = path.join(cacheDir(), process.platform === 'win32' ? 'benmore.exe' : 'benmore');
  if (!fs.existsSync(binPath)) await install(binPath);
  const res = spawnSync(binPath, process.argv.slice(2), { stdio: 'inherit' });
  if (res.error) fail(res.error.message);
  process.exit(res.status === null ? 1 : res.status);
}

main().catch((err) => fail(err && err.message ? err.message : String(err)));
