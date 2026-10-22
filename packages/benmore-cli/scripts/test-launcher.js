#!/usr/bin/env node
// Behavior test for bin/benmore.js (not shipped). The launcher must accept a
// download only when it matches the SHA-256 embedded at publish time, and must
// never fall back to the release's own checksums.txt. Run by
// scripts/test-cli-distribution.sh.
'use strict';

const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const pkgDir = path.join(__dirname, '..');
const version = require(path.join(pkgDir, 'package.json')).version;
const OS = { darwin: 'darwin', linux: 'linux', win32: 'windows' }[process.platform];
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];
if (!OS || !ARCH || OS === 'windows') {
  console.log('skip: launcher test needs a darwin/linux amd64/arm64 host');
  process.exit(0);
}
const archive = 'benmore_' + version + '_' + OS + '_' + ARCH + '.tar.gz';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'benmore-launcher-'));
let passed = 0;
function check(cond, msg) {
  if (!cond) {
    console.error('FAIL: ' + msg);
    fs.rmSync(root, { recursive: true, force: true });
    process.exit(1);
  }
}

try {
  // A real archive holding a stand-in binary.
  const src = path.join(root, 'src');
  fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, 'benmore'), '#!/bin/sh\necho launcher-test-binary\n', { mode: 0o755 });
  const archivePath = path.join(root, archive);
  check(spawnSync('tar', ['-czf', archivePath, '-C', src, 'benmore']).status === 0, 'could not build fixture archive');
  const good = crypto.createHash('sha256').update(fs.readFileSync(archivePath)).digest('hex');

  // fetch stub: serves the archive, and a checksums.txt that AGREES with any
  // tampered value, to prove the launcher ignores it.
  const stub = path.join(root, 'fetch-stub.js');
  fs.writeFileSync(stub, `
    const fs = require('node:fs');
    globalThis.fetch = async (url) => {
      fs.appendFileSync(process.env.FETCH_LOG, url + '\\n');
      if (url.endsWith('/checksums.txt')) {
        return new Response(process.env.RELEASE_SUMS || '', { status: 200 });
      }
      if (url.endsWith('/${archive}')) return new Response(fs.readFileSync(process.env.SERVE), { status: 200 });
      return new Response('', { status: 404 });
    };
  `);

  function runCase(name, pinned, serve) {
    const dir = path.join(root, name);
    fs.mkdirSync(path.join(dir, 'bin'), { recursive: true });
    fs.copyFileSync(path.join(pkgDir, 'package.json'), path.join(dir, 'package.json'));
    fs.copyFileSync(path.join(pkgDir, 'bin', 'benmore.js'), path.join(dir, 'bin', 'benmore.js'));
    if (pinned !== undefined) fs.writeFileSync(path.join(dir, 'bin', 'checksums.json'), JSON.stringify(pinned));
    const servedSum = crypto.createHash('sha256').update(fs.readFileSync(serve)).digest('hex');
    const log = path.join(dir, 'fetch.log');
    const res = spawnSync(process.execPath, ['--require', stub, path.join(dir, 'bin', 'benmore.js'), 'version'], {
      env: { ...process.env, BENMORE_NPM_CACHE: path.join(dir, 'cache'), FETCH_LOG: log, SERVE: serve,
        RELEASE_SUMS: servedSum + '  ' + archive + '\n' },
      encoding: 'utf8',
    });
    const installed = fs.existsSync(path.join(dir, 'cache', version, 'benmore'));
    const fetched = fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '';
    return { status: res.status, out: res.stdout + res.stderr, installed, fetched };
  }

  const ok = runCase('good', { version, archives: { [archive]: good } }, archivePath);
  check(ok.status === 0 && ok.out.includes('launcher-test-binary') && ok.installed, 'pinned archive did not install and run: ' + ok.out);
  check(!ok.fetched.includes('checksums.txt'), 'launcher still consults the release checksums.txt');
  passed++;

  const tampered = path.join(root, 'tampered.tar.gz');
  fs.writeFileSync(tampered, 'not the release archive');
  const bad = runCase('tampered', { version, archives: { [archive]: good } }, tampered);
  check(bad.status !== 0 && /checksum mismatch/.test(bad.out) && !bad.installed,
    'tampered archive accepted (release checksums.txt agreed with it): ' + bad.out);
  passed++;

  const missing = runCase('missing', undefined, archivePath);
  check(missing.status !== 0 && /no embedded checksums/.test(missing.out) && !missing.installed && missing.fetched === '',
    'package without embedded checksums downloaded anyway: ' + missing.out);
  passed++;

  const otherPlatform = runCase('noentry', { version, archives: { ['benmore_' + version + '_plan9_amd64.tar.gz']: good } }, archivePath);
  check(otherPlatform.status !== 0 && /no embedded checksum for/.test(otherPlatform.out) && !otherPlatform.installed,
    'platform without an embedded checksum downloaded anyway: ' + otherPlatform.out);
  passed++;

  const stale = runCase('stale', { version: '0.0.0', archives: { [archive]: good } }, archivePath);
  check(stale.status !== 0 && !stale.installed, 'checksums for another version accepted');
  passed++;

  // embed-checksums.js refuses an incomplete checksums.txt.
  const sums = path.join(root, 'checksums.txt');
  fs.writeFileSync(sums, good + '  ' + archive + '\n');
  const copy = path.join(root, 'embedpkg');
  fs.mkdirSync(path.join(copy, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(copy, 'scripts'));
  fs.copyFileSync(path.join(__dirname, 'embed-checksums.js'), path.join(copy, 'scripts', 'embed-checksums.js'));
  const partial = spawnSync(process.execPath, [path.join(copy, 'scripts', 'embed-checksums.js'), sums, version], { encoding: 'utf8' });
  check(partial.status !== 0 && !fs.existsSync(path.join(copy, 'bin', 'checksums.json')), 'embed-checksums accepted a checksums.txt missing platforms');
  const all = ['darwin_amd64.tar.gz', 'darwin_arm64.tar.gz', 'linux_amd64.tar.gz', 'linux_arm64.tar.gz', 'windows_amd64.zip']
    .map((s) => 'a'.repeat(64) + '  benmore_' + version + '_' + s).join('\n') + '\n';
  fs.writeFileSync(sums, all);
  const full = spawnSync(process.execPath, [path.join(copy, 'scripts', 'embed-checksums.js'), sums, version], { encoding: 'utf8' });
  const embedded = full.status === 0 && JSON.parse(fs.readFileSync(path.join(copy, 'bin', 'checksums.json'), 'utf8'));
  check(embedded && embedded.version === version && Object.keys(embedded.archives).length === 5, 'embed-checksums did not write all five platforms: ' + full.stderr);
  passed++;

  console.log('ok: npm launcher verifies against embedded checksums (' + passed + ' cases)');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
