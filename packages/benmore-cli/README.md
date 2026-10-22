# benmore

The Benmore CLI, for building, deploying and verifying apps on [benmore.ai](https://benmore.ai).

```sh
npx benmore login          # or: npm i -g benmore
benmore new my-app && cd my-app && benmore deploy
```

This package is a small launcher. On first run it downloads the CLI release
matching its version from
[Benmore-Studio/benmore-cli](https://github.com/Benmore-Studio/benmore-cli/releases),
checks the archive's SHA-256 against the value embedded in this package at
publish time (taken from the release's `checksums.txt` after its Sigstore
signature was verified in the release workflow, so editing the GitHub release
later cannot change what the launcher accepts), caches the
binary under `~/.cache/benmore/npm/<version>` (`%LOCALAPPDATA%\benmore\npm` on
Windows, or `$BENMORE_NPM_CACHE`) and runs it. It has no install scripts.

On macOS, Homebrew is the preferred install:
`brew install benmore-studio/benmore/benmore`.
