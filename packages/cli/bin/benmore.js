#!/usr/bin/env node

console.error(`@benmore/cli is a deprecated redirect, not the Benmore CLI.

macOS: brew install benmore-studio/benmore/benmore-cli
Linux/CI: curl -fsSL https://benmore.ai/install-cli.sh | sh`);
process.exit(1);
