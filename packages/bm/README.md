# @benmore/bm

The zero-dependency ESM browser SDK for frontends hosted outside Benmore.

```js
import bm from "@benmore/bm";

const contacts = await bm.table("contacts").list();
```

Native Benmore apps keep using `import bm from "bm"`; their generated
`src/bm.d.ts` augments the SDK with schema-specific table, flow, and app types.

This package's `index.js` is staged byte-for-byte from the framework's canonical
`embedded/bm.js`; it has no separate runtime implementation or build step.

App-building agents use the [harness guide](../../docs/agent/harness.md) and
canonical `sdk` / `existing-frontends` API recipes. The SDK is separate from the
native hosted CLI and does not install agent skills or deploy an app. Inspect
live tables and authorization before replacing `contacts` in the example.
