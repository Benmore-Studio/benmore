# Runtime Frontiers (contributor notes)

Design/roadmap notes for framework contributors — NOT app-builder topics.

These live here, outside `docs/agent/`, on purpose: `docs/agent/*.md` is the
embedded, served `api(at:<topic>)` catalog shown to app builders (and shipped
in the user-facing cloud CLI). These notes discuss internal runtime/hosting
direction (in-process reload, Postgres dialect boundary, durable-job
transaction semantics, type-contract CI fixtures) and would both mislead app
builders and leak hosting internals into the cloud CLI if served as topics.
