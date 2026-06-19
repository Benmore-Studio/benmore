# Durable Jobs Frontier

Benmore already has a lightweight durable queue in `_benmore_jobs`: delayed
run times, attempts, retries, worker claiming, and a status endpoint. The first
River-like hardening slice is transaction correctness: jobs created inside a
transactional flow should commit or roll back with that flow, and worker-run
flows should honor their own `transaction: true` flag.

```mermaid
flowchart LR
  HTTP[async HTTP flow] --> Jobs[_benmore_jobs]
  Enqueue[run: enqueue] --> Jobs
  Hooks[hooks] --> Jobs
  Jobs --> Worker[StartJobWorker]
  Worker --> Flow[executeFlowJob]
  Flow --> Tx{transaction: true?}
  Tx -->|yes| Commit[commit all steps]
  Tx -->|error| Rollback[rollback all steps]
  Tx -->|no| Direct[existing step behavior]
```

This does not import River. It keeps the existing embedded queue and makes the
transaction boundary reliable before adding leases, uniqueness, stale-running
recovery, or cron-to-jobs conversion.

