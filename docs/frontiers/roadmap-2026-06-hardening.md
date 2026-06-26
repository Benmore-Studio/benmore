# Roadmap — post-deploy hardening (Jun 2026)

Master rollup for the hardening batch kicked off 2026-06-23. Tracks #65.

## Done

- **SSM zero-downtime binary deploy** (#58, merged) — `scripts/deploy-prod-ssm.sh`
  + `.github/workflows/deploy-platform.yml`. No SSH key / no SG change; OIDC +
  protected `production` environment. `2.7.184` redeployed live, benmore.ai 200.
- One-command deploy documented in `CLAUDE.md`, `docs/deployment/release-runbook.md`,
  `docs/deployment/cloudformation.md` (SSM architecture diagram).

## Open work (children of #65)

| Issue | Scope | PR |
|---|---|---|
| #59 | `/docs` usability + "Copy for LLM" button | #63 — md export (`/docs?format=md`) + Copy-for-LLM + tests done; visual usability folded into #62 |
| #60 | Public OpenAPI + Redoc + Swagger UI, with tests | — |
| #61 | CLI robustness (errors, retries, auth, tests) | — |
| #62 | UI design pass (`/impeccable` + `/design-director`) | — (also owns #59's sticky-headers / nav / mobile pass) |
| #64 | Adopt prod host into CloudFormation via resource IMPORT | #69 — adopt-only import template (all resources `Retain`) + pre-import evidence; CI green |

## Key constraint for #64 (IaC)

The prod host is live and hand-created (no stack). It must be brought under
CloudFormation by **resource import**, not a blind `create`/`apply` — the
template models 80/443 ingress as prefix lists while the live SG uses inline
Cloudflare CIDRs, so a careless converge could drop `:443` to users. Reconcile
the template to live properties first, import read-only, then converge in a
separate reviewed change. Deployments are independent of this and already
automated.
