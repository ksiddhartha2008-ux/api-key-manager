# API Control Center

A local-first hackathon implementation for managing platform API keys, inspecting real protected-endpoint usage, and showing provider data with explicit provenance.

It was built from an empty workspace. There was no existing application source to audit, and no MiroFish source or endpoint was provided. Consequently, the Simulation Lab is intentionally marked unavailable rather than faking a simulation integration.

## What is implemented

- Real persistent SQLite storage via Node's built-in `node:sqlite`; no frontend-only key state.
- CSPRNG-generated `sk_live_…` / `sk_test_…` API keys; SHA-256 hashes only are persisted. The raw secret is returned one time at creation or rotation.
- Scoped protected endpoint: `GET /api/demo/data` with `X-API-Key`.
- Server-side status, expiry, scope, quota, per-minute rate-limit, constant-time hash comparison, revoke, and rotation-with-grace-period checks.
- Database-backed usage events and audit events without secret values.
- Honest provider monitoring UI. No credentials are accepted in the browser and absent provider data is labelled `UNAVAILABLE`; user budgets are `USER_CONFIGURED`.
- Responsive dark/light dashboard, empty/error/loading states, keyboard focus styles, and a real Try-it Console.
- Simulation routes fail safely with `503 SIMULATION_UNAVAILABLE` until a private, pinned MiroFish adapter is actually supplied and validated.

## Start

Requires Node 22.5+ (the runtime must support `node:sqlite`). No packages need to be installed.

```bash
npm run setup
npm run dev
```

Open [http://localhost:4173](http://localhost:4173). Data lives in `data/api-control-center.db`, created on first start.

To change a setting, set environment variables before starting. See `.env.example`. A `.env` file is not automatically read to avoid silently importing local secrets; use your shell or deployment configuration instead.

## API routes

| Route | Purpose |
| --- | --- |
| `GET /api/health` | Real local health state |
| `GET /api/dashboard` | Database-backed dashboard summary |
| `GET`, `POST /api/keys` | List and create platform keys |
| `POST /api/keys/:id/revoke` | Irreversibly revoke a key |
| `POST /api/keys/:id/rotate` | Create successor key; old key receives a grace period |
| `GET /api/demo/data` | Protected test endpoint (`X-API-Key`, `demo:read`) |
| `GET /api/audit` | Sanitized audit events |
| `GET /api/providers` | Provider metric source classifications |
| `/api/simulations/*` | Explicit safe-unavailable response until a verified adapter exists |

## Tests

```bash
npm test
```

The integration test verifies this exact flow against a temporary SQLite database:

```text
create key → protected call → rate limit (429) → revoke → denied (403)
```

## Security notes

- Never commit provider keys or `MIROFISH_INTERNAL_TOKEN`; server configuration only.
- This lightweight demo hashes platform keys using SHA-256 to support direct indexed lookup and applies a constant-time verification of the matching hash. A production system should additionally use a managed pepper/HSM or a dedicated key management service and a production authentication layer.
- SQLite is appropriate for a single-process hackathon deployment. A multi-instance production deployment needs a centralized database plus distributed rate limiting.
- Provider balances are not fabricated. This project does not call external provider usage APIs because no provider credential or authoritative account configuration was supplied.

## Simulation Lab status

The requested MiroFish integration cannot be implemented honestly from a prompt alone. Before enabling it, pin and inspect an actual upstream commit, add a private backend-only adapter with internal authentication, ownership checks, timeouts, agent/round limits, idempotency, and then run the required 10/50/100/500/1000-agent tests. Do not expose MiroFish to the browser or claim those tests were run.

## Legal

The interface’s Privacy Policy and Terms links are placeholders marked “Draft, needs legal review.”
