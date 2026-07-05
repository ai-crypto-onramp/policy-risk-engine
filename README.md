# Policy / Risk Engine

![CI](https://github.com/ai-crypto-onramp/policy-risk-engine/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/ai-crypto-onramp/policy-risk-engine/branch/main/graph/badge.svg)](https://codecov.io/gh/ai-crypto-onramp/policy-risk-engine)

Per-tx caps, velocity limits, whitelisting, source auth. Auto-approves or routes to manual review. The single gatekeeper before MPC signing.

## Overview / Responsibilities

The Policy / Risk Engine is the compliance and risk decision point on the transaction
path. Every request to move funds passes through this service before the
Transaction Orchestrator may call the MPC Signing Service. It aggregates signals from
KYC, KYT, and Fraud Detection, evaluates them against versioned policy rules, and
returns one of three decisions: `allow`, `deny`, or `manual_review`.

Responsibilities:

- Enforce per-transaction amount caps by user tier, asset, and fiat rail.
- Enforce velocity limits over rolling time windows (per-minute / per-hour / per-day).
- Enforce destination address whitelisting.
- Enforce source authentication requirements (valid user session; 2FA for high-value tx).
- Compute an aggregate risk score from KYT verdict, fraud score, and KYC status.
- Decide between auto-approve and routing to the manual review queue.
- Version every policy bundle and hot-reload rules without redeploy.
- Emit a signed decision record for every evaluation to the audit-event-log.

In the architecture it is called by both the **API Gateway** (pre-flight checks
before quoting) and the **Transaction Orchestrator** (synchronous gate on the tx
saga). It consumes status/verdict/score inputs from **KYC**, **KYT**, and
**Fraud Detection**. It is the last gate before `ORCH -> MPC` signing.

## Language & Tech Stack

- **Go** — service implementation, REST + gRPC servers, decision orchestration.
- **OPA / Rego** — embedded policy decision engine; rules authored in Rego and
  bundled via the OPA bundle service.
- **Redis** — velocity counters (rolling windows) and idempotency keys.
- **PostgreSQL** — durable store for policies, policy versions, whitelist, review
  queue, and decision audit records.
- **gRPC** — internal transport on the transaction path (low latency).
- **REST / JSON** — external/admin API for rule management and pre-flight from the
  API Gateway.

## System Requirements

### Per-tx amount caps

- Caps configurable per **user tier** (e.g. `tier_1`, `tier_2`, `tier_3`, `institutional`).
- Caps configurable per **asset** (e.g. BTC, ETH, USDC) and per **fiat rail**
  (card, ACH, SEPA, PIX, UPI).
- Caps expressed in USD-equivalent; FX conversion applied at evaluation time using
  the latest quote snapshot.
- Hard deny on exceed; optionally route near-cap transactions to manual review.

### Velocity limits

- Rolling windows: **per-minute**, **per-hour**, **per-day**.
- Tracked per `user_id`, optionally per `asset` and per `rail`.
- Counters maintained in Redis using atomic increment with TTL equal to the window
  length.
- On decision rollback (tx failed downstream), counters must be decremented via a
  compensating callback from the Transaction Orchestrator.

### Destination address whitelisting

- Each user maintains an allowlist of approved destination addresses per chain.
- New whitelist entries require a verification flow (e.g. micro-transfer or signed
  message) before activation.
- Transactions to non-whitelisted addresses are denied unless the policy explicitly
  permits a one-time override routed to manual review.

### Source auth

- Requires a **valid authenticated user session** (JWT issued by Identity & Auth).
- Requires **2FA** for high-value transactions above a configurable threshold
  (`HIGH_VALUE_2FA_THRESHOLD_USD`).
- Validates session scope and caller (API Gateway vs. Transaction Orchestrator)
  via mTLS service identity in addition to user-level auth.

### Aggregate risk score

- Inputs: `kyt_verdict` (clean / suspicious / high_risk), `fraud_score`
  (0.0–1.0 from Fraud Detection), `kyc_status` (verified / restricted / expired).
- Composite score computed by Rego rules; thresholds configurable.
- Score above `MANUAL_REVIEW_THRESHOLD` routes to manual review; above
  `DENY_THRESHOLD` denies outright.

### Auto-approve vs manual-review routing

- `allow` — tx proceeds on the saga path.
- `manual_review` — tx parked in `review_queue`; Transaction Orchestrator receives
  a non-final response and holds the saga pending a reviewer decision.
- `deny` — tx blocked; reason codes returned; audit record emitted.

### Policy versioning & hot-reload

- Every published rule bundle is immutable and versioned (`policy_versions`).
- The active version is pointed at by a `policies.active_version` row.
- Hot-reload polls the OPA bundle service on `POLICY_HOT_RELOAD_INTERVAL` and swaps
  the embedded decision engine atomically without restart.
- Previous versions remain queryable for audit replay.

### Decision audit

- Every `evaluate` call produces a signed decision record (service identity +
  payload hash) persisted to `policy_decisions` and emitted to the audit-event-log.
- Record includes: request payload, matched rules, computed score, decision,
  policy version hash, timestamp, evaluator node id.

## Non-Functional Requirements

- **Latency:** synchronous decision p99 **< 50 ms** on the transaction path
  (in-process OPA evaluation + Redis velocity lookup).
- **Determinism:** given the same inputs and the same active policy version, the
  decision MUST be identical — required for replay and dispute resolution.
- **Hot reload:** rules MUST be reloadable without redeploy or restart; swap is
  atomic and versioned.
- **Availability:** 99.99% — the engine gates all signing; downtime blocks the
  entire on-ramp. Multi-AZ deployment with health-checked replicas.
- **Auditability:** 100% of decisions durable within the same transaction
  boundary (decision record committed before responding to the caller).
- **Observability:** metrics for decision counts by outcome, rule hit rates,
  evaluation latency, hot-reload events; traces propagated from the orchestrator.

## Technical Specifications

### API surface

- **REST + JSON** — admin / pre-flight path; consumed by API Gateway and the
  policy management UI.
- **gRPC** — high-throughput internal path; consumed by the Transaction
  Orchestrator on the tx saga.
- **OPA** — embedded as a library (not a sidecar); Rego policies compiled into the
  decision engine in-process to keep latency below the 50 ms budget.
- AuthN/Z: mTLS for service-to-service; OAuth/scope-checked bearer tokens for the
  admin REST surface.

### Endpoints

#### `POST /v1/policy/evaluate`

Synchronous decision call. Used by both API Gateway (pre-flight) and Transaction
Orchestrator (tx gate).

Request body:

```json
{
  "user_id": "usr_123",
  "amount": "1500.00",
  "currency": "USD",
  "asset": "USDC",
  "rail": "card",
  "dest_address": "0xabc...",
  "dest_chain": "ethereum",
  "kyt_verdict": "clean",
  "fraud_score": 0.12,
  "kyc_status": "verified",
  "session": { "id": "sess_...", "2fa_passed": true }
}
```

Response body:

```json
{
  "decision": "allow | deny | manual_review",
  "reasons": ["velocity_daily_ok", "kyt_clean", "whitelisted"],
  "applied_rules": [
    { "id": "cap.daily.tier_2", "version": "v2026.07.06-01" }
  ],
  "policy_version": "v2026.07.06-01",
  "score": 0.18,
  "decision_id": "dec_..."
}
```

#### `GET /v1/policy/rules`

List available policy bundles (metadata only).

#### `POST /v1/policy/rules`

Publish a new policy bundle (YAML/Rego). Creates a new immutable
`policy_versions` row; does not activate unless `activate=true`.

#### `GET /v1/policy/rules/:version`

Fetch a specific immutable policy version (Rego source + metadata).

#### `POST /v1/policy/whitelist`

Add a destination address to a user's allowlist (subject to verification flow).

#### `GET /v1/policy/whitelist/:user_id`

List whitelisted addresses for a user.

#### `POST /v1/policy/review/:decision_id/resolve`

Reviewer endpoint to resolve a parked `manual_review` decision into `allow` or
`deny`; updates `review_queue` and emits a follow-up audit record.

### Data model

PostgreSQL tables:

- **`policies`** — one row per logical policy scope; `active_version` FK.
- **`policy_versions`** — immutable versioned bundles; columns: `id`, `policy_id`,
  `version`, `rego_hash`, `rego_source`, `created_at`, `created_by`.
- **`policy_decisions`** — append-only audit of every evaluation; columns:
  `decision_id`, `policy_version`, `request_hash`, `decision`, `reasons[]`,
  `applied_rules[]`, `score`, `signature`, `created_at`.
- **`whitelist_addresses`** — `user_id`, `chain`, `address`, `label`,
  `verified_at`, `status`.
- **`review_queue`** — `decision_id`, `tx_id`, `status` (`pending | resolved`),
  `assigned_to`, `resolved_at`, `resolution`.

Redis keys:

- **`velocity_counters`** — `vel:{user_id}:{window}` counters with TTL = window
  length (e.g. `vel:usr_123:60s`, `vel:usr_123:1h`, `vel:usr_123:1d`).
- Optional per-asset / per-rail buckets: `vel:{user_id}:{asset}:{window}`.

### Rule structure

Rules authored as YAML descriptors plus Rego modules:

```yaml
# policies/caps.yaml
- id: cap.daily.tier_2
  scope: user_tier
  tier: tier_2
  window: 1d
  usd_cap: 25000
  on_exceed: deny
- id: cap.tx.card.high_value_2fa
  scope: tx
  rail: card
  usd_threshold: 1000
  requires_2fa: true
  on_fail: manual_review
```

```rego
# policies/decisions.rego
package policy.decisions

default allow := false

allow if {
  input.amount_usd <= data.caps.tx.max_usd
  input.kyt_verdict == "clean"
  input.fraud_score < 0.5
  data.whitelist[input.user_id][input.dest_address]
}

manual_review if {
  input.fraud_score >= 0.5
  input.fraud_score < 0.8
}
```

Per-tier overrides are resolved by Rego data documents keyed by `user_tier`.

### Integrations

- **Consumes (sync):**
  - `kyc_status` — passed in evaluate request (sourced from Onboarding/KYC).
  - `kyt_verdict` — passed in evaluate request (sourced from AML/KYT).
  - `fraud_score` — passed in evaluate request (sourced from Fraud Detection).
- **Consumed by:**
  - `api-gateway` — calls `POST /v1/policy/evaluate` for pre-flight checks before
    returning a quote to the client.
  - `transaction-orchestrator` — calls gRPC `Evaluate` as the gate step in the
    tx saga before invoking MPC Signing.
- **Emits (async):**
  - `audit-event-log` — signed `PolicyDecisionRecord` event for every evaluation,
    including denies and manual_review outcomes.
- **Depends on:**
  - OPA bundle service for hot-reloaded rule bundles.

### Decision audit

- Each decision record is signed by the evaluating node's service identity
  (Ed25519 over canonical-JSON payload + policy version hash).
- Record persisted to `policy_decisions` in the same DB transaction as the
  response write to the caller.
- Record also published to the audit-event-log bus for downstream consumers
  (Reconciliation, Audit service, compliance reporting).
- Decisions are replay-safe: re-evaluating the same payload against the same
  policy version reproduces the same outcome and the same record hash.

## Dependencies

| Dependency | Purpose |
|---|---|
| **PostgreSQL** | Durable store for policies, versions, decisions, whitelist, review queue. |
| **Redis** | Velocity counters (rolling windows), idempotency keys, hot counter cache. |
| **OPA bundle service** | Source of hot-reloadable Rego policy bundles. |
| **audit-event-log** | Sink for signed decision records (compliance + forensics). |

Indirect upstream services whose outputs are required as inputs on each
evaluate call: **Onboarding / KYC**, **AML / KYT Screening**, **Fraud Detection**.

## Configuration

Environment variables:

| Variable | Description | Default |
|---|---|---|
| `PORT` | REST API listen port. | `8080` |
| `GRPC_PORT` | gRPC listen port. | `9090` |
| `DB_URL` | PostgreSQL DSN (`postgres://...`). | — |
| `REDIS_URL` | Redis endpoint (`redis://...`). | — |
| `OPA_BUNDLE_URL` | OPA bundle service base URL for hot reload. | — |
| `OPA_BUNDLE_POLL_INTERVAL` | Poll interval for bundle hot-reload (seconds). | `30` |
| `POLICY_HOT_RELOAD_INTERVAL` | Coarse policy reload cadence (seconds). | `30` |
| `DEFAULT_DAILY_CAP_USD` | Default per-user daily cap when tier rule absent. | `10000` |
| `DEFAULT_TX_CAP_USD` | Default per-tx cap when asset/rail rule absent. | `2500` |
| `MANUAL_REVIEW_THRESHOLD_USD` | USD amount above which tx routes to manual review. | `5000` |
| `HIGH_VALUE_2FA_THRESHOLD_USD` | USD amount above which 2FA is required. | `1000` |
| `DENY_FRAUD_SCORE_THRESHOLD` | Fraud score at or above which tx is denied. | `0.8` |
| `MANUAL_REVIEW_FRAUD_SCORE_THRESHOLD` | Fraud score at or above which tx routes to manual review. | `0.5` |
| `VELOCITY_WINDOW_MIN_SEC` | Per-minute velocity window length (seconds). | `60` |
| `VELOCITY_WINDOW_HOUR_SEC` | Per-hour velocity window length (seconds). | `3600` |
| `VELOCITY_WINDOW_DAY_SEC` | Per-day velocity window length (seconds). | `86400` |
| `AUDIT_EVENT_LOG_URL` | Endpoint for the audit-event-log sink. | — |
| `MTLS_CA_CERT` | Path to CA cert for service-to-service mTLS. | — |
| `SERVICE_IDENTITY_KEY` | Path to signing key for decision record signatures. | — |
| `LOG_LEVEL` | Structured log level (`debug|info|warn|error`). | `info` |

## Local Development

```bash
# Build
go build -o bin/policy-engine ./cmd/policy-engine

# Run (requires PostgreSQL + Redis + OPA bundle service reachable)
go run ./cmd/policy-engine

# Run tests
go test ./... -race -cover

# Lint
golangci-lint run ./...

# Rego policy tests
opa test ./policies/...

# Generate gRPC stubs
buf generate ./proto
```
