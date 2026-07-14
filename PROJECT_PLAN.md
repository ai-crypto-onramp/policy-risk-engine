# Project Plan — Policy / Risk Engine

This plan decomposes the Policy / Risk Engine described in `README.md` into a
sequence of incremental, independently verifiable implementation stages. Each
stage ends with a shippable slice and explicit acceptance criteria. Stages are
ordered so that foundational layers (DB schema, OPA integration) land first,
followed by the decision path, then supporting features (whitelisting, review
queue, hot-reload, audit), and finally hardening (tests, coverage, Docker).

## Stage 1 — Database Schema & Migrations

**Goal:** Establish the PostgreSQL persistence layer with all durable tables and
migration tooling required by downstream stages.

**Tasks:**
- [x] Choose a migration tool (e.g. `golang-migrate` or `goose`) and add it to the Makefile.
- [x] Create `migrations/` directory with ordered up/down SQL files.
- [x] Define `policies` table (id, scope, active_version FK, created_at).
- [x] Define `policy_versions` table (id, policy_id, version, rego_hash, rego_source, created_at, created_by).
- [x] Define `policy_decisions` append-only audit table (decision_id, policy_version, request_hash, decision, reasons[], applied_rules[], score, signature, created_at).
- [x] Define `whitelist_addresses` table (user_id, chain, address, label, verified_at, status).
- [x] Define `review_queue` table (decision_id, tx_id, status, assigned_to, resolved_at, resolution).
- [x] Add DB connection bootstrap in `cmd/policy-engine` using `DB_URL`.
- [x] Add a `make migrate-up` / `make migrate-down` target and a docker-compose snippet for local Postgres.

**Acceptance criteria:**
- `make migrate-up` brings a fresh Postgres to the full schema; `make migrate-down` reverses it cleanly.
- All five tables exist with correct columns, types, foreign keys, and indexes on lookup paths (`policy_versions.version`, `whitelist_addresses(user_id, chain, address)`, `policy_decisions(decision_id)`, `review_queue(status)`).
- App boots, connects to Postgres via `DB_URL`, and logs a healthy `db ready` line.

## Stage 2 — OPA Integration & Bundle Loading

**Goal:** Embed OPA as an in-process library, load Rego policies from a bundle, and
expose a minimal internal `Evaluate(input) → result` entry point.

**Tasks:**
- [x] Add `github.com/open-policy-agent/opa` dependency and pin version.
- [x] Implement a `policy/engine` package wrapping `opa.Context` with a swappable decision engine.
- [x] Support loading a bundle from disk (`policies/`) and from `OPA_BUNDLE_URL` (bundle service).
- [x] Compute and store `rego_hash` (SHA-256 of canonical Rego source) per bundle.
- [x] Seed `policies/decisions.rego` and `policies/caps.yaml` from README examples.
- [x] Add `OPA_BUNDLE_POLL_INTERVAL` polling loop that downloads and stages a new bundle without activating it.
- [x] Unit test: load a known Rego bundle and assert deterministic `allow` / `manual_review` outcomes for fixture inputs.

**Acceptance criteria:**
- `go test ./policy/engine/...` loads the seed bundle and returns expected decisions for the README example inputs.
- Bundle hash is deterministic and persisted in `policy_versions.rego_hash`.
- Polling loop downloads a new bundle and logs `bundle staged v<X>` without crashing on transient fetch errors.

## Stage 3 — Evaluate Endpoint (REST + gRPC)

**Goal:** Expose `POST /v1/policy/evaluate` (REST) and gRPC `Evaluate` returning the
documented request/response contract, backed by the OPA engine from Stage 2.

**Tasks:**
- [x] Define `proto/policy/v1/policy.proto` with `EvaluateRequest` / `EvaluateResponse`.
- [x] Generate gRPC stubs via `buf generate ./proto` and commit generated code.
- [x] Implement REST handler with the exact JSON contract from README (decision, reasons, applied_rules, policy_version, score, decision_id).
- [x] Implement gRPC server mirroring the same logic.
- [x] Generate `decision_id` as `dec_<ULID>` and stamp the active `policy_version` on every response.
- [x] Wire mTLS for gRPC (`MTLS_CA_CERT`) and scope-checked bearer auth for REST admin paths.
- [x] Add request validation (required fields, amount > 0, currency in allowlist).
- [x] Add structured logging + Prometheus metrics for decision counts by outcome and latency histogram.

**Acceptance criteria:**
- `curl POST /v1/policy/evaluate` with the README request body returns the README response shape with a populated `decision_id` and `policy_version`.
- gRPC client can call `Evaluate` and receive the same decision as REST for identical inputs.
- Invalid requests return `400` with a structured error body; mTLS absent returns `UNAVAILABLE`.

## Stage 4 — Velocity Counters (Redis Rolling Windows)

**Goal:** Enforce per-minute / per-hour / per-day velocity limits using Redis
atomic counters with TTLs equal to the window length, and feed results into the
OPA decision input.

**Tasks:**
- [x] Add a Redis client wired from `REDIS_URL` with health check.
- [x] Implement `vel:{user_id}:{window}` counters using atomic `INCR` + `EXPIRE`.
- [x] Support optional per-asset / per-rail buckets `vel:{user_id}:{asset}:{window}`.
- [x] Read window lengths from `VELOCITY_WINDOW_MIN_SEC` / `_HOUR_SEC` / `_DAY_SEC`.
- [x] Expose a `Counter.Increment` / `Counter.Rollback` API for the compensating decrement path.
- [x] Inject velocity counters into the OPA input document under `input.velocity`.
- [x] Unit + integration tests with a real Redis (testcontainers or miniredis).

**Acceptance criteria:**
- After N evaluates within 60s, the per-minute counter equals N and `EXPIRE` is set to `VELOCITY_WINDOW_MIN_SEC`.
- A tx exceeding the daily cap is denied with reason `velocity_daily_exceeded`.
- Rollback decrements the counter atomically; concurrent increments + rollback do not produce negative counters.

## Stage 5 — Per-Tx Caps & Tier Overrides

**Goal:** Enforce per-transaction USD caps by user tier, asset, and fiat rail, with
FX conversion to USD-equivalent at evaluation time, and near-cap routing to
manual review.

**Tasks:**
- [x] Load tier / asset / rail cap rules from `policies/caps.yaml` into OPA data documents.
- [x] Add FX conversion step using latest quote snapshot (input `fx_rate_to_usd` or fetched externally).
- [x] Implement `on_exceed: deny` and `on_exceed: manual_review` branches.
- [x] Apply per-tier overrides resolved by Rego data keyed on `user_tier`.
- [x] Add `DEFAULT_DAILY_CAP_USD` and `DEFAULT_TX_CAP_USD` fallbacks when no rule matches.
- [x] Add near-cap threshold (e.g. 90% of cap) routing to `manual_review`.
- [x] Tests: each tier × asset × rail combination produces the expected decision and `applied_rules` entry.

**Acceptance criteria:**
- A `tier_2` user attempting a $30k card tx is denied with `applied_rules` containing `cap.daily.tier_2`.
- A tx at 95% of its cap routes to `manual_review`.
- Missing rule falls back to `DEFAULT_TX_CAP_USD` and the decision is deterministic.

## Stage 6 — Whitelisting & Source Auth

**Goal:** Enforce destination address whitelisting (with verification flow) and
source authentication (valid session + 2FA for high-value tx) inside the
decision path and admin API.

**Tasks:**
- [x] Implement `POST /v1/policy/whitelist` and `GET /v1/policy/whitelist/:user_id` REST handlers.
- [x] Implement whitelist verification flow (status transitions: `pending` → `verified` after micro-transfer / signed message confirmation).
- [x] Inject whitelist into OPA input as `data.whitelist[user_id]` map.
- [x] Deny non-whitelisted destinations unless a one-time override policy routes to `manual_review`.
- [x] Validate JWT session from Identity & Auth on the REST path; enforce scope checks for admin endpoints.
- [x] Require `2fa_passed=true` when `amount_usd >= HIGH_VALUE_2FA_THRESHOLD_USD`.
- [x] Tests: whitelisted / non-whitelisted / unverified / override paths; 2FA required and bypassed cases.

**Acceptance criteria:**
- A tx to an unverified address returns `deny` with reason `dest_not_whitelisted`.
- A high-value tx without `2fa_passed` is denied with reason `2fa_required`.
- A verified address appears in `GET /v1/policy/whitelist/:user_id` with `status: verified`.

## Stage 7 — Manual Review Queue

**Goal:** Park `manual_review` decisions in `review_queue` and let reviewers resolve
them into `allow` / `deny`, emitting a follow-up audit record.

**Tasks:**
- [x] On `manual_review`, insert a `review_queue` row with `status=pending`, `tx_id`, `decision_id`.
- [x] Implement `POST /v1/policy/review/:decision_id/resolve` (reviewer auth scope required).
- [x] On resolve, update `review_queue.status=resolved`, set `resolution`, `resolved_at`, `assigned_to`.
- [x] Emit a follow-up signed `PolicyDecisionRecord` with the final decision.
- [x] Notify the Transaction Orchestrator of resolution (webhook or poll endpoint) so the saga can resume.
- [x] Tests: pending → resolved lifecycle; unauthorized reviewer rejected; double-resolve rejected.

**Acceptance criteria:**
- A `manual_review` decision creates a `review_queue` row visible to assigned reviewers.
- Resolution produces a new `policy_decisions` row linked to the original `decision_id`.
- Re-resolving an already-resolved decision returns `409 Conflict`.

## Stage 8 — Hot-Reload & Policy Versioning

**Goal:** Make rule bundles immutable and versioned, swap the active version
atomically via hot-reload, and keep previous versions queryable for replay.

**Tasks:**
- [x] Implement `GET /v1/policy/rules`, `POST /v1/policy/rules` (with `activate=true|false`), `GET /v1/policy/rules/:version`.
- [x] On publish: create a new immutable `policy_versions` row; never mutate existing rows.
- [x] On activate: update `policies.active_version` in a single transaction.
- [x] Hot-reload: poll OPA bundle service on `POLICY_HOT_RELOAD_INTERVAL`, stage, validate hash, then atomically swap the in-memory decision engine.
- [x] Keep a versioned history of loaded engines for audit replay.
- [x] Tests: publish → activate → evaluate → rollback to previous version reproduces prior decision.

**Acceptance criteria:**
- Publishing a bundle creates an immutable `policy_versions` row; re-publishing the same source returns the existing version.
- Hot-reload swaps the active engine without dropping in-flight evaluate requests.
- Re-evaluating a past payload against the version active at its original time reproduces the same decision.

## Stage 9 — Audit Emission

**Goal:** Produce a signed decision record for every evaluation, persist it
durably in the same transaction as the response, and emit it to the
audit-event-log.

**Tasks:**
- [x] Load the service identity signing key from `SERVICE_IDENTITY_KEY` (Ed25519).
- [x] Compute canonical-JSON payload + policy version hash; sign with Ed25519.
- [x] Persist the signed record to `policy_decisions` in the same DB transaction as the response write.
- [x] Publish `PolicyDecisionRecord` event to `audit-event-log` via `AUDIT_EVENT_LOG_URL` (at-least-once with idempotency key = `decision_id`).
- [x] Ensure replay-safety: re-evaluating the same payload against the same version reproduces the same record hash.
- [x] Tests: signing determinism, audit emission on deny/manual_review/allow, DB-transaction atomicity (rollback emits nothing).

**Acceptance criteria:**
- 100% of evaluate calls produce a `policy_decisions` row with a valid Ed25519 signature verifiable offline.
- If the DB transaction rolls back, no audit event is published.
- Replaying a stored request against its original policy version reproduces an identical decision record hash.

## Stage 10 — Tests, Coverage & Docker

**Goal:** Harden the service for production: comprehensive test suite, coverage
gating, Rego policy tests, and a reproducible container image.

**Tasks:**
- [x] Add `opa test ./policies/...` to CI for Rego unit tests.
- [x] Add comprehensive unit test coverage across Go packages.
- [x] Add integration tests (testcontainers Postgres + Redis) for the full evaluate path.
- [x] Add golangci-lint to CI and resolve findings.
- [x] Finalize `Dockerfile` (multi-stage, distroless or scratch runtime, non-root user).
- [x] Add `docker-compose.yml` for local Postgres + Redis + OPA bundle mock + the service.
- [x] Add load test harness asserting p99 < 50ms on the gRPC evaluate path.
- [x] Update README with the finalized dev workflow.

**Acceptance criteria:**
- `go test ./... -race -cover` passes and reports it to Codecov.
- `docker compose up` brings a healthy service reachable on `:8080` (REST) and `:9090` (gRPC).
- Load test confirms p99 evaluate latency < 50ms with the in-process OPA + Redis path.