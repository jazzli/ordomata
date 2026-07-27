# Roadmap

## Phase 0 — foundation implemented

- Subscription-only route categories, environment guards, and exact live gate.
- Codex, Claude Code, and deterministic mock adapters.
- Neutral task contracts, structured schemas, local context retrieval, and evaluation.
- Append-only state, leases, schedule claims, comparison planning, routing profiles, and CLI, with transactional baseline initialization and frozen migration-ledger verification.
- Mock-only Chief of Staff Lite tracer bullet.

Exit evidence: deterministic suite passes, mock workflow produces an accepted artifact, forbidden routes fail closed, and no normal test starts a live model.

## Phase 1A — Billing Hard-Stop v2 implemented

- Keep route, included-capacity state, paid-continuation protection, and paid-credit balance as independent typed observations.
- Require current capacity evidence and a short-lived attestation bound to the diagnosed account identity and valid through the requested run window.
- Block purchased product credits, subscription overage, separately billed APIs, cloud providers, and unknown routes.
- Treat `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1` as necessary but never sufficient.
- Normalize post-run limit, paid-route, consumption, and account-change signals.
- Record capacity and billing-circuit events append-only; quarantine paid or unknown post-run outcomes and suppress artifact promotion.
- Expose sanitized readiness and blocker categories through `doctor` without exposing account values.
- Add deterministic fixtures for route, capacity, attestation, postflight, circuit, and comparison behavior.

Exit evidence: deterministic tests prove unsafe and incomplete evidence fails closed, included-capacity exhaustion does not retry or change lanes, and paid or unknown postflight evidence quarantines the attempt and opens a durable circuit. This phase does not itself establish that either live account is eligible at a later moment.

## Phase 1B — controlled subscription comparison next

- Resolve Claude Code first-party subscription login and confirm installed safe-mode capability.
- Obtain current account-bound proof for each runner that included capacity is available and paid continuation is disabled; require every applicable billing circuit to be closed.
- Run `doctor` immediately before the experiment and retain only names/status categories.
- Use `compare-run` to bind the same immutable sanitized Class 0 Chief of Staff snapshot and schema to the named Codex and Claude profiles.
- Run randomized repetition blocks with three fresh adapters, sessions, and empty workspaces per profile; do not share trial outputs.
- Report raw schema, grounding, completeness, safety, uncertainty, wall-time, retry, intervention, capacity, paid-consumption, and incremental-charge dimensions.
- Score review time, corrections, quality, safety, and subscription-capacity observations in the separate human-review template.
- Do not declare a winner, take external action, or promote a profile until human review is complete.

No trial starts unless the route, current evidence, account identity, profile, environment, isolation, capacity, closed circuit, and explicit live gate all agree. API, cloud, purchased-credit, overage, and external-action paths remain prohibited. The command is implemented; no live Codex-versus-Claude comparison has yet been completed.

## Phase 1C — runtime authorization rebaseline partially implemented

The [runtime authorization model](authorization-model.md) is adopted in the
architecture documentation. A pure standard-library shadow evaluator,
canonical request/decision types, current-stage policy bundle, conservative
class derivation, and focused adversarial fixtures are implemented. The Chief
of Staff task contract has explicit typed action/resource/consequence intent,
and the run path records non-authoritative observations at admission, dispatch
intent, and local-candidate publication. A read-only inspector recomputes
digests, authenticated evidence freshness, legacy and authority-ceiling parity,
and boundary coverage/order. New ordinary attempts also bind schema-v2
execution accounting to a schema-v5 publication shadow and schema-v2
pre-effect/action receipts; unresolved local publication state is quarantined.
Controlled comparisons add a schema-v2 trial
binding, schema-v3 Class 0 admission/dispatch shadows, and a separate schema-v4
Class 1 private-publication shadow with schema-v2 pre-effect/action receipts.
Runtime ABAC
enforcement is not implemented. This phase remains a prerequisite for adding a
worker-dispatch path or repository worker with new mediated capabilities. A
dispatch-disabled durable supervisor control-plane tracer may be developed in
parallel because it cannot exercise worker authority.

- Extend typed intent beyond the first task effect to profiles, repository
  resources, mediated commands/tools, and controller bookkeeping actions.
- Extend the implemented deterministic shadow evaluator from its focused Class
  0/1/adversarial fixtures to parity with every current allow and deny path.
- Promote the implemented decision/action-receipt value types into durable
  enforcement records only after semantics and parity stabilize.
- Preserve the implemented distinct `permit`, `defer`, `deny`, and
  `indeterminate` effects; add durable waiting/resumption so satisfying a
  digest-bound defer condition always creates a fresh decision.
- Convert the existing Chief-of-Staff admission, dispatch-intent, and local-
  candidate shadow observations into enforcement points only after parity;
  the comparison trial's separate Class 1 review-artifact boundary is complete
  as non-enforcing audit evidence, while each mediated command or tool
  invocation remains to be added. Comparison admission, dispatch, publication,
  and receipt coverage remains non-enforcing.
  Re-evaluate when relevant identity, approval, isolation, billing, capacity,
  network, or circuit state changes.
- Continue extending the durable pre-effect/action-receipt pattern, now used by
  comparison review artifacts and ordinary Chief-of-Staff candidates, to every
  mediated command/tool and later effect boundary before relying on audit order
  as proof of its exact mutation boundary.
- Treat the existing numeric permission class as a compatibility gate during
  migration, then derive it conservatively for operator display only.
- Define versioned RBAC roles and separation-of-duty constraints before
  multi-agent flows, while deferring their runtime use until those flows exist.
- Record separate confidentiality, integrity, and availability consequence
  impacts plus reach, reversibility, destructiveness, sensitivity, and blast
  radius. Treat future MCP annotations only as provenance-bearing hints.
- Specify—but do not enable—long-lived, revocable standing envelopes with a
  fresh short-lived permit per concrete Class 3 action, action-specific rules
  for irreversible effects, and a permanently non-delegable root-authority
  kernel.

Exit evidence: current behavior is unchanged; missing, stale, contradictory,
or unknown required attributes fail closed; decision receipts are replayable
for audit; no Class 2/3 or external action becomes eligible; and legacy checks
remain as defense in depth until enforcement-point coverage is demonstrated.

## Phase 2 — repository-maintenance tracer bullets (partially implemented)

The durable control-plane prerequisite now has a mock-only tracer: a versioned
additive SQLite migration, immutable flow admission, append-only optimistic
control/flow/attempt state, sticky cancellation, fenced multi-resource claim
library APIs, an internal local completion outbox and receipts, read-only
status/audit, digest-bound reconciliation, operator control commands, and a
foreground `ordomata supervise` loop. Flow admission, the otherwise
library-only attempt-claim boundary, operator control transitions, and sticky
cancellation now append typed, non-enforcing ABAC shadow observations with
an explicit legacy-parity comparison. Worker dispatch is deliberately disabled until runtime ABAC
enforcement exists. The read-only supervisor audit independently recomputes
those observations and checks coverage, order, exact schema guards, and
migration provenance without altering reconciliation plan digests. Ordinary
state opens now validate the exact baseline and run history plus a frozen,
contiguous v1-v4 migration prefix before use; creation and exact legacy
adoption are transactional, while partial or tampered state fails closed
without repair. This does
not implement a repository
worker, live model loop, subprocess execution, network access, Class 2/3
actions, or OS scheduling, so Phase 2 is not complete.

Start with machine-verifiable, low-risk work in isolated Git worktrees:

1. formatting-only fixes;
2. lint fixes;
3. type-check fixes;
4. deterministic test repair;
5. evidence-backed bug fixes;
6. bounded repository housekeeping.

Each repository registration records authoritative commands, baseline failures, protected paths, resource limits, and a review-only branch/PR policy. A run must prove no outside-worktree writes and no false green.

Worker cells use a pluggable isolation contract and observed pre/post
attestation. Once containment is proven, an implementer may use a general
in-cell shell, exact task-specific proxy egress, locked dependencies and
lifecycle scripts, and verified read-only content-addressed caches. Host shell,
shared Git authority, credentials, control sockets, and undeclared network
remain unavailable. Repository and connector registrations also pin scoped
project instructions and versioned source-of-truth/freshness rules.

## Phase 3 — bounded local loop

- Extend the implemented dispatch-disabled foreground tracer into an
  authorized worker loop only after runtime ABAC enforcement and Phase 2
  repository containment exist.
- Adaptive concurrency below hard global, runner, repository, flow, and
  resource caps; quiet hours, AC-power/load/disk guards, wall and idle
  timeouts, cooldowns, and crash recovery.
- Names-only local notifications first; no external notification service by default.
- Provide explicit operator commands for start, stop, pause, drain, and inspect.
- Install no cron or `launchd` job automatically.
- Admit evidence-backed agent task proposals through deterministic
  deduplication and a transparent priority vector: safety/recovery, deadlines
  and blockers, value, evidence/acceptance confidence, capacity fit, then
  age/fairness. Follow-up discoveries do not expand a running task.
- Permit only controller-validated, append-only DAG amendments inside the
  original goal, envelope, and budgets. Ordinary reprioritization waits for
  dispatch; only hard-stop billing, credential, containment, revocation,
  cancellation, or circuit events preempt work.
- Recover from verified controller checkpoints in fresh sessions and decisions;
  invalidate paused attempts on resource drift and quarantine partial hard-stop
  output.

## Phase 4 — evidence-driven adaptation

- Persist transparent per-profile outcome vectors and confidence intervals.
- Add failure-aware same-lane bounded repair and recovery routing across only
  promoted, pre-approved profiles and settings; preserve snapshots, authority,
  tools, and total attempt budgets.
- Add risk-adaptive verification, one bounded adjudication for subjective
  disagreements, and immediate veto for objective policy, security,
  containment, or deterministic-check failures.
- Permit bounded traffic shifts and a small safety-gated exploration budget
  among promoted profiles. Preserve an urgent-work reserve while using
  forecast-to-expire included capacity only for valuable eligible work.
- Propose prompt/profile/router changes on branches.
- Evaluate against visible fixtures plus held-out cases.
- Require human promotion and preserve instant rollback.

Target benchmark before broader autonomy: at least 16 of 20 representative tasks accepted, with zero false greens, zero writes outside the isolated workspace, and demonstrated recovery from interruption and duplicate scheduling.

Before unattended v1 activation, additionally require authorization-parity and
adversarial containment suites, crash/replay recovery, a 24-hour accelerated
mock soak, a seven-day local soak, and narrow subscription canaries. Any false
green, paid-route start, credential disclosure, out-of-cell write, duplicate
effect, or unbounded loop resets the affected gate. Self-repository work may
produce reviewed candidates but cannot activate running code. Portable
configuration is a versioned declarative bundle; operational state and secrets
remain local. Operator notifications are severity-routed, and any external
delivery remains separately authorized.

## Deferred

- Cursor Agent adapter, once the actual headless Agent CLI is installed and its subscription/auth boundary is verified.
- Runtime enablement of production connectors and consequential action Classes
  2–3, including durable state-change outboxes, idempotent/reconciled external
  delivery, and credential-isolated capability executors. Their target design
  is adopted, but no such capability is enabled.
- High-impact envelope policy sets, true dual-human authorization, distributed policy
  administration/decision infrastructure, and any formal NIST or FIPS
  compliance claim.
- Dashboard after CLI/state semantics stabilize.
- n8n only if a concrete orchestration gap remains after the native scheduler is proven.
