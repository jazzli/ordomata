# Implementation status

Product identity: **Ordomata** — a local control plane for governed autonomous
work. The distribution, Python package, and CLI are `ordomata`; `.ordomata/` is
the canonical state root. A sole `.agentops/` directory and the former live-
gate variable remain fail-closed compatibility inputs for pre-rename state.

## Repository context

The repository was an initialized but otherwise empty Git repository: no files, commits, remote, instructions, architecture, implementation, database, or tests existed.

The implementation therefore adds the first vertical slice directly to the existing root. It does not create a nested repository or parallel project.

## Preserved decisions

- Local, single-operator execution.
- Python 3.12+ with `uv` compatibility.
- Deterministic `run-once` core with optional local scheduling.
- SQLite as local state and audit storage.
- Provider-neutral adapters, with Codex first and Claude second.
- Work remains local or becomes a reviewable draft; no automatic merge or deployment.
- Risk-tiered verification; unsupported retry/repair declarations currently fail closed.
- Versioned model/settings profiles and evidence-backed routing.
- Self-improvement only through benchmarked, human-promoted proposals.

## Scope reconciliation

Earlier design discussion selected machine-verifiable repository maintenance as the first slice. Supplemental requirements later name Chief of Staff Lite as the first practical workflow. The conservative integration is to implement Chief of Staff Lite as the first controlled end-to-end fixture while retaining repository maintenance as the next workflow family.

## Current-stage boundaries

- Only work represented by the current Permission Classes 0 and 1 is eligible.
  The runtime still enforces that interim numeric representation; the adopted
  target will derive the same summaries from an authoritative ABAC decision.
- No production inbox, calendar, Drive, Slack, or similar connectors.
- No n8n dependency.
- No purchased-credit, subscription-overage, AI API SDK, cloud-model, or metered fallback.
- No recurring schedule installation.
- No supervisor worker dispatch: the implemented foreground loop is a
  mock-only control-plane tracer and cannot claim or execute queued work.
- No live harness comparison in normal tests or setup; no live Codex-versus-Claude comparison has been completed.
- No Git remote mutation.

Detailed component and verification status is updated in the session completion report and README.

## Authorization status

**Implemented foundations and a non-enforcing shadow slice:** deterministic controller-owned
fail-closed gates; the current Class 0/1 approval ceiling; role, task,
capability, route, billing, identity, capacity, environment, isolation, and
circuit checks; narrow harness configurations; and append-only run evidence.
These checks are distributed, and the current `ApprovalPolicy` decides from
`PermissionClass`. Standard-library ABAC request/decision/action-receipt value
types, a deny-by-default current-stage shadow evaluator, conservative class
derivation, and focused adversarial tests now exist. The task schema and Chief
of Staff contract now carry optional typed action/resource/consequence intent;
absence remains explicit and the bridge records a legacy-class fallback.
Chief of Staff appends exact, secret-free observations at admission, dispatch
intent, and local-candidate publication, with policy/evidence/intent digests,
fixed reasons, obligations, legacy-result parity, and independent derived-class
authority-ceiling parity. Publication uses a controller-owned local-create
projection that inherits task protection, sensitivity, and confidentiality/
integrity/availability impact, rather than relabeling a Class 0 read intent as
a write or high-impact content as low. Mock
observations permit; a
live runner's pre-dispatch circuit/network facts remain unknown and therefore
stay truthfully indeterminate. Known shadow deny, defer, indeterminate, build,
evaluation, or append failures cannot change the legacy run or candidate
outcome. `auth-inspect` opens state read-only, emits a strict redacted
projection, recomputes legacy executability from persisted run state, validates
intent lineage and evidence authenticity/freshness, independently derives the
class from validated request attributes, and detects class-ceiling mismatches
plus missing, duplicate, swapped, or controller-event-misordered boundaries
without creating state.
The inspector can prove ordering against persisted billing, running,
runner-event, accounting, and terminal markers. Exact publication-before-first-
filesystem-mutation placement is covered by orchestrator call-order tests but
does not yet have a separate durable staging marker.

**Adopted architecture and remaining runtime migration:** the
[runtime authorization model](authorization-model.md) defines versioned
subject/action/resource/environment/consequence requests, default-deny
decisions with distinct `permit`, `defer`, `deny`, and `indeterminate`
effects, policy and evidence digests, obligations, continuous enforcement,
RBAC role constraints, adapted confidentiality/integrity/availability impact
labels, untrusted MCP claim handling, and conservatively derived Class 0-3
summaries. There is still no enforcing central PDP, RBAC separation-of-duty
enforcement, approval resumption, mediated command/tool coverage, or persisted
runtime action receipt. The controlled comparison path also lacks a durable
per-trial event stream and therefore has no shadow PEP coverage. Its reports
now mark that limit with
`authorization_shadow_coverage=deferred_not_covered`. Enforcement follows only
after broader parity evidence.

**Adopted target design, not implemented:** revocable standing authorization
envelopes and fresh per-action permits; permissive but exactly bounded Class 3
and irreversible-action policy; a non-delegable root kernel; adaptive
verification, bounded adjudication/repair, recovery routing, promoted-profile
learning/exploration, capacity-aware admission, agent task proposals,
transparent backlog priority, hard-stop/recovery rules, durable consequential-
action outboxes and credential executors, tainted-data and memory isolation,
ephemeral digest-bound context, source-of-truth rules, attested pluggable
worker cells, bounded DAG amendments, adaptive concurrency, candidate-only
self-code changes, severity-routed attention, portable declarative bundles,
and staged unattended-release gates. These decisions constrain later phases;
they add no current command, connector, shell, network, or external authority.

**Deferred:** Class 2/3 runtime enablement, standing-envelope enforcement,
external connectors and writes, durable effect executors, high-impact policy
sets, true dual-human authorization, distributed policy administration/
decision infrastructure, third-party policy engines, and formal standards-
compliance claims.

## Durable supervisor status

**Partially implemented Phase 2 control-plane tracer:** a versioned additive
SQLite migration extends the existing state database with immutable mock-only
flow admission; append-only optimistic control, flow, and attempt revisions;
sticky cancellation; fenced multi-resource claim library APIs; and an internal
local completion outbox with idempotency keys and append-only receipts.
Startup verifies canonical baseline, migration-ledger, and supervisor schema
objects, including non-prefixed triggers targeting owned tables, before use.
Read-only status and audit do not create absent state. Reconciliation is
preview-first and apply requires the exact current plan digest. The
`ordomata supervisor` command group exposes enqueue and explicit control,
cancellation, inspection, recovery, and local completion-receipt operations;
`ordomata supervise` runs the fenced loop only in the foreground.

This is not a completed supervisor. The foreground loop deliberately never
calls the claim library or a runner because enforcing runtime ABAC remains a
prerequisite. It starts no live model, worker subprocess, network action,
repository worker, Class 2/3 action, or OS schedule. Queue execution, worker
cells, runtime authorization enforcement, and soak evidence remain planned.

## Implemented vertical slice

- `ordomata doctor`: value-free, non-model diagnostics for Codex, Claude, mock, paths, SQLite/FTS5, route, current capacity, paid-continuation protection, account-identity verification, attestation status, and fixed blocker categories.
- `ordomata billing-attest --runner codex|claude`: TTY-only, exact-confirmation refresh of short-lived account-bound evidence after independent machine inspection; private atomic storage contains no raw identity, numeric balance, token, or diagnostic free text.
- `ordomata profiles` and `ordomata route`: versioned execution profiles, exact billing lanes, capability filters, and auditable ranking.
- `ordomata task-validate` and `context-inspect`: strict contract/schema loading and immutable local context construction.
- `ordomata auth-inspect`: source-preserving, SQLite read-only inspection of
  authorization shadow integrity, authenticated freshness, legacy and
  authority-ceiling parity, and expected Chief-of-Staff boundary
  coverage/order.
- `ordomata demo`: end-to-end deterministic Chief of Staff Lite run with append-only state and a validated local artifact.
- Billing Hard-Stop v2: independent route/capacity/protection/balance axes; strict account-bound, short-lived attestations; a necessary-but-insufficient live gate; and explicit rejection of credits, overage, APIs, cloud routes, and unknown evidence.
- Post-run billing disposition: normalized capacity/paid/account-change evidence, typed paid-capacity and incremental-AI-charge accounting, quarantine before promotion, durable append-only capacity state, atomic capacity persistence before lease release, restart-safe capacity blocking, and account/profile circuit breakers.
- `ordomata run --profile ...`: explicit live-adapter entry point guarded by diagnostics, current evidence, environment/profile/isolation checks, a closed durable circuit, and the exact live gate.
- `ordomata compare-plan`: identical-snapshot, repeated, block-randomized, fresh-session plan creation without execution.
- `ordomata compare-run`: preflight-all controlled execution for explicit named profiles using one immutable sanitized Class 0 snapshot, fresh adapters/sessions/empty workspaces, randomized repetition blocks, private per-trial review artifacts, raw reports, and a separate human-review template. It performs no ranking or promotion and retains partial results after a stop condition.
- `ordomata schedule-inspect`: non-mutating run-once schedule inspection; atomic claims and leases are available as library primitives.
- `ordomata supervisor ...`: mock-only immutable admission; append-only
  start/pause/resume/drain/stop and sticky cancel intent; read-only status,
  audit, and completion inspection; digest-bound reconcile; and local
  completion acknowledgement.
- `ordomata supervise`: explicit foreground control-loop ticks with a fenced
  singleton lease and worker dispatch hard-disabled.

The deterministic suite is the verification source of truth; documentation
intentionally does not pin a count that becomes stale as coverage grows. A
dispatch-disabled foreground control loop is present, but no worker loop,
scheduler installation, live comparison result, connector, or repository-
maintenance executor has been enabled.

## Live-readiness status

Implemented controls do not make an account eligible by themselves. A live attempt remains blocked unless `doctor` can establish, for the exact runner/account/profile and requested duration, first-party subscription identity, available included capacity, the provider-specific paid-continuation protection, a valid matching attestation, a sanitized environment, safe capabilities/isolation, a closed billing circuit, and the explicit live gate. Subscription login alone is not sufficient.

The controlled comparison machinery has been implemented and tested with deterministic fixtures. No claim is made that the planned three-runs-per-profile live experiment has run, passed automated checks, received human scores, or produced a winner.
