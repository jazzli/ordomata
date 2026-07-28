# Model and harness routing

Routing is a deterministic control-plane concern. It filters and ranks eligible
profiles; it never grants authority. Model output cannot select its own billing
route, widen permissions, modify profile policy, or promote a new profile. The
target runtime requires a fresh decision under the
[authorization model](authorization-model.md) at each enforcement point.
Three narrow PEPs now apply only when routing selects the
exact controller-owned built-in mock implementation for a new ordinary Class 1
attempt: task admission, mock dispatch, and the resulting owner-private local-
candidate publication. Admission inherits the full task consequence vector
and precedes billing. All live, comparison, supervisor, general-admission, and
other dispatch/effect boundaries remain non-enforcing or disabled. Existing
Class 0/1 checks remain independent authoritative compatibility gates.
The dispatch policy remains limited to Class 0/1 requests for the exact
profile-backed controller-owned `MockRunner`; new attempts reaching it still
require the Class 1 admission permit.

## Execution profile

Each versioned profile binds:

- a first-party harness adapter;
- an optional model identifier (`null` means the harness default);
- a role such as `synthesis` or `test`;
- provider-specific settings translated through a strict allowlist;
- declared capabilities and task kinds;
- an explicit billing-route allowlist;
- typed capability/context limits and, during migration, a maximum permission
  class compatibility ceiling;
- initial quality and latency priors.

Credential, endpoint, provider, cloud-route, billing, and API-enabling settings are rejected when profiles load. Codex currently accepts only `model` and `reasoning_effort` at its adapter boundary. Claude accepts only `model`, `effort`, and `max_turns`. The mock's fixture selection is not forwarded to a process.

## Decision pipeline

```text
task features + routing lane + runtime diagnostics + profiles
  -> reject identity/confidence/route/attestation mismatches
  -> reject paid, overage, API, cloud, unknown, unavailable,
     cooling, exhausted-capacity, and open-circuit profiles
  -> reject role/task/capability/permission/context mismatches
  -> rank eligible profiles tier by tier using auditable raw metrics
  -> select one profile or block
```

No score can overcome an eligibility failure. The ranking priority among eligible profiles is:

1. **Correctness and risk:** verified success adjusted by recent failures, accepted-result rate, evidence confidence, least privilege, and task-risk fit.
2. **Included-subscription efficiency:** accepted results per observed included-capacity unit, but only when both candidates use the same runner, named quota pool, and capacity unit.
3. **Latency:** median or reviewed-prior wall time.

The ordering is lexicographic across tiers: neither efficiency nor speed can compensate for a correctness/risk disadvantage, and speed cannot compensate for an efficiency disadvantage inside a compatible quota pool. Incompatible provider quota pools—such as Codex and Claude—remain incomparable at the efficiency tier instead of being coerced to zero or given an invented exchange rate. Missing efficiency observations remain unavailable; there is no provider-independent efficiency prior. An exact tie is resolved by stable profile ID.

The dimensions remain visible; comparison reports do not collapse quality, latency, regressions, human intervention, changes, or usage into one winner score. The comparison schema has explicit nullable fields for schema validity, correctness, grounding, completeness, prioritization, actionability, safety, uncertainty handling, context size, turns, tool activity, human setup/review time, corrections, billing route, included-capacity state, paid-capacity consumption, incremental AI charge, subscription limits, and local compute. Until sufficient quality or latency observations exist, profiles use reviewed priors; efficiency remains unavailable until a compatible observation exists. Persisted outcome learning and confidence intervals are a later phase.

## Durable execution-selection evidence

Every started profile-backed Chief-of-Staff attempt persists one immutable
`task_execution_selection` event before task binding or billing preflight. The
content-addressed record includes the routing-policy identity/version,
captured evaluation time, required billing-validity horizon, exact task-feature
projection, immutable task/context/authorization refs, every canonical candidate, fixed rejection
codes, raw score dimensions, explicit observed/profile-prior/unavailable
markers, compatible-efficiency pool/unit refs, selected profile version and
configuration, and the translated runner-overrides digest.

Profile IDs are bounded controller-owned routing identifiers and are retained
so the governed stable-ID tie-break can be independently replayed. Sensitive
or mutable values are not copied into the event. Model identifiers,
profile settings, account/subscription identity, assessment evidence and
warnings, capacity pool names, environment names, and local paths are omitted
or represented by canonical digest refs. The event is linked by an ordinary
task binding—schema v6 for current exact built-in-mock attempts, frozen schema
v5 for the same three enforcement chains without self-contained lineage, schema
v4 for dispatch-plus-publication attempts, schema v3 for historical dispatch-
only mock attempts, and schema v2 for live or historical selected attempts—and
by admission/dispatch parameter digests. The selection and task-attempt binding
both use exact readback reconciliation: an unproven write blocks before the
runner executes, while a commit-then-raise write may continue only after exact
payload and event-ID readback.

Before execution, every source candidate must match the controller-loaded
profile catalog. The selected source assessment must also match a fresh runner
preflight on billing security semantics, and that fresh evidence must remain
valid through the recorded attempt horizon. A mismatch blocks before `RUNNING`
or runner execution.

For a schema-v6 built-in-mock attempt, routing evidence and the bounded
canonical task-intent lineage are first inputs to a separate exact Class 1
admission request. The controller persists its decision, rebuilds current
inputs, requires exact persisted-wrapper equality,
independently replays policy, checks freshness, and appends a durable succeeded
receipt before the admission shadow or billing. The run record and private
directories that precede it are inert scaffolding. Class 0, unsafe/high-impact,
non-permit, stale, evaluation, or evidence failures stop pre-billing. Routing
evidence is then an input to a separate exact execute request. The controller
must persist a fixed-policy decision only after exact readback of the mock
billing assessment, and the decision itself must read back exactly. Before
`RUNNING`, the PEP rebuilds current authoritative inputs, requires the resolved
task intent and digest to equal the lineage committed by the binding,
independently constructs the canonical wrapper for comparison with the retained
persisted payload, independently replays the fixed policy, checks finite
freshness, exact obligations, the Class 0/1 ceiling, and the unchanged shipped
runner class and instance boundaries. The `RUNNING` record must read back
exactly before the PEP repeats current binding, fixed-policy, freshness, and
runner-ownership checks immediately before invocation. A linked action receipt
and execution accounting must read back exactly before candidate publication;
unprovable post-effect receipt persistence quarantines the attempt. If the
result reaches candidate publication, the selection and succeeded dispatch
receipt are inputs to a second exact Class 1 request. That PEP reuses the v6
lineage, checks it against the captured shipped resolver, independently replays
the shipped evaluator and fixed policy, and exactly reads back its decision and
pre-effect record. At the final PEP it exactly rereads the binding, decision,
and pre-effect record before rebuilding the permit, capturing the action-start
time, checking freshness, and staging. Selection and lineage grant neither
permit. This slice changes no enforcing decision-event or action-receipt schema
and widens no permission.

The read-only authorization inspector validates one-and-only-one coverage for
schema-v2/v3/v4/v5/v6 attempts and independently recomputes the candidate-set
and policy digests, eligibility codes, six score dimensions, rank,
selected-candidate links, plus the applicable shadow and enforcement order.
Historical schema-v1 bindings remain readable. For v6, it validates dispatch
and publication intent from the authoritative binding lineage and never from a
shadow preimage.
Selection evidence never grants authority and never makes stale or unsafe billing
evidence eligible. The `route` command remains a read-only preview, and an
explicit profile rejected before run creation intentionally leaves no event.

The next recommended narrow slice is a versioned, privacy-bounded repository-
registration contract and read-only validator for canonical repository
identity, exact verification argv, protected and allowed paths, and resource
and isolation limits. It must not create a worktree, invoke a command or worker,
enable supervisor dispatch, or enable a live route.

## Adaptive promoted-profile routing (target)

Later outcome learning may update success, intervention, capacity-efficiency,
and latency estimates continuously and shift bounded traffic among profiles
that are already versioned, promoted, and eligible. It cannot redefine profile
settings, safety floors, lexicographic objective order, authority, or
eligibility policy. New or changed profiles remain unavailable until the
normal benchmark, review, and promotion path completes.

A small explicit exploration budget may sample under-observed promoted
profiles. Exploration is capacity-aware, starts with Class 0/1 or reversible
canaries, never bypasses a quality or safety floor, and stops on regression or
circuit evidence. The scheduler may use forecast-to-expire included capacity
for valuable queued maintenance, benchmarks, or exploration after preserving
a configurable reserve for urgent work. Synthetic work whose only purpose is
to consume allowance is ineligible. None of this automatic adaptation is
implemented yet.

## Billing lanes

Routing lanes prevent semantic fallback:

- `subscription`: only `subscription_included` synthesis profiles;
- `mock`: only deterministic `mock` test profiles;
- future local deterministic lanes may use `local_non_ai`.

Purchased product credit, subscription overage, API, cloud-provider, unknown, low-confidence, stale-evidence, missing-attestation, runner/account-identity-mismatched, exhausted-capacity, and open-circuit assessments are always ineligible. Setting the live gate cannot change that result. The live gate is necessary, never sufficient.

## Controlled exploration

`compare-plan` creates a deterministic randomized plan without execution. `compare-run` executes an explicit set of named, versioned profiles only after `doctor` and every route/profile gate pass. These explicit experiments are the current mechanism; the target exploration budget described above remains planned.

The controlled workflow fixes one immutable sanitized Class 0 task/context snapshot and output schema, randomizes profile order within each repetition block, and uses a fresh adapter, session, and empty workspace for every trial. Trial output is written to a private review artifact and is not shared with later trials. The generated report contains raw measurements and a separate human-review template; it deliberately performs no ranking, winner selection, or profile promotion. Any live comparison remains operator-gated, and none has yet been completed for Codex versus Claude in this repository.

New comparison trials bind that Class 0 execution with a schema-v2 audit
record and schema-v3 non-enforcing admission/dispatch shadows. The separate
owner-private artifact write is a controller-owned Class 1 effect with a
schema-v4 non-enforcing publication shadow and schema-v2 pre-effect/action
receipts. This audit split does not raise the runner request, profile, snapshot,
or `RunRecord` above Class 0 and grants no failover, promotion, shared, external,
Class 2, or Class 3 authority. Historical schema-v1 trials remain readable as
partial coverage with their original publication gap.

## Failover policy

Recovery and failover must remain inside the original lane, immutable resource
and context snapshot, authorization envelope, tool set, repair ceiling, and
total attempt budget. They are not yet automated. The intended sequence is:

1. retry a bounded number of times only for a classified transient failure;
2. classify correctable failure evidence and cool down the failing profile;
3. let a deterministic recovery router choose the original implementer, a
   specialist, or a stronger eligible profile;
4. escalate reasoning effort, context allowance, or turn limits only by
   choosing a versioned, pre-approved recovery profile;
5. preserve the immutable goal, resource and context snapshot, billing lane,
   authority envelope, tools, and total attempt ceiling;
6. use a fresh session and workspace, record every route switch, and require
   fresh risk-adaptive verification; and
7. retain the task as blocked or deferred if no eligible profile remains.

No failover may introduce purchased credits, overage, an API key, a cloud provider, a broader tool set, a wider action/resource/consequence envelope, a higher derived-class ceiling, or an unreviewed model setting. A failover requires a fresh authorization decision and must preserve all obligations. Included-capacity exhaustion is not a transient error and must not trigger an immediate retry or cross-lane failover.

A complete deterministic oracle may satisfy verification. When material
judgment remains, a fresh reviewer role sees frozen declared artifacts and no
hidden implementer transcript; it need not use a different provider unless the
policy identifies substantial correlated-error risk and an eligible route is
available. Objective safety or containment failures veto immediately.
Subjective disagreement receives at most one fresh adjudication; unresolved
disagreement defers. Only correctable defects receive bounded repair.
