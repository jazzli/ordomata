# Ordomata Implementation Plan

Status: proposed expansion; baseline and Billing Hard-Stop v2 implemented; profile-backed exact built-in-mock Class 1 admission, dispatch, and local-candidate publication PEPs implemented; Phase 2 durable supervisor control-plane tracer partially implemented with dispatch disabled; broader enforcement planned

Date: 2026-07-28

Scope: local, single-operator orchestration of subscription-backed coding harnesses

## Objective

Evolve the current Ordomata into a durable local "subscription worker OS": a deterministic control plane that can keep a backlog moving, dispatch bounded Codex and Claude Code workers, verify their work, recover after interruption, and improve through reviewed evidence without introducing separately billed inference.

The target is not a continuously thinking chatbot. The controller may remain available continuously, but model workers start only for eligible work and only while verified included subscription capacity is available.

The runtime remains local and single-operator. Source, tests, plans, fixtures,
and deliberately sanitized configuration may be published in the public
[`jazzli/ordomata`](https://github.com/jazzli/ordomata) repository for provenance
and portability, but GitHub is not the runtime queue or source of live state.
Private inputs, credentials, account attestations containing sensitive evidence,
local databases, logs, worktrees, and run artifacts stay local and ignored. The
system does not push or mutate the remote automatically.

```text
operator / future constrained ingress
                 |
       deterministic supervisor
 billing | policy | queue | schedules | state
                 |
          typed durable flows
                 |
        isolated worker cells
    planner | implementer | reviewer
                 |
 immutable artifacts + deterministic gates
                 |
       local reviewable candidate
```

## Current baseline

The repository already provides the foundation this plan extends:

- Python 3.12+ and standard-library-only runtime;
- strict task contracts and structured output validation;
- Codex and Claude Code runners that fail closed for purchased-credit, overage, API, cloud, contradictory, and unknown routes, plus a deterministic mock runner;
- Billing Hard-Stop v2 with independent route, capacity, paid-continuation, and paid-balance axes; short-lived account-bound attestations; post-run quarantine; and durable capacity/circuit state;
- an exact subscription live-run gate that is necessary but never sufficient, plus narrow child environments;
- versioned runner/model/role/settings profiles;
- billing-lane-aware deterministic routing;
- isolated per-run directories and read-only/tool-disabled synthesis runs;
- append-only SQLite runs, events, artifacts, schedule claims, and leases, with
  transactional baseline initialization and frozen migration-ledger integrity;
- pure, version-dispatched validation for frozen repository-registration
  schemas v1 through v4, including generated/vendor exclusions, aggregate-only
  controller-supplied baseline results, and opaque executable/toolchain claims;
  a separate library-only schema-v1 direct-executable resolver returns bounded
  sequential evidence after fresh exact-v4 revalidation without claiming an
  atomic snapshot, freshness, authority, or execution; and library-only,
  controller-owned repository-proposal selection and binding remains pinned to
  v1 evidence: an existing `CREATED`
  `repository-proposal-disabled` run receives exactly two statusless, content-
  addressed events after fresh registration validation and an explicit canonical
  proposal digest, with exact readback and no dispatch or authority;
- library-only, source-preserving inspection that proves one caller-named
  repository-proposal run from one read-only SQLite snapshot and returns only
  bounded single-run coverage, validated linkage, and fixed privacy-safe
  findings without repair or authority;
- a library-only repository-proposal admission ABAC shadow that freshly invokes
  that inspector, projects only exact clean Class 0 `READ` or Class 1 `CREATE`
  local attributes under fixed class-specific policy, and returns only an
  explicitly non-authoritative, non-persistent observation;
- a versioned additive SQLite supervisor migration with immutable mock-only
  flow admission, append-only optimistic control/flow/attempt revisions, sticky
  cancellation, fenced multi-resource claim APIs, and an internal local
  completion outbox plus receipts;
- deterministic comparison planning and controlled execution using immutable Class 0 snapshots, randomized blocks, fresh sessions/workspaces, and a bounded six-trial evidence envelope compatible with short-lived attestations;
- proposal-only, human-promoted self-improvement policy;
- a mock Chief of Staff Lite tracer bullet and a deterministic test suite that makes no live model calls.

The next work should extend these mechanisms rather than introduce a parallel framework.

### Billing-safety implementation checkpoint

The original live-run diagnosis proved only the intended subscription authentication route; that was insufficient because Codex product credits and Claude extra usage can continue inference beyond included capacity. Billing Hard-Stop v2 now separates route, included-capacity state, paid-continuation protection, and paid-balance state. It requires current capacity evidence, a short-lived matching account attestation, no durable capacity stop, a closed durable circuit, and post-run billing assessment. Capacity and breakers are checked atomically with dispatch; postflight capacity is persisted before lease release. Paid or unknown post-run evidence quarantines the attempt and artifacts and opens a circuit; verified included-capacity exhaustion survives restart and blocks until strictly newer verified post-reset availability without changing lanes.

Implementation does not make either account permanently eligible. Every live Codex or Claude attempt remains blocked unless `doctor` can establish current evidence for the exact runner/account/profile through the full requested run window and `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1` is also set. The gate and subscription login are necessary, never sufficient. The controlled `compare-run` workflow is implemented, but no live Codex-versus-Claude comparison has been completed or human-scored.

### Authorization-model checkpoint

The [runtime authorization model](authorization-model.md) is now the adopted
target architecture. Its standards mapping, attribute taxonomy, conservative
Class 0-3 summaries, four decision effects (`permit`, `defer`, `deny`, and
`indeterminate`), and no-authority-widening migration are adopted. The first
non-enforcing code slice is also implemented: canonical value types, a pure
current-stage evaluator, adversarial fixtures, typed Chief-of-Staff task-effect
intent, three append-only boundary observations with legacy-result and
authority-ceiling parity, and a strictly read-only parity/coverage/order
inspector. New ordinary Chief-of-Staff attempts add a privacy-bounded binding,
schema-v2 accounting, and a schema-v5 publication shadow. Current schema-v6
exact-mock attempts retain schema-v5 Class 1 admission enforcement and schema-
v4's dispatch and publication chains while adding a bounded canonical task-
intent lineage to the authoritative binding. The separate enforcing publication
decision and schema-v3 pre-effect/action receipts retain exact local effect
reconciliation; schema-v1-v3 paths retain schema-v2 non-enforcing publication
receipts. Controlled comparisons add a schema-v2 trial binding, schema-v3 Class
0 admission/dispatch shadows, and a separate schema-v4 non-enforcing Class 1
private-publication shadow with schema-v2 pre-effect/action receipts.

The first three runtime ABAC enforcement points now gate only new
profile-backed ordinary Class 1 attempts through the exact controller-owned
in-memory mock implementation and the resulting owner-private candidate write.
A schema-v6 binding declares admission, dispatch, and publication and commits
the canonical task-intent preimage, its controller-owned source, and exact
digests needed for authoritative replay; frozen schema-v5 retains the three
chains without self-contained lineage, and schema-v4 declares dispatch plus
publication. The run record and private
directories before admission are inert controller scaffolding. Admission
inherits the full task consequence vector, persists a fixed-policy decision,
rebuilds current inputs, compares the exact persisted wrapper, independently
replays policy, checks freshness, and requires a durable succeeded receipt
before the admission shadow or billing. Class 0, unsafe/high-impact,
non-permit, stale, evaluation, or evidence failures stop pre-billing. The
selection and task-attempt binding require exact readback. The controller then
persists a fixed-policy dispatch
decision after exactly reading back the mock billing evidence, then exactly
reads back the decision. Before `RUNNING`, it rebuilds current inputs, requires
the resolved task intent and digest to equal the durable schema-v6 lineage,
independently constructs and compares the canonical persisted wrapper,
independently replays fixed policy, checks finite freshness, exact obligations,
the derived Class 0/1 ceiling, the independent legacy gate, and the unchanged
shipped runner class and instance boundaries. It exactly reads back `RUNNING`
and repeats the current binding,
policy, freshness, and ownership checks immediately before invocation. The
linked action receipt and execution accounting must read back exactly before
publication, and an unprovable post-effect receipt quarantines the attempt. An
accepted, credential-clean result then receives a separate fixed-policy Class 1
decision. That PEP reuses the schema-v6 lineage, checks equality with the
captured shipped resolver, independently replays the shipped evaluator and
fixed policy, and exactly reads back its decision and enforcing pre-effect
record. Immediately before staging, it exactly rereads the binding, decision,
and pre-effect record, rebuilds the permit, and checks a new post-replay action
time for freshness; its reconciled filesystem receipt is the canonical action
receipt.
General runtime ABAC enforcement is still **planned**. `PermissionClass`
remains authoritative across contracts, approval, routing, runner validation,
persistence, evaluation, and comparison, alongside the distributed billing,
identity, environment, profile, isolation, capacity, and circuit gates.
General/live/comparison/supervisor admission, shared publication or promotion,
comparison execution, supervisor workers, live harnesses, approval resumption,
and mediated commands/tools remain non-enforcing or disabled. Comparison
publication receipts and historical ordinary receipts are migration evidence
only; schema-v4/v5/v6 ordinary publication is the narrow
authoritative exception and cannot grant any broader effect.

The lineage slices use the existing enforcing decision-event and action-receipt
schemas and advance only current exact-mock attempt bindings to schema v6, so
they add no authority. The final dispatch and publication PEPs compare
the durable canonical lineage with the captured shipped resolver and replay the
shipped evaluator and fixed policy; read-only inspection replays v6 without a
shadow preimage. Publication exactly rereads the binding, decision, and pre-
effect record before post-replay action-time freshness and staging. Schema-v1
through v5 histories retain their frozen meanings. Dispatch remains limited to
Class 0/1 requests for the exact profile-backed controller-owned `MockRunner`,
while new attempts still require Class 1 admission and publication remains an
owner-private Class 1 local effect.

The first Phase 3 repository-registration slice preserves a standalone
schema-v1 contract, the sixth adds a separate schema-v2 contract, and the
seventh adds schema v3; the eighth adds separate schema v4. The pure
read-only validator dispatches on an exact integer version and reduces a strict controller-
supplied ordinary Git root to stable repository/filesystem references;
validates exact verification argv-array (not shell-text) declarations,
canonical protected/allowed paths, bounded resource limits, fixed local-
container/network-disabled isolation, and patch-only review policy; and returns
digest-only evidence declaring read-only use, disabled dispatch, and no granted
authority. Git and Ordomata state paths are always protected, while traversal
and symlink escapes fail closed. Schema v2 requires bounded literal
`generated_paths` and `vendor_paths` deny/classification roots strictly
beneath allowed paths. They are canonical and digest-bound, cannot overlap
within or across categories or with protected/sensitive paths, and reject case
aliases, glob/expansion syntax, symlinks, and special files. Missing leaves are
accepted without creation. These declarations attest neither generation nor
vendor provenance and cannot hide a diff or authorize a change. The validator
remains pure, creates no state, and authorizes or executes nothing.

Schema v3 preserves the v2 path policy and requires a controller-supplied
baseline result for every declared verification command. Each result is linked
exactly once by command kind, identifier, and a digest of the exact canonical
command declaration, and all results share one bounded opaque snapshot digest.
The result grammar accepts bounded integer timing and exactly one tagged
`exited`, `signaled`, or `timed_out` termination. A timeout must carry the
controller-supplied `termination_confirmed: true` assertion. It derives pass
only from an exited zero code and accepts no caller-supplied success, output or
output hash, environment, path, message, or arbitrary metadata. The canonical
aggregate binds declaration-ordered observations to the repository reference
and complete verification-command digest.

V3 validation establishes internal consistency only. It does not authenticate
the controller-supplied observations, compare their times with the current
clock, recompute the snapshot, resolve an executable/toolchain, or establish
reproducibility. Privacy-bounded evidence exposes only aggregate baseline
evidence with fixed controller-supplied source, bounded result count,
`baseline_authenticity_verified: false`, and
`baseline_freshness_verified: false`, never the snapshot or individual results.

Schema v4 preserves the v3 contract and requires one controller-supplied
executable/toolchain identity claim for every declared command. Each is linked
by exact command kind, identifier, and domain-separated command digest and
carries only bounded opaque `executable_identity_digest` and
`toolchain_identity_digest` values. Canonicalization follows declaration order
and derives a syntax-only declared-executable reference bound to the exact
command context plus the repository reference, complete verification-command
digest, and exact v3 baseline aggregate digest. The identity digests have no
standardized or trusted preimage or provenance. Derived context binding does
not prevent cross-context transplantation—the claim block can validate with a
different aggregate—or same-context replay. The baseline link proves only
co-declaration, not that its process used the claimed executable or toolchain
bytes.

V4 evidence exposes only controller-supplied source, aggregate digest, and a
bounded identity count. Authenticity, freshness, resolution, content,
toolchain completeness, and execution correspondence are explicit false facts;
individual identities and declared-executable references remain private. V4
identity-block validation adds no PATH, PATHEXT, environment, runtime-cwd,
stat, content, symlink, shebang, interpreter, launcher, module, plugin,
dynamic-loader, package, or version inspection and executes nothing. Existing
registration root and repository-relative path/executable safety checks are
unchanged.

The ninth slice adds the separate library-only schema-v1 receipt in
`ordomata.repository_executable_resolution`. It rejects schemas v1 through v3
before resolution inspection and freshly revalidates exact schema v4. Under
fixed `controller_measured` / `posix_nofollow_v1` semantics, bare names use
only bounded, ordered, controller-supplied absolute search directories; no
ambient `PATH`, relative/empty entry, implicit cwd, or suffix expansion is
accepted. Slash-containing `argv[0]` initially requires `cwd: "."` and resolves
from the registered repository root. Pinned directory descriptors, no-follow
descriptor-relative lookup, complete direct-file hashing, metadata/namespace/
precedence rechecks, and final registration revalidation reject symlinks,
special or sparse files, missing execute bits, and detected drift/races. Each
unique file is limited to 64 MiB and the aggregate to 256 MiB.

The receipt binds the registration, repository, verification-command,
baseline, schema-v4 opaque-identity aggregate, and resolution-context digests.
Its evidence is aggregate-only and bounded. This is a point-in-time,
non-reusable direct-file observation: current freshness, provenance,
invocability, interpreter/dependency identity, complete toolchain,
snapshot/baseline correspondence, and future execution correspondence remain
false. The receipt grants no authority or dispatch, is not an action receipt,
route/billing/capacity fact, or live eligibility, and adds no CLI, persistence,
subprocess, or execution path. Evidence fixes
`sequential_resolution_measurement_complete: true` and
`atomic_snapshot_verified: false`; no atomic filesystem snapshot is claimed.

The tenth slice adds the separate library-only schema-v1
`ordomata.repository_executable_staging` boundary. Its public staging function
requires an exact typed expected resolver receipt and a new caller-owned lease
under fixed `controller_copied` / `posix_unlinked_readonly_v1` semantics.
During a fresh action resolver pass, it rereads each unique executable from the
same still-pinned descriptor into immutable process-local chunks. The expected
and action receipts must match exactly before the first staging mutation. A
complete resolver pass after staging must again match both, rejecting detected
source, namespace, registration, or search-precedence drift without claiming
atomicity or current freshness.

The caller supplies an already-created exact absolute staging root. It must be
empty, reached without following a symlink, owned by the effective user,
exactly mode `0700`, and nonoverlapping with the repository and explicit search
directories. V1 checks lexical containment and exact-root inode equality only;
it does not verify exclusion of other mount aliases. The root is dedicated to
one controller process and one lease, without concurrent use. Unique files
remain bounded to 64 MiB each and 256 MiB total. For each source the controller
exclusively creates a random zero-length mode-
`0600` entry, opens a reader, unlinks and fsyncs the entry before writing any
captured byte, then writes, hashes, fsyncs, sets non-executable mode `0400`, and
reads the unlinked inode back. It closes every writer and leases only read-only,
close-on-exec descriptors; no staged executable bytes remain path-addressable.

The receipt binds expected/action/post-stage resolution, staging context,
staged-file measurements, and declaration-order command bindings while outward
evidence remains aggregate-only. Cleanup reports `removed`,
`already_absent_verified`, or `unverifiable` and retains still-verified handles
when absence or release is uncertain, without retrying an ambiguously closed
descriptor number. It cannot restore root timestamps or establish secure
erasure.

This is a temporary Class 1 local filesystem effect whose required
authorization remains caller-owned. Kernel/filesystem immutability, same-UID
exclusion, ACL privacy, external-writer absence, atomic snapshot, current
freshness, future execution correspondence, authority, authorization, action
receipt, dispatch, durable control-plane persistence, proposal-lineage
extension, routing, billing/capacity/circuit evidence, live eligibility, and
execution remain false. No CLI, state, proposal, runner, worker, subprocess, or
harness path consumes it. Same-UID adversarial interference is outside V1
protection; the lease must never be given to or integrated with an untrusted
same-UID worker.

The second Phase 3 slice is the separate
`ordomata.repository_proposal.bind_repository_proposal_attempt` evidence API.
It freshly revalidates a registration and requires an explicit canonical
`proposal_digest` plus an existing immutable Class 0/1
`repository-proposal-disabled` run with only its initial `CREATED` status. It
appends exactly one content-addressed, statusless
`repository_registration_selection` event and then one content-addressed,
statusless `repository_proposal_attempt_binding`; each append atomically
requires current status `CREATED` plus the exact ordered predecessor event IDs.
Commit failures roll back before reconciliation, and exact history/readback
from one consistent SQLite snapshot is mandatory. Only digest/reference and
bounded version/control metadata is stored; raw
proposal content and registration/path/argv/workspace/run-directory values are
not. The events reuse existing `run_events` and add no migration, run creation
or status transition, authorization decision or action receipt, worktree,
command/process/worker/supervisor dispatch, routing, billing, harness, or live-
route effect. This chain remains pinned to frozen registration evidence v1 and
rejects v2 through v4 before any event append. The separate executable-
resolution receipt is not proposal evidence and does not widen that chain.
Complete interpreter/dependency/toolchain attestation and execution receipts
remain deferred.
Only Class 0/1 effects remain enabled.

The third Phase 3 slice is the library-only
`ordomata.repository_proposal_inspection` API
`inspect_repository_proposal_evidence(database_path, *, run_id)`. It returns a
privacy-bounded `RepositoryProposalInspectionReport` for exactly one
caller-named run with fixed `inspection_scope: "single_run"`, `run_ref`,
permission class/current
status, `clean`, `coverage`, `truncated`, capped inspected-event count, optional
validated proposal/registration/repository references and version, optional
selection/binding digests and sequences, and bounded fixed-code findings. The
mapping also fixes read-only inspection/validation, no repair, disabled
dispatch, and no granted authority, and reports evidence completeness and
finding count. An exact protocol-recoverable `CREATED`-only or
`CREATED`-plus-selection evidence prefix is incomplete; only the exact clean three-event
chain is complete; every other history is invalid. `clean` requires complete,
untruncated, finding-free
evidence. More than four events sets `truncated` because the capped inspection
cannot cover the history; the result never claims whole-database coverage.

The exact signed main file and optional WAL are staged into owner-private
temporary storage under a fixed controller-owned 512 MiB combined ceiling;
oversized state fails before copy. A no-WAL snapshot opens through an immutable
read-only URI, while an in-budget WAL pair opens read-only. SQLite opens only
the staged identity, and before/after source signatures detect concurrent
changes. One query-only SQLite snapshot covers the immutable run and
ordered events. The inspector independently replays cardinality/order,
content-addressed event and canonical payload digests, durable-run, proposal,
and registration-component linkage, and fixed Class 0/1, runner, `CREATED`,
read-only, dispatch-disabled, and no-authority semantics. It never instantiates
`SQLiteStateStore`, creates source schema or sidecars, repairs evidence, or
revalidates the registration against the live filesystem. Its fixed findings
and errors expose no raw identifiers, SQLite diagnostics, paths, argv,
registration documents, proposal content, workspace/run-directory values, or
artifact content, and it is not an external tamper anchor.

Inspection creates no source database/schema/sidecar or migration and persists
no run, status, event, authorization decision, or action receipt. It creates no
worktree and performs no Git/command/process invocation, worker or supervisor
dispatch, route/profile selection, billing/capacity/circuit change,
harness/network action, or live eligibility.

The fourth Phase 3 slice is the library-only
`ordomata.repository_proposal_admission` API
`evaluate_repository_proposal_admission_shadow(database_path, *, run_id,
evaluated_at)`. It freshly calls the independent inspector and accepts no
caller-supplied report, class, request, policy, or evaluator. Shadow evaluation
requires a clean, evidence-complete, complete, untruncated, finding-free exact
three-event Class 0/1 inspection. A nonclean result constructs no request,
policy, or decision and returns `not_evaluated`, `indeterminate`, and the fixed
`inspection_not_clean_complete` block code. Binding, evaluator, or exact replay
failure also remains an inert fixed failed/indeterminate result.

The controller derives exactly two class-specific projections: Class 0 local
`READ` observation with a read-only operation/resource/policy and unenforced
audit-receipt plus read-only obligations, and Class 1 local `CREATE` nomination
with a local-draft operation/resource/policy and unenforced audit-receipt plus
isolated-local-only obligations. Each policy
enables only its projected class and fixed controller, local-boundary,
network-disabled, local-non-AI attributes. The request digest-binds the
privacy-safe inspection mapping and validated proposal, registration,
repository, selection, and binding lineage. The active shadow evaluation must
equal both the captured built-in replay and the controller's exact expected
decision.

An exact permit remains observational and cannot become admission authority.
The mapping fixes all authoritative decision, enforcement, authority,
admission/action, receipt, evidence-persistence, repair, dispatch, route,
billing, and obligation-enforcement flags to false. The API has no CLI and
persists nothing; it creates no source state, event, durable decision/receipt,
worktree, Git/command/process invocation, worker/supervisor dispatch,
route/profile choice, billing/capacity/circuit fact, harness/network action, or
live eligibility. Raw identifiers/paths, argv, registration/proposal content,
SQLite diagnostics, workspace/run-directory values, and artifact content do
not enter the result.

The fifth Phase 3 slice is the library-only
`ordomata.repository_proposal_admission_verification` API
`verify_repository_proposal_admission_shadow_mapping(value)`. It accepts only
an exact built-in `dict`, takes a bounded detached JSON snapshot, and
independently mirrors the inspection contract. Evaluated inputs replay the
Class 0/1 request, policy, manual expected decision, and captured evaluator;
inert inputs must match an exact state-machine branch, and a reported replay
failure must retain a constructible replay boundary. It emits only fixed
value-free findings. `contract_valid` means internal consistency only, not
authenticity, durable reinspection or source truth, current freshness, or
authority. A coherent forgery or replay remains indistinguishable without a
trusted anchor. The verifier persists or repairs nothing, enforces or authorizes
nothing, and creates no worker, repository, command, route, billing, network,
harness, dispatch, or live effect.

The sixth bounded Phase 3 slice is the schema-v2 generated/vendor exclusion
contract described above. Nonempty categories are bound into path-policy and
registration digests, while raw paths remain absent from evidence. It performs
no automatic exclusion discovery, ignore-file inference, persistence, repair,
execution, worker, route, billing, network, harness, dispatch, authorization, or
live effect. Schema v1 and proposal lineage remain frozen.

The seventh bounded Phase 3 slice is the schema-v3 baseline contract described
above. It performs no snapshot computation, executable resolution, command
execution, persistence, repair, worker, route, billing, network, harness,
dispatch, authorization, or live effect. Schemas v1 and v2 retain their exact
canonical/evidence meanings, and proposal lineage remains v1-only.

The eighth bounded Phase 3 slice is the schema-v4 opaque executable/toolchain
identity-claim contract described above. It performs no additional identity
lookup, resolution, or inspection and no execution, persistence, repair,
worker, route, billing, network, harness, dispatch, authorization, or live
effect. Frozen schemas v1 through v3
retain their exact canonical/evidence meanings, and proposal lineage remains
v1-only.

The ninth bounded Phase 3 slice is the separate schema-v1 direct-executable
receipt described above. Exact schema-v4 revalidation plus bounded descriptor-
based `controller_measured` / `posix_nofollow_v1` lookup measures only direct
`argv[0]` bytes and emits aggregate-only, point-in-time, non-reusable evidence.
It changes no registration schema or proposal lineage and adds no persistence,
authority, dispatch, action receipt, routing, billing, live eligibility, or
execution. The separate tenth slice supplies bounded action-boundary capture
and staging; complete interpreter/dependency manifests and execution remain
future boundaries.

The tenth bounded Phase 3 slice is the separate executable-staging lease
described above. It establishes only bounded namespace-detached mode-`0400`
descriptor copies after exact expected/action/post-stage resolution equality.
It widens no registration or proposal schema and adds no authority,
authorization, action receipt, durable control-plane persistence,
CLI/state/runner integration, route, billing, live, or execution path.
Complete interpreter/dependency
manifests and any lease-consumption action remain future boundaries.

The target semantics for Class 3 standing envelopes, irreversible actions,
the non-delegable root-authority kernel, consequential outbox execution,
adaptive verification/recovery, trusted-context boundaries, and attested
worker cells are adopted below. Class 2/3 runtime enablement, external
connectors and writes, true dual-human authorization, distributed policy
infrastructure, third-party policy engines, and compliance claims remain
**deferred**. The migration does not grant a worker any new capability.

## Relationship to the current roadmap

This remains the proposed long-form expansion of [the current roadmap](roadmap.md). The roadmap now explicitly places Billing Hard-Stop v2 before the operator-gated live experiment; the phase mapping below preserves that dependency.

| Current roadmap | Expanded plan |
|---|---|
| Phase 0 - foundation implemented | Baseline entering expanded Phase 0 |
| Phase 1A - Billing Hard-Stop v2 implemented | Expanded Phase 1 core billing controls |
| Phase 1B - controlled subscription comparison next | Operator-gated experiment after current Billing Hard-Stop v2 evidence; its evidence informs routing without auto-promotion |
| Phase 1C - runtime authorization rebaseline partially implemented | Typed Chief-of-Staff task intent, three-boundary shadow parity/inspection, exact built-in-mock Class 1 admission, dispatch, and local-candidate publication PEPs, then broader path coverage and enforcement prerequisites in Phases 2-3 |
| Phase 2 - repository-maintenance tracer bullets, control-plane prerequisite partially implemented | Expanded Phase 2 dispatch-disabled tracer plus Phases 3-4 repository work |
| Phase 3 - bounded local loop | Remaining expanded Phase 2 worker loop and Phase 7 |
| Phase 4 - evidence-driven adaptation | Expanded Phases 5-7 |

Phase 8 is a new conditional evaluation track and is not part of the core roadmap.

## Non-negotiable invariants

1. AI inference is eligible only through a verified first-party subscription-backed harness and included subscription capacity.
2. API-key, cloud-provider, purchased-credit, overage, contradictory, and unknown billing routes fail closed.
3. `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1` remains necessary but never sufficient for a live run.
4. Deterministic code owns authorization, scheduling, state transitions, routing eligibility, evaluation, approvals, and promotion. The target authorization mechanism is a versioned, deny-by-default ABAC decision; the current Class 0/1 gate remains authoritative until the migration is proven.
5. Workers cannot modify billing policy, runner policy, repository registration, protected tests, historical records, or their own authority.
6. Only actions within the current Class 0/1 ceiling remain eligible in the
   runtime through this plan. Class 0-3 becomes a derived operator summary only
   after ABAC parity and enforcement coverage are proven; Classes 2 and 3 stay
   disabled even though their target authorization semantics are specified.
7. Tests and CI use mocks. No normal test, benchmark, repair loop, or self-improvement run invokes a live model.
8. No automatic merge, push, deployment, schedule installation, message send, calendar change, or other consequential external action is introduced.
9. Missing evidence is `unknown` or `unavailable`, never optimistically inferred.
10. Agent output is evidence, not authority.
11. Active authorization/billing policy, worker authority expansion,
    audit/containment weakening, and credential material form a root kernel
    that is never delegable to agents or ordinary workflows.

During the Ordomata identity transition, the former live-gate variable remains
an exact-value compatibility alias. Conflicting canonical and legacy values
fail closed. Existing `.agentops/` state is used in place only when it is the
sole state root; dual roots are rejected rather than merged. Persisted v1
fingerprint, migration, schema, and authorization-evidence namespaces remain
unchanged as historical protocol identities.

## OpenClaw ecosystem decision

### Decision

OpenClaw is a **reference implementation**, not a runtime dependency or policy kernel, for Phases 0-7.

Reasons:

- its durable task ledger, Task Flow, typed workflow, sub-agent, skill-proposal, gateway, and audit patterns are valuable;
- its broad provider, plugin, channel, API, credential, and external-action surfaces conflict with this project's deliberately narrow billing and permission boundaries;
- adding its Node runtime and ecosystem would violate the current standard-library-only simplicity without yet solving a demonstrated gap;
- its general provider failover is not equivalent to this project's hard subscription-only billing lane;
- its extension supply chain and in-process gateway surface would materially enlarge the trusted computing base.

### Possible future role

After the seven-day soak gate, OpenClaw may be evaluated as an **optional frontend adapter only**. Such an adapter would be treated as untrusted ingress and could submit a typed local task request or read a redacted status projection. It would not:

- write the orchestrator database;
- invoke a harness directly;
- select a billing route or model profile;
- mutate policy, schedules, skills, memory, or repository registration;
- receive worker subscription credentials;
- approve or perform Class 2/3 actions;
- become the source of truth for tasks, artifacts, or completion state.

No OpenClaw dependency or frontend adapter is part of the initial implementation path.

## Routing policy

Routing has two stages: fail-closed eligibility, then lexicographic optimization.
It does not grant authority. In the target design, a selected route remains
subject to a fresh authorization decision at dispatch and at each later
enforcement point. Until that migration is complete, the current numeric class
checks remain compatibility gates.

### Eligibility gates

A profile is ineligible unless all of the following are true:

- runner identity and first-party subscription authentication are proven with high confidence;
- account-level overage protections are current and the effective route is `subscription_included`;
- task action/resource/consequence requirements, current Class 0/1
  compatibility ceiling, capability, context, and tool requirements fit the
  profile;
- the worker isolation mode required by the task is available and verified;
- included subscription capacity is available and the profile is not cooling down;
- no policy, environment, provider, endpoint, or settings contradiction exists.

No score can overcome an eligibility failure.

### Ranking order

Among eligible profiles, rank lexicographically in this order:

1. **Correctness and risk:** verified success, accepted-result rate, regression history, evidence confidence, least privilege, isolation strength, and task-risk fit.
2. **Included-subscription efficiency:** accepted results per observed included-capacity unit, avoidable turns, context size, retries, and tool activity. Missing capacity telemetry remains `unavailable`; no dollar value is invented.
3. **Latency:** queue wait and wall time, used only after correctness/risk and subscription efficiency.

Consequences:

- a faster profile never outranks a safer or more correct profile merely because it is faster;
- a weaker model is not used for untrusted or privileged work merely to save capacity;
- efficiency means better use of already included capacity, not access to a cheaper paid route;
- route order, thresholds, priors, and tie-break rules are versioned policy and require reviewed promotion;
- failover stays inside the original billing lane, authorized action/resource/
  consequence envelope, current derived-class ceiling, and isolation
  requirement, and requires a fresh decision.

No blended scalar score may trade a lower-priority tier against a higher-priority tier. Within the correctness-and-risk tier, each task family uses a reviewed tuple of minimum safety floors and visible quality dimensions. The efficiency tier likewise uses a reviewed visible tuple rather than a hidden score. Quota consumption is compared only within a compatible provider quota pool and unit, or through a reviewed, documented normalization. Codex and Claude measurements are not presumed commensurate; incompatible or unavailable observations remain incomparable rather than being coerced to zero. If a tier cannot distinguish two candidates, comparison advances to the next tier. The task-family policy supplies any remaining deterministic tie-break; an exact tie is resolved by stable profile id. Missing quality observations use an explicit low-confidence prior or remain `unavailable`, never zero. The current runtime performs deliberate exploration only in a separately declared comparison run. Phase 7 may add a small explicit exploration budget among promoted eligible profiles; it cannot silently add settings, relax a safety floor, or alter governing policy.

### Versioned worker profiles and routing decisions

Extend the existing execution profile rather than adding a competing abstraction. Each immutable profile version binds:

- harness adapter and detected harness-version range;
- explicit model id, or a reviewed `null` meaning the harness's subscription catalog default;
- role and task-family eligibility;
- reasoning/effort, turn, context, and tool settings accepted by that adapter's strict allowlist;
- capability tags, required isolation backend, concurrency ceiling, typed
  action/resource limits, and a temporary maximum-class compatibility ceiling;
- the sole permitted billing lane; and
- reviewed quality/risk priors used only until sufficient compatible observations exist.

Unsupported, contradictory, or silently ignored settings make a profile ineligible. Model catalog and capability discovery are timestamped observations, not permanent assumptions.

Every selection persists an immutable routing decision containing the policy/profile versions, task features, candidate set, each rejection reason, raw metric tiers, missing-evidence markers, selected profile and settings, and final tie-break. Retries and failovers create new attempts and routing decisions; they never rewrite the original decision or task snapshot.

## Target state model

Extend the existing SQLite state rather than replacing it. Migrations must be versioned, transactional, backward-compatible when possible, and covered by fixture databases.

**Implemented integrity checkpoint:** baseline creation and adoption of an
exact pre-ledger baseline execute statement-by-statement in one explicit
transaction. Every ordinary state open verifies the exact baseline schema,
baseline foreign-key and run-status lineage, append-only migration guards, a
contiguous frozen v1-v4 identity prefix, and agreement between the recorded
version and installed supervisor tables before use. Partial schemas, missing
guards, gaps, future versions, or changed identities fail closed without
automatic repair. Read-only authorization inspection exposes only bounded
global finding codes and accepts an exact pre-ledger baseline without mutating
it. This hardens the existing Class 0/1 state substrate; it does not enable a
worker, runtime ABAC enforcement, Class 2/3 effects, or any live model route.

Planned logical records:

- **authorization policy bundles:** immutable schema and rule versions,
  digests, activation records, and rollback targets controlled by the operator;
- **standing authorization envelopes:** immutable operator-approved action,
  target, consequence, rate, blast-radius, verification, expiry/invalidation,
  and circuit bounds; these remain inactive while Class 2/3 is disabled;
- **authorization requests and decisions:** canonical subject, action,
  resource, environment, consequence and evidence digests plus effect, reason
  codes, obligations, expiry, and derived display class;
- **action receipts:** the exact enforced object, decision id, outcome, and any
  artifact or state transition produced;
- **repository registrations:** immutable repository identity plus versioned
  controller-validated command declarations, protected paths, limits, and
  worker requirements; declarations do not authorize execution;
- **flow definitions/runs:** versioned DAG, goal digest, immutable input snapshot, controller id, revision, status, and cancellation intent;
- **flow steps:** typed dependencies, required actions/resources, environment
  and consequence requirements, required capabilities, derived class, retry
  policy, and accepted artifact kinds;
- **task attempts:** selected profile, runner version, billing assessment, isolation assessment, timing, terminal state, and normalized accounting;
- **completion outbox:** durable, idempotent controller notifications that survive restart;
- **consequential-action outbox:** future exact authorized Class 2/3 intents,
  executor leases, idempotency keys, reconciliation state, and append-only
  receipts, separate from worker-accessible state;
- **approval records:** exact reviewed object digest, scope, decision, actor, expiry, and resume pointer;
- **billing attestations:** non-secret account identity fingerprint, provider, evidence kind, overage settings, verification time, and expiry;
- **skill and improvement proposals:** immutable candidate, benchmark evidence, protected-set results, review decision, and promoted version;
- **candidate-work proposals:** evidence, expected value, scope, acceptance
  checks, required authority, deduplication key, and transparent priority
  dimensions;
- **context and memory records:** digest-bound context packs and deltas,
  repository/project/role/trust-domain namespaces, provenance, taint,
  retention authority, and non-sensitive disposal tombstones;
- **isolation attestations:** observed preflight user/mount/network/resource/
  credential/control-socket state and post-run cleanup evidence;
- **outcome evidence:** raw quality, risk, intervention, efficiency, and latency dimensions without a hidden aggregate winner score.

The current additive schema migration implements only the bounded Phase 2
control-plane subset: mock-only immutable flow records, append-only control/
flow/attempt events, sticky cancellation requests, fenced leases/claims, and
the internal local completion outbox/delivery receipts. The standalone
repository-registration schema and validator still do not persist registration
documents. The separate proposal-evidence layer now stores one controller-owned
selection and one linked proposal-attempt binding as content-addressed existing
run events; this required no migration and retains only privacy-bounded digest/
version metadata plus bounded attempt controls. Independent proposal-evidence
inspection, authorization records for repository actions, worker execution,
and consequential-action delivery remain planned.

Historical run, event, attempt, artifact, authorization request/decision,
action receipt, outbox intent/outcome, approval, policy activation, context
lineage, disposal tombstone, and promotion records remain append-only. Mutable
desired schedules, leases, cooldowns, queue claims, and unexpired sensitive
evidence payloads remain separate operational state.

## Phase 0 - Rebaseline and encode the threat model

### Deliverables

- Record the current state/schema version and deterministic verification baseline.
- Maintain the adopted authorization architecture and a compatibility inventory
  identifying every current class, identity, billing, environment, isolation,
  routing, approval, and publication gate; do not describe documentation as
  runtime ABAC.
- Define the versioned canonical authorization request/decision contract,
  policy-bundle rules, attribute provenance/freshness rules, conservative class
  derivation, and behavior-parity fixtures before implementing an enforcing
  PDP.
- Define `permit`, `defer`, `deny`, and `indeterminate` precisely. A deferred
  approval or prerequisite is digest-bound and always triggers a fresh
  decision; indeterminate evidence remains fail-closed and non-approvable.
- Specify standing-envelope invalidation, fresh per-action permits,
  action-specific irreversible-effect rules, and the non-delegable root kernel
  as target policy contracts without enabling Class 2/3.
- Add a versioned threat-model contract covering billing spillover, hostile repository content, prompt injection, worker escape, credential access, command mutation, extension supply chain, duplicate dispatch, stale completion, and self-modification.
- Define feature flags for supervisor, flows, repository workers, containers, role delegation, and optional ingress; all default off.
- Define stable error categories and state transitions before adding background execution.
- Document which existing fields remain authoritative and which require migration.
- Define repository/connector source-of-truth, freshness, precedence, and
  reconciliation contracts, and establish repository-local instructions as
  digest-bound scoped guidance that cannot modify controller policy.

### Acceptance criteria

- Existing unprofiled/historical mock behavior remains compatible; the covered
  profile-backed built-in-mock Class 1 path admits the attempt, invokes the
  runner, and mutates the local candidate only from its respective fresh exact
  permits and receipts and otherwise fails closed.
- Every new feature has an explicit disabled default.
- Threat cases map to a deterministic prevention, detection, or fail-closed response.
- The implemented shadow evaluator has focused parity and adversarial cases for
  missing, stale, future, unauthenticated, contradictory, and unknown
  attributes, independently reports a derived class above persisted authority,
  and does not change a
  current allow or deny outcome. Chief-of-Staff admission, dispatch intent, and
  local-candidate publication shadows remain observed and inspectable; new
  schema-v6 mock attempts also carry an independent enforcing admission
  decision/receipt plus the schema-v4 dispatch and publication chains and a
  canonical task-intent lineage; schema-v5 retains the same three chains without
  self-contained lineage. Their
  admission order, current-input replay, persisted wrapper, upstream,
  artifact, billing, and v6 lineage links are independently checked without
  using shadow preimages for v6 dispatch or publication. Older histories
  retain their frozen semantics. New controlled
  comparison trials have a schema-v2 digest-bound Class 0 binding, Class 0
  admission/dispatch shadows, and a separately bounded non-enforcing Class 1
  private-artifact publication shadow with pre-effect/action receipts. Legacy
  schema-v1 trials remain valid partial evidence. Mediated commands/tools and
  complete legacy-path parity remain exit requirements.
- No live harness, schedule, repository, or external system is touched.

### Deferred

- New runtime behavior.
- OS daemon or schedule installation.

## Phase 1 - Billing Hard-Stop v2 and router contract v2

Subscription authentication alone no longer proves zero incremental cost. Codex can consume purchased ChatGPT credits after included limits, and Claude usage credits can continue at separately billed rates if enabled.

**Implementation checkpoint:** the billing axes and prohibited routes, strict file-attestation loader, TTY-only operator attestation lifecycle, current-evidence checks, post-run disposition, append-only capacity/circuit records, sanitized `doctor` fields, controlled `compare-run` path, and immutable privacy-safe routing-decision evidence for started profile-backed Chief-of-Staff attempts are implemented with deterministic tests. No live comparison has run. A broader cross-workflow routing ledger, blocked pre-run decision history, richer worker-profile schema, and outcome learning remain work unless separately shown as complete.

### Deliverables

- Keep three billing-related axes separate rather than encoding capacity as a route:
  - `billing_route`: `subscription_included`, `purchased_product_credit`, `subscription_overage`, `separately_billed_api`, `cloud_provider_billing`, `unknown`, `mock`, or `local_non_ai`;
  - `capacity_state`: `available`, `limit_reached`, `blocked_until_reset`, `cooldown`, `unknown`, or `not_applicable`;
  - `paid_continuation_protection`: `provider_enforced_disabled`, `verified_zero_balance_and_auto_top_up_disabled`, `enabled`, `unknown`, or `not_applicable`.
- Permit a live AI run only for `subscription_included` + `available` + a verified disabled/zero-balance continuation state. Keep the existing eligibility rules for `mock` and `local_non_ai`. Every other combination blocks.
- Add provider-specific, non-secret billing attestation records:
  - Codex auto top-up disabled and the usable product-credit balance verified as zero, unless OpenAI later exposes a provider-enforced included-only mode; a positive or unverifiable balance blocks the live route;
  - Claude usage credits/extra usage disabled and no Console/API credential attached;
  - verified account identity fingerprint matches the harness diagnostic;
  - evidence timestamp and expiry are explicit.
- Extend execution accounting with `paid_capacity_consumed` (`yes`, `no`, `unknown`, `not_applicable`) and `incremental_ai_charge` (`none`, `possible`, `confirmed`, `unknown`). Retain `incremental_api_charge` only as the narrower API-specific field for compatibility.
- Require current evidence in addition to route diagnosis and the live gate. If the relevant account setting cannot be machine-read, a short-lived operator attestation may record directly observed provider UI evidence, but it cannot override a positive/unknown balance, an enabled/unknown paid-continuation setting, or provider semantics that make spillover possible.
- Recognize normalized limit, credit, overage, purchase, and account-switch signals from bounded runner diagnostics/events.
- Convert included-capacity exhaustion into a durable `capacity_state=blocked_until_reset` or cooldown outcome. Do not retry immediately or switch lanes.
- If a post-run diagnostic indicates paid consumption or cannot establish the route, quarantine the attempt and artifacts, record a billing violation/unknown outcome, and trip an account/profile circuit breaker. Nothing from that attempt may be promoted or retried automatically.
- Add `doctor` output for names-only attestation status, expiry, route, capacity state, and paid-continuation protection.
- Preserve account and credential values outside SQLite, logs, prompts, commands, and artifacts.
- Extend versioned execution profiles with the worker-profile fields above and validate every model/setting against observed adapter capabilities.
- Extend the implemented immutable profile-backed Chief-of-Staff routing record
  (every canonical candidate, fixed rejection code, metric/source tier,
  selected profile/configuration/overrides refs, and policy version) to later
  workflow families, retries, and failovers without rewriting prior attempts.
- Implement tier-by-tier comparison without a cross-tier aggregate score: correctness/risk first, included-subscription efficiency second, latency third.
- Keep deliberate profile exploration inside explicit controlled comparisons; unattended runs use only promoted policy and profiles.
- Keep `subscription-only-policy.md`, `routing.md`, `roadmap.md`, `architecture.md`, `implementation-status.md`, and the README aligned with the new billing categories and per-attempt live eligibility rule.

### Acceptance criteria

- OAuth or ChatGPT login without current paid-continuation protection evidence is blocked.
- Stale, mismatched, contradictory, or unavailable attestation evidence is blocked.
- A positive or unverifiable Codex product-credit balance, enabled or unverifiable Claude usage-credit setting, or enabled auto top-up/reload is blocked.
- Purchased-credit and overage fixtures cannot be classified as `subscription_included`.
- Capacity exhaustion creates no retry storm, route mutation, or fallback.
- Paid or unknown post-run billing fixtures quarantine the attempt, prevent promotion, and open the correct circuit breaker.
- Accounting never equates `incremental_api_charge: none` with `incremental_ai_charge: none`; missing evidence is `unknown`.
- Prohibited credential variables remain absent from child environments.
- Router fixtures prove that no amount of efficiency or speed can overcome a correctness/risk disadvantage, and no amount of speed can overcome an efficiency disadvantage.
- Unsupported settings, stale capability observations, ineligible profiles, and missing required evidence cannot win; exact ties are deterministic and auditable.
- Mock tests cover every category and transition; normal verification makes zero live calls.
- A live run can start only when route, account attestation, environment, profile, capability, isolation, capacity, and explicit gate all agree.
- Project documentation and `doctor` output no longer present subscription login by itself as sufficient billing proof.

### Deferred

- Browser automation of account billing settings.
- Purchase, top-up, credit redemption, or provider billing APIs.
- Promotional-credit routing unless a later explicit policy adds a separately reviewed no-charge category.

## Phase 2 - Durable foreground supervisor and flows

**Implementation checkpoint — partial control-plane tracer, not phase
completion:** the versioned additive SQLite migration, mock-only immutable flow
admission, append-only optimistic control/flow/attempt state, sticky
cancellation, fenced multi-resource claim library APIs, internal local
completion outbox and receipts, read-only status/audit, digest-bound
reconciliation, operator control commands, and foreground `ordomata supervise`
loop are implemented. Admission, library-only claim, operator control
transitions, and sticky cancellation now emit append-only authorization
shadows, and the read-only audit independently verifies their digests, parity,
coverage/order, schema guards, and migration provenance. The loop deliberately
uses the shared verified migration ledger; missing v2-v4 schema statements and
their immutable ledger rows commit atomically or roll back together. It
deliberately
does not call the claim API or any
runner. Authoritative coverage at the exact worker dispatch/tool boundaries
and verified repository containment remain prerequisites for dispatch; the
narrow ordinary mock PEPs supply neither. No live
model, worker subprocess, network action, repository worker, Class 2/3 effect,
or OS schedule is enabled, and the Phase 2 acceptance criteria are not yet
satisfied.

### Deliverables

- Extend the initial enforcing PDP beyond the three profile-backed built-in-mock PEPs
  only after boundary-specific shadow parity. Keep the legacy Class 0/1 gate as
  defense in depth, and persist each exact request, decision, obligations,
  policy/evidence digests, and enforcement outcome append-only.
- Make queue admission, claim, dispatch, resume/reconcile, cancellation,
  and artifact publication explicit enforcement points.
  Re-evaluate after any relevant identity, resource version, approval,
  isolation, billing, capacity, network, lease, or circuit change; a stale
  permit is not ambient agent authority.
- Type and audit controller bookkeeping such as queue, lease, cancellation,
  event, and receipt writes separately from requested task effects. These
  deterministic operations maintain the control plane and never become worker
  authority. Active-policy changes remain explicit operator-only actions and
  are not enabled by the supervisor phase.
- Preserve the implemented foreground `ordomata supervise` process; connect it
  to claiming and execution only after the exact claim, dispatch, and mediated
  worker boundaries have authoritative ABAC enforcement.
- Preserve the implemented operator commands for `start`, `pause`, `resume`,
  `drain`, `stop`, `status`, `audit`, and `reconcile`; control commands never
  install or launch an OS service.
- Separate schedule definitions, task records, flow records, attempts, and completion delivery.
- Implement flow states such as `queued`, `running`, `waiting`, `blocked`, `succeeded`, `failed`, `timed_out`, `cancelled`, and `lost`.
- Map `defer` to a durable, resumable waiting state only when the decision names
  a satisfiable approval or prerequisite. Satisfaction creates a new request
  and decision rather than mutating the old record.
- Use optimistic flow revisions so stale controllers cannot overwrite newer state.
- Permit append-only DAG amendments only when the controller proves they stay
  inside the original goal and standing envelope, preserve completed history,
  respect depth/concurrency/attempt budgets, and receive fresh authorization.
  Scope-expanding proposals return to central admission.
- Make cancellation intent sticky: once requested, no new child attempt may start.
- Add a durable completion outbox with idempotency keys; completion is push/event-driven rather than polling.
- Reconcile orphan processes, expired leases, stale claims, partial attempts, and undelivered completion records after restart.
- Admit agent-proposed work only through a central candidate queue containing
  reproducible evidence, expected value, scope, acceptance checks, and required
  authority. Deterministically deduplicate, classify, and budget it; follow-up
  discoveries cannot inherit priority or expand a running attempt unless they
  were already authorized children.
- Rank backlog work by a visible lexicographic vector: mandatory safety/
  recovery, deadlines and blockers, expected operator/project value, evidence
  and acceptance confidence, capacity fit, then age/fairness. Preserve every
  raw dimension rather than emitting an opaque value score.
- Adapt concurrency to host load, isolation capacity, repository/resource
  conflicts, and subscription availability below hard global, per-runner,
  per-repository, per-flow, and per-resource caps. Reduce immediately under
  memory, disk, thermal, power, circuit, or capacity pressure and increase only
  gradually after stable evidence.
- Preempt active work only for billing risk, credential exposure, containment
  failure, revoked authorization, cancellation, or a safety circuit. Revoke
  capabilities immediately; permit a short tool-disabled checkpoint only when
  no filesystem, network, credential, or external effect remains possible,
  then terminate and quarantine partial output.
- Resume only from a verified controller-owned workflow boundary using a fresh
  session and fresh decision. Cancellation remains terminal. Resource drift
  invalidates the old attempt and creates a new candidate; prior artifacts may
  be reused only after explicit revalidation.
- Add quiet hours, load/disk guards, cooldowns, and a monotonic next-wakeup calculation without sleeping inside unit tests.
- Keep schedule installation out of scope; the operator starts the supervisor explicitly.

### Acceptance criteria

- Kill-and-restart tests recover queued/running/waiting work without duplicate dispatch.
- Replaying the same wake or completion event is idempotent.
- Stale revision writes fail without changing flow state.
- Cancellation survives restart and prevents further children.
- `audit` reports stale, lost, inconsistent, and delivery-failed records; `reconcile` previews before applying changes.
- A mock flow can run for hundreds of accelerated schedule ticks with bounded SQLite/WAL growth and no leaked subprocesses.
- No live model or OS schedule is started during tests.
- Indeterminate authorization, stale evidence, expired approvals, or changed
  bound resources cannot dispatch or resume work.
- Ordinary higher-priority arrivals do not interrupt a valid attempt, and every
  hard-stop fixture proves immediate capability revocation, bounded cleanup,
  and quarantined partial output.
- DAG amendment, candidate admission, and concurrency fixtures cannot exceed
  goal, authority, priority, depth, resource, or attempt caps.

### Deferred

- `launchd`, cron, systemd, or Windows service installation.
- Remote supervisors and distributed queues.
- External notifications.

## Phase 3 - Repository registrations and isolated worker cells

**Implementation checkpoint — read-only registration, proposal evidence,
single-run inspection, inert admission shadow, and independent shadow-contract
verification, not worker-cell enablement:** frozen
`schemas/repository-registration.schema.json` schema v1, separate
`schemas/repository-registration-v2.schema.json` and
`schemas/repository-registration-v3.schema.json`, all frozen, plus
`schemas/repository-registration-v4.schema.json`, and the pure
`ordomata.repository_registration` validator implement the current contract
boundary. They validate a controller-supplied ordinary Git root and stable
repository/filesystem references; format, lint, type-check, test, and build as
exact argv-array (not shell-text) declarations; canonical protected and allowed
POSIX paths with mandatory `.git`, `.ordomata`, and `.agentops` protection;
bounded CPU, memory, process, workspace, output, artifact, wall, and idle
limits; fixed local-container/network-disabled isolation; and patch-only/no-
Git-publication review policy. Case-insensitive aliases of controller-owned
paths, traversal, and symlink escapes fail closed. Registration versions are
bounded canonical SemVer; credential/billing option names, known shell
launchers, and protected relative executables are rejected. V2 additionally
requires canonical, bounded literal generated/vendor carve-outs strictly below
allowed paths. They are pairwise non-overlapping, disjoint from
protected/sensitive paths, and provide only deny/classification metadata—not
ignore, generation, provenance, or permission semantics. The result is
digest-only evidence with fixed read-only, dispatch-disabled, and no-authority
facts. The validator creates no state and authorizes or executes nothing.

Schema v3 additionally requires exact one-to-one command-result linkage under
one opaque snapshot digest. Its bounded integer observations use tagged exited,
signaled, or timed-out termination; a timeout carries the controller-supplied
`termination_confirmed: true` assertion. Results contain no supplied success,
output/output hash, environment, path, message, or arbitrary metadata. The
validator canonicalizes and digest-binds the aggregate but explicitly does not
authenticate it, prove current freshness, recompute the snapshot, or resolve or
execute an executable/toolchain. Outward evidence remains aggregate-only, with
fixed false authenticity and freshness claims.

Schema v4 preserves v3 and requires exactly one controller-supplied opaque
executable/toolchain identity claim per declared command. Exact kind,
identifier, and command-digest linkage is mandatory. Canonicalization derives a
syntax-only, command-context-bound declared-executable reference and binds the
aggregate to the repository, complete verification-command set, and exact v3
baseline aggregate. The supplied executable and toolchain digests have no
standardized or trusted preimage or provenance. Cross-context transplantation
can validate with a different aggregate, same-context replay remains
indistinguishable, and baseline binding proves co-declaration rather than the
bytes used during execution. Aggregate-only evidence reports authenticity,
freshness, resolution, content, completeness, and execution correspondence as
false. The identity block adds no PATH/environment lookup, stat/content read,
symlink/shebang or interpreter/launcher/module/plugin/loader/package
inspection, or execution. Existing registration root and repository-relative
path/executable safety checks are unchanged.

The separate proposal-evidence API freshly revalidates that registration and
binds its controller-owned selection plus an explicit canonical proposal
digest to an existing immutable Class 0/1 `repository-proposal-disabled` run.
It writes exactly two ordered, statusless, content-addressed events while each
append atomically requires the run to remain `CREATED` with the exact ordered
predecessor event IDs, then requires exact readback from one consistent SQLite
snapshot. Only privacy-bounded digest/version and attempt-control metadata is
stored. It creates no run or status transition and adds no SQLite migration,
authorization, worktree, command, process, worker, dispatch, route, billing, or
live capability. The implemented library-only inspector now proves one
caller-named run from one read-only SQLite snapshot, distinguishes exact
protocol-recoverable prefixes from the complete three-event chain and invalid history,
and emits only bounded fixed-code findings. It makes no whole-database or
external-tamper-anchor claim and does not revalidate registration against the
live filesystem. The implemented admission shadow freshly invokes that
inspector, evaluates only its exact clean and complete Class 0/1 evidence, and
uses a fixed class-specific Class 0 `READ` or Class 1 `CREATE` local projection
with privacy-safe digest binding and exact built-in replay. A nonclean result is
indeterminate and not evaluated; an exact permit is still non-authoritative,
non-persistent, and no-effect. The library-only verifier takes one untrusted
exact built-in `dict` shadow mapping, snapshots it as bounded detached JSON, and
checks an independent mirror of the inspection contract, evaluated-input Class
0/1 manual-decision and captured-evaluator replay, and exact inert branches. A
reported replay failure still requires a constructible replay boundary. Its
fixed value-free findings and `contract_valid` establish internal consistency only;
without a trusted anchor, coherent forgery or replay remains indistinguishable.
It performs no durable reinspection, freshness proof, persistence, repair,
enforcement, authorization, or action. The proposal chain remains registration-
evidence-v1-only, so v2 through v4 fail before an event append. The separate
point-in-time direct-executable receipt is implemented but is not proposal
evidence or execution authority. Complete interpreter/dependency/toolchain
receipts, future `shell=False` action-boundary execution, and every worker-cell
deliverable below remain deferred. Only Class 0/1 effects remain enabled.

### Deliverables

- Complete the versioned repository-registration contract containing:
  - canonical repository path and identity;
  - controller-validated format, lint, type-check, test, and build argv-array
    declarations, which are configuration inputs rather than execution
    authority;
  - baseline command results (schema v3 validation implemented; authenticated
    provenance and operational consumption remain deferred);
  - opaque executable/toolchain identity claims (schema v4 validation
    implemented; their opaque values remain unverified and unconsumed);
  - controller-measured direct-executable resolution (separate schema-v1
    receipt implemented; current freshness, provenance, invocability,
    interpreter/dependency coverage, and completeness remain unverified; the
    narrow descriptor-staging consumer below is implemented, while execution
    consumption remains deferred);
  - controller-copied direct-executable byte staging (separate schema-v1
    process-local lease implemented; authorization, isolation-cell handoff,
    and execution consumption remain deferred);
  - protected and allowed paths;
  - generated/vendor exclusions (schema v2 validation implemented; operational
    consumption remains deferred);
  - resource, timeout, network, and artifact limits;
  - required isolation backend;
  - review-only branch/patch policy.
- Preserve the implemented independent, single-run, read-only evidence
  inspection as a mandatory proof boundary before any future worktree or
  command path; a clean report alone still grants no authority.
- Preserve the implemented fresh-inspection admission shadow as an
  observational boundary only: neither its Class 0/1 projection nor an exact
  permit may be reused as authority or enable a worktree, command, route,
  worker, or external effect.
- Create one disposable detached Git worktree per Class 1 job. Never modify the operator's primary checkout or create a branch.
- Keep the base repository read-only from the worker's perspective and expose only the job worktree plus bounded temporary storage.
- Keep the repository's shared Git directory, refs, config, hooks, indexes, and credentials controller-only. Hide the worktree's `.git` pointer and do not mount the common Git directory into the worker cell. A worker edits only materialized source files without Git authority; the controller owns worktree lifecycle and computes the resulting patch.
- Add a worker-cell backend interface with deterministic mock/process backends first and a local container backend next.
- Container requirements for unattended code work:
  - fresh container per attempt;
  - non-root user;
  - explicit mounts only;
  - no Docker socket or host control socket;
  - blocked credential/system paths;
  - read-only root filesystem where practical;
  - CPU, memory, process, output, wall, and idle limits;
  - network denied by default, with any harness-required path explicitly assessed;
  - orphan cleanup and post-run containment verification.
- Do not rely on shell-text parsing. Registered verification commands are exact argv arrays launched without a shell.
- Bind authorization and any approval to the authenticated subject, typed
  action, canonical resource/version, argv, cwd, input artifact,
  environment-name set, consequence vector, registration version, and policy
  digest; execute that exact object only.
- Define runner-specific credential isolation. An unattended tool-enabled runner remains ineligible until tests show that model-invoked tools cannot read or exfiltrate the harness auth store. If this cannot be proven with a native harness sandbox, use controller-mediated filesystem/command capabilities with native shell/filesystem tools disabled.
- Scan prompts, model outputs, diffs, logs, and artifacts for credential-shaped material before persistence or promotion.

### Acceptance criteria

- Fault-injection tests prove zero writes outside the disposable worktree and run directory.
- Symlink, `..`, alternate-root, worktree-race, and protected-path attacks fail closed.
- Exact-command approval cannot be replayed with changed argv, cwd, environment, or inputs.
- Worker processes cannot access prohibited credential locations in the effective tool environment.
- Unexpected network destinations fail closed for network-constrained cells.
- Timeout, idle timeout, process-tree termination, disk exhaustion, and crash cleanup leave no active worker or locked worktree.
- The primary checkout remains byte-for-byte unchanged after mock success and failure cases.
- Worker code cannot mutate Git refs, config, hooks, indexes, remotes, sibling worktrees, or the repository's shared worktree metadata.

### Deferred

- Kubernetes, remote VMs, SSH workers, or multi-host scheduling.
- General-purpose arbitrary shell authorization.
- Tool-enabled live execution where subscription-auth isolation is not yet demonstrated.

## Phase 4 - Repository Maintenance Worker v1

### Deliverables

- Add deterministic candidate discovery before any model call.
- Implement tracer bullets in increasing risk order:
  1. formatting-only changes;
  2. lint fixes;
  3. type-check fixes;
  4. deterministic test repair;
  5. evidence-backed bounded bug fixes;
  6. bounded housekeeping.
- Freeze task definition, repository snapshot, baseline failures, acceptance commands, and allowed diff before dispatch.
- Require the worker to return a structured patch/report rather than a success assertion.
- Apply and validate the candidate only inside its worktree.
- Compare pre/post command results and reject false greens, skipped checks, new failures, protected-path changes, generated noise, and unexplained dependency changes.
- Store a local review bundle: patch, command evidence, raw outcome dimensions, risk notes, runner/profile/billing evidence, and reproduction instructions.
- Keep the candidate in its detached disposable worktree and export a reviewable patch. Do not create a branch, commit, push, open a PR, merge, or deploy automatically.

### Acceptance criteria

- Formatting and lint tracer bullets pass end to end with deterministic mock workers.
- Verification demonstrates that a passing exit code with missing expected evidence is rejected.
- Baseline-known failures are not misreported as fixed.
- Every accepted change is reproducible from the frozen base and task inputs.
- No accepted patch touches protected or out-of-scope paths.
- No model call occurs when deterministic discovery finds no eligible work.
- Live subscription trials, if later authorized, use sanitized repositories/fixtures, the exact gate, current billing attestation, and a unique worktree.

### Deferred

- Local branch creation, commits, or other Git-metadata mutation require a
  separately designed action/resource policy and are not assigned a blanket
  class in advance. GitHub push or PR creation, merge, release, and deployment
  are external or otherwise high-impact actions that conservatively derive to
  Class 3; all remain disabled.
- Dependency upgrades with lifecycle or supply-chain impact.
- Ambiguous product changes without an executable oracle.

## Phase 5 - Bounded worker roles and multi-agent flows

### Deliverables

- Define versioned roles with minimal capabilities:
  - controller: deterministic flow controller, not a model role by default;
  - planner: produces a bounded task DAG or implementation proposal;
  - implementer: edits one isolated worktree;
  - verifier: runs deterministic registered checks and cannot edit;
  - reviewer: inspects frozen task, patch, and evidence in a fresh context;
  - recovery worker: receives a classified failure and bounded repair brief.
- Treat these as RBAC subject attributes and enforce static/dynamic separation
  of duties: an implementer cannot review, approve, verify, or promote its own
  candidate; a reviewer cannot edit it; workers never acquire the controller
  role; recovery receives only a strict subset of the failed attempt's
  authority. Role eligibility never overrides the contextual ABAC decision.
- Pass schema-validated artifact references between roles. Agents never communicate through unrestricted chat or shared mutable memory.
- Default child context to isolated. Fork prior conversational context only when explicitly justified and recorded.
- Set controller-enforced depth, child, concurrency, turn, context, and attempt limits. Recommended initial maximums are depth 2, four concurrent workers globally, and two repair attempts.
- Children cannot change profile, permission, billing lane, repository registration, or spawn policy.
- Children cannot assign their own role or trusted attributes, and delegated
  authority must be a strict subset bound to the child's exact work item.
- Completion goes through the durable outbox; the parent/controller verifies status and artifacts before advancing.
- Cascade cancellation through every active descendant.
- Use independent review where capacity permits. Reviewer rejection may create one bounded repair task; exhaustion becomes `blocked`, not an infinite loop.

### Acceptance criteria

- Fan-out, depth, attempts, turns, and concurrency cannot exceed policy under adversarial model output.
- A child cannot address another child, invoke an external channel, or widen its capabilities.
- Parent restart does not lose child completion or advance twice.
- Reviewer context excludes implementer hidden transcript and receives only declared artifacts/evidence.
- Rejection/repair cycles terminate at the configured bound.
- Separation-of-duty violations and attempts at role confusion fail closed and
  produce auditable decisions.
- Same-lane failover preserves the immutable task/context/base snapshot and records a fresh attempt.

### Deferred

- Open-ended agent societies or peer-to-peer messaging.
- Worker-selected agents, profiles, tools, or budgets.
- Unbounded recursive delegation.

## Phase 6 - Curated skills, memory, and self-improvement

### Deliverables

- Adopt an AgentSkills-compatible instruction format while keeping repository policy authoritative.
- Add a local curated skill manifest containing source, version, full-directory
  digest, supported tasks, required binaries, capabilities, writable paths,
  network needs, action/resource/consequence requirements, derived class,
  compatible profiles, and verification fixtures.
- Treat every imported skill as untrusted supply-chain input:
  - stage outside active roots;
  - reject symlinks, path traversal, binaries, install hooks, undeclared scripts, and credential requests;
  - pin exact source and digest;
  - show the diff and capability envelope;
  - require human approval before activation;
  - never auto-update.
- Keep executable plugins disabled initially. Instruction skills cannot grant tools or permissions.
- Treat MCP tool annotations and comparable plugin metadata as
  provenance-bearing hints only. A reviewed local registry derives the
  effective action/resource/consequence envelope for each concrete invocation;
  unknown or mismatched tools remain disabled and annotations never lower a
  requirement or authorize a retry.
- Separate durable knowledge into:
  - append-only evidence and observations;
  - curated factual/project memory with provenance, confidence, freshness, and namespace;
  - procedural skills loaded only when relevant.
- Keep billing, permission, identity, protected-path, and promotion policy outside agent-writable memory.
- Use SQLite FTS5 retrieval by default. Any later semantic retrieval must be local, deterministic enough to test, and incapable of triggering paid inference.
- Extend the existing self-improvement lifecycle:

```text
collect evidence -> classify failure -> propose versioned variant
-> visible + held-out benchmark -> regression and safety checks
-> human review -> explicit promotion -> rollbackable release
```

- Improvement workers may propose prompts, profiles, role instructions, skills, retrieval settings, or routing priors. They cannot edit active policy or promote themselves.

### Acceptance criteria

- A malicious or malformed skill fixture cannot escape staging, request credentials, add dependencies, or become active.
- Skill activation is reproducible from a reviewed digest.
- Tool metadata alone cannot grant a capability, reduce containment, or turn an
  indeterminate authorization result into a permit.
- Memory from one repository/role is not visible to another unless an explicit redacted projection is configured.
- Retrieved memory is marked as untrusted evidence and cannot override current instructions.
- A proposal with any protected-set regression cannot be promoted.
- Promotion requires an explicit operator action and produces a rollback target.
- Self-improvement tests and benchmarks use mocks/local deterministic workers only by default.

### Deferred

- Public skill marketplaces and automatic skill installation.
- Agent-authored direct changes to active `SKILL.md`, prompts, profiles, or router policy.
- Cloud embeddings or AI memory APIs.

## Phase 7 - Capacity-aware unattended loop and soak gates

### Deliverables

- Run deterministic monitors and candidate discovery continuously while invoking models only for queued eligible work.
- Add per-subscription capacity state, reset estimates where observed, circuit breakers, exponential cooldowns, and fairness across repositories.
- Revoke or re-evaluate outstanding decisions when billing, capacity,
  approvals, policy, isolation, network, or circuit attributes change.
- Schedule high-risk or context-heavy tasks only when adequate verified included capacity exists.
- Continue local indexing, verification, cleanup, audit, and queue maintenance while subscription workers are unavailable.
- Add operator-visible metrics:
  - accepted tasks per observed included-capacity unit;
  - false-green and regression rate;
  - human setup/review/correction time;
  - queue age and throughput;
  - retries and intervention;
  - runner/profile/capacity availability;
  - containment, credential, and policy violations;
  - orphan/lost/duplicate task counts;
  - local CPU, memory, disk, and wall time.
- Run a 24-hour mock-only accelerated/real-time soak, then a seven-day local soak. Any live subscription portion remains separately operator-gated and may be omitted without invalidating controller reliability testing.

### Acceptance criteria

- At least 20 representative repository tasks are exercised, with a target of at least 16 accepted.
- Zero false greens, paid-route starts, out-of-cell writes, credential disclosures, unbounded loops, duplicate promotions, or consequential external actions occur.
- Controller restart, machine sleep/wake, runner crash, limit exhaustion, low disk, and duplicate wake scenarios recover deterministically.
- Subscription limit exhaustion pauses until reset and never consumes purchased credit or overage.
- Queue and resource use remain bounded for seven days.
- Every accepted result has reproducible evidence and remains a local review candidate.

### Deferred

- Automatic OS service installation; provide reviewed install instructions only after soak evidence.
- External channels and dashboards.
- Permission Classes 2 and 3.

## Phase 8 - Optional frontend and read-only ingress evaluation

This phase is conditional and is not required for the worker OS core.

### Deliverables

- Compare a minimal native local UI with an optional OpenClaw frontend adapter.
- If OpenClaw is evaluated, pin a reviewed version and expose a narrow, authenticated local protocol containing only:
  - submit a task request whose eventual derived summary cannot exceed the current Class 0/1 ceiling;
  - query redacted task/flow status;
  - request cancellation;
  - retrieve a local review-bundle reference.
- Normalize all sender/channel/content fields into an immutable untrusted-input envelope.
- Keep delivery disabled or names-only until separately reviewed.
- Threat-test replay, sender confusion, prompt injection, malformed payloads, status leakage, and attempts to mutate billing/profile/policy state.

### Acceptance criteria

- Removing or stopping the frontend does not affect supervisor correctness or state integrity.
- The frontend cannot invoke a harness, access credentials, approve work, or write authoritative state directly.
- Every accepted request passes the same task, billing, permission, isolation, and routing gates as CLI-originated work.
- Ingress failures cannot create duplicate tasks or bypass idempotency.

### Deferred

- Messaging sends, calendar/email writes, remote browser control, GitHub writes, and other Class 2/3 actions.
- Making OpenClaw a required dependency or source of truth.

## Cross-phase verification strategy

Every phase must add deterministic tests before enabling its feature flag.

Required test families:

- state-machine and schema tests;
- billing-route, overage, capacity, and contradiction fixtures;
- property-oriented path, symlink, argv, idempotency, and revision tests;
- crash, timeout, process-tree, orphan, stale-lease, and restart fault injection;
- malicious repository, prompt-injection, skill, output, and credential fixtures;
- worktree/container containment checks;
- false-green and protected-regression tests;
- router ordering tests proving correctness/risk outranks efficiency and efficiency outranks latency;
- tests proving no ineligible route can win regardless of score;
- authorization parity and default-deny tests, including missing/stale/
  contradictory attributes, changed resource digests, expired approvals,
  decision replay outside scope, role confusion, revocation, and lying or
  absent tool annotations;
- receipt tests proving the exact enforced action and obligations are
  reproducible without persisting credentials;
- migration tests from the current SQLite schema;
- CLI smoke tests with feature flags disabled and enabled under mock mode.

The standard verification remains:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests
```

Optional live tests must be individually selected, use sanitized fixtures and fresh sessions, require the exact live gate plus current route, identity, capacity, paid-continuation, profile, isolation, environment, attestation, and circuit evidence, and never run in normal CI.

## Delivery discipline

- Implement each phase as tracer-bullet slices that keep the mock path passing.
- Prefer narrow SQLite migrations and adapters over whole-component replacement.
- Keep new external dependencies at zero unless a concrete containment/runtime need is documented and approved.
- Preserve reviewable local changes; do not commit, push, publish, or install schedules automatically.
- Do not begin a later phase merely because code exists. Its prior phase acceptance criteria must have recorded evidence.
- Treat benchmark and soak results as raw evidence; do not hide correctness, risk, intervention, usage, and latency inside one score.

## Explicit long-term deferrals

The following remain outside this plan unless separately authorized and designed:

- separately billed APIs, cloud inference routes, overage, and purchased-credit continuation;
- multi-tenant hosting;
- remote/distributed worker fleets;
- autonomous merge, push, deployment, release, purchasing, sending, or account mutation;
- arbitrary third-party plugins and skills;
- n8n or another general workflow platform;
- unrestricted browser automation;
- fully autonomous policy or self-code promotion;
- claims that the system replaces human accountability for consequential decisions.

## Primary research inputs

- OpenClaw gateway and protocol: <https://docs.openclaw.ai/gateway> and <https://docs.openclaw.ai/gateway/protocol>
- OpenClaw tasks and Task Flow: <https://docs.openclaw.ai/automation/tasks> and <https://docs.openclaw.ai/automation/taskflow>
- OpenClaw deterministic workflows: <https://docs.openclaw.ai/tools/lobster>
- OpenClaw sub-agents and skills: <https://docs.openclaw.ai/tools/subagents> and <https://docs.openclaw.ai/tools/skills>
- OpenClaw security model and advisories: <https://docs.openclaw.ai/gateway/security> and <https://github.com/openclaw/openclaw/security/advisories>
- NanoClaw isolation: <https://github.com/nanocoai/nanoclaw/blob/main/docs/SECURITY.md>
- IronClaw capability-oriented security: <https://github.com/nearai/ironclaw>
- Hermes procedural learning: <https://github.com/NousResearch/hermes-agent>
- OpenFang autonomous worker packages: <https://github.com/RightNow-AI/openfang>
- OpenAI Codex credit behavior: <https://help.openai.com/en/articles/12642688-using-credits-for-flexible-usage-in-chatgpt-freegopluspro-sora>
- Anthropic Claude usage-credit behavior: <https://support.claude.com/en/articles/12429409-manage-usage-credits-for-paid-claude-plans>

## Related project documents

- [OpenClaw ecosystem assessment](openclaw-ecosystem-assessment.md)
- [Architecture](architecture.md)
- [Runtime authorization model](authorization-model.md)
- [Routing](routing.md)
- [Subscription-only policy](subscription-only-policy.md)
- [Roadmap](roadmap.md)
