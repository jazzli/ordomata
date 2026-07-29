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
  The runtime still enforces that interim numeric representation. The three
  narrow profile-backed exact built-in-mock PEPs for Class 1 admission,
  dispatch, and local-candidate publication also derive and enforce the same
  ceiling from exact ABAC requests; the dispatch policy itself remains limited
  to Class 0/1, while every new attempt reaching it still requires Class 1
  admission. Broader target coverage remains incomplete.
- No production inbox, calendar, Drive, Slack, or similar connectors.
- No n8n dependency.
- No purchased-credit, subscription-overage, AI API SDK, cloud-model, or metered fallback.
- No recurring schedule installation.
- No supervisor worker dispatch: the implemented foreground loop is a
  mock-only control-plane tracer and cannot claim or execute queued work.
- Repository-proposal selection and binding are inert evidence only. They
  require an existing `repository-proposal-disabled` run to remain `CREATED`
  and cannot admit, claim, dispatch, or execute it.
- No live harness comparison in normal tests or setup; no live Codex-versus-Claude comparison has been completed.
- No Git remote mutation.

Detailed component and verification status is updated in the session completion report and README.

## Authorization status

**Implemented foundations, shadow coverage, and three narrow PEPs:** deterministic controller-owned
fail-closed gates; the current Class 0/1 approval ceiling; role, task,
capability, route, billing, identity, capacity, environment, isolation, and
circuit checks; narrow harness configurations; and append-only run evidence.
These checks are distributed, and the current `ApprovalPolicy` decides from
`PermissionClass`. Standard-library ABAC request/decision/action-receipt value
types, a deny-by-default current-stage evaluator, conservative class
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
The inspector can prove ordering against persisted admission, billing, running,
runner-event, accounting, and terminal markers. New ordinary Chief-of-Staff
attempts have a privacy-bounded controller binding, schema-v2 execution
accounting, and a schema-v5 publication shadow. Current schema-v6 exact-mock
attempts retain schema-v5's Class 1 admission decision and durable succeeded
receipt plus schema-v4's dispatch and publication chains, while adding bounded
canonical task-intent lineage to the authoritative binding. Schema-v4 exact-
mock attempts retain their separate publication decision and linked schema-v3
enforcing pre-effect/action receipts before and after the local candidate
mutation; schema-v1-v3 paths retain schema-v2 non-enforcing publication
receipts. Historical unbound task attempts remain readable as legacy
shadow-only evidence and are not reinterpreted as receipt-complete. The
controlled comparison path has its own separately bounded pre-effect and
post-effect receipt pair.

For a new profile-backed ordinary Class 1 attempt using the exact
controller-owned `MockRunner` implementation, a schema-v6 binding declares
separate admission, dispatch, and local-candidate publication enforcement
coverage and commits the canonical task-intent preimage, its controller-owned
source, and exact digests needed for replay. The run record and private
directories created first are inert
controller scaffolding. After required selection and binding records, the
controller builds a fixed admission CREATE request, inherits the task's full
consequence vector, persists its decision, rebuilds current authoritative
inputs, compares the exact persisted wrapper, independently replays policy,
checks freshness, and requires a durable succeeded receipt. Class 0,
unsafe/high-impact, non-permit, stale, evaluation, or evidence failures stop
before the admission shadow and billing. After admission and billing, the controller builds
an exact mock-only execute request, evaluates a fixed versioned policy,
exactly reads back the selection, task-attempt binding, mock billing assessment
and decision, and then rebuilds from current authoritative inputs. Before
`RUNNING`, it requires the resolved task intent and digest to equal the durable
lineage, independently
constructs the canonical wrapper and compares it with the retained persisted
payload, independently replays the fixed policy, checks finite freshness,
supported obligations, the derived Class 0/1 ceiling, the independent legacy
gate, and unchanged shipped runner class and instance boundaries. It requires
exact `RUNNING` readback and
repeats the current binding, policy, freshness, and runner-ownership checks
immediately before invocation. A non-permit, evaluation failure, stale
decision, unsupported obligation, or uncertain pre-effect evidence invokes no
runner. Once invocation starts, a linked terminal action receipt and execution
accounting must read back exactly before publication; unprovable receipt
persistence after the effect quarantines the attempt. Read-only inspection of
schema v6 derives dispatch and publication intent only from that authoritative
binding and never from a shadow preimage. It requires exact terminal linkage for non-
permits and rejects any dispatch
receipt that contradicts a claimed pre-effect stop. Only a validated
identity-matched no-process mock
result may receive a succeeded receipt. Accepted, credential-clean output then
passes a second fixed Class 1 policy that binds the dispatch receipt,
content-addressed accounting, billing disposition, and exact candidate. It
reuses the v6 lineage, checks equality with the captured shipped resolver, and
independently replays the shipped evaluator and fixed policy. Its decision and
pre-effect receipt read back exactly. Immediately before staging, the binding,
decision, and pre-effect record read back again; the permit is rebuilt and a
new post-replay action time must be fresh. The reconciled filesystem receipt is
the canonical
action receipt. These PEPs do not cover unprofiled schema-v1 history,
historical/live schema-v2 selections, historical schema-v3/v4 admission,
comparison trials, supervisor workers, general or live admission, shared
publication, tools, commands, or external effects.

These lineage slices advance only current exact-mock task bindings to schema v6;
they change no enforcing decision-event or action-receipt schema and add no
authority. Frozen schema-v1 through v5 histories retain their prior
interpretation.

The repository-registration boundary preserves standalone
`schemas/repository-registration.schema.json` schema v1 and adds
`schemas/repository-registration-v2.schema.json`. The pure
`ordomata.repository_registration` validator dispatches on an exact integer
version and reduces a strict controller-supplied ordinary Git root to stable
repository/filesystem references. The
validator accepts exact argv-array (not shell-text) declarations for format,
lint, type-check, test, and build; canonical protected and allowed repository-
relative POSIX paths; bounded CPU, memory, process, workspace, output, artifact,
wall, and idle limits; fixed local-container/network-disabled isolation; and
patch-only review policy. `.git`, `.ordomata`, and `.agentops` are
unconditionally protected, and case-insensitive aliases of controller-owned
paths, traversal, or symlink escapes fail closed. Registration versions are
bounded canonical SemVer; credential/billing option names, known shell
launchers, and protected relative executables are rejected. Its evidence
exposes only bounded digest references, version metadata, and fixed
`validation_mode: "read_only"`, `dispatch_enabled: false`, and
`authority_granted: false` facts. Schema v2 additionally requires bounded
`generated_paths` and `vendor_paths` arrays under `path_policy`. They are
sorted, digest-bound literal deny/classification roots strictly below allowed
paths. Cross-category nesting, case aliases, protected/sensitive overlap,
traversal, glob/expansion syntax, symlinks, and special files fail closed;
missing leaves remain valid and are never created. The declarations attest
neither generation nor vendor provenance and cannot hide a diff or authorize a
change. The validator remains pure, creates no state, and authorizes or executes
nothing.

The separate `ordomata.repository_proposal` evidence layer implements
`bind_repository_proposal_attempt(state, *, run_id, proposal_digest,
registration)`. It freshly revalidates the registration and accepts only a
canonical proposal digest for an existing immutable Class 0/1
`repository-proposal-disabled` run with no history beyond its initial
`CREATED` event. It appends exactly one schema-v1, content-addressed, statusless
`repository_registration_selection` event and then exactly one schema-v1,
content-addressed, statusless `repository_proposal_attempt_binding`. Each
append atomically requires current status `CREATED` and the exact ordered
predecessor event IDs. Commit failures roll back before reconciliation; the
complete history, event identifiers, payloads, order, registration links,
proposal digest, and status must then read back exactly from one consistent
SQLite snapshot. Exact retry and exact selection-only interruption are
reconciled; conflicting or ambiguous history fails closed.

The two events contain privacy-bounded digest/reference and version/control
metadata only; no registration body, raw proposal content, identifier, path,
argv, workspace, run directory, or artifact content is stored. They reuse the
existing `run_events` table and add no SQLite migration, CLI, sample
registration, run creation or status transition, authorization decision or
action receipt, worktree, Git/subprocess/command invocation, worker or
supervisor dispatch, profile route, billing/capacity/circuit change, harness
call, or live eligibility. The proposal chain remains pinned to frozen
registration evidence v1 and rejects v2 before any event append. Baseline
command results, bare executable resolution/content attestation, and future
`shell=False` execution remain deferred.

The third slice is the library-only `ordomata.repository_proposal_inspection`
API `inspect_repository_proposal_evidence(database_path, *, run_id)`. It proves
one caller-named durable run and returns a privacy-bounded
`RepositoryProposalInspectionReport` with fixed
`inspection_scope: "single_run"`, `run_ref`, permission class, current status,
`clean`, `coverage`, `truncated`, a capped inspected-event count, optional
validated proposal/registration/repository references and version, optional
selection/binding digests and sequences, and bounded
`RepositoryProposalInspectionFinding` objects containing fixed codes only.
Its mapping also fixes read-only inspection/validation, no repair, disabled
dispatch, and no granted authority, and reports `evidence_complete` and finding
count.
`coverage: "incomplete"` is limited to an exact protocol-recoverable
`CREATED`-only or `CREATED`-plus-selection evidence prefix. The exact clean
three-event chain is
`complete`; every other history is `invalid`. `clean` requires complete,
untruncated, finding-free evidence. More than four events sets `truncated`
because the capped inspection cannot cover the history. This does not claim
whole-database coverage.

The inspector stages the exact signed main file and optional WAL into owner-
private temporary storage under a fixed controller-owned 512 MiB combined
ceiling; oversized state fails before copy. A no-WAL snapshot opens through an
immutable read-only URI, while an in-budget WAL pair opens read-only. SQLite
opens only the staged identity, and before/after source signatures detect
concurrent changes. One query-only SQLite
snapshot then covers the immutable run and ordered events. It independently
replays exact cardinality/order, content-addressed event and canonical payload
digests, durable-run, proposal, and registration-component linkage, and fixed Class 0/1,
runner, `CREATED`, read-only, dispatch-disabled, and no-authority semantics. It
never instantiates `SQLiteStateStore`, creates source schema or sidecars,
repairs state, or revalidates the registration against the live filesystem.
Fixed findings and errors expose no raw identifiers, SQLite diagnostics, paths,
argv, registration documents, proposal content, workspace/run-directory
values, or artifact content. It is not an external tamper anchor.

A missing database or caller-named run raises fixed `RecordNotFoundError`;
invalid run input raises fixed `ValidationError`; and unreadable, malformed,
schema-incompatible, or concurrently changed state raises fixed
`ConfigurationError`. Rejected values and SQLite diagnostics are never echoed.

Inspection creates no source database/schema/sidecar or migration and persists
no run, status, event, authorization decision, or action receipt. It creates no
worktree and performs no Git/command/process invocation, worker or supervisor
dispatch, route/profile selection, billing/capacity/circuit change,
harness/network action, or live eligibility.

The fourth slice is the library-only
`ordomata.repository_proposal_admission` API
`evaluate_repository_proposal_admission_shadow(database_path, *, run_id,
evaluated_at)`. It freshly invokes the independent inspector and accepts no
caller-provided report, class, request, policy, or evaluator. Only a clean,
evidence-complete, complete, untruncated, finding-free exact three-event Class
0/1 report proceeds to shadow evaluation. A nonclean report returns no request,
policy, or decision: its status is `not_evaluated`, its effect is
`indeterminate`, and its fixed block code is
`inspection_not_clean_complete`. Run-binding, evaluator, or replay failure
also produces an inert fixed failed/indeterminate result.

The fixed Class 0 projection is a local `READ` observation under a
class-specific policy with unenforced audit-receipt plus read-only obligations.
The fixed Class 1 projection is a local `CREATE` nomination under a
class-specific local-draft policy with unenforced audit-receipt plus
isolated-local-only obligations. Each policy enables exactly its projected
class, verb, operation, and resource type plus the controller role, local
control-plane boundary, disabled network, and local non-AI route. The request
digest-binds the privacy-safe inspection mapping and validated
proposal/registration/repository lineage. The active evaluator, a captured
built-in replay, and the controller's exact expected decision must agree.

Any returned shadow permit remains descriptive. The mapping fixes authority,
enforcement, admission/action, receipt, evidence persistence, repair, dispatch,
route, billing, and obligation enforcement to false. There is no CLI,
persistence, source-state change, event, durable authorization record,
worktree, Git/command/process invocation, worker/supervisor dispatch,
route/profile selection, billing/capacity/circuit fact, harness/network action,
or live eligibility, and no raw path/identifier, argv, registration/proposal
content, SQLite diagnostic, workspace/run-directory value, or artifact content
is exposed.

The fifth repository-proposal slice is the library-only
`ordomata.repository_proposal_admission_verification` API
`verify_repository_proposal_admission_shadow_mapping(value)`. It requires an
exact built-in `dict`, takes a bounded detached JSON snapshot, and independently
mirrors the inspection contract. Evaluated inputs replay the Class 0/1 request,
policy, manual expected decision, and captured evaluator; inert inputs must
match an exact state-machine branch, and a reported replay failure must retain a
constructible replay boundary. Every finding is fixed and value-free.
`contract_valid` reports internal consistency only; it proves neither
authenticity, durable reinspection or source truth, current freshness, nor
authority. Coherent forgery or replay remains indistinguishable without a
trusted anchor. The verifier has no persistence, repair, enforcement,
authorization, worker, repository, command, route, billing, network, harness,
dispatch, or live effect.

The sixth bounded Phase 3 slice is the schema-v2 exclusion contract described
above. Nonempty categories are included in the canonical path-policy and
registration digests while raw paths remain absent from evidence. It adds no
ignore-file inference, automatic exclusion discovery, persistence, repair,
execution, worker, route, billing, network, harness, dispatch, authority, or
live effect. Schema v1 and its proposal-evidence meaning remain frozen.

The next recommended bounded slice is pure schema/validator support for
controller-supplied baseline command-result attestations in schema v3,
still without command execution or proposal-lineage widening.

Started profile-backed Chief-of-Staff attempts additionally persist exactly
one content-addressed `task_execution_selection` event between `created` and
their task binding. New built-in-mock attempts use schema v6; frozen schema v5
retains admission, dispatch, and publication without self-contained dispatch
lineage, schema v4 means dispatch plus publication, historical dispatch-only
mock attempts use schema v3, and live or historical selected attempts use
schema v2. The privacy-safe record binds a
captured routing
policy clock, exact task/context/authorization refs, canonical candidates,
fixed rejection codes, raw score tiers and evidence-source markers, safe
billing projections, and selected profile version/configuration/overrides
digests. Bounded profile IDs remain visible solely to replay the governed
lexical tie-break. Every source candidate is rebound to the controller-loaded
catalog, and selected billing security semantics must match a fresh runner
preflight that remains valid through the recorded attempt horizon. The binding
and admission/dispatch parameter digests link the selection. A
required append that cannot be proven exact blocks before execution; one that
commits then raises is accepted only after exact readback. The read-only
inspector independently checks policy/candidate digests, filters, scores,
ranking, selected linkage, cardinality, and ordering while projecting no raw
candidate data. Selection is evidence, not authority; on the narrow built-in-
mock path it is one required input to the separate enforcing decision. The
deterministic permission, billing, environment, isolation, circuit, and live-
run gates remain separate and authoritative. Rejected pre-run selections and
`route` previews do not create run evidence.

Ordinary accounting persists only a digest reference for runner version text
and a fixed controller-known execution-mode label. Its billing and accounting
events use deterministic identifiers with exact commit readback, so an
ambiguous local audit write cannot silently strand an attempt before
publication.
The inspector also reports a fixed incomplete-history finding when either
bound path reaches billing or accounting without a controller-owned terminal
record; pre-billing task attempts remain eligible to be in progress.

**Adopted architecture and remaining runtime migration:** the
[runtime authorization model](authorization-model.md) defines versioned
subject/action/resource/environment/consequence requests, default-deny
decisions with distinct `permit`, `defer`, `deny`, and `indeterminate`
effects, policy and evidence digests, obligations, continuous enforcement,
RBAC role constraints, adapted confidentiality/integrity/availability impact
labels, untrusted MCP claim handling, and conservatively derived Class 0-3
summaries. There is still no general/live/comparison/supervisor admission or
shared-publication PDP, RBAC
separation-of-duty enforcement, approval resumption, mediated command/tool
coverage, supervisor worker permit, or live-harness ABAC enforcement. The three
persisted enforcing decision/action-receipt chains are limited to Class 1
admission of a new profile-backed exact built-in-mock attempt, its dispatch,
and its owner-private local-candidate publication. The
controlled comparison path now records a
durable Class 0 run/event stream for every started trial, including a schema-v2
digest-only binding, bounded billing/accounting facts, runner-event ordinals,
and schema-v3 non-enforcing admission and immediate pre-dispatch shadows. Its
owner-private review artifact remains a separate controller-owned Class 1
effect observed by a schema-v4 non-enforcing publication shadow and linked
schema-v2 pre-effect/action-receipt events. The read-only inspector cross-checks
their bindings, source evidence, independently recomputed billing-disposition
digest, request projection, cardinality, and order. Coverage declarations name
the expected instrumentation; the inspector, not the declaration, determines
whether an observed history is complete.
Ordinary candidate and comparison private publication also have durable
namespace reconciliation: staged bytes and directory entries are fsynced,
verified parent and inode descriptors remain leased through receipt
reconciliation, unexpected hard-link aliases fail closed, action receipts use
deterministic identifiers for exact post-error readback, and unresolved
temp/final/receipt state is quarantined rather than reported as an ordinary
failed write. Ordinary immutable artifact metadata is treated as a proposal
until a succeeded action receipt proves publication; commit-then-raise metadata
and receipt writes are reconciled by exact readback.
Controller-derived post-run billing disposition governs quarantine, circuit
scope, output withholding, and terminal reporting; adapter flags cannot make
unknown or changed evidence succeed. Historical schema-v1 comparison evidence
remains backward-compatible partial coverage with an explicit publication gap.
Comparison publication observations and receipts remain non-enforcing; the
ordinary schema-v4/v5/v6 publication chain is the narrow exception and grants no
shared, promotion, live, comparison, Class 2/3, or external authority.

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
Subsequent additive migrations record canonical, non-enforcing supervisor ABAC
shadow observations at flow admission, attempt claim, operator control
transition, and sticky cancellation, including exact request/decision digests,
conservatively derived class, legacy executability, and parity. The read-only
supervisor audit verifies those records from one consistent SQLite snapshot,
independently recomputing requests and decisions while checking coverage/order,
exact append-only schema, and migration provenance. Frozen migration baselines
exclude pre-shadow flow, attempt, control-event, and cancellation-request
identifiers so historical records are not falsely treated as missing evidence.
Control shadows bind the previous control revision; cancellation shadows bind
the exact source flow revision and deterministic local state/outbox effect.
Sticky cancellation is conservatively irreversible, derives Class 3, and is
retained as a denied legacy-parity mismatch without blocking the existing
operator safety path. This does not enable Class 2/3; current policy remains
Class 0/1 only.
Startup verifies canonical baseline, migration-ledger, and supervisor schema
objects, including non-prefixed triggers targeting owned tables, before use.
Fresh baseline creation and exact pre-ledger baseline adoption are atomic; all
schema statements and frozen migration rows commit together or not at all.
Existing databases must carry a contiguous known v1-v4 migration prefix whose
identities agree with the installed supervisor tables. Baseline foreign keys,
the atomic first `created` event, and subsequent status-transition lineage are
also checked. Missing guards, partial schemas, ledger gaps, future versions,
identity changes, and version/schema disagreement fail closed without repair;
WAL mode is not selected until the baseline has been accepted.
Read-only status and audit do not create absent state. Reconciliation is
preview-first and apply requires the exact current plan digest. The
`ordomata supervisor` command group exposes enqueue and explicit control,
cancellation, inspection, recovery, and local completion-receipt operations;
`ordomata supervise` runs the fenced loop only in the foreground.

This is not a completed supervisor. The foreground loop deliberately never
calls the claim library or a runner because its exact claim, worker-dispatch,
and mediated-tool boundaries lack authoritative ABAC coverage and verified
repository containment. The narrow ordinary mock PEPs supply neither. It
starts no live model, worker subprocess, network action, repository worker,
Class 2/3 action, or OS schedule. Queue execution, worker cells, boundary-
specific authorization enforcement, and soak evidence remain planned.

## Implemented vertical slice

- `ordomata doctor`: value-free, non-model diagnostics for Codex, Claude, mock, paths, SQLite/FTS5, route, current capacity, paid-continuation protection, account-identity verification, attestation status, and fixed blocker categories.
- `ordomata billing-attest --runner codex|claude`: TTY-only, exact-confirmation refresh of short-lived account-bound evidence after independent machine inspection; private atomic storage contains no raw identity, numeric balance, token, or diagnostic free text.
- `ordomata profiles` and `ordomata route`: versioned execution profiles, exact billing lanes, capability filters, and auditable ranking.
- `ordomata task-validate` and `context-inspect`: strict contract/schema loading and immutable local context construction.
- `ordomata.repository_proposal.bind_repository_proposal_attempt`: library-only
  controller selection and exact durable binding of a freshly revalidated
  repository registration plus explicit canonical proposal digest to an
  existing `CREATED` dispatch-disabled sentinel run; it appends exactly two
  statusless content-addressed events and does not execute or authorize work.
- `ordomata.repository_registration`: pure, version-dispatched validation of
  frozen schema v1 and schema v2; v2 adds bounded literal generated/vendor
  carve-outs whose raw paths remain digest-only in evidence and which provide no
  ignore, execution, persistence, or authority behavior.
- `ordomata.repository_proposal_inspection.inspect_repository_proposal_evidence`:
  library-only, source-preserving proof of one caller-named proposal run from
  one read-only SQLite snapshot; the bounded report distinguishes exact
  protocol-recoverable prefixes, a complete three-event chain, and every invalid
  history with fixed privacy-safe finding codes and no repair or authority.
- `ordomata.repository_proposal_admission.evaluate_repository_proposal_admission_shadow`:
  library-only, fresh-inspection Class 0 `READ`/Class 1 `CREATE` admission
  observation under fixed class-specific policy; nonclean evidence remains
  indeterminate and even an exact shadow permit grants no authority, persists
  nothing, and performs no action.
- `ordomata.repository_proposal_admission_verification.verify_repository_proposal_admission_shadow_mapping`:
  library-only, bounded detached verification of an untrusted exact-dict shadow
  mapping through an independent contract mirror, evaluated-input manual
  decision/evaluator replay, and exact inert-branch validation; fixed findings
  and `contract_valid` establish internal consistency only, not authenticity,
  freshness, authority, or durable truth.
- `ordomata auth-inspect`: source-preserving, SQLite read-only inspection of
  baseline schema/history and frozen migration-ledger integrity, authorization
  shadow integrity, authenticated freshness, legacy and authority-ceiling
  parity, and expected Chief-of-Staff boundary coverage/order. Global state
  findings are bounded value-free codes and never trigger repair; an exact
  pre-ledger baseline remains readable without mutation.
- `ordomata demo`: end-to-end deterministic Chief of Staff Lite run with append-only state and a validated local artifact.
- Billing Hard-Stop v2: independent route/capacity/protection/balance axes; strict account-bound, short-lived attestations; a necessary-but-insufficient live gate; and explicit rejection of credits, overage, APIs, cloud routes, and unknown evidence.
- Post-run billing disposition: normalized capacity/paid/account-change evidence, typed paid-capacity and incremental-AI-charge accounting, quarantine before promotion, durable append-only capacity state, atomic capacity persistence before lease release, restart-safe capacity blocking, and account/profile circuit breakers.
- `ordomata run --profile ...`: explicit live-adapter entry point guarded by diagnostics, current evidence, environment/profile/isolation checks, a closed durable circuit, and the exact live gate.
- `ordomata compare-plan`: identical-snapshot, repeated, block-randomized, fresh-session plan creation without execution.
- `ordomata compare-run`: preflight-all controlled execution for explicit named profiles using one immutable sanitized Class 0 snapshot, fresh adapters/sessions/empty workspaces, randomized repetition blocks, and append-only digest-bound per-trial audit streams. Schema-v3 admission/dispatch and schema-v4 Class 1 private-publication shadows remain non-enforcing; schema-v2 pre-effect/action receipts bind private review artifacts. Raw reports and a separate human-review template perform no ranking or promotion and retain partial results after a stop condition.
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
