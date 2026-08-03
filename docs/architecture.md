# Architecture

## Purpose

Ordomata is a local, single-operator control plane for governed autonomous work. It runs neutral tasks through first-party subscription-backed coding harnesses and is intended to support both repository maintenance and information-synthesis workflows without purchased product credits, subscription overage, separately billed model APIs, or cloud inference routes.

Source, tests, plans, fixtures, and deliberately sanitized configuration may be
published in the public [`jazzli/ordomata`](https://github.com/jazzli/ordomata)
repository. GitHub is not the runtime queue or state store: private inputs,
credentials, account or billing attestations, databases, logs, workspaces, and
run artifacts remain local and ignored, and the orchestrator does not push
automatically.

The control plane is deterministic. Coding harnesses are bounded workers used only for stages where model judgment materially improves the result.

## Identity and compatibility boundary

`Ordomata` is the product name, pronounced **or-doh-MAH-tuh** (four syllables,
primary stress on “MAH”; IPA: `/ˌɔːr.doʊˈmɑː.tə/`). The repository,
distribution, import package, and CLI use `ordomata`. New runtime state uses
`.ordomata/`. A sole legacy `.agentops/` root is selected and used in place
without moving the root or rewriting existing records; normal versioned SQLite
initialization may append migration metadata. The presence of both roots is an
integrity conflict and fails closed. This preserves append-only records and
their original absolute-path provenance.

The canonical live gate is `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1`. The legacy
`AGENTOPS_ALLOW_SUBSCRIPTION_RUNS` spelling is accepted only as an exact,
non-conflicting compatibility alias. Both names are controller-only and are
excluded from worker environments.

The renamed distribution does not expose legacy `agentops` import-package or
CLI aliases. Operators must quiesce and remove pre-rename installed runtimes
before starting Ordomata because old code cannot honor the dual-root integrity
check. A legacy-only state root remains in place pending a separately verified
offline migration.

Some v1 protocol identifiers retain the former namespace because they are
inputs to persisted hashes, migration verification, or append-only shadow
evidence. These include the account-fingerprint domain separator, supervisor
baseline-migration digest seed, current shadow-policy/controller/source IDs,
v1 JSON Schema `$id` URIs, and the existing Codex billing-probe client label.
Future branded protocol identifiers require a new explicit version; existing
records are never rewritten for cosmetic reasons.

## System boundary

The orchestrator owns:

- task definitions and versions;
- context selection and immutable snapshots;
- billing-route enforcement;
- child-process environments;
- permissions and approvals;
- scheduling, leases, supported-limit validation, and wall timeouts;
- durable mock-only flow admission, supervisor control/flow/attempt revisions,
  sticky cancellation, fenced claims, local completion delivery, and recovery
  inspection;
- structured-output validation;
- evaluation and comparison;
- append-only run history;
- routing and human-gated profile-promotion policy.

Harnesses may synthesize, prioritize, plan, critique, review, or produce a local draft. They cannot change billing policy, promote themselves, widen permissions, modify historical records, install schedules, or perform consequential external actions.

## Runtime authorization

The adopted target is a deterministic, deny-by-default ABAC decision aligned
with NIST SP 800-162. The controller evaluates authenticated subject, concrete
action, canonical resource, and current environment attributes against a
versioned policy. A project-specific consequence vector records confidentiality,
integrity, and availability impact plus reach, destructiveness, reversibility,
sensitivity, and blast radius. Roles such as controller, planner, implementer,
verifier, reviewer, and recovery are versioned RBAC subject attributes with
separation-of-duty constraints; a role never grants authority by itself.

This remains principally a target architecture, not a claim of general ABAC
coverage. The first three narrow authoritative PEPs now apply only to new
profile-backed ordinary Class 1 attempts using the controller-owned in-memory
mock runner implementation. Subclasses and instances with rebound runner
boundary methods cannot receive those permits. After
the run record, private run directories, selection, and binding exist as inert
controller scaffolding, the admission PEP constructs a fixed Class 1 CREATE
request for the isolated attempt, inherits the task's full consequence vector,
persists its decision, rebuilds the request from current controller inputs,
compares the exact persisted wrapper, independently replays the fixed policy,
and appends a durable succeeded admission receipt. Class 0, unsafe/high-impact,
non-permit, stale, or unprovable admission evidence stops before the admission
shadow, billing preflight, dispatch, or `RUNNING`. The dispatch PEP constructs
a separate exact `runner.execute` request, evaluates a fixed mock-only policy,
and requires exact readback of the selection, task-attempt binding, mock
billing assessment, and decision. Current attempts use a schema-v6 binding
whose bounded canonical task-intent lineage is part of the binding digest.
Before `RUNNING`, the PEP rebuilds from current authoritative inputs, requires
the current controller-resolved intent and digest to equal that durable
lineage, independently constructs the canonical wrapper and compares it with
the retained persisted payload, independently replays the fixed policy, checks
finite freshness, and rechecks exact runner ownership, including the unchanged
shipped class and instance boundary definitions. The exact `RUNNING` record
must then read back
before a second ownership, binding, policy, and freshness check immediately
precedes invocation. A linked terminal action receipt must read back exactly
before publication can proceed; if its persistence is unprovable after the
runner effect, the attempt is quarantined. Only a validated identity-matched
no-process mock result can produce a succeeded receipt. Its execution
accounting must also read back exactly before publication. If that result is
accepted and credential-clean, the controller constructs a second exact
local-candidate CREATE request from the existing schema-v6 lineage. It compares
that lineage with the captured shipped resolver, independently replays the
shipped evaluator and fixed policy, and persists its decision and enforcing
pre-effect record with exact readback. Immediately before staging, it exactly
rereads the binding, decision, and pre-effect record, rebuilds the permit,
captures a new post-replay action time, and requires that time to remain fresh.
Its existing
descriptor-anchored reconciliation chain carries the canonical enforcing
action receipt. Existing
`PermissionClass` and distributed deterministic eligibility gates remain
independent prerequisites and defense in depth. Task contracts may declare a
typed task-effect action, resource, and consequence vector independently of
that class. The Chief of Staff path evaluates task intent non-authoritatively
at admission and runner/model dispatch. At local-candidate publication it uses
a truthful controller-owned local-create projection even when the task intent
is read-only, while conservatively inheriting task protection, sensitivity,
and confidentiality/integrity/availability impact, then appends canonical
policy/evidence digests, legacy-result parity, and
independent authority-ceiling parity. These observations
remain non-permits and cannot authorize execution or publication;
shadow-decision persistence remains best-effort. Schema-v3 mock attempt
bindings declare dispatch enforcement; frozen schema-v4 bindings add
local-candidate publication enforcement; schema-v5 bindings add Class 1 task-
admission enforcement; and current schema-v6 bindings retain all three chains
while carrying the bounded canonical task-intent lineage required for
authoritative dispatch and publication replay. Their enforcing decisions and
action receipts
are distinct from the shadows. Unprofiled schema-v1 bindings, live or
historical schema-v2 bindings, historical schema-v3/v4/v5 bindings, and every
comparison path retain their prior meaning.
These lineage slices use the existing enforcing decision-event and action-
receipt schemas and advance only the current exact-mock attempt binding to
schema v6; they add no authority. The dispatch PEP remains
limited to Class 0/1 requests for the exact profile-backed controller-owned
`MockRunner`, while every new attempt that reaches it still requires the Class
1 admission permit.
Separately, one narrow PEP mediates only an exact reversible local
supervisor control transition. It binds the prior control revision and intended
next revision, retains only a digest of the operator identity, persists and
exactly rereads its fixed Class 1 decision before the append-only control event,
then appends and rereads an action receipt in the same SQLite transaction. It
does not authorize flow admission, cancellation, claims, worker dispatch,
repository work, network access, or any Class 2/3 effect. A separate fixed
Class 1 PEP now mediates only an immutable deterministic-mock flow admission.
It persists and exactly rereads a privacy-bounded permit before the flow and
initial queued revision, then appends and rereads its action receipt in the same
SQLite transaction. That permit controls only the local bookkeeping write, not
the requested task effect, and cannot authorize claims, cancellation, worker
dispatch, repository work, network access, or Class 2/3 effects.
A third fixed Class 1 PEP mediates only a local deterministic-mock supervisor
attempt claim. It binds the exact queued source and running target revisions,
flow and attempt digests, initial attempt/flow event references, control
revision, and digest-only controller/lease references. It persists and exactly
rereads its permit before any claim lease, attempt, or flow-revision write,
then appends and rereads an action receipt in the same SQLite transaction. It
cannot authorize worker dispatch, task execution, cancellation, repository
work, network access, or Class 2/3 effects.
A fourth fixed Class 1 PEP mediates only a local supervisor `created` →
`dispatching` bookkeeping append. It binds the exact running-flow and created
attempt source events, redacted active-lease snapshot, and generated target;
persists and exactly rereads its permit before the target event; independently
replays the fixed policy; and appends and rereads a succeeded receipt before
commit. It cannot authorize a worker, task execution, cancellation,
repository work, network access, or a Class 2/3 effect.
There is still no general, live, comparison, or supervisor worker-dispatch
admission PEP, live/shared
publication or promotion PEP, per-command/tool mediation,
approval-resumption path, supervisor worker permit, or live-harness ABAC
enforcement. Existing gates remain in force, and the migration cannot widen
the Class 0/1 ceiling.

The target separates operator-controlled policy administration, authoritative
attribute collection, pure policy evaluation, and controller-owned enforcement
at admission, dispatch, every mediated command/tool call, artifact publication,
and any future external action. Missing, stale, contradictory, or unknown
evidence is indeterminate and fails closed. Existing billing prohibitions are
mandatory deny rules that no approval or lower-precedence policy can override.
MCP annotations are provenance-bearing descriptive claims, never grants.

Target decisions use four distinct effects: `permit`, `defer`, `deny`, and
`indeterminate`. `Defer` means a named, satisfiable approval or prerequisite is
missing and supports a resumable waiting state; it does not weaken fail-closed
handling for indeterminate evidence. A versioned standing envelope may make a
precisely bounded Class 3 action routinely eligible, including an
action-specific irreversible effect, but each invocation still needs a fresh,
short-lived permit. Class 3 is an impact summary rather than an automatic
target-state block. The root-authority kernel—active authorization and billing
policy, authority expansion, audit/containment weakening, and credential
material—is never delegable to a worker. None of these Class 2/3 mechanisms is
enabled in the current runtime.

Class 0-3 remains useful only as a conservatively derived operator summary in
the target model. NIST AI RMF governs lifecycle risk and measurement rather
than per-action permission decisions; NIST SP 800-53 supplies control
traceability; and FIPS 199 impact terms are adapted without claiming that
individual actions receive FIPS categorizations. The request, decision,
enforcement, role, impact, status, and migration details are defined in the
[runtime authorization model](authorization-model.md).

## Execution flow

```text
trigger
  -> load neutral task version
  -> apply the current Class 0/1 compatibility gate and information needs
  -> construct immutable context pack
  -> inspect harness capabilities, route, account identity, and capacity
  -> require current paid-continuation attestation, no durable capacity stop,
     and closed billing circuit
  -> build sanitized child environment
  -> choose an eligible execution profile
  -> create the append-only run record, private directories, execution
     selection, and task binding as inert controller scaffolding; current exact
     mocks bind a bounded canonical task-intent lineage in schema v6
  -> for a new profile-backed exact built-in-mock Class 1 attempt only,
     persist an admission decision, rebuild/replay it at the boundary, and
     require a durable succeeded admission receipt
  -> append the non-authoritative Phase 1C task-admission observation
  -> inspect, persist, and exactly read back billing preflight evidence
  -> for that same narrow path, persist and exactly read back a fixed-policy
     decision for the exact mock runner invocation
  -> rebuild from current inputs, require exact current-intent/lineage equality,
     construct and compare the canonical wrapper, replay fixed policy, and check
     finite freshness and runner ownership
  -> transition to RUNNING and exactly read back that record
  -> append the non-authoritative task-effect dispatch-intent observation
  -> recheck current binding, fixed policy, finite freshness, and exact runner
     ownership immediately at the invocation boundary
  -> execute bounded harness or deterministic worker
  -> append and exactly read back the enforced mock action receipt when that
     narrow PEP applied; quarantine if post-effect persistence is unprovable
  -> normalize events and result
  -> perform post-run billing assessment
  -> record capacity/circuit outcome; quarantine on paid or unknown evidence
  -> validate output schema
  -> run deterministic evaluation
  -> append a shadow local-candidate observation bound to the validated bytes
     and digest, using the controller-owned local-create projection
  -> for the schema-v4/v5/v6 exact-mock paths, persist a separate fixed-policy
     Class 1 publication decision and enforcing pre-effect record
  -> recheck that permit immediately before the first staging mutation
  -> reconcile the local artifact, metadata, and integrated action receipt;
     historical paths retain non-enforcing receipt semantics
  -> require human promotion or external-action approval
```

Unknown billing, authentication, account identity, capacity, paid-continuation protection, capabilities, circuit, postflight, or terminal result state causes a blocked, failed, or quarantined run. It never causes a credit, overage, API, cloud, or mock fallback.

## Portable runner interface

Runner adapters expose capability detection, billing-route inspection, environment validation, execution, cancellation, and normalized events. The initial adapters are:

- `codex`: eligible only with verified ChatGPT-backed CLI authentication, a matching identity, current included capacity, zero usable paid-credit balance, and a current attestation that automatic top-up is disabled;
- `claude`: eligible only with a verified paid Claude subscription/OAuth identity, current included capacity, a current attestation that extra usage is disabled, and no API/cloud-provider route;
- `mock`: deterministic and always safe for tests;
- local deterministic workers: no model inference.

The CLI subprocess contract is the portability baseline. Provider SDKs are deliberately absent because model API routes are prohibited and first-party CLI authentication is the intended boundary.

## Harness, model, and settings routing

Routing separates four concerns:

1. **Harness** — the executable and subscription authentication boundary.
2. **Model** — a model identifier or detected harness default.
3. **Role** — triage, synthesis, implementation, recovery, or review.
4. **Execution profile** — versioned settings including permissions, reasoning intent, tools, timeouts, turn bounds, and context limits.

The router first applies non-negotiable eligibility filters:

- the billing assessment has high confidence and names the same runner and account as the current evidence;
- the route is allowed globally, by the versioned profile, and by the explicit routing lane;
- included capacity is currently available, paid continuation is proven disabled, and the applicable durable circuit is closed;
- harness and required capabilities are available;
- the profile is not cooling down;
- task permission and context fit profile limits.

It then ranks eligible profiles lexicographically by three non-interchangeable tiers: correctness/risk first, included-subscription efficiency second, and latency third. Efficiency observations are compared only within a compatible provider quota pool and unit; Codex and Claude capacity is not presumed commensurate. No provider-specific setting is assumed to have identical semantics on another provider. Adapters translate profile intent into supported flags.

Profile outcomes are evidence, not self-modifying policy. A routing or profile revision must be versioned, benchmarked, reviewed, and promoted by the operator.

For a started profile-backed Chief-of-Staff attempt, the controller now
content-addresses and appends a `task_execution_selection` record immediately
after the run's `created` marker and before the task binding. The record fixes
the routing-policy version and clock, immutable task/context/authorization
refs, canonical candidate set, safe billing projections, observed/prior/
unavailable metric markers, fixed rejection codes, ranking, selected profile
version/configuration, and translated-overrides digest. The bounded profile ID
is retained to replay the governed lexical tie-break; raw model names,
settings, account/subscription values, diagnostics, prompts, paths, and
environment values are represented only by digests or omitted. Every source
candidate must still match the controller-loaded catalog, and the selected
source assessment must match fresh horizon-valid runner preflight evidence. A
schema-v6 binding links current exact built-in-mock admission, dispatch, and
publication enforcement and adds canonical task-intent lineage; frozen schema
v5 retains those three chains without self-contained lineage, schema v4 retains
dispatch-plus-publication, schema v3 retains its historical dispatch-only
meaning, and schema v2 remains for live and historical selected attempts. Both
admission/dispatch observations
link the selection digest. Exact persistence is required before execution; the
read-only
inspector independently recomputes shape, digests, filters, scores, rank,
cardinality, cross-links, and order. This record is descriptive evidence, not
an authorization decision, and cannot replace fresh billing, environment,
isolation, circuit, or legacy Class 0/1 checks. A rejected pre-run profile and
the read-only `route` preview create no run or routing ledger entry.

The target router may continuously update outcome estimates and shift bounded
traffic among already promoted, eligible profiles. A small explicit
exploration budget may sample under-observed promoted profiles, beginning with
Class 0/1 or reversible canaries and stopping on regression or circuit
signals. It may also use forecast-to-expire included capacity for valuable
queued maintenance, benchmarks, and exploration after preserving an urgent-
work reserve. Agents cannot define new settings, change safety floors or
objective ordering, promote profiles, or consume capacity merely to exhaust an
allowance.

## State and crash recovery

Run identity, task version, context snapshot, runner, and creation metadata are immutable. Billing assessments, capacity outcomes, billing-circuit transitions, state transitions, and artifact metadata are appended as immutable events. SQLite triggers prevent updates or deletion of historical run data. Mutable scheduler leases are separate operational records and do not rewrite history.

Dispatch-disabled repository proposals reuse that existing run-event substrate;
they add no table or SQLite migration. An existing immutable Class 0/1 run with
the fixed `repository-proposal-disabled` runner must contain only its initial
`CREATED` status before the controller may append a content-addressed
`repository_registration_selection` event and then a content-addressed
`repository_proposal_attempt_binding` event. Both are statusless, each append
atomically requires current status `CREATED` plus the exact ordered predecessor
event IDs, and the binding stores an explicit canonical proposal digest rather
than proposal content. Commit failure is rolled back before reconciliation.
Exact retry and selection-only interruption recovery succeed only when one
transactionally consistent SQLite read returns the exact event identifiers,
types, payloads, order, durable run linkage, and current status. This proves
local evidence persistence, not authorization, an effect receipt, dispatch, or
an external tamper anchor.

Independent proposal inspection stages the exact signed main file and optional
WAL into owner-private temporary storage under a fixed controller-owned 512 MiB
combined ceiling; oversized state fails before copying. A no-WAL snapshot opens
through an immutable read-only URI, while an in-budget WAL pair opens read-only.
SQLite opens only the staged identity, and before/after source signatures detect
concurrent changes. One query-only SQLite snapshot then covers the immutable run
and ordered events. It
never opens the mutating state-store abstraction, creates source schema or
sidecars, repairs history, or claims that one caller-named run proves whole-
database integrity.

A run is successful only when all of the following hold:

1. the process exits successfully;
2. the runner emits its documented terminal-success event;
3. the output matches the task schema;
4. deterministic evaluation passes.

Missing telemetry is `unavailable`, never zero.

Each completed attempt also records the adapter-authored harness version and execution mode, whether a harness process started, whether live model execution was observed, observed-or-unavailable subscription-capacity consumption, `paid_capacity_consumed`, `incremental_ai_charge`, the narrower `incremental_api_charge`, postflight disposition, and wall time. `incremental_api_charge: none` does not imply `incremental_ai_charge: none`; only a verified safe, matching postflight supports the latter. No per-run subscription dollar cost is invented.

Included-capacity exhaustion becomes an append-only `blocked_until_reset` observation and stops automatic retry. The atomic reservation checks account-global, account/profile, provider/profile, and provider-global capacity scopes as well as circuits. Reservation acquisition and completion sample controller time only after acquiring the SQLite write lock, so lock contention cannot admit an expired lease or finalize one from a stale pre-lock timestamp. A blocking capacity observation survives restart and can be superseded only by a strictly newer verified `available` observation after any recorded reset. Completion persists postflight capacity before releasing the dispatch leases. Paid, changed-account, or unknown post-run evidence quarantines the attempt and any output before promotion and opens the account/profile billing circuit. Later live dispatches fail while that circuit is open.

Only hard-stop events—billing risk, credential exposure, containment failure,
revoked authorization, cancellation, or a safety circuit—preempt an active
attempt. The controller first revokes every tool and capability; it may allow a
very short tool-disabled local checkpoint only when isolation can prove that
no filesystem, network, credential, or external action remains possible. It
then terminates the process tree and quarantines partial output.

Recovery starts from the last verified controller-owned workflow boundary in
a fresh session with a fresh authorization decision. It never resumes an
interrupted model session. Cancellation is terminal; billing-capacity work may
resume after fresh evidence; credential, containment, policy, and integrity
events require reconciliation and a new attempt. Resource drift invalidates
the old permit and creates a new candidate against the new version. Prior
artifacts remain lineage evidence and are reusable only after explicit
revalidation.

## Context pipeline

Large corpora are processed as:

```text
ingest -> normalize -> hash -> deduplicate -> index -> retrieve -> filter
       -> bounded context pack -> synthesis -> validation -> evaluation -> report
```

Source content is always untrusted data. Context packs preserve source IDs, timestamps, hashes, selection rules, exclusions, size information, task and prompt versions, and a snapshot hash.

Authenticated connector data and model output remain tainted. Bounded typed
projections, provenance labels, structural capability separation, and
deterministic authorization remain effective even when prompt-injection
detection misses an attack. Tainted material may be retained as namespaced
evidence, but not promoted into trusted memory, instructions, or skills
without the reviewed promotion path. Repository/project/role/trust-domain
namespaces prevent cross-project retrieval by default; retention expiry erases
payloads while preserving non-sensitive tombstones.

Worker sessions are ephemeral and reconstructed from declared digest-bound
inputs and approved memory projections. Additional context is requested by
information need through the controller and returned as an immutable,
scope-checked context delta. A delta invalidates future permits bound to the
old context. Repository and connector registrations version their
source-of-truth, freshness, precedence, and reconciliation rules; unresolved
decision-critical conflicts defer, while proven-immaterial conflicts do not.
Repository-local instruction files are scoped, digest-bound guidance and
cannot alter controller policy or authority.

Credential-shaped source content or metadata is rejected before indexing. Accepted model output is scanned again before the controller may write an artifact; suspect output is quarantined. Full source bodies exist only in the local context index and immutable prompt snapshot; durable run history stores neither prompts nor source content.

## Live process isolation

Live workspaces must be non-symlinked children of a unique, effective-user-owned
mode-`0700` run directory. For Chief of Staff Lite they start empty, so source
material is available only through the bounded stdin prompt.

- Codex uses a read-only sandbox, `never` approval mode, strict/ignored user configuration, ignored exec-policy rules, ephemeral sessions, and structured JSONL. Class 1 currently means the controller may write a validated local draft; it does not grant the harness filesystem writes. The adapter extracts the final structured answer from the bounded, redacted in-memory event stream and does not ask Codex to persist a raw last-message file.
- Claude Code uses safe mode, an explicitly empty settings-source list, strict empty MCP configuration, no Chrome, no session persistence, disabled skills, and an empty built-in tool list. It returns structured output; the controller performs the only artifact write.

Current diagnostic and first-party harness children are launched without a
shell as leaders of new POSIX sessions. The controller immediately verifies
the leader's session/process-group identity, drains stdout and stderr under
fixed byte and line ceilings, bounds retained JSONL events and parse failures,
and reaps the direct child only after bounded original-group TERM/KILL cleanup.
Normal direct exit is also reconciled: a descendant that remains in the
original group makes the execution outcome unknown even if cleanup removes it.
Cancellation during process creation is deferred until any returned child has
been reconciled, and unsupported process-group hosts fail before diagnostics or
billing reservation. Diagnostic probe results without affirmative cleanup
evidence, or with a timeout even if the child exits cleanly during cleanup, are
unusable. A containment-specific diagnostic failure aborts capability
discovery rather than being treated as an optional missing result.

Before command construction, the controller pins the run-directory inode with
a no-follow directory descriptor. Controller schema creation and output
open/unlink operations use validated leaf names relative to that descriptor;
raw output is unlinked while its verified regular-file descriptor is still
open, before decoding or validation. A renamed or replaced pathname therefore
causes fail-closed output withholding and cannot redirect the controller's read
or deletion. Live harnesses accept only the exact sealed controller event sink:
a fixed-ceiling, count-only in-memory callback with no I/O, locks, or extension
hooks. Arbitrary synchronous or asynchronous callbacks are rejected before
reservation or launch. Production orchestration persists only ordinal event
observations after runner execution finishes, so SQLite contention cannot delay
the live process timeout, cleanup, postflight, or reservation finalization.

The operation wall timeout covers process creation and stdin delivery once the
host spawn operation resolves; stream and process-group cleanup then use a
small controller-owned allowance inside the billing-reservation margin. That
margin separately budgets cleanup, bounded postflight inspection, durable
finalization including its retry, and scheduling slack. Evidence validity is
rechecked after reservation acquisition through the execution-and-cleanup
horizon; a postflight budget overrun becomes unknown evidence, quarantine, and
a broad circuit. A wedged operating-system spawn cannot be abandoned safely
because it might
later return an untracked child, so cancellation waits for spawn resolution
before cleanup. This is an explicit hard-wall limitation, not a success case.
Stream, event capture or deferred event-persistence, output-file, cleanup, or
launch uncertainty causes sanitized failure; after a possible live launch it
also causes output withholding, UNKNOWN charge accounting, quarantine, and a
broad billing circuit.

This mechanism is only POSIX **process-group lifecycle control**. A descendant
can escape the original group with `setsid()` or `setpgid()`, so positive group
cleanup evidence is not process-tree containment, a sandbox, or the planned
repository-worker isolation boundary. It grants no authority and does not
satisfy the worker-dispatch gate below. A non-escapable container/cgroup or
equivalent platform backend with post-run reconciliation remains required for
unattended repository work.

The current child-facing output-schema argument remains a pathname governed by
the adapter sandbox. Pinning controller file operations does not make that
pathname immutable against an adversarial worker; a future worker-cell handoff
must close that separate boundary.

For repository work, the target worker-cell interface is backend-pluggable and
declares minimum filesystem, process, network, credential, and resource
assurances. Containers, OS sandboxes, or later VMs are eligible only when
observed preflight state attests the effective user, mounts, writable paths,
network policy, limits, credential absence, and lack of control sockets;
post-run evidence verifies containment and cleanup. The controller never
silently downgrades an assurance requirement.

The current `ordomata.worker_cell_containment` v1 implementation is only the
inert contract seam for that future boundary. It binds a bounded, digest-only
schema-v4 registration-evidence snapshot to the declared local-container,
network-disabled assurance profile and to typed preflight/postflight evidence
shapes. Its only backend is a deterministic no-I/O mock: it creates no cell,
does not inspect a host or repository, starts no process, persists no state,
and always reports containment unproven with execution and dispatch disabled.
Even a shape-complete mock assessment is non-authoritative. A real backend
requires a separately reviewed contract version with observed host evidence;
the controller cannot reinterpret this mock as successful containment.

[`ordomata.repository_worker_job_tree`](../src/ordomata/repository_worker_job_tree.py)
now supplies a separate v1, no-I/O source-bundle contract for the controller
materialization stage. It binds bounded in-memory regular-file entries to the
exact schema-v4 registration evidence, raw path-policy, and resource-limit
snapshots by digest; it rejects protected, generated, vendor, Git-metadata,
credential-shaped, ambiguous, and over-budget entries. Its output contains no
source bytes or paths and permanently reports that materialization,
reconciliation, worker execution, and dispatch are unimplemented or disabled.
It does not itself freeze a checkout, create a directory, copy a file, or
prove containment.

[`ordomata.repository_worker_job_tree_snapshot`](../src/ordomata/repository_worker_job_tree_snapshot.py)
now provides the preceding controller-only snapshot step. It walks an explicit
source root through no-follow descriptors, rejects symlinks, hardlinks,
casefold ambiguity, protected and credential-shaped paths, detected in-capture
source drift, and over-budget files before retaining detached in-memory bytes.
Its public projection contains digest/count evidence only. Capture writes no
source data,
does not materialize a job tree, and is not registration-bound or
authoritative until the separate source-bundle contract is derived from fresh
v4 registration evidence.

[`ordomata.repository_worker_job_tree_materialization`](../src/ordomata/repository_worker_job_tree_materialization.py)
implements the next, still library-only Class 1 copy boundary. It accepts only
an exact detached snapshot, its matching source-bundle contract, and a
caller-provided existing absolute target root that is empty, owner-mode `0700`,
not itself a symlink, and neither the captured source root nor its ancestor or
descendant. It traverses that root through held no-follow
descriptors, creates only the detached source entries, uses private `0700`
directories and executable files plus `0600` regular files, and verifies the
resulting namespace, bytes, modes, identities, root binding, and absence of
unexpected entries before issuing a digest-only receipt. On ordinary failure it
rolls back only entries it can still prove it created; an unknown entry or
uncertain cleanup is not deleted or reported clean. The primitive does not
prove caller ownership of the root beyond those local checks, exclude a
same-UID writer or mount alias, retain immutable worker input, reconcile a
candidate, persist state, create a worker or container, or enable execution or
dispatch.

[`ordomata.repository_worker_job_tree_reconciliation`](../src/ordomata/repository_worker_job_tree_reconciliation.py)
now supplies a separate pure comparison seam. It accepts only an already
detached bounded candidate bundle together with the exact snapshot, contract,
materialization receipt, path policy, and resource limits; it rechecks that
complete lineage and derives private deterministic add/modify/delete operations.
Its public evidence contains only digest/count references. It reads no
candidate filesystem, cannot show that supplied bytes originated in the
materialized job tree, and does not apply or persist a patch, provision a
worker cell, authorize work, or enable execution or dispatch.

[`ordomata.repository_worker_job_tree_candidate_snapshot`](../src/ordomata/repository_worker_job_tree_candidate_snapshot.py)
now supplies the preceding read-only candidate-tree reader. It accepts only an
active materialization lease and exact input lineage, traverses the held root
through no-follow descriptors, rejects root replacement, symlinks, hard links,
unsafe modes, unexpected empty directories, unapproved paths, and unstable
double reads, and emits bounded private bytes with digest/count-only evidence.
It does not prove candidate origin, worker containment, same-UID writer
exclusion, lifecycle cleanup, patch safety, authorization, execution, or
dispatch. Those custody and lifecycle properties remain separate gates.

[`worker-dispatch-security-design.md`](worker-dispatch-security-design.md)
records the proposed non-enabling VM-contained-container design, the exact
future worker PEP binding, and the evidence and adversarial-test gates that a
real backend must satisfy. It is not an implementation approval or a runtime
capability.

Once that containment is proven, an implementation worker may use a general
shell inside its disposable cell and bounded temporary storage. It receives no
host shell, shared Git metadata, credentials, or control socket. Network is
denied by default and may be opened only through a task-specific,
controller-managed egress envelope defining destinations, protocols, methods,
time, and transfer limits, with SSRF/DNS-rebinding defenses and credentials at
the proxy boundary. Locked registered dependencies and required lifecycle
scripts may run inside the cell; dependency changes are separate candidates,
and network closes after fetch unless independently authorized. A verified,
content-addressed dependency cache is read-only to workers, with private
staging before controller promotion. Registered exact commands remain the
authoritative acceptance checks.

## Ordinary local-candidate publication

Every new Chief-of-Staff attempt records a privacy-bounded binding before its
admission shadow. For a schema-v6 exact-mock attempt, the run record and
private run directories that precede the binding are inert controller
scaffolding: they cannot authorize billing, dispatch, `RUNNING`, or
publication. The binding covers the controller-resolved typed authorization
intent as well as immutable run inputs; schema v6 also retains its strict,
bounded canonical preimage and source inside the binding digest so dispatch and
publication inspection no longer need a shadow preimage. Dispatch binds the
persisted preflight billing assessment. After runner execution, schema-v2
accounting projects the identity and billing disposition fields needed to
recompute one sanitized billing digest. Runner-provided version text is reduced
to a content reference, execution mode is restricted to controller-known
labels, and billing/accounting events are content-addressed for exact ambiguous
write reconciliation. An accepted, credential-clean candidate then receives a
schema-v5 non-enforcing publication shadow. On the schema-v4/v5/v6 exact-mock
paths, the controller also persists a separate fixed-policy publication
decision and a schema-v3 enforcing pre-effect receipt before the first
artifact-directory mutation. Frozen schema-v4/v5 retain the same enforcing
publication chain; schema-v1-v3 paths retain schema-v2 non-enforcing pre-effect
receipts.

The controller stages owner-private bytes under a deterministic name, opens the
parent chain without following mutable symlinks, and retains verified parent
and inode descriptors through receipt reconciliation. It fsyncs the file and
namespace, reconciles immutable artifact metadata by exact readback, promotes
without overwrite, and verifies the final bytes, mode, size, inode, parent
identity, and expected hard-link count. A deterministic action receipt records
succeeded, failed, cancelled, or unknown outcome. For schema-v4/v5/v6 enforcing
attempts it is schema v3 and embeds the canonical ABAC action receipt;
schema-v1-v3 paths retain the schema-v2 legacy-gate receipt. Proven
missing receipts roll back only the owned final inode; an unexpected surviving
link or any unprovable metadata, staging, final-name, directory-sync, receipt,
or terminal state quarantines the attempt. An artifact metadata row alone is
proposed evidence, not proof of publication. Historical ordinary attempts
without the binding retain their prior shadow-only interpretation.
For both bound paths, billing or accounting evidence without a later
controller-owned terminal record is an attention-required incomplete history;
a bound attempt that has not reached billing may still be legitimately in
progress.

For a selected controller-owned mock profile, the current binding is schema v6
and declares three separate chains. The first is an exact Class 1 admission
CREATE request and fixed-policy decision followed by current-input rebuild,
exact persisted-wrapper comparison, independent policy replay, freshness
checking, and a durable succeeded admission receipt. It inherits the full task
consequence vector; Class 0, unsafe/high-impact, non-permit, stale, evaluation,
or evidence failures stop before the admission shadow and billing preflight.
The second is billing assessment, exact mock-dispatch request and fixed-policy
decision, with exact readback for the selection, task-attempt binding, billing,
decision, and `RUNNING` evidence. Before `RUNNING`, the controller rebuilds
current authoritative inputs, compares the resolved task intent and digest with
the canonical lineage committed by the binding, independently constructs and
compares the canonical wrapper,
independently replays the fixed policy, checks finite freshness and the Class
0/1 ceiling, and rechecks exact runner ownership. It repeats the binding,
policy, freshness, and ownership check immediately before invocation. A
terminal action receipt linked to the decision and enforced action, followed
by execution accounting, must read back exactly before publication; an
unprovable post-effect receipt quarantines the attempt. A deny, defer,
indeterminate result, stale permit, unsupported
obligation, ceiling mismatch, or unproven pre-effect evidence invokes no
runner. Read-only inspection accepts a non-permit or pre-effect stop only with
its exact terminal phase/status and no contradictory dispatch receipt or
downstream effect evidence.
The third binds that succeeded dispatch receipt, content-addressed accounting,
billing disposition, exact artifact and destination, accepted evaluation, and
credential scan into an independent Class 1 publication request. It reuses the
same v6 lineage, requires equality with the captured shipped resolver, and
independently replays the shipped evaluator and fixed policy. Its required
decision and pre-effect append read back exactly. At the final pre-mutation PEP,
the binding, decision, and pre-effect record read back exactly again; only then
does the controller rebuild the permit, capture the action-start time, recheck
freshness, exact obligations, and both Class ceilings, and stage. A non-permit
or uncertain readback creates no staged bytes or metadata. Schema-v1 unprofiled,
schema-v2 selected/live, and historical schema-v3/v4/v5 histories remain valid
with their previous semantics. For v6, the read-only inspector validates task
intent for both dispatch and publication only from the authoritative binding
lineage; shadow observations are inspected separately and cannot supply or
repair that preimage.

None of the three chains authorizes shared, remote, active-policy, promotion,
deployment, live-harness, supervisor-worker, or Class 2/3 effects. The existing
Class 0/1 gate remains an independent prerequisite and cannot be widened by any
PEP.

The repository-registration boundary preserves the standalone
`schemas/repository-registration.schema.json` schema-v1 contract and adds the
separate `schemas/repository-registration-v2.schema.json` and
`schemas/repository-registration-v3.schema.json` contracts, all frozen, plus
the separate `schemas/repository-registration-v4.schema.json` contract. The pure
`repository_registration` validator dispatches on an exact integer version.
From a controller-supplied ordinary Git
root it derives stable repository and filesystem references, validates exact
argv-array (not shell-text) declarations for format, lint, type-check, test, and
build, and canonicalizes protected and allowed repository-relative POSIX paths.
`.git`, `.ordomata`, and `.agentops` are always protected; traversal and symlink
escapes fail closed, including case-insensitive aliases of those controller-
owned paths. Registration versions are bounded canonical SemVer.
Credential/billing option names, known shell launchers, and protected relative
executables are rejected. The contract also fixes bounded CPU, memory, process,
workspace, output, artifact, wall, and idle limits; a local-container, network-
disabled isolation requirement; and a patch-only policy that forbids branch,
commit, push, PR, and promotion actions. Its privacy-bounded evidence contains
bounded digest references, version metadata, and fixed
`validation_mode: "read_only"`, `dispatch_enabled: false`, and
`authority_granted: false` facts rather than local paths or declarations.

Schema v2 adds required, bounded `generated_paths` and `vendor_paths`
arrays to the path policy. Entries are canonical literal repository-relative
deny/classification roots strictly below exactly one allowed root, never glob,
ignore, discovery, or matching rules. They are sorted and digest-bound; overlap
within or across categories, protected or credential-sensitive overlap,
case-fold aliases, traversal, expansion syntax, symlinks, and special files
fail closed. Missing leaves are accepted without creation. Generated
classification attests no reproducibility, and vendor classification attests
no provenance, integrity, or license. Neither category hides changes or grants
authority. Schema v1 remains unchanged, and the existing proposal-evidence
chain remains pinned to registration evidence v1, so v2 through v4 fail before
any event append.

Schema v3 preserves the v2 path-policy semantics and requires a
controller-supplied baseline command-result block. It covers every declared
verification command exactly once by kind, identifier, and a domain-separated
digest of its exact canonical declaration. All observations share one bounded
opaque snapshot digest. Each observation carries bounded integer start and
completion timing and exactly one tagged termination: an exit code, a signal,
or a timeout carrying the controller-supplied `termination_confirmed: true`
assertion. Pass is derived only from an exited zero code; the
input cannot supply a separate success/status claim. The block admits no raw
output, output hash, environment, path, message, or arbitrary metadata.
Canonical result ordering follows the fixed command-kind and declaration order,
and the aggregate digest additionally binds the derived repository reference
and complete verification-command digest.

V3 validation proves only the block's internal shape, coverage, and linkage.
The snapshot and timing are opaque controller-supplied claims: the validator
does not authenticate them, compare them with the clock, recompute repository
content, resolve a bare executable or toolchain, or attest reproducibility.
Outward evidence adds only fixed controller-supplied source, an aggregate
baseline digest, bounded result count, and
`baseline_authenticity_verified: false` plus
`baseline_freshness_verified: false`; it exposes neither the snapshot nor
individual observations. Bare executable resolution and
executable/toolchain content attestation are not properties of this validator;
the separate direct-file measurement receipt described below does not change
those v3 facts. Future `shell=False` action-boundary execution remains deferred.
The validator remains pure, has no CLI or sample registration, creates no
state, and authorizes or executes nothing.

Schema v4 preserves the v3 baseline contract and adds one bounded
controller-supplied executable/toolchain identity claim for every declared
command. Each identity repeats the exact command kind, identifier, and
domain-separated command digest and carries only opaque
`executable_identity_digest` and `toolchain_identity_digest` values. The
validator canonicalizes claims in declaration order and derives a syntax-only
declared-executable reference bound to the exact command context, together with
the repository reference, complete verification-command digest, and exact v3
baseline aggregate digest. Those derived values bind the aggregate to its
current registration context; they provide no standardized or trusted digest
preimage or provenance. Cross-context transplantation can still validate but
produces a different aggregate, while same-context replay is indistinguishable.
Binding the baseline proves co-declaration only, not that its process used the
claimed executable or toolchain bytes.

Outward v4 evidence is aggregate-only: fixed controller-supplied source, one
bounded identity count, one aggregate digest, and explicit false facts for
authenticity, freshness, executable resolution, content verification,
toolchain completeness, and baseline-execution correspondence. It exposes no
individual identity or declared-executable reference. V4 identity-block
validation adds no PATH, PATHEXT, environment, runtime-cwd, executable metadata
or content, symlink, shebang, interpreter, launcher, module, plugin, dynamic-
loader, package, or version inspection and executes nothing. Existing
registration root and repository-relative path/executable safety checks are
unchanged. These claims are descriptive PIP input, never authorization or an
action receipt.

The separate library-only
`ordomata.repository_executable_resolution.resolve_repository_executables`
boundary produces an independently versioned schema-v1 receipt. It rejects
registration schemas v1 through v3 before inspecting resolution inputs,
freshly revalidates exact schema v4, and binds the registration, repository,
verification-command, baseline, opaque-identity aggregate, and resolution-
context digests. Its fixed source/scope pair is `controller_measured` and
`posix_nofollow_v1`. Bare names use only bounded, ordered, controller-supplied
absolute search directories; ambient `PATH`, relative or empty entries,
implicit cwd, and suffix expansion are excluded. Slash-containing declarations
initially require `cwd: "."` and resolve from the registered repository root.

Resolution pins directories, walks repository-relative components by
descriptor, rejects symlinks and non-regular, non-executable, or sparse
entries, hashes the complete selected direct file, and rechecks metadata,
namespace selection, search precedence, directory identity, and the
registration. Per-unique-file and aggregate content limits are 64 MiB and
256 MiB. These checks reject detected drift/races; they do not establish an
atomic view of a mutable filesystem. Evidence exposes only aggregate digests
and bounded counts and fixes `sequential_resolution_measurement_complete: true`
with `atomic_snapshot_verified: false`. The receipt is point-in-time and
non-reusable: it verifies neither current
freshness, provenance/authenticity, effective invocability, interpreter or
dependency identity, toolchain completeness, repository-snapshot/baseline
correspondence, nor future execution correspondence. It is not authority, an
action receipt, routing or billing evidence, or live eligibility and adds no
CLI, persistence, subprocess, or execution path.

The independently versioned library-only schema-v1
`ordomata.repository_executable_staging` boundary accepts an exact typed
`RepositoryExecutableResolutionReceipt` and a caller-owned, one-shot
`RepositoryExecutableStageLease`. Its fixed staging source/scope pair is
`controller_copied` and `posix_unlinked_readonly_v1`. The action-boundary
resolver pass captures
each unique executable into immutable in-process chunks by rereading the same
still-pinned source descriptor. Its complete canonical receipt must equal the
expected receipt before any staging mutation. After all staging, a second full
resolver pass must equal both; this brackets the local effect and rejects
detected source, namespace, registration, or search-precedence drift without
claiming an atomic filesystem view or current freshness.

The caller creates the staging root before invocation. It must be an exact
concrete absolute path, no-follow traversable, empty, owned by the effective
user, exactly mode `0700`, and lexically neither equal to, above, nor below the
registered repository or any search directory; exact-root inode aliases are
also rejected, while mount-alias exclusion remains false. The root is dedicated
to one controller process and one lease, without concurrent use. For each
unique source, the controller uses random exclusive no-follow creation for a
zero-length mode-`0600` file,
opens the future reader, then unlinks and fsyncs the name before copying any
captured bytes. The copy is hashed and fsynced, normalized to non-executable
mode `0400`, read back through the retained descriptor, and accepted only after
the writer closes. Successful leases retain only read-only, close-on-exec
descriptors to link-count-zero inodes; the caller root is empty again before
the receipt is issued. The resolver's 64 MiB-per-unique-file and 256 MiB
aggregate limits remain authoritative.

The receipt digest-binds the expected, action, and post-stage resolution
receipts, staging context, unique staged-file measurements, and declaration-
ordered command bindings. Only aggregate digests and counts appear in outward
evidence. Cleanup returns an independently validated outcome of `removed`,
`already_absent_verified`, or `unverifiable`; uncertain cleanup retains still-
verified private descriptors for conservative retry and never retries an
ambiguously closed descriptor number. Namespace absence and
descriptor release do not restore staging-root timestamps and are not secure
erasure.

This is a bounded Class 1 local staging primitive, not a PEP: the caller must
already possess any required authorization. Kernel/filesystem immutability,
same-UID exclusion, mount-alias exclusion, ACL privacy, absence of external
writable descriptors, atomic snapshot, current freshness, future-execution
correspondence, authority, authorization, action-receipt status, dispatch, durable control-
plane persistence, proposal-lineage extension, routing, billing, capacity,
circuit, live eligibility, and execution are explicit false facts. There is no
CLI, database/state, proposal, runner, worker, subprocess, or harness
integration. V1 does not protect against adversarial interference by another
process with the same UID, and the descriptor lease must never be handed to or
integrated with an untrusted same-UID worker.

The separate library-only schema-v1
`ordomata.repository_executable_runtime_manifest` boundary exposes
`inspect_staged_executable_runtime_manifest(expected_staging, *, lease)`. The
caller must supply an exact typed staging receipt and the active process-local
`RepositoryExecutableStageLease` anchored to that exact receipt; a different
PID, lifecycle state, canonical receipt, declaration binding, or retained-file
set fails closed. Under fixed `controller_inspected` /
`posix_staged_runtime_header_v1` semantics, the inspector fully rehashes every
private retained descriptor before and after reading at most 4,096 header bytes
and opens no source path. Its fixed byte-level classifications are `elf`,
`mach_o`, `posix_shebang`, `unsupported_shebang`, and `unknown`; an accepted
shebang directive is ASCII and capped at 255 bytes. A shebang classification
is syntax measurement only and neither interprets the directive nor resolves
an interpreter.

Each manifest entry is limited to digest/reference, classification, and bounded
measurement metadata; raw repository or staging paths, argv, file/header bytes,
and shebang directives are not exposed. Outward evidence is aggregate-only.
Inspection is read-only and neither changes lease state nor performs cleanup.
Effective invocability; interpreter identity, provenance, authenticity,
resolution, or compatibility; loader, library, module, plugin, package,
configuration, environment, dependency, runtime, or toolchain closure; and
manifest completeness remain unverified. Execution correspondence, authority,
authorization, action-receipt status, dispatch, proposal lineage, durable
control-plane persistence, worktree integration, routing, billing, capacity,
circuit, and live eligibility are explicit false facts. There is no CLI,
database/state, runner, worker, subprocess, harness, or execution integration.

The separate library-only schema-v1
`ordomata.repository_executable_shebang_requirements` boundary exposes
`inspect_staged_executable_shebang_requirements(expected_runtime, *,
expected_staging, lease)`. It accepts only exact typed runtime-manifest and
staging receipts plus the active process-local lease created by the same PID
and exactly anchored to that staging receipt. The Class 0 inspector freshly
reproduces the runtime manifest, requires exact correspondence with
`expected_runtime`, and remeasures the private leased descriptors while
opening no path. Independent frozen staging-v1 and runtime-manifest-v1
canonical mirrors validate exact lease anchoring and runtime shape instead of
trusting projection helpers. A local frozen-v1 mirror derives header,
shebang/directive-reference, and native ELF/Mach-O classification rather than
dynamically trusting upstream helpers. Every full descriptor remeasurement
recomputes the bounded header length and digest, runtime bindings must exactly
correlate command and staged-file fields with staging bindings, and the same
independent descriptor proof must repeat after the final runtime reproduction.
Under fixed `controller_inspected` /
`posix_staged_shebang_requirements_v1` semantics, it fixes
`native_binary_no_shebang` for ELF/Mach-O, `absolute_interpreter_token` or
`non_absolute_interpreter_token` for a valid POSIX shebang,
`unsupported_shebang`, or `unknown_runtime_format`. In this syntax-only
taxonomy, `absolute_interpreter_token` means only that the first token byte is
`/`; it claims no canonicality, usability, compatibility, or resolution, so
`/`, repeated or trailing slashes, and dot components remain absolute syntax.
The immutable
`RepositoryExecutableShebangRequirement`,
`RepositoryExecutableShebangRequirementBinding`, and
`RepositoryExecutableShebangRequirementsReceipt` records split a valid private
directive at the first contiguous ASCII space/tab boundary run. The whole run
is consumed, only its first byte determines the separator kind, and neither
the run nor the remaining opaque argument tail is interpreted. Only digest
references plus bounded byte counts are exposed for the token and tail.

The split is bounded syntax extraction only. It does not resolve or interpret
the interpreter token, `env`, `PATH`, the opaque argument tail, or kernel and
launcher semantics, and establishes no invocability, interpreter identity,
availability, provenance, authenticity or compatibility, dependency coverage,
or runtime/toolchain closure. The inspector neither mutates nor cleans up the
lease and creates no authority, authorization decision, action receipt,
durable persistence, proposal lineage, worktree, dispatch, routing, billing,
capacity, circuit, live eligibility, CLI/state/runner integration, subprocess,
harness, or execution path. Complete interpreter, dependency, and toolchain
closure remains required before any operational widening.

The thirteenth bounded Phase 3 slice is the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_resolution` Class 0 PIP.
`inspect_staged_executable_shebang_targets(expected_requirements, *,
expected_runtime, expected_staging, lease, expected_target_paths)` requires the
exact typed upstream receipts and their exactly anchored active same-PID lease.
The controller supplies the exact set of used canonical ASCII absolute target
paths in first-use order; it is a closed measurement expectation, not an
authority grant, root, or search path.
Fixed `controller_measured` /
`posix_absolute_shebang_target_nofollow_v1` semantics emit only
`native_not_applicable` for ELF/Mach-O or
`direct_absolute_target_measured` for a POSIX shebang. Any non-absolute,
non-canonical, not-exactly-expected, unsupported-shebang, or unknown-runtime
requirement invalidates the entire inspection.

Every unique direct target is opened from `/` through exact-spelling,
descriptor-relative, no-follow component checks. Two sequential complete
content measurements plus namespace, identity, and metadata rechecks must
produce matching results. Records and aggregate evidence expose no raw target
paths or target bytes; they contain only digest/reference fields, bounded
command identifiers/kinds and counts/sizes, fixed classifications/
dispositions, and schema-bounded evidence booleans/metadata. `/usr/bin/env`, when
exactly expected, is only
the measured direct shebang target: the opaque tail and any downstream program
selection remain uninterpreted. This is not semantic interpreter resolution,
dependency/environment/runtime closure, invocability, authority,
authorization, an action receipt, proposal lineage, worktree or route input,
live eligibility, subprocess creation, or execution, and it neither mutates nor
cleans up the lease. Two expected paths selecting the same inode fail, but
external hardlink or mount aliases, same-UID tampering, absence of external
writable descriptors, filesystem immutability, atomicity, and current freshness
remain unverified.

The fourteenth bounded Phase 3 slice is the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_staging` Class 1 boundary.
`stage_repository_executable_shebang_target_bytes` consumes the exact expected
target-resolution receipt, the complete requirements/runtime/staging receipt
chain, and the exactly anchored active same-PID executable-source lease. It
freshly revalidates the registration, exact search directories, and exact
target-path expectation. Its action-boundary inspection captures every unique
target through the same still-pinned descriptor used for measurement and must
exactly reproduce the expected resolution before mutation. The target root is
a dedicated caller-owned, exact concrete absolute, owner-mode-`0700`, empty
directory. Its authoritative protected roots come from the revalidated
registration, exact search directories and targets, and source staging root;
any overlap fails closed.

Each unique script target is copied once to an exclusive no-follow temporary
regular file. The pathname is unlinked and the target-root directory is
synchronized before any target bytes are written; the file is then fixed at
mode `0400`, synchronized, independently read back, and retained only through
a non-inheritable `O_RDONLY` descriptor after the writer closes. Command-to-
target correspondence remains exact and ordered. A native-only target set
creates a zero-file receipt and active lease without inspecting or mutating the
target root. Post-stage target resolution must equal both expected and action
receipts, and the complete upstream chain and source lease must still validate.
The immutable `RepositoryExecutableShebangTargetStagingReceipt` and outward
evidence exclude raw target paths, target bytes, temporary names, and
descriptor numbers. The `RepositoryExecutableShebangTargetStageLease` keeps
the caller-supplied root and private descriptor state process-locally and is
not canonical evidence; explicit
`cleanup_repository_executable_shebang_target_stage` releases the target lease.

This is temporary Class 1 byte staging, not a PEP or execution boundary. It
adds no authority, authorization decision, action receipt, durable persistence,
proposal/worktree lineage, dispatch, route, billing, capacity, circuit, live
eligibility, CLI/state/runner integration, subprocess, harness, or execution
path. It interprets no interpreter, `env`, `PATH`, argument, recursive
interpreter, loader, or dependency semantics and proves no immutability,
same-UID/external-writer or fork exclusion, external-hardlink or mount-alias
exclusion, atomic or current freshness, authenticity or provenance, effective
invocability, crash cleanup, or secure erasure. The Class 0/1 ceiling is
unchanged.

The fifteenth bounded Phase 3 slice is the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_runtime_manifest` Class 0
boundary. `inspect_staged_executable_shebang_target_runtime_manifest(
expected_target_staging, *, lease)` accepts only the exact target-staging
receipt object and its active same-PID target-stage lease. An independent
frozen target-staging-v1 canonical mirror verifies the complete receipt shape,
digest and file-reference anchors, original receipt and retained-file tuple
object anchors, unmodified lifecycle and cleanup state, and stored root
context. Under fixed `controller_inspected` /
`posix_staged_shebang_target_runtime_header_v1` semantics, a used root must
reproduce its owner-mode-`0700` context digest from the retained metadata
without reopening the root. Native-only input instead requires the exact
no-op context and preserves the complete requirements and command bindings
with zero target files.

For each retained target, the inspector verifies the mode-`0400`, link-count-
zero, non-inheritable `O_RDONLY` descriptor and fully remeasures its content.
It reads at most 4,096 header bytes with `pread`, requires them to equal the
header captured by that complete pass, revalidates the exact lease snapshot,
and fully remeasures every descriptor again. The fixed byte-level
classifications are `elf`, `mach_o`, `posix_shebang`,
`unsupported_shebang`, and `unknown`. Immutable
`RepositoryExecutableShebangTargetRuntimeFile`,
`RepositoryExecutableShebangTargetRuntimeRequirement`,
`RepositoryExecutableShebangTargetRuntimeBinding`, and
`RepositoryExecutableShebangTargetRuntimeManifestReceipt` records retain
digest-only target, upstream-requirement, and command correspondence. Direct
requirements become `direct_absolute_target_runtime_inspected`, native
requirements remain `native_not_applicable`, and shared targets appear once.
Outward evidence is aggregate-only and exposes no path, target or header bytes,
directive, temporary name, or descriptor number.

This boundary opens no source, target, or staging-root path, mutates or cleans
up no lease, and invokes no model or live harness. It does not recursively
resolve a shebang or interpret interpreter, `env`, `PATH`, or argument
semantics. It establishes no dependency, loader, environment, runtime, or
toolchain closure; current freshness, atomicity, authenticity, provenance, or
effective invocability; authority, authorization, action receipt,
proposal/worktree lineage, durable persistence, dispatch, routing, billing,
capacity, circuit, live eligibility, CLI/state/runner integration, subprocess,
harness, or execution fact. Only Class 0/1 effects remain enabled.

The sixteenth bounded Phase 3 slice is the separate library-only schema-v1
Class 0 `ordomata.repository_executable_shebang_target_requirements`
boundary. `inspect_staged_executable_shebang_target_requirements(
expected_target_runtime, *, expected_target_staging, lease)` accepts the exact
typed target-runtime manifest, the exact target-staging receipt anchored by its
active same-PID lease, and no caller-supplied path or bytes. Frozen independent
canonical mirrors validate both receipts and the complete lineage under fixed
`controller_inspected` / `posix_staged_shebang_target_requirements_v1`
semantics. The controller freshly reproduces the target-runtime manifest from
the lease before and after extraction. Exact lease snapshots bracket two
independent full descriptor passes, both derived result sets must agree, and
canonical receipt validation is followed by a closing exact lease snapshot and
path-free descriptor identity/metadata/flags anchor check.

The immutable `RepositoryExecutableShebangTargetRequirementsReceipt` holds
one `RepositoryExecutableShebangTargetShebangRequirement` per upstream target-
runtime requirement and one
`RepositoryExecutableShebangTargetShebangRequirementBinding` per upstream
binding. Each unique target-runtime file is parsed once per descriptor pass;
shared upstream rows reuse its directive, token, and tail references while
retaining distinct terminal requirement references bound to their own
lineage. Fixed outcomes are
`native_not_applicable`, `native_binary_no_shebang`,
`absolute_interpreter_token`, `non_absolute_interpreter_token`,
`unsupported_shebang`, and `unknown_runtime_format`. The parser treats only a
bounded ASCII/HTAB first-line token and optional opaque tail; a leading `/` is
syntactic classification, not resolution. Native-only input preserves its
nonempty requirements and bindings with zero files and zero descriptor reads.
`unique_target_count`, `target_posix_shebang_requirement_count`,
`argument_tail_requirement_count`, `total_interpreter_token_bytes`, and
`total_argument_tail_bytes` are over unique file extractions;
`requirement_count`, `direct_target_requirement_count`, and
`native_not_applicable_count` are per upstream row, and `command_count` is per
binding.

Canonical output is digest/reference- and bounded-count-only, and evidence is
aggregate-only: neither includes paths, bytes, directives, tokens, tails,
temporary names, or descriptors. Digest equality and lengths remain visible
and potentially guessable, so this is data minimization rather than secrecy or
unlinkability. No source, target, staged-target, or root path is reopened and
no lease is changed or cleaned up. The result proves no recursive resolution
or staging, interpreter/`env`/`PATH`/launcher/argument semantics, dependency/
loader/environment/runtime/toolchain closure, freshness, atomicity,
immutability, same-UID/external-writer/fork/hardlink/mount-alias exclusion,
authenticity, provenance, or invocability. It grants no authority or
authorization and supplies no action receipt, proposal/worktree lineage,
persistence, dispatch, route, billing, capacity, circuit, live eligibility,
CLI/state/runner, subprocess, harness, model, or execution capability. The
Class 0/1 ceiling is unchanged.

The seventeenth bounded Phase 3 slice is the separate library-only schema-v1
Class 0 `ordomata.repository_executable_shebang_nested_target_resolution`
boundary. `inspect_staged_executable_shebang_nested_targets(
expected_target_requirements, *, expected_target_runtime,
expected_target_staging, lease, expected_nested_target_paths)` consumes the
exact staged-target shebang-requirements, target-runtime, and target-staging
proof chain, the exactly anchored active same-PID target-stage lease, and the
controller's exact first-use-ordered tuple of canonical ASCII absolute nested-
target paths. The depth is fixed at 2: exactly one additional token-named
target may be measured. Fixed `controller_measured` /
`posix_absolute_shebang_nested_target_nofollow_v1` measurement and
`immediate_target_reentry_v1` controls yield
`source_native_not_applicable`, `target_native_not_applicable`, or
`direct_absolute_nested_target_measured`. Each unique selected path is opened
component by component with exact spelling and no symlink following, fully
measured twice, and accepted only when both content, identity, metadata, and
namespace results plus a closing namespace snapshot match. Known depth-1 path-
reference or filesystem-identity re-entry is rejected, and a walk whose directory chain
descends through the anchored target-stage-root identity fails closed. Native-
only correspondence remains exact: source-native input performs zero
descriptor or filesystem-path reads, while a native depth-1 target is freshly
reproduced from its staged descriptor but causes no nested-path lookup or
measurement.

The receipt fixes `requirement_count`, `command_count`,
`nested_target_requirement_count`, `target_native_not_applicable_count`,
`source_native_not_applicable_count`, `unique_nested_target_count`, and
`total_measured_bytes`.

The receipt is immutable historical measurement evidence containing only
digest/reference lineage, fixed outcomes, bounded identifiers, counts, and byte
totals; outward evidence is aggregate-only. Raw paths, content, token and tail
bytes, temporary names, and descriptor numbers are absent, although digest
equality and lengths remain potentially guessable. The boundary does not parse
or follow a measured depth-2 target, recurse beyond depth 2, stage bytes, mutate
or clean up the lease, create a subprocess, or execute. It establishes no
semantic interpreter, `env`, `PATH`, launcher, or argument resolution; no
source-chain or generic cycle closure or broader protected-root closure; no
dependency, loader, environment, runtime, or toolchain closure; no freshness,
atomicity, immutability, authenticity, provenance, authority, authorization,
action receipt, proposal/worktree lineage, persistence, dispatch, route,
billing, capacity, circuit, live eligibility, CLI/state/runner, harness, model,
or execution capability. Only Class 0/1 effects remain enabled.

The eighteenth bounded Phase 3 slice is the separate library-only schema-v1
Class 0
`ordomata.repository_executable_shebang_nested_target_chain_guard` boundary.
`inspect_staged_executable_shebang_nested_target_chain_guard(
expected_nested_resolution, *, expected_target_requirements,
expected_target_runtime, expected_target_staging, target_lease,
expected_source_staging, source_lease, expected_nested_target_paths)` consumes
the exact expected nested-resolution receipt, its exact staged-target
requirements/runtime/staging proof chain and active same-PID target-stage
lease, plus the exact source-staging receipt and active same-PID source-stage
lease. Frozen independent source-staging validation and the active target-stage
snapshot establish exact receipt-object, digest, retained-descriptor, root-
metadata, lifecycle, and same-process lineage. Fixed `controller_inspected` /
`known_source_chain_identity_and_staging_root_identity_v1` semantics then
freshly reproduce the depth-2 nested resolution with a stronger private guard
installed inside its measurement engine.

The guard set includes the original and namespace-detached staged identity of
every source executable and direct shebang target. Its protected-root set
includes the source staging-root identity and, when the target stage used a
root, that target staging-root identity. The exact-spelling no-follow walk
rejects any protected root at `/` or at any directory component and rejects
a leaf in any known original or staged source/target identity domain before
reading candidate bytes. Both measurements, descriptor reopen checks, and the
closing namespace check use the same exclusions. The action result must
exactly reproduce the expected nested-resolution receipt. Source and target
snapshots are checked before and after receipt construction; the final guarded
reproduction checks target descriptor anchors, then re-anchors the source
lease immediately before its final guarded namespace validation. Fixed requirement outcomes are
`source_native_not_applicable`,
`target_native_not_applicable`, and `known_chain_guard_verified`. Native-only
chains preserve exact nonempty requirements and bindings with no guarded
measurement and no nested-target or staging-root path lookup; native depth-1
targets still receive the upstream staged-descriptor validation needed by the
nested resolver.

`RepositoryExecutableShebangNestedTargetChainGuardReceipt` and its
`RepositoryExecutableShebangNestedTargetChainGuardedMeasurement`,
`RepositoryExecutableShebangNestedTargetChainGuardRequirement`, and
`RepositoryExecutableShebangNestedTargetChainGuardBinding` records expose only
digest/reference lineage, fixed outcomes, bounded identifiers, identity-set
digests, counts, and byte totals. The bounded totals are `requirement_count`,
`command_count`, `known_chain_guard_verified_count`,
`target_native_not_applicable_count`, `source_native_not_applicable_count`,
`guarded_measurement_count`, `known_source_identity_count`,
`known_target_identity_count`, `protected_staging_root_identity_count`, and
`total_guarded_bytes`. Raw paths, content, device/inode values, temporary
names, and descriptors are absent. The deterministic unkeyed
`guard_summary_ref` binds the identity-set digests, counts, nested receipt
digest, and byte total for internal consistency, not authenticity. This
boundary proves only the enumerated
known-identity and staging-root-identity exclusions. It proves no source-path
or staging-root-path exclusion, generic cycle closure, or broader protected-
root closure and performs no staging, write, cleanup, lease mutation,
subprocess, harness, model, or execution. It grants no authority,
authorization, action receipt, proposal/worktree lineage, persistence,
dispatch, route, billing, capacity, circuit, live eligibility, or CLI/state/
runner capability. The seventeenth resolver retains its narrower contract;
the nineteenth slice consumes the guard freshly at a separate Class 1 effect
boundary while the public resolver and guard remain unchanged.

The nineteenth bounded Phase 3 slice is the separate library-only schema-v1
Class 1 `ordomata.repository_executable_shebang_nested_target_staging`
boundary. `stage_repository_executable_shebang_nested_target_bytes(
registration, *, search_directories, expected_chain_guard,
expected_nested_resolution, expected_target_requirements,
expected_target_runtime, expected_target_staging, target_lease,
expected_source_staging, source_lease, expected_nested_target_paths, lease)`
consumes the exact expected nested-resolution and known-chain-guard receipts,
their complete active same-PID source- and target-stage receipt/lease lineages,
the exact nested-target path expectation, a freshly revalidated schema-v4
registration and search context, and a new caller-owned nested-target stage
lease. Under fixed `controller_copied` /
`posix_shebang_nested_target_unlinked_readonly_v1` semantics, an action replay
of the private guarded measurement hands each unique depth-2 target's same
still-pinned descriptor to the staging sink. Descriptor metadata, identity,
status and descriptor flags, offset, and inheritance state are unchanged by
capture. The action guard must exactly match the expected guard, and a complete
post-stage guarded replay must match both before return.
Only the first guarded action measurement invokes the capture sink; its later
measurement, closing reproduction, and the post-stage replay are consumer-free.
Capture is capped at 80 unique targets, 64 MiB per target, and 256 MiB total;
the receipt admits at most 80 requirements and 80 command bindings.

The caller's nested-target staging root is required to be an exact concrete
absolute, effective-user-owned mode-`0700`, empty directory. Freshly pinned
registration, search, source-stage, and target-stage roots must remain
identity-stable and distinct; path overlap with any of those roots or an
expected nested target fails closed, as does a nested-target ancestor alias of
the staging-root identity. Every unique captured target is copied once through
an exclusive no-follow temporary file. Its name is unlinked and the directory
is synchronized before writing; mode `0400`, synchronization, full independent
readback, writer closure, and retention solely by a non-inheritable `O_RDONLY`
descriptor follow. Shared nested targets retain exact ordered requirement and
command bindings. Source-native and target-native chains yield an active
zero-file lease without inspecting or mutating the nested-target staging root.

`RepositoryExecutableShebangNestedTargetStagingReceipt` contains exact
`RepositoryExecutableShebangNestedTargetStagedFile`,
`RepositoryExecutableShebangNestedTargetStageRequirement`, and
`RepositoryExecutableShebangNestedTargetStageBinding` records. It digest-binds
expected/action/post-stage guard evidence, the complete upstream and guarded
identity-set lineage, the staging context, and bounded requirement, command,
disposition, unique-file, and byte totals. Canonical records and aggregate
evidence contain no raw paths, bytes, device/inode values, temporary names, or
descriptor numbers. Deterministic digests and sizes still expose equality and
bounded lengths and can be guessable; they are data minimization, not secrecy
or unlinkability.
The lease is same-PID, one-shot, noncopyable, nonserializable process-local
state rather than canonical evidence.

`cleanup_repository_executable_shebang_nested_target_stage` explicitly and
idempotently releases only this lease. The cleanup receipt fixes `removed`,
`already_absent_verified`, or `unverifiable`; an unproved namespace or
descriptor outcome fails closed, and neither staging-root metadata restoration
nor secure erasure is claimed. This is temporary Class 1 staging, not a PDP
decision, PEP authorization, or action receipt. It adds no persistence,
proposal/worktree lineage, dispatch, routing,
billing, capacity, circuit, live eligibility, worker, CLI/state/runner
integration, subprocess, harness, model, or execution. It parses and follows no copied
target, recurses no further than the already measured depth 2, and establishes
no interpreter/`env`/`PATH`/launcher/argument semantics, dependency/loader/
runtime/toolchain closure, generic original-source-path or staging-root-path-
domain exclusion beyond the explicit disjointness above, generic cycle or
broader protected-root closure, freshness, atomicity, immutability,
authenticity, provenance, invocability, same-UID/external-writer/fork/
hardlink/mount-alias exclusion, crash cleanup, or secure erasure. The Class
0/1 ceiling is unchanged.

The twentieth bounded Phase 3 slice is the separate library-only schema-v1
Class 0
`ordomata.repository_executable_shebang_nested_target_runtime_manifest` PIP.
`inspect_staged_executable_shebang_nested_target_runtime_manifest(
expected_nested_target_staging, *, lease)` accepts only the exact nested-stage
receipt anchored by an active same-PID lease. The frozen proof graph checks the
receipt and object anchors, unchanged retained-file tuple, staging-root context
from stored metadata, and every detached mode-`0400`, link-count-zero,
non-inheritable `O_RDONLY` descriptor. It performs no path lookup, lease
mutation, or cleanup.

For each unique retained file the inspector completes one full hash while
capturing at most 4,096 header bytes, a separate position-independent bounded
header read, a second full remeasurement, and a closing lease snapshot. The
fixed classifications are ELF, Mach-O, valid bounded ASCII POSIX shebang,
unsupported shebang, and unknown. Only a digest reference to a valid shebang
directive is retained. Runtime-file, runtime-requirement, and command-binding
records preserve the complete nested-staging, guard, target, source, and
registration lineage and fixed source-/target-native no-op outcomes. Native-
only receipts contain zero files and cause zero descriptor reads.

Canonical records and aggregate evidence contain no raw path, header, content,
device/inode value, temporary name, or descriptor number. This is a Class 0
historical inspection, not current freshness, authority, authorization, or an
action receipt. It adds no write, cleanup, persistence, proposal/worktree,
dispatch, route, billing, live, network, worker, subprocess, harness, model, or
execution path and establishes no recursion beyond depth 2 or interpreter,
argument, dependency, loader, runtime, toolchain, immutability, authenticity,
provenance, invocability, alias, containment, or future-execution semantics.
The Class 0/1 ceiling is unchanged.

The twenty-first bounded Phase 3 slice is the separate library-only schema-v1
Class 0 `ordomata.repository_executable_shebang_nested_target_requirements`
PIP. Its inspector consumes only the exact nested-target runtime and staging
receipts plus the active same-PID staging lease. The frozen proof graph checks
full runtime/staging correspondence, reproduces the runtime manifest before
and after extraction, performs two matching independent full descriptor
remeasurements, and finishes with exact lease and descriptor anchors.

For each unique retained file, fixed syntax handling reports source-native,
target-native, native-binary, absolute interpreter token, non-absolute token,
unsupported shebang, or unknown format. A POSIX token and opaque argument tail
become only digest references, byte counts, a separator kind, and an absolute-
token boolean. Shared files are parsed once while their complete distinct
source, target, nested-resolution, guard, staging, runtime-requirement, and
command-binding lineage remains exact. Native-only evidence causes no
descriptor read.

Canonical records contain no raw path, header, content, token, argument tail,
identity number, temporary name, or descriptor. The Class 0 receipt neither
resolves nor follows a token and adds no path/environment lookup, recursion
beyond depth 2, write, cleanup, persistence, proposal/worktree, dispatch,
route, billing, live, network, worker, subprocess, harness, model, or execution
path. Interpreter, launcher, argument, dependency, loader, toolchain,
freshness, authenticity, provenance, invocability, alias, containment, and
future-execution closure remain deferred. The Class 0/1 ceiling is unchanged.

The twenty-second bounded Phase 3 slice is the separate library-only schema-v1
Class 0 `ordomata.repository_executable_native_loader_requirements` PIP.
`inspect_staged_executable_native_loader_requirements(expected_runtime, *,
expected_staging, lease)` accepts only the exact direct staged-executable
runtime/staging receipts and their active same-PID lease. The frozen proof
graph checks complete receipt correspondence, reproduces runtime evidence
before and after parsing, runs matching bounded extraction passes bracketed by
full detached-descriptor remeasurement, and requires closing lease anchors.

The parser reads only bounded native declaration tables: ELF32/ELF64 program
headers for at most one `PT_INTERP`, and thin 32-/64-bit Mach-O load commands
for at most one `LC_LOAD_DYLINKER`. It neither selects an architecture from a
fat Mach-O image nor follows any declaration. Malformed, duplicate, fat, or
otherwise unsupported layouts collapse to the fixed
`unsupported_native_layout` outcome without diagnostic or byte disclosure.
Supported records contain only format class, byte order, image kind, a
declared/absent disposition, canonical-absolute-path boolean, bounded path
byte count, digest-only path reference, and exact file/command lineage.
Non-native inputs produce `non_native_not_applicable`.

Raw loader paths, headers, content, identity numbers, temporary names, and
descriptors remain outside canonical records and aggregate evidence. The
receipt is historical Class 0 syntax evidence, not authority, authorization,
or an action receipt. It performs no loader/path resolution, shared-library or
dependency closure, architecture selection, write, cleanup, persistence,
proposal/worktree, dispatch, routing, billing, live, network, worker,
subprocess, harness, model, or execution. Loader identity, runtime/toolchain
completeness, freshness, authenticity, provenance, invocability, containment,
and future-action correspondence remain deferred. The Class 0/1 ceiling is
unchanged.

The twenty-third bounded Phase 3 slice is the separate library-only schema-v1
Class 0 `ordomata.repository_executable_native_loader_target_resolution` PIP.
Its inspector consumes only the exact loader-requirements/runtime/staging
receipts, their active same-PID lease, and an exactly expected ordered unique
tuple of canonical ASCII absolute loader paths. Before target I/O, each
supplied path must recompute the digest-only `PT_INTERP` or
`LC_LOAD_DYLINKER` reference for its exact upstream runtime file, format, and
declaration kind. The first-appearance path order must equal the caller's
tuple; absent, unsupported/fat, and non-native requirements bind no path.

Each unique matched target undergoes two complete bounded measurements through
component-by-component `O_NOFOLLOW` traversal from a pinned root descriptor.
Exact namespace spelling is required. Symlinks, non-regular or non-executable
files, sparse or oversized content, duplicate identities, path aliases, and
content/metadata/ancestor/leaf drift fail closed. A final no-follow namespace
walk and active-lease anchor close the point-in-time boundary. Public records
contain only digest references for path, filesystem identity, metadata, and
content, exact upstream requirement/command lineage, counts, and byte totals;
raw target paths and bytes are omitted. Deterministic digests and lengths
remain correlatable and potentially guessable; the boundary minimizes data but
does not claim secrecy or unlinkability.

This target measurement is historical Class 0 evidence, not a loader identity
or authenticity verdict, PDP decision, PEP receipt, or future freshness proof.
It adds no shared-library/dependency closure, fat-image architecture selection,
staging, write, cleanup, persistence, proposal/worktree, dispatch, routing,
billing, live, network, worker, subprocess, harness, model, loader invocation,
or execution. Runtime/toolchain completeness, provenance, invocability,
containment, and future-action correspondence remain deferred. The Class 0/1
ceiling is unchanged.

The twenty-fourth bounded Phase 3 slice is the separate library-only schema-v1
Class 1 `ordomata.repository_executable_native_loader_target_staging`
primitive. Its staging API consumes the exact loader-target resolution,
loader-requirements, runtime-manifest, and source-staging chain; the active
same-PID source lease; the exact loader-path tuple; a freshly revalidated
schema-v4 registration and search context; and a fresh caller-scoped target
lease. The caller-provided target-staging root must already be an empty,
owner-controlled mode-0700 directory disjoint from every pinned repository,
search, source-stage, and loader-target path.

During a fresh action-bound target remeasurement, the still-pinned unique file
descriptor is passed directly to a bounded copy sink. The sink writes an
unpredictably named mode-0400 copy, synchronizes it, reopens and fully reads it
back, unlinks the name, and retains only a non-inheritable read-only descriptor.
Content, metadata, namespace, protected-root, source-lease, and complete
target-resolution correspondence are rechecked after staging. Duplicate
declarations share one retained copy. A zero-target chain establishes an active
empty lease without touching the candidate root. Cleanup is explicit,
idempotent, receipt-bound, and fail-closed on any unproved owned-name or
descriptor release.

The target-stage lease provides a namespace-detached point-in-time byte copy,
not immutability, authenticity, authority, or future freshness. Same-UID
writes through other descriptors, external hardlink or mount aliases, fork or
crash behavior, and secure erasure remain unproved. Public records omit raw
paths, bytes, temporary names, descriptors, and identity numbers, although
deterministic digests remain correlatable and potentially guessable. No loader
is parsed or invoked; no fat-image architecture, shared-library/dependency
closure, persistence, proposal/worktree integration, dispatch, route, billing,
network, worker, subprocess, harness, model, or execution is added. The Class
0/1 ceiling is unchanged.

The twenty-fifth bounded Phase 3 slice is the separate library-only schema-v1
Class 0
`ordomata.repository_executable_native_loader_target_runtime_manifest` PIP.
It accepts only one exact native-loader target-staging receipt and active same-
PID lease. Receipt/digest/object anchors, the stored staging-root context, the
retained tuple identity, and complete staged-file/requirement/command
correspondence are validated before descriptor inspection.

For each retained target, the PIP performs a complete descriptor remeasurement
while capturing at most 4,096 header bytes, reads that header independently by
bounded position-independent `pread`, performs a second complete
remeasurement, and closes on another exact active-stage snapshot. The fixed
classifier emits ELF, Mach-O, valid bounded ASCII POSIX-shebang, unsupported-
shebang, or unknown evidence. No-target input performs no descriptor read.
Public records keep only digest-bound header/classification and exact upstream
lineage; raw paths, headers, content, identity numbers, temporary names, and
descriptors are absent, while deterministic digests remain correlatable and
potentially guessable.

The manifest is a historical Class 0 description of detached bytes, not loader
identity/authenticity, semantic compatibility, invocability, authorization,
dependency/shared-library closure, or an action receipt. It opens no path,
mutates or cleans up no lease, selects no fat-image architecture, persists no
state, routes or dispatches no worker, creates no subprocess, invokes no
harness/model/network/loader, and executes nothing. Freshness, containment,
runtime/toolchain completeness, and future-action correspondence remain
deferred. The Class 0/1 ceiling is unchanged.

The twenty-sixth bounded Phase 3 slice is the separate library-only schema-v1
Class 0
`ordomata.repository_executable_native_loader_target_loader_requirements`
PIP. It accepts the exact target-runtime manifest, exact target-staging
receipt, and active same-PID lease. The controller validates their complete
digest, object, file, requirement, command, and retained-tuple
correspondence, freshly reproduces the runtime manifest before and after
extraction, and repeats the complete syntax measurement before a closing
active-stage snapshot.

Each unique detached loader target is fully remeasured before and after
bounded ELF32/ELF64 `PT_INTERP` or thin Mach-O32/Mach-O64
`LC_LOAD_DYLINKER` parsing. Fat Mach-O and bounded unsupported layouts receive
fixed unsupported outcomes; non-native targets receive a fixed not-applicable
outcome. Shared target syntax is inspected once and bound to every exact
upstream requirement and command. A no-target chain performs no descriptor
read. Canonical records retain fixed format, byte-order, image-kind,
disposition, digest-only loader-path, bounded byte-count, and exact lineage
facts. Raw paths, headers, content, identity numbers, temporary names, and
descriptors remain private, while deterministic digests remain correlatable
and potentially guessable.

This is one-hop historical loader-of-loader syntax evidence. A newly declared
loader is not resolved or followed, and no compatibility, identity,
authenticity, invocability, shared-library/dependency closure, authority,
authorization, or action receipt is established. The PIP opens no path,
mutates or cleans up no lease, selects no fat-image architecture, persists no
state, integrates no proposal/worktree/route/worker, invokes no network,
subprocess, harness, model, or loader, and executes nothing. Recursive closure,
freshness, containment, runtime/toolchain completeness, and future-action
correspondence remain deferred. The Class 0/1 ceiling is unchanged.

The twenty-seventh bounded Phase 3 slice is the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_native_loader_nested_target_resolution` PIP.
Its input chain is the exact loader-of-loader requirements receipt, exact
target-runtime manifest, exact target-staging receipt, exact first-hop target-
resolution receipt, active same-PID target-stage lease, exact ordered current-
loader paths, and exact ordered newly declared nested-loader paths. Three full
chain snapshots freshly reproduce the loader-of-loader receipt and retain the
same detached target tuple before, between, and after the two path
measurements, followed by a closing active-stage snapshot.

The conceptual flow is `exact chain -> declaration/path reproduction ->
private re-entry guard -> two no-follow measurements -> digest-only depth-two
receipt`. Each declared canonical ASCII absolute path must reproduce the
loader-path declaration digest. Shared declarations deduplicate measurement
without collapsing target, source, requirement, lineage, or command bindings.
The private guard rejects exact current-loader path re-entry before lookup and
rejects original first-hop target identities, detached staged-target
identities, and the target staging-root identity before leaf reads. Fixed
absent, unsupported/fat, and non-native outcomes need no nested path, and a
no-target chain performs no nested lookup or descriptor read.

Public records contain only digest-bound path, identity, metadata, content,
bounded byte-count, disposition, count, and lineage facts. Raw paths, bytes,
identity numbers, target-stage names, and descriptors remain private, although
deterministic digests remain correlatable and potentially guessable. Resolution
stops at depth two: the newly measured bytes remain opaque and are not parsed,
staged, followed, invoked, or executed. Source-path/source-staging-root re-entry,
general cycle detection, broader protected-root closure, loader authenticity,
compatibility, invocability, shared-library/dependency/runtime/toolchain
closure, current freshness, authorization, and future-execution correspondence
remain deferred. The PIP mutates no lease, persists no state, integrates no
proposal/worktree/route/worker, invokes no network, subprocess, harness, model,
or loader, and executes nothing. The Class 0/1 ceiling is unchanged.

The twenty-eighth bounded Phase 3 slice is the separate library-only schema-v1
Class 0
`ordomata.repository_executable_native_loader_nested_target_chain_guard` PIP.
Its input is the exact depth-two native-loader receipt and complete source/
target proof chain: target loader requirements, target runtime, target staging,
first-hop resolution, source staging, both active same-PID leases, and both
ordered path sets. The conceptual flow is `exact depth-two receipt -> combined
source/target identity guard -> exact guarded reproduction -> digest-only guard
receipt -> closing source anchor -> final exact guarded reproduction`.

The combined guard preserves the resolver's original/staged target identities
and target staging-root identity, and adds each original/staged source
executable identity plus the source staging-root identity. The guard checks
directory ancestry and leaf identity before candidate bytes are read, so exact
source re-entry, hardlink aliases, detached staged-copy aliases, and candidates
below the anchored source staging root fail closed. Shared nested declarations
still deduplicate measurement without collapsing requirements, source
lineages, or command bindings. Fixed absent, unsupported/fat, non-native, and
no-target outcomes perform no unnecessary lookup or read. Source and target
stage snapshots surround receipt construction; the final private reproduction
requires canonical equality and invokes the closing source anchor after target
lease revalidation, leaving guarded namespace validation as the last proof
action.

Canonical output contains digest-only known-identity sets, protected-root sets,
measurements, requirements, lineages, bindings, counts, and bounded byte totals.
Raw paths, candidate bytes, device/inode values, temporary names, and
descriptors stay private, although deterministic digests remain correlatable
and potentially guessable. This remains historical depth-two evidence: the
newly measured bytes are not parsed, staged, followed, invoked, or executed.
General cycle closure, source path-spelling re-entry beyond exact anchored
identities, broader protected-root closure, loader authenticity, compatibility,
invocability, dependency/shared-library/runtime/toolchain closure, freshness,
authorization, and future-execution correspondence remain deferred. No lease
mutation/cleanup, persistence, proposal/worktree/route/worker integration,
network, subprocess, harness, model, loader invocation, or execution is added.
The Class 0/1 ceiling is unchanged.

The twenty-ninth bounded Phase 3 slice is the matching library-only schema-v1
Class 1 native-loader nested-target staging boundary. Its conceptual flow is
`exact guarded chain -> action-bound guarded remeasurement -> pinned-descriptor
copy -> read-only unlink -> post-stage guard replay -> active process-bound
lease`. It requires the exact depth-two and known-chain receipts, complete
source/target proof chain, both active same-PID leases, both ordered path sets,
and a caller-selected private mode-`0700` directory.

Each unique target is copied through the exact descriptor used for its guarded
measurement. The bounded copy is read back, changed to mode `0400`, reopened
read-only and non-inheritable, unlinked, and retained only by descriptor. Shared
targets deduplicate storage without collapsing requirements, source lineages,
or commands. Empty outcomes preserve explicit lineage without opening a
staging root. Root containment covers repository/search roots, source and
target staging roots, and both supplied loader-path sets. Exact source/target
leases and protected directory anchors must remain unchanged throughout.

Canonical output is digest-only; raw paths, bytes, filesystem numbers,
temporary names, and descriptors remain private. Cleanup uncertainty is
explicit and fails closed. This is staging, not authorization: a separate
controller decision must authorize the Class 1 local effect. The primitive
does not parse, recurse, follow, invoke, execute, persist, route, or widen
authority. General cycles, broader protected-root closure, dependency/shared-
library closure, freshness, future correspondence, crash cleanup, secure
erasure, and external descriptor absence remain deferred. The Class 0/1
ceiling is unchanged.

The thirtieth bounded Phase 3 slice is the matching library-only schema-v1
Class 0 native-loader nested-target runtime-manifest PIP. Its conceptual flow
is `exact active nested stage -> full descriptor remeasurement -> bounded
position-independent header read -> fixed classification -> full
remeasurement -> closing lease snapshot`. It accepts only the exact staging
receipt and same-PID lease, validates their immutable anchors and private
staging-root context, and opens no path or mutation boundary.

Each unique detached file is classified as ELF, Mach-O, a valid bounded ASCII
POSIX shebang, an unsupported shebang, or unknown. Only a digest reference to a
valid directive is retained. Runtime-file, requirement, source-lineage, and
command-binding records preserve the full depth-two staging and guard
correspondence; shared files remain deduplicated without collapsing lineage,
and empty outcomes produce no descriptor reads.

Canonical output is digest-only and excludes raw paths, headers, content,
filesystem numbers, temporary names, and descriptors. This is historical PIP
evidence, not freshness, authorization, or an action receipt. It adds no lease
mutation/cleanup, recursive resolution, dependency closure, loader invocation,
execution, persistence, routing, network, subprocess, harness, model, or
permission widening. The Class 0/1 ceiling is unchanged.

The thirty-first bounded Phase 3 slice is the matching library-only schema-v1
Class 0 native-loader nested-target loader-requirements PIP. Its conceptual
flow is `exact nested runtime + exact active nested stage -> fresh runtime
reproduction -> complete descriptor/parser pass -> fresh runtime reproduction
-> matching complete descriptor/parser pass -> closing lease snapshot`. The
fixed parser recognizes ELF32/ELF64 `PT_INTERP` and thin Mach-O32/Mach-O64
`LC_LOAD_DYLINKER`; it also records absent declarations, unsupported native
layouts, and non-native non-applicability.

One syntax requirement is emitted per unique runtime file. Full digest lineage
continues through target-loader inspection, depth-two resolution, the known-
chain guard, nested staging, nested runtime inspection, original source
requirements, and command bindings. Shared files therefore stay deduplicated
without collapsing provenance, while terminal source lineages that produced no
nested file remain explicit and require no descriptor read.

Canonical output contains only digest references, fixed classifications and
dispositions, bounded counts, absolute-path booleans, and byte totals. Raw
loader paths, headers, content, filesystem numbers, staging names, and
descriptors remain private. This historical PIP evidence neither resolves nor
follows a newly declared loader path. It opens no path, mutates or cleans up no
lease, invokes no loader, and grants no recursive/dependency/shared-library
closure, freshness, authorization, execution, persistence, routing, network,
subprocess, harness, model, or wider permission. The Class 0/1 ceiling is
unchanged.

The thirty-second bounded Phase 3 slice is a separate library-only schema-v1
Class 0 native-dependency declaration PIP. Its conceptual flow is `exact direct
native-loader + exact runtime + exact active stage -> fresh loader reproduction
-> complete descriptor/parser pass -> fresh loader reproduction -> matching
complete descriptor/parser pass -> closing lease snapshot`. One requirement is
emitted per unique direct runtime file and remains bound to every registered
command that uses it.

The fixed parser accepts bounded ELF32/ELF64 program and dynamic tables and
records ordered `DT_NEEDED` declarations. For thin Mach-O32/Mach-O64 it records
ordered required, weak, re-export, upward, and lazy dylib load commands plus
their fixed-width version metadata. Dependency names are immediately converted
to runtime-file- and format-bound digest references, byte counts, and fixed
path-style labels; raw names never enter a receipt or evidence projection.
Malformed or unsupported layouts collapse to a fixed unsupported disposition.

This historical evidence does not resolve a dependency name or select a fat
Mach-O architecture. It opens no path, stages no dependency, mutates or cleans
up no lease, invokes no loader, and grants no shared-library/recursive
dependency closure, freshness, authorization, execution, persistence, routing,
network, subprocess, harness, model, or wider permission. The Class 0/1 ceiling
is unchanged.

The thirty-third bounded Phase 3 slice is a separate library-only schema-v1
Class 0 canonical-absolute dependency-target PIP. Its conceptual flow is
`exact dependency receipt + exact active direct stage + exact absolute path
expectation -> fresh dependency-chain snapshot -> first no-follow measurement
-> fresh snapshot -> matching second measurement -> fresh snapshot -> closing
namespace and lease anchors`. Every absolute declaration must uniquely
reproduce one expected canonical ASCII path before any target read, and the
ordered first-use target set must exactly equal the caller's expectation.

One target outcome is retained per upstream dependency declaration. Absolute
declarations bind a digest-only measurement; bare, relative, `@rpath`,
`@loader_path`, and `@executable_path` declarations bind a fixed unresolved
outcome. Shared absolute targets deduplicate measurement without collapsing
file, declaration, requirement, or command provenance. Non-absolute and
terminal inputs perform no target reads.

This historical evidence contains no raw dependency name, target path, file
content, filesystem number, or descriptor. It does not emulate ELF or Mach-O
search rules, stage a target, select a fat architecture, mutate a lease, invoke
a loader, or establish recursive dependency/shared-library/runtime/toolchain
closure, freshness, authorization, execution, persistence, routing, network,
subprocess, harness, model, or wider permission. The Class 0/1 ceiling is
unchanged.

The thirty-fourth bounded Phase 3 slice is a separate library-only schema-v1
Class 0 explicit dependency-manifest PIP. Its conceptual flow is `exact
dependency receipt + exact active direct stage + ordered controller manifest ->
three fresh dependency-chain snapshots -> digest-only binding receipt`. Every
bare, relative, `@rpath`, `@loader_path`, and `@executable_path` declaration
must reproduce one private ordered manifest name and bind a canonical ASCII
absolute target-path reference. Absolute declarations are not manifest inputs.
The PIP neither consults loader environment/cache/RPATH/RUNPATH state nor
expands Mach-O tokens, opens no target, stages no target, and grants no
dependency closure, freshness, authorization, or execution authority.

The thirty-fifth bounded Phase 3 slice is a separate library-only schema-v1
Class 0 manifest-target measurement PIP. It re-proves the ordered controller
manifest on three fresh direct-chain snapshots around two matching no-follow
measurements and closing namespace validation. The only opened paths are the
already manifest-bound canonical targets; shared targets deduplicate their
measurements without collapsing declaration or command provenance. Host loader
state and token expansion remain excluded, and no staging, loading, closure,
authorization, or execution authority is granted.

The second slice is the separate
`ordomata.repository_proposal.bind_repository_proposal_attempt` controller API.
It freshly revalidates a `RepositoryRegistration`, requires an existing
immutable Class 0/1 `repository-proposal-disabled` run to be exactly at
`CREATED`, requires an explicit canonical `proposal_digest`, and binds the
controller-owned selection to that proposal attempt without storing proposal
content. The selection event contains the validator's privacy-bounded evidence,
its digest, the exact proposal digest, the run reference, and fixed
`controller_owned` selection mode. The binding links that selection, repeats
the proposal digest, and binds every registration component digest plus
privacy-safe references for the
immutable run, proposal version, runner, workspace, run directory, context,
attempt, timeout, and current Class 0/1 ceiling. It fixes read-only validation,
disabled dispatch, and no granted authority. Neither event is an ABAC request,
decision, pre-effect record, action receipt, routing selection, or run status.

The API appends exactly those two schema-v1 events after `CREATED`, atomically
guarding current status and exact ordered predecessor event IDs on each append,
reconciles only an exact retry or exact selection-only partial history, and
then rereads the complete three-event history in one consistent SQLite
snapshot. Commit failures roll back before any readback reconciliation.
Conflicting, ambiguous, status-bearing, reordered, stale-registration, or
otherwise inexact histories fail closed.
No registration document or raw path, argv, proposal ID/content, workspace,
run directory, or artifact content is persisted. There is no new SQLite
migration, run creation or status transition, authorization or authority,
worktree, Git or command execution, process, worker or supervisor dispatch,
model/profile route,
billing/capacity/circuit change, harness call, or live eligibility.

The third slice is the library-only `ordomata.repository_proposal_inspection`
API `inspect_repository_proposal_evidence(database_path, *, run_id)`. It
returns one `RepositoryProposalInspectionReport` with fixed
`inspection_scope: "single_run"`, privacy-safe `run_ref`, permission class,
current status, capped inspected-event count, optional validated proposal,
registration, repository, selection, and binding references, digests, versions,
and sequences, plus a bounded tuple of fixed-code
`RepositoryProposalInspectionFinding` objects. `coverage: "incomplete"` means
only an exact protocol-recoverable `CREATED`-only or
`CREATED`-plus-selection evidence prefix.
The mapping also fixes read-only inspection/validation, no repair, disabled
dispatch, and no authority, and reports `evidence_complete` and finding count.
`coverage: "complete"` requires the exact clean
`CREATED < repository_registration_selection <
repository_proposal_attempt_binding` chain; every other history is `invalid`.
`clean` requires complete, untruncated evidence with no findings, and
`truncated` is set when more than four events exist and the capped inspection
cannot cover the history.
The result proves exactly one caller-named run, not whole-state coverage.

From that one read-only, query-only SQLite snapshot the inspector independently
replays exact cardinality/order, content-addressed event identifiers, canonical
payload digests, durable `RunRecord` and registration-component linkage, the
repeated proposal digest, and the fixed Class 0/1, runner, `CREATED`, read-only,
dispatch-disabled, and no-authority semantics. It never instantiates
`SQLiteStateStore`, creates source schema or WAL/SHM sidecars, repairs state, or
revalidates the registration against the live filesystem. Fixed findings and
errors expose no raw identifiers, SQLite diagnostics, paths, argv,
registration documents, proposal content, workspace/run-directory values, or
artifact content.

Inspection creates no run, status, event, authorization decision, action
receipt, worktree, Git/command/process invocation, worker or supervisor
dispatch, route/profile selection, billing/capacity/circuit change,
harness/network action, or live eligibility.

The fourth slice is the controller-owned, library-only
`ordomata.repository_proposal_admission` shadow. Its sole entry point accepts a
durable database path, caller-named run, and controller evaluation time, then
freshly invokes the independent inspector. It deliberately accepts no supplied
inspection object, permission class, request, policy, or evaluator. ABAC
evaluation occurs only when that fresh result is clean, evidence-complete,
complete, untruncated, finding-free, and exactly the expected three-event Class
0/1 chain. A nonclean result constructs no request, policy, or decision: it is
`not_evaluated`, has the `indeterminate` effect, and carries only the fixed
`inspection_not_clean_complete` block code. Run-binding, evaluator, or exact
replay failures are likewise inert failed/indeterminate observations.

The projection is closed and class-specific. Class 0 maps to a local `READ`
observation with the fixed read-only operation, resource type, policy, and
unenforced audit-receipt plus read-only obligations. Class 1 maps to a local
`CREATE` nomination with the fixed local-draft operation, resource type,
policy, and unenforced audit-receipt plus isolated-local-only obligations. A
class policy enables exactly its projected class, verb,
operation, resource type, controller role, local-control-plane trust boundary,
disabled network, and local non-AI route. The request binds the canonical
digest of the privacy-safe inspection mapping and validated proposal,
registration, repository, selection, and binding lineage. The shadow evaluator
and captured built-in replay must both equal the controller's exact expected
decision, preventing an injected or substituted evaluator from becoming a
grant boundary.

Even an exact observational permit is not a PEP decision, reusable capability,
or admission. The returned mapping fixes all authority, enforcement,
admission/action, receipt, evidence-persistence, repair, dispatch, route,
billing, and obligation-enforcement flags to false. Nothing is persisted or
written to source state: there is no CLI, database/schema/sidecar/migration
change, run event, durable authorization decision, receipt, worktree,
Git/command/process invocation,
worker or supervisor dispatch, profile choice, billing/capacity/circuit fact,
harness/network action, or live eligibility. Raw paths and identifiers, argv,
registration/proposal content, workspace/run-directory values, SQLite
diagnostics, and artifact content do not enter the shadow mapping.

The fifth slice is the library-only
`ordomata.repository_proposal_admission_verification` API
`verify_repository_proposal_admission_shadow_mapping(value)`. Its sole input
must be an exact built-in `dict`; the verifier takes a bounded detached JSON
snapshot and independently mirrors the inspection contract. Evaluated inputs
replay the Class 0/1 request, policy, manual expected decision, and captured
built-in evaluator; inert inputs must match an exact state-machine branch, and
a reported replay failure must still have a constructible replay boundary. Its
findings are fixed and value-free. `contract_valid` means only that the
supplied snapshot is internally consistent: the verifier supplies no
authenticity, durable reinspection or source truth, current freshness, or
authority, and a coherent forgery or replay is indistinguishable without a
trusted anchor. It persists and repairs nothing, enforces and authorizes
nothing, and has no worker, repository, command, route, billing, network,
harness, dispatch, or live effect.

The sixth bounded Phase 3 slice is that schema-v2 exclusion contract. It adds no
automatic exclusion discovery, ignore behavior, persistence, repair, execution,
worker, route, billing, network, harness, dispatch, or live effect.

The seventh bounded Phase 3 slice is the schema-v3 baseline contract described
above. It adds no snapshot computation, executable resolution, command
execution, persistence, repair, worker, route, billing, network, harness,
dispatch, authority, or live effect. Frozen schemas v1 and v2 retain their
prior canonical and evidence meanings, and proposal lineage remains v1-only.

The eighth bounded Phase 3 slice is the schema-v4 opaque executable/toolchain
identity-claim contract described above. It adds no additional PATH or
environment lookup, resolution, stat or content inspection, chain or package
discovery, command execution, persistence, repair, worker, route, billing,
network, harness,
dispatch, authority, or live effect. Frozen schemas v1 through v3 retain their
prior canonical and evidence meanings, and proposal lineage remains v1-only.

The ninth bounded Phase 3 slice is the separate schema-v1 direct-executable
resolution receipt described above. It measures direct `argv[0]` bytes for a
fresh exact schema-v4 registration under bounded explicit search roots and
descriptor-based `controller_measured` / `posix_nofollow_v1` semantics. Its
aggregate evidence is point-in-time, non-reusable, non-authorizing, and outside
proposal lineage. Complete interpreter, dependency, and toolchain manifests,
and execution remain future boundaries; the separate tenth slice supplies the
bounded action-boundary capture and staging contract. Only Class 0/1 effects
remain enabled.

The tenth bounded Phase 3 slice is the separate schema-v1 executable-staging
lease described above. It turns an exact typed preflight receipt into a
freshly bracketed, same-descriptor-captured, namespace-detached and read-only
in-process lease without making the bytes executable. It widens neither
registration nor proposal lineage and supplies no authority, authorization,
action receipt, durable control-plane persistence, dispatch, route, billing,
live, CLI/state/runner, or execution capability. Complete interpreter/
dependency/toolchain coverage and any consumer that mutates or executes staged
bytes remain deferred; the existing lifecycle cleanup only releases the lease,
and only the eleventh through thirteenth slices' Class 0 inspections and the
fourteenth slice's separate Class 1 target staging otherwise read it. Only
Class 0/1 effects remain enabled.

The eleventh bounded Phase 3 slice is the separate schema-v1 staged-executable
runtime-manifest inspection described above. An active same-PID lease anchored
to the exact expected staging receipt is mandatory. Complete descriptor rehash
and bounded byte-level classification produce only digest/reference entries and
aggregate evidence for ELF, Mach-O, bounded ASCII shebang, unsupported shebang,
or unknown content. The slice neither resolves interpreters nor establishes
invocability, completeness, dependency/runtime closure, authority,
authorization, an action receipt, proposal/worktree integration, dispatch,
routing, billing, live eligibility, CLI/state/runner integration, subprocess,
or execution. It does not mutate or clean up the lease. Only Class 0/1 effects
remain enabled.

The twelfth bounded Phase 3 slice is the separate schema-v1 staged-executable
shebang-requirements inspection described above. It requires exact typed
runtime and staging receipts plus their active same-PID anchored lease, freshly
reproduces the runtime manifest, and remeasures the leased descriptors. It
fixes `native_binary_no_shebang`, `absolute_interpreter_token`,
`non_absolute_interpreter_token`, `unsupported_shebang`, or
`unknown_runtime_format` as appropriate; only a valid POSIX shebang yields
digest-only interpreter-token and opaque argument-tail requirements split at
the first contiguous ASCII space/tab boundary run. Only the run's first byte
determines the separator kind, and neither the run nor tail is interpreted.
The Class 0 call opens no path, changes or
cleans up no lease, interprets or resolves no interpreter, `env`, `PATH`,
arguments, or kernel semantics, and adds no authority, authorization, action
receipt, persistence, proposal/worktree integration, dispatch, routing,
billing, live eligibility, CLI/state/runner integration, subprocess, harness,
or execution. Complete interpreter/dependency/toolchain closure remains a
prerequisite to widening. Only Class 0/1 effects remain enabled.

The thirteenth bounded Phase 3 slice is the separate schema-v1 direct shebang-
target measurement PIP described above. It requires the exact upstream receipt
chain, active lease, and complete first-use target-path expectation. Native
entries are not applicable; every script target must match across two
sequential full measurements and a final exact-namespace revalidation. The
raw-path/raw-byte-free historical receipt grants no authority, extends no
proposal lineage, and supplies no routing, live, subprocess, or execution fact.

The fourteenth bounded Phase 3 slice is the separate schema-v1 direct shebang-
target staging lease described above. Exact expected/action/post-stage target
resolution, the complete active upstream chain, same-descriptor capture, and a
dedicated protected-root contract yield only unlinked mode-`0400` read-only
descriptors. Native-only input is a zero-file no-op. The Class 1 library
primitive supplies no persistence, authority, proposal lineage, routing,
billing, live, subprocess, harness, or execution capability. Only Class 0/1
effects remain enabled.

The fifteenth bounded Phase 3 slice is the separate schema-v1 staged shebang-
target runtime-header inspection described above. The Class 0 call validates
the exact active target-stage receipt, object anchors, retained descriptors,
and stored root context without opening a path; brackets an at-most-4,096-byte
five-way header classification with complete descriptor remeasurement; and
preserves native-only zero-file requirements and bindings. It adds no
authority, persistence, proposal lineage, routing, billing, live, subprocess,
harness, model, or execution capability. Only Class 0/1 effects remain
enabled.

The sixteenth bounded Phase 3 slice adds the separate schema-v1 staged-target
shebang-requirements Class 0 inspection described above. It independently
mirrors and freshly reproduces the target-runtime proof, requires two matching
full descriptor passes plus closing snapshots, parses each unique target once
per pass, and emits one lineage-distinct requirement and binding per upstream
row. Native-only input remains zero-file and zero-read. The result is digest-only,
non-authorizing, non-recursive evidence with no persistence, routing, billing,
live, subprocess, harness, model, or execution capability.

The seventeenth bounded Phase 3 slice adds the separate schema-v1 nested
shebang-target resolution Class 0 inspection described above. The exact active
target-stage chain and exact ordered canonical absolute depth-2 paths are
mandatory; every unique nested target must agree across two no-follow
measurements and a closing namespace check. Immediate depth-1 path/identity
re-entry and target-stage-root descent fail closed, while native-only input is
handled without a nested-path read. Source-native input is also zero-file and
zero descriptor-read; a native depth-1 target still validates its staged
descriptor. The privacy-bounded historical receipt contains digest/reference
lineage, fixed outcomes, bounded command identifiers, counts, and byte totals;
it stops after one additional hop and grants no generic cycle/protected-root
closure, staging, authority, persistence, routing, billing, live, subprocess,
harness, model, or execution capability. Only Class 0/1 effects remain
enabled.

The eighteenth bounded Phase 3 slice adds the separate schema-v1 nested-target
known-chain guard Class 0 inspection described above. It requires exact active
source- and target-stage lineage and freshly reproduces the expected depth-2
resolution with original and staged source/target identities and the one or
two staging-root identities present excluded throughout measurement and
closing namespace validation. Native-only input makes no nested-target or
staging-root path lookup. The privacy-bounded result is non-authorizing and proves no
source-path/root-path exclusion, generic cycle closure, broader protected-root
closure, staging, write, persistence, routing, billing, live, subprocess,
harness, model, or execution capability. The seventeenth resolver remains
unchanged, as does the public guard.

The nineteenth bounded Phase 3 slice adds the separate schema-v1 Class 1
nested-target staging boundary described above. Exact guarded same-descriptor
capture, active source/target lease lineage, a protected owner-private root,
unlinked mode-`0400` retained descriptors, and matching action/post-stage guard
replays preserve the depth-2 bytes for later controller inspection. Native-
only input is a zero-file, no-root-touch no-op. Privacy-bounded staging and
cleanup receipts grant no authority, proposal/worktree, persistence, route,
billing, live, subprocess, harness, model, or execution capability.

The twentieth slice adds the matching Class 0 nested-target runtime-header PIP.
It twice remeasures only the active detached descriptors around a bounded
header read, emits fixed privacy-bounded classification and lineage evidence,
and preserves native-only zero-read behavior. It adds no authority, route,
worker, subprocess, harness, model, or execution capability.

The twenty-first slice adds the matching Class 0 nested-target shebang-
requirements PIP. It reproduces runtime evidence around two independent
remeasurement passes and emits only digest-bound token/tail syntax and exact
lineage; it resolves, follows, and executes nothing.

The twenty-second slice adds the matching Class 0 direct native-loader
declaration PIP. It reads only bounded ELF `PT_INTERP` and thin Mach-O
`LC_LOAD_DYLINKER` syntax and emits digest-only path references; it resolves
no loader or shared library, selects no fat-binary architecture, and executes
nothing.

The twenty-third slice adds the matching Class 0 native-loader target-
measurement PIP. Exact expected paths must reproduce the declaration digests
before two no-follow measurements; only digest-bound identity/content evidence
is returned, and no loader, shared library, dependency, or process is invoked.

The twenty-fourth slice adds matching Class 1 native-loader target staging.
The same pinned action-measurement descriptor supplies each unique unlinked
mode-0400 read-only copy; post-stage chain replay and explicit cleanup preserve
correspondence without adding loader, dependency, subprocess, model, or
execution capability.

The twenty-fifth slice adds matching Class 0 runtime-header inspection of the
detached loader copies. Two full descriptor remeasurements bracket one bounded
position-independent header read; the fixed privacy-bounded classification
adds no loader, dependency, subprocess, model, or execution capability.

The twenty-sixth slice adds matching Class 0 loader-of-loader declaration
inspection. Fresh runtime reproduction and repeated descriptor remeasurement
bind bounded ELF `PT_INTERP` or thin Mach-O `LC_LOAD_DYLINKER` syntax to exact
target and command lineage without path resolution, loader invocation,
subprocess, model, or execution capability.

The twenty-seventh slice adds matching Class 0 resolution and measurement of
one newly declared native-loader hop. Exact path/declaration reproduction,
two guarded no-follow measurements, and immediate current-target, hardlink,
staged-target, and target-staging-root re-entry exclusions extend digest-only
lineage to depth two without parsing the new bytes, invoking a loader, or
executing anything.

The twenty-eighth slice adds a separate Class 0 source-chain guard over that
depth-two native-loader receipt. Exact guarded reproduction now includes
original/staged source identities and the source staging-root identity alongside
the existing target protections, with closing source/target lease anchors. It
rejects source identity, hardlink, staged-copy, and source-stage-root re-entry
before leaf reads without parsing the measured bytes or adding staging, loader,
subprocess, model, or execution capability.

The twenty-ninth slice adds the matching Class 1 descriptor-staging boundary.
It copies each unique guarded target through its pinned action-measurement
descriptor into an unlinked mode-`0400`, read-only, non-inheritable process-
bound lease and replays the exact guard after staging. Empty outcomes preserve
command lineage without opening a staging root. Separate authorization remains
required; no parsing, recursion, loader invocation, execution, persistence,
routing, or permission widening is added.

The thirtieth slice adds the matching Class 0 nested-target runtime-manifest
boundary. It fully remeasures each detached descriptor around a separate
bounded position-independent header read, preserves exact requirement,
source-lineage, and command correspondence, and performs no reads for empty
stages. It opens no path, mutates no lease, follows no further declaration,
invokes no loader, and executes nothing.

The thirty-first slice adds the matching Class 0 nested-target loader-
requirements boundary. It freshly reproduces the exact runtime evidence around
two matching complete descriptor/parser passes, extracts only bounded ELF
`PT_INTERP` or thin Mach-O `LC_LOAD_DYLINKER` syntax, and preserves the full
digest lineage. It resolves and follows no declaration, invokes no loader,
mutates no lease, and executes nothing.

The thirty-second slice adds a separate Class 0 direct-native dependency-
declaration boundary. Exact native-loader/runtime/staging/lease lineage and two
matching complete descriptor/parser passes produce digest-only ordered ELF
`DT_NEEDED` and thin Mach-O dylib-load metadata. It performs no dependency
lookup, resolution, staging, path open, loader invocation, or execution and
proves no shared-library or recursive dependency closure.

The thirty-third slice adds a separate Class 0 canonical-absolute dependency-
target measurement boundary. Exact caller paths, three fresh dependency-chain
snapshots, two matching no-follow measurements, and closing namespace checks
produce digest-only evidence while every non-absolute declaration remains
unresolved and zero-read. No loader search semantics, dependency staging, or
recursive/shared-library closure is added.

The thirty-fourth slice adds a separate Class 0 explicit controller-manifest
binding boundary for non-absolute direct dependencies. It validates an ordered
private declaration-name-to-canonical-path manifest against three fresh direct
chains, retaining digest-only mappings. It applies no host loader search or
Mach-O token semantics and opens or stages no mapped path; closure remains
unverified.

The thirty-fifth slice adds a separate Class 0 no-follow measurement boundary
for those explicit-manifest targets. It re-proves the mapping before and after
matching measurements and preserves digest-only target, declaration, and
command lineage. It performs no loader search, staging, loading, or closure.

The lineage digest, downstream content links, and SQLite append-only guards
detect ordinary in-place mutation; they are not an external tamper anchor
against an operator who can replace and coherently rewrite the entire local
state database. External anchoring remains target work rather than an authority
claim of this stage.

## Controlled comparison

The `compare-run` workflow is a controller-owned experiment, not a second execution path. Before it writes a plan or trial record, all selected named profiles must pass the same `doctor`, routing, current-evidence, durable-capacity, and durable-circuit gates as an individual live run.

Every trial receives the exact same immutable sanitized Class 0 task/context snapshot, schema, two-minute timeout ceiling, and empty workspace. The six-trial plan also requires a one-minute whole-run evidence margin, so its maximum envelope fits inside the current 15-minute Claude attestation window. Order is randomized within repetition blocks, while each adapter and session is fresh. Trial output is kept in an owner-private review artifact and is never fed to another trial. The report preserves raw automated dimensions and a separate human-review template; it contains no aggregate score, winner, or automatic promotion. Partial outcomes are retained if a billing or capacity stop prevents the remaining trials. The workflow is implemented, but no live Codex-versus-Claude comparison has been completed.

The comparison path is a separate `runner.execute` caller, so every started
trial now receives its own durable Class 0 `RunRecord` and ordered `run_events`
stream. A schema-v2 digest-only controller binding covers the plan, snapshot,
controls, profile version/configuration, runner settings, current billing
assessment, and trial cell. Schema-v3 non-enforcing shadows observe Class 0
admission and the immediate pre-dispatch boundary. After accounting, a
schema-v4 non-enforcing shadow observes the separate Class 1 owner-private
artifact publication; schema-v2 pre-effect and action-receipt events bind the
exact proposed and observed artifact without retaining its content or path.
Their sanitized billing-disposition digest is independently recomputed from
the durable execution-accounting source facts before linkage is accepted.
The controller stages and fsyncs the private bytes, promotes without overwrite,
fsyncs the containing directory after promotion or reconciliation, and uses the
receipt identifier as the append-only event identifier for exact readback after
an ambiguous append result. Any unprovable staging, final-name, directory-sync,
or receipt state becomes an unknown effect and quarantines the trial.
Model-controlled events are reduced to ordinals. The read-only inspector
independently verifies binding and receipt cardinality, digests, source-event
agreement, and boundary ordering.

The comparison controller reuses the normal run path's deterministic post-run
billing reconciliation. Missing or changed evidence, interrupted execution, or
failed durable billing accounting is never accepted from adapter flags: the
trial is quarantined, remaining cells stop, usable review output is withheld,
and account/profile plus runner-wide circuits are opened where identity is
unknown. A report is never returned unless the trial has durable terminal state.

The owner-private review artifact remains a distinct controller-owned Class 1
effect; it is not folded into or delegated through the trial's Class 0 runner
authority. The publication shadow and receipts are non-enforcing migration
evidence: legacy Class 0/1 gates still decide behavior, and no shared, external,
promotion, Class 2, or Class 3 action becomes eligible. Historical schema-v1
comparison bindings and artifact intent/observation records remain readable as
valid partial admission/dispatch coverage with an explicit publication gap.
Only schema-v2 bindings with the linked schema-v4 publication shadow and
schema-v2 receipt pair claim complete comparison-boundary audit coverage.
The coverage values in bindings and reports declare expected instrumentation,
not observed completeness; the read-only inspector reports missing, malformed,
misordered, or mismatched evidence.

## Scheduling

The current scheduler performs a single caller-driven inspection or atomic
claim. Immutable slot claims prevent duplicate dispatch, leases protect shared
resources, and each claim has a fixed deadline. No OS schedule is installed.

### Durable supervisor control-plane tracer

An additive, versioned SQLite migration now supplies a partial Phase 2
supervisor control plane. It persists immutable mock-only flow specifications;
append-only optimistic control, flow, and attempt revisions; sticky
cancellation; fenced multi-resource claim library APIs; and an internal local
completion outbox with idempotency keys and append-only delivery receipts.
Startup fingerprints every baseline-, migration-, and supervisor-owned schema
object and fails closed on missing, replaced, or unexpected triggers. A new
baseline, or the migration-ledger adoption of an exact legacy baseline, is
created statement-by-statement in one explicit transaction. Existing state is
verified before any schema DDL: the ledger must be a contiguous prefix of the
frozen v1-v12 identities, its version must agree with the installed supervisor
tables, baseline foreign keys and run-status lineage must remain valid, and a
rejected database is not repaired. WAL mode is selected only after baseline
acceptance.
Status and audit open existing state read-only and return empty reports for
absent state without creating it.
Reconciliation is preview-first and its apply step must present the exact
current plan digest.

Flow admission, library-only attempt claims, the local `created` → `dispatching`
pre-dispatch intent, and sticky cancellation retain separate, non-enforcing
ABAC compatibility shadows. Reversible operator control transitions, local
mock attempt claims, and each new local pre-dispatch bookkeeping append first
pass their separate authoritative Class 1 PEPs.
The read-only authorization inspector and supervisor audit each hold one
SQLite snapshot while checking baseline and migration integrity. The
supervisor audit independently recomputes both the shadow observations and
post-v5 control-PEP, post-v6 flow-admission-PEP, post-v7 attempt-claim-PEP,
and post-v9 pre-dispatch-intent-PEP decision/receipt pairs, plus post-v10
completion, post-v11 expired-claim reconciliation, and post-v12 queued-deadline
reconciliation shadow evidence, then checks coverage, order, parity, append-only
guards, and migration provenance. It also verifies that each local completion
receipt has its outbox's exact idempotency key and one matching local `delivered`
event; other local delivery-event dispositions or a delivered event without a
receipt are reported without modifying state.
For a non-running cancellation, it also binds the terminal revision and local
outbox to the durable cancellation source without modifying state.
The v9 PEP binds the local intent transition, running source revision, and
redacted active-lease facts before the target write; the v8 shadow remains
best-effort afterward. The v10 shadow is post-write, binds only the durable
local completion flow/attempt/outbox effect and redacted pre-release lease
facts. The v11 shadow separately binds a deterministic expired-claim terminal
repair, including redacted inactive lease evidence. The v12 shadow separately
binds a deterministic queued-deadline terminal repair and its local outbox.
None of these shadows can deliver or execute anything, or authorize a worker.
Frozen migration baselines exclude history created before each applicable
schema. None of the narrow supervisor PEPs authorizes a worker, and their
shadows do not replace the deterministic control path.
Control observations bind the exact previous control revision. Cancellation
observations bind the exact source flow revision and resulting local state/
outbox writes. The original flow remains irreversibly sticky-cancelled;
explicitly re-admitting equivalent work is a compensating action, not a
reversal. Cancellation therefore derives Class 3, remains denied by the
current Class 0/1 policy, and is reported as a legacy parity mismatch while the
non-enforcing operator safety path remains unchanged. Observation storage
retains that denied evidence; it does not enable Class 2/3 execution.

`ordomata supervisor` exposes enqueue, start, pause, resume, drain, stop,
status, cancel, audit, reconcile, completion inspection, and local receipt
commands. `ordomata supervise` holds a fenced foreground lease and processes
control intent, including drain/stop completion, without installing a service.
This is deliberately a control-plane tracer, not a completed supervisor:
claim APIs are not connected to the CLI loop, and worker/runner dispatch stays
hard-disabled until its exact worker-dispatch/tool boundaries have authoritative
ABAC coverage and verified repository containment. The narrow ordinary mock
PEP supplies neither. The loop starts no model,
worker subprocess, network action, repository-maintenance cell, Class 2/3
effect, or OS schedule.

The target backlog admits agent-proposed maintenance, testing, bug-finding,
and self-improvement work only when each proposal supplies reproducible
evidence, expected value, scope, acceptance checks, and required authority.
Deterministic admission deduplicates, classifies, budgets, and prioritizes it.
Follow-up discoveries return to the central candidate queue; only child work
already authorized by the bounded flow may start inline.

Priority is a transparent lexicographic vector: mandatory safety/recovery,
deadlines and blockers, expected operator/project value, evidence and
acceptance confidence, capacity fit, then age/fairness. Ordinary reprioritizing
waits for the next dispatch rather than preempting valid work. Concurrency
adapts to host load, isolation capacity, repository/resource conflicts, and
subscription availability within hard global, runner, repository, flow, and
resource caps; it reduces immediately under pressure and increases gradually
after stable evidence.

Flows may accept append-only DAG revisions proposed by workers, but the
controller validates that each amendment remains inside the original goal and
standing envelope, preserves completed history, respects depth/concurrency/
attempt budgets, and receives fresh authorization. Scope expansion becomes a
new centrally admitted candidate.

Future Class 2/3 effects pass through an authorized durable controller outbox
and dedicated credential-holding executors; workers only propose exact intents.
Delivery is modeled as at-least-once with idempotency and authoritative-state
reconciliation. Unknown ambiguous outcomes defer rather than risk a blind
retry.

## Derived operator summaries

The target controller derives these labels from the exact authorization
request and decision; the labels do not authorize an action:

- Class 0: read-only.
- Class 1: isolated local changes.
- Class 2: shared but normally reversible changes; disabled at this stage.
- Class 3: external, destructive, irreversible, or otherwise high-impact
  actions; disabled at this stage.

Until the planned runtime migration passes parity and adversarial tests, the
existing numeric Class 0/1 fields remain authoritative compatibility gates and
defense in depth. Target derivation uses the highest applicable class, so a
high-impact read is not forced into Class 0. This and consequential additive
writes show why the one-dimensional summary cannot replace contextual
authorization.

## Initial and subsequent workflows

Chief of Staff Lite is the first controlled demonstration because it exercises ingestion, retrieval, grounding, structured output, comparison, and human review without external actions. Repository maintenance remains the next tracer-bullet family: formatting, linting, type-checking, tests, builds, and evidence-backed bug repair in isolated worktrees.

## Self-improvement

Self-improvement is proposal-based:

```text
collect failures -> classify -> propose versioned variant -> benchmark
-> compare with baseline -> detect regressions -> human promotion -> rollbackable release
```

Held-out fixtures, billing policy, approval policy, and historical run records cannot be changed by an improvement run.

In v1 the orchestrator may inspect and improve its own repository only by
producing isolated, tested, independently reviewed candidates. The running
controller cannot activate its own code or policy. Operator attention is
severity-routed: billing, credential, containment, integrity, root-policy, and
urgent-deadline incidents alert immediately; routine deferrals, exhausted
repairs, ambiguous judgments, and low-priority blockers are batched into a
ranked digest. Sending a notification is itself an authorized external action.

Portable configuration is a declarative, versioned Git bundle of schemas,
policies, roles, profiles, workflows, repository-registration templates,
fixtures, and migrations. Secrets, account attestations, live databases,
leases, logs, worktrees, and private artifacts remain machine-local. Import
validates versions, capabilities, paths, and policy compatibility before
activation.

Unattended v1 activation requires the deterministic suite, authorization-
parity tests, adversarial containment tests, crash/replay recovery, a 24-hour
accelerated mock soak, a seven-day local soak, and narrow live-subscription
canaries. A false green, paid-route start, credential disclosure, out-of-cell
write, duplicate external effect, or unbounded loop resets the affected gate.
