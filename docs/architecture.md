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
coverage. The first narrow authoritative PEP now applies only to new
profile-backed ordinary attempts using the controller-owned in-memory mock
runner implementation. Subclasses cannot receive that permit. It constructs a
separate exact `runner.execute` request, evaluates a fixed mock-only policy,
persists the decision before `RUNNING`, rechecks its
fresh Class 0/1 ceiling immediately before invocation, and appends a linked
terminal action receipt. Only a validated identity-matched no-process mock
result can produce a succeeded receipt. Existing
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
bindings, enforcing dispatch decisions, and action receipts are distinct from
those shadows. Unprofiled schema-v1 bindings, live or historical schema-v2
bindings, and every comparison path retain their non-enforcing interpretation.
There is still no
general admission/publication PEP, per-command/tool mediation,
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
  -> create append-only run record
  -> append the non-authoritative Phase 1C task-admission observation
  -> for a new profile-backed controller mock attempt only, persist and enforce
     a fresh fixed-policy decision for the exact mock runner invocation
  -> transition to RUNNING only after that narrow decision is eligible
  -> append the non-authoritative task-effect dispatch-intent observation
  -> recheck the permit freshness immediately at the invocation boundary
  -> execute bounded harness or deterministic worker
  -> append the enforced mock action receipt when that narrow PEP applied
  -> normalize events and result
  -> perform post-run billing assessment
  -> record capacity/circuit outcome; quarantine on paid or unknown evidence
  -> validate output schema
  -> run deterministic evaluation
  -> append a shadow local-candidate observation bound to the validated bytes
     and digest, using the controller-owned local-create projection, before the
     first artifact filesystem mutation
  -> save local artifact and metrics only when promotion remains safe
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
schema-v3 binding links new exact built-in-mock enforcement; schema-v2 remains
for live and historical selected attempts. Both admission/dispatch observations
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

A run is successful only when all of the following hold:

1. the process exits successfully;
2. the runner emits its documented terminal-success event;
3. the output matches the task schema;
4. deterministic evaluation passes.

Missing telemetry is `unavailable`, never zero.

Each completed attempt also records the adapter-authored harness version and execution mode, whether a harness process started, whether live model execution was observed, observed-or-unavailable subscription-capacity consumption, `paid_capacity_consumed`, `incremental_ai_charge`, the narrower `incremental_api_charge`, postflight disposition, and wall time. `incremental_api_charge: none` does not imply `incremental_ai_charge: none`; only a verified safe, matching postflight supports the latter. No per-run subscription dollar cost is invented.

Included-capacity exhaustion becomes an append-only `blocked_until_reset` observation and stops automatic retry. The atomic reservation checks account-global, account/profile, provider/profile, and provider-global capacity scopes as well as circuits. A blocking capacity observation survives restart and can be superseded only by a strictly newer verified `available` observation after any recorded reset. Completion persists postflight capacity before releasing the dispatch leases. Paid, changed-account, or unknown post-run evidence quarantines the attempt and any output before promotion and opens the account/profile billing circuit. Later live dispatches fail while that circuit is open.

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

Live workspaces must be non-symlinked children of a unique run directory. For Chief of Staff Lite they start empty, so source material is available only through the bounded stdin prompt.

- Codex uses a read-only sandbox, `never` approval mode, strict/ignored user configuration, ignored exec-policy rules, ephemeral sessions, and structured JSONL. Class 1 currently means the controller may write a validated local draft; it does not grant the harness filesystem writes. The adapter extracts the final structured answer from the bounded, redacted in-memory event stream and does not ask Codex to persist a raw last-message file.
- Claude Code uses safe mode, an explicitly empty settings-source list, strict empty MCP configuration, no Chrome, no session persistence, disabled skills, and an empty built-in tool list. It returns structured output; the controller performs the only artifact write.

The entire process lifecycle—including process creation and stdin delivery—is covered by the wall timeout.

For repository work, the target worker-cell interface is backend-pluggable and
declares minimum filesystem, process, network, credential, and resource
assurances. Containers, OS sandboxes, or later VMs are eligible only when
observed preflight state attests the effective user, mounts, writable paths,
network policy, limits, credential absence, and lack of control sockets;
post-run evidence verifies containment and cleanup. The controller never
silently downgrades an assurance requirement.

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

Every new Chief-of-Staff attempt records a digest-only binding before its
admission shadow. The binding covers the controller-resolved typed
authorization intent as well as immutable run inputs, and dispatch binds the
persisted preflight billing assessment. After runner execution, schema-v2
accounting projects the identity and billing disposition fields needed to
recompute one sanitized billing digest. Runner-provided version text is reduced
to a content reference, execution mode is restricted to controller-known
labels, and billing/accounting events are content-addressed for exact ambiguous
write reconciliation. An accepted, credential-clean candidate then receives a
schema-v5 non-enforcing publication shadow and a required schema-v2 pre-effect
receipt before the first artifact-directory mutation.

The controller stages owner-private bytes under a deterministic name, opens the
parent chain without following mutable symlinks, and retains verified parent
and inode descriptors through receipt reconciliation. It fsyncs the file and
namespace, reconciles immutable artifact metadata by exact readback, promotes
without overwrite, and verifies the final bytes, mode, size, inode, parent
identity, and expected hard-link count. A deterministic schema-v2 action
receipt records succeeded, failed, cancelled, or unknown outcome. Proven
missing receipts roll back only the owned final inode; an unexpected surviving
link or any unprovable metadata, staging, final-name, directory-sync, receipt,
or terminal state quarantines the attempt. An artifact metadata row alone is
proposed evidence, not proof of publication. Historical ordinary attempts
without the binding retain their prior shadow-only interpretation.
For both bound paths, billing or accounting evidence without a later
controller-owned terminal record is an attention-required incomplete history;
a bound attempt that has not reached billing may still be legitimately in
progress.

For a selected controller-owned mock profile, the binding is schema v3 and
declares one additional, separate chain: billing assessment, exact mock-
dispatch request and fixed-policy decision, Class 0/1 eligibility enforcement
before `RUNNING`, a final freshness check immediately before invocation, and a
terminal action receipt linked to the decision and enforced action. A deny,
defer, indeterminate result, stale permit, unsupported
obligation, ceiling mismatch, or unproven decision append invokes no runner.
Schema-v1 unprofiled and schema-v2 selected histories remain valid
shadow-only evidence; live runners continue to use schema v2.

Neither the mock-dispatch chain nor the publication receipt authorizes the
candidate write. Publication still relies on the existing Class 0/1 gate, its
shadow can expose an authority-ceiling mismatch, and no shared, remote,
promotion, deployment, live-harness, supervisor-worker, or Class 2/3 effect is
enabled.

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
frozen v1-v4 identities, its version must agree with the installed supervisor
tables, baseline foreign keys and run-status lineage must remain valid, and a
rejected database is not repaired. WAL mode is selected only after baseline
acceptance.
Status and audit open existing state read-only and return empty reports for
absent state without creating it.
Reconciliation is preview-first and its apply step must present the exact
current plan digest.

Flow admission, library-only attempt claims, operator control transitions, and
sticky cancellation append separate, non-enforcing ABAC shadow observations.
The read-only authorization inspector and supervisor audit each hold one
SQLite snapshot while checking baseline and migration integrity. The
supervisor audit also independently recomputes shadow requests and decisions
and checks coverage, order, parity,
append-only guards, and migration provenance. Frozen migration baselines
exclude history created before each shadow schema. These observations do not
authorize a worker or replace the deterministic control path.
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
hard-disabled until its exact claim/dispatch/tool boundaries have authoritative
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
