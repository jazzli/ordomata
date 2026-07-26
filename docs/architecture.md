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
`.ordomata/`. A sole legacy `.agentops/` root is selected in place without
mutation; the presence of both roots is an integrity conflict and fails closed.
This preserves append-only records and their original absolute-path provenance.

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

This is principally a target architecture, not a claim that ABAC now enforces
runtime authority. The implemented code still uses `PermissionClass` and
distributed deterministic eligibility gates. Task contracts may now declare a
typed task-effect action, resource, and consequence vector independently of
that class. The Chief of Staff path evaluates task intent non-authoritatively
at admission and runner/model dispatch. At local-candidate publication it uses
a truthful controller-owned local-create projection even when the task intent
is read-only, while conservatively inheriting task protection, sensitivity,
and confidentiality/integrity/availability impact, then appends canonical
policy/evidence digests, legacy-result parity, and
independent authority-ceiling parity. These observations
are not permits or enforcement receipts and cannot affect execution or
publication; even their persistence is best-effort. There is still no central
enforcing policy-decision point, per-command/tool mediation,
approval-resumption path, or runtime action receipt. Existing gates remain in
force, and migration must not widen the Class 0/1 ceiling.

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
  -> append a fresh shadow dispatch-intent observation immediately before the
     controller calls the runner
  -> execute bounded harness or deterministic worker
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

## Controlled comparison

The `compare-run` workflow is a controller-owned experiment, not a second execution path. Before it writes a plan or trial record, all selected named profiles must pass the same `doctor`, routing, current-evidence, durable-capacity, and durable-circuit gates as an individual live run.

Every trial receives the exact same immutable sanitized Class 0 task/context snapshot, schema, two-minute timeout ceiling, and empty workspace. The six-trial plan also requires a one-minute whole-run evidence margin, so its maximum envelope fits inside the current 15-minute Claude attestation window. Order is randomized within repetition blocks, while each adapter and session is fresh. Trial output is kept in an owner-private review artifact and is never fed to another trial. The report preserves raw automated dimensions and a separate human-review template; it contains no aggregate score, winner, or automatic promotion. Partial outcomes are retained if a billing or capacity stop prevents the remaining trials. The workflow is implemented, but no live Codex-versus-Claude comparison has been completed.

The comparison path is a separate `runner.execute` caller and currently has no
durable per-trial `RunRecord`/`run_events` stream. Its private report files are
not treated as authorization receipts. Admission, dispatch, and publication
shadow coverage for comparison trials remains deferred until that audit model
is designed. Reports record this state as
`authorization_shadow_coverage=deferred_not_covered`; the three implemented
boundary observations apply only to the Chief-of-Staff run path.

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
object and fails closed on missing, replaced, or unexpected triggers.
Status and audit open existing state read-only and return empty reports for
absent state without creating it.
Reconciliation is preview-first and its apply step must present the exact
current plan digest.

`ordomata supervisor` exposes enqueue, start, pause, resume, drain, stop,
status, cancel, audit, reconcile, completion inspection, and local receipt
commands. `ordomata supervise` holds a fenced foreground lease and processes
control intent, including drain/stop completion, without installing a service.
This is deliberately a control-plane tracer, not a completed supervisor:
claim APIs are not connected to the CLI loop, and worker/runner dispatch stays
hard-disabled until runtime ABAC enforcement exists. The loop starts no model,
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
