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
and boundary coverage/order. Current schema-v6 exact-mock attempts retain
schema-v5 admission enforcement and schema-v4's dispatch and publication chains
while adding bounded canonical task-intent lineage to the authoritative binding,
including schema-v2 execution accounting, a schema-v5 publication shadow, a
separate publication decision, and schema-v3 enforcing pre-effect/action
receipts. Schema-v1-v3 paths retain schema-v2 non-enforcing publication
receipts, and unresolved local publication state is quarantined.
Controlled comparisons add a schema-v2 trial
binding, schema-v3 Class 0 admission/dispatch shadows, and a separate schema-v4
Class 1 private-publication shadow with schema-v2 pre-effect/action receipts.
Profile-backed ordinary attempts also append a required, content-addressed
execution-selection event before their task binding. New exact built-in-mock
attempts use schema v6; frozen schema v5 retains all three enforcement chains
without self-contained lineage, schema v4 means dispatch plus publication,
historical dispatch-only mock attempts use schema v3, and live or historical
selected attempts use schema v2.
It fixes the
policy clock, task features, candidate set, fixed rejection codes, metric
sources/scores/rank, and selected profile/version/configuration/overrides refs;
the inspector independently recomputes those semantics and their binding and
dispatch order. Raw model/settings/account/diagnostic values remain private.
The first three authoritative PEPs now gate only new profile-backed ordinary
Class 1 attempts through the exact controller-owned in-memory mock
implementation and their owner-private candidate publication. Schema-v5 adds
an admission decision and durable succeeded receipt before the admission
shadow, billing, dispatch, or `RUNNING`; the preceding run record and private
directories are inert controller scaffolding. Admission inherits the full task
consequence vector, and Class 0, unsafe/high-impact, non-permit, stale,
evaluation, or evidence failures stop before billing. The selection and
task-attempt binding require exact readback. The dispatch PEP persists a
fixed-policy decision only after exact mock billing evidence is durable, then
requires exact decision readback. Before `RUNNING`, it rebuilds current
controller inputs, independently constructs and compares the canonical
wrapper, independently replays the fixed policy, checks finite freshness and
the independent Class 0/1 ceiling, and rechecks the unchanged shipped runner
class and instance boundaries. It
requires exact `RUNNING` readback and repeats those current checks immediately
before invocation. The linked action receipt and execution accounting must
read back exactly before publication; unprovable post-effect receipt persistence quarantines the
attempt. The
publication PEP independently binds the succeeded dispatch and accounting,
reuses the v6 lineage with captured shipped resolver and evaluator replay,
persists and exactly rereads its own decision and pre-effect record, exactly
rereads the binding at the final PEP, and checks a new post-replay action time
immediately before the first staging mutation. It uses the reconciled filesystem
receipt as its action receipt.
Schema v6 now commits a bounded canonical task-intent lineage in the binding.
The final dispatch and publication PEPs require exact equality with the captured
shipped resolver, and read-only inspection replays v6 without a shadow preimage.
The enforcing decision-event and action-receipt schemas remain unchanged:
dispatch remains limited to Class 0/1 requests for the exact profile-backed
controller-owned `MockRunner`, new attempts still require Class 1 admission,
and publication remains an owner-private Class 1 local effect.
General runtime ABAC enforcement is not implemented. This phase remains a
prerequisite for adding a worker-dispatch path or repository worker with new
mediated capabilities. A
dispatch-disabled durable supervisor control-plane tracer may be developed in
parallel because it cannot exercise worker authority.

- Extend typed intent beyond the first task effect to profiles, repository
  resources, mediated commands/tools, and controller bookkeeping actions.
- Extend the implemented deterministic shadow evaluator from its focused Class
  0/1/adversarial fixtures to parity with every current allow and deny path.
- Preserve the implemented schema-v6 authoritative task-intent lineage and its
  shadow-independent dispatch and publication replay; schema-v1 through v5
  histories retain their frozen meanings.
- The standalone schema-v1 repository-registration contract and pure read-only
  validator are implemented. They derive stable repository/filesystem
  references from a controller-supplied ordinary Git root; validate exact argv-
  array (not shell-text) verification declarations, canonical protected/
  allowed paths, bounded resource limits, fixed local-container/network-
  disabled isolation, and patch-only review policy; and return digest-only
  evidence that explicitly grants no authority or dispatch. Mandatory `.git`,
  `.ordomata`, and `.agentops` protection plus traversal/symlink rejection fail
  closed. The validator remains pure and creates no state. Baselines and
  generated/vendor exclusions remain deferred.
- Controller-owned repository-proposal evidence is also implemented. For an
  existing immutable Class 0/1 `repository-proposal-disabled` run with only its
  initial `CREATED` event,
  `ordomata.repository_proposal.bind_repository_proposal_attempt` freshly
  revalidates one registration, requires an explicit canonical proposal
  digest, appends a content-addressed, statusless
  `repository_registration_selection` event followed by a content-addressed,
  statusless `repository_proposal_attempt_binding`, and requires exact
  readback from one consistent SQLite snapshot. Each append atomically requires
  current status `CREATED` and the exact ordered predecessor event IDs; commit
  failures roll back before reconciliation. It reuses existing `run_events`;
  persists no registration body or raw proposal content, path, argv, workspace,
  run directory, identifier, or artifact content; adds
  no SQLite migration; and creates no run/status transition, worktree, command,
  worker, supervisor dispatch, authorization, billing/route change, or live
  eligibility.
- Independent single-run repository-proposal inspection is implemented in the
  library-only `ordomata.repository_proposal_inspection` API
  `inspect_repository_proposal_evidence(database_path, *, run_id)`. Its
  privacy-bounded `RepositoryProposalInspectionReport` fixes
  `inspection_scope: "single_run"` and reports `clean`, `coverage`,
  `truncated`, a capped event count, permission class/current status, optional
  validated proposal/registration/repository references and version, optional
  selection/binding digests and sequences, and bounded fixed-code findings.
  Its mapping also fixes read-only inspection/validation, no repair, disabled
  dispatch, and no granted authority, and reports evidence completeness and
  finding count.
  Only exact `CREATED`-only or `CREATED`-plus-selection prefixes are incomplete;
  the exact clean three-event chain is complete; all other histories are
  invalid. `clean` requires complete, untruncated, finding-free evidence, while
  more than four events sets `truncated` because the capped inspection cannot
  cover the history.
  One result proves only its caller-named run, never the whole database.
- Inspection stages the exact signed main file and optional WAL into owner-
  private temporary storage under a fixed controller-owned 512 MiB combined
  ceiling; oversized state fails before copy. A no-WAL snapshot opens through
  an immutable read-only URI, while an in-budget WAL pair opens read-only.
  SQLite opens only the staged identity, and before/after source signatures
  detect concurrent changes. One query-only SQLite snapshot independently
  replays cardinality/order, digests, durable-run/component/proposal linkage,
  and fixed disabled/no-authority semantics; creates no source schema or
  sidecars; performs no repair or live-filesystem registration revalidation;
  and emits no raw identifiers, SQLite diagnostics, paths, argv, proposal or
  registration content, workspace/run-directory values, or artifact content.
  It is not an external tamper anchor and has no run/status/event,
  authorization, worktree, Git/command/process, worker/supervisor, routing,
  billing/capacity/circuit, harness/network, dispatch, or live effect.
- Controller-owned repository-proposal admission observation is implemented in
  the library-only `ordomata.repository_proposal_admission` API
  `evaluate_repository_proposal_admission_shadow(database_path, *, run_id,
  evaluated_at)`. Each call freshly invokes the independent inspector and
  accepts no supplied report, class, request, policy, or evaluator. Only a
  clean, evidence-complete, complete, untruncated, finding-free exact
  three-event Class 0/1 result is evaluated. Every nonclean result is inert:
  `not_evaluated`, `indeterminate`, and contains no request, policy, or
  decision.
- Its fixed class-specific ABAC projection is exactly Class 0 local `READ`
  observation with unenforced audit-receipt plus read-only obligations, or
  Class 1 local `CREATE` nomination with unenforced audit-receipt plus
  isolated-local-only obligations. The request digest-binds
  the privacy-safe inspection mapping and validated lineage; the active shadow
  result must match a captured built-in replay and the controller's expected
  decision. Even an exact permit is observational only. The mapping fixes all
  authority, enforcement, persistence, admission/action, receipt, repair,
  dispatch, route, billing, and obligation-enforcement facts to false and no
  repository, command, worker, harness, network, or live effect occurs.
- The next recommended bounded slice is a separate, library-only verifier for
  an untrusted returned admission-shadow mapping. It should emit only fixed
  privacy-safe replay findings and must not add persistence, repair,
  enforcement, authority, worker enablement, or any repository/external effect.
- Extend the three durable enforcing decision/action-receipt chains beyond the
  narrow profile-backed built-in-mock admission, dispatch, and publication
  boundaries only after semantics and parity stabilize.
- Preserve the implemented distinct `permit`, `defer`, `deny`, and
  `indeterminate` effects; add durable waiting/resumption so satisfying a
  digest-bound defer condition always creates a fresh decision.
- Keep the Chief-of-Staff admission and dispatch-intent shadows as descriptive
  evidence. The separate exact built-in-mock Class 1 admission, execute, and
  local-candidate boundaries are enforced; general/live/comparison/supervisor
  admission remains non-enforcing or disabled;
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

Exit evidence: the covered mock boundary executes only from a fresh exact
permit and otherwise fails closed without invoking the runner; decision and
action receipts are replayable for audit; no Class 2/3, live, worker, or
external action becomes eligible; and legacy checks remain as defense in depth
until enforcement-point coverage is demonstrated.

## Phase 2 — repository-maintenance tracer bullets (partially implemented)

The durable control-plane prerequisite now has a mock-only tracer: a versioned
additive SQLite migration, immutable flow admission, append-only optimistic
control/flow/attempt state, sticky cancellation, fenced multi-resource claim
library APIs, an internal local completion outbox and receipts, read-only
status/audit, digest-bound reconciliation, operator control commands, and a
foreground `ordomata supervise` loop. Flow admission, the otherwise
library-only attempt-claim boundary, operator control transitions, and sticky
cancellation now append typed, non-enforcing ABAC shadow observations with
an explicit legacy-parity comparison. Worker dispatch is deliberately disabled
until the exact worker boundary has authoritative ABAC coverage and verified
repository containment; the narrow ordinary mock PEPs do not supply either.
The read-only supervisor audit independently recomputes
those observations and checks coverage, order, exact schema guards, and
migration provenance without altering reconciliation plan digests. Ordinary
state opens now validate the exact baseline and run history plus a frozen,
contiguous v1-v4 migration prefix before use; creation and exact legacy
adoption are transactional, while partial or tampered state fails closed
without repair. This does
not implement a repository
worker, live model loop, subprocess execution, network access, Class 2/3
actions, or OS scheduling, so Phase 2 is not complete.

The implemented repository-proposal selection and binding records are inert
PIP lineage for an existing `CREATED` sentinel run. Each append atomically
requires that status and the exact ordered predecessor event IDs, then one
consistent snapshot proves exact readback. The records store only a canonical
`proposal_digest`, never raw proposal content. They do not satisfy repository
containment, worker admission, command authorization, or dispatch
prerequisites.

Start with machine-verifiable, low-risk work in isolated Git worktrees:

1. formatting-only fixes;
2. lint fixes;
3. type-check fixes;
4. deterministic test repair;
5. evidence-backed bug fixes;
6. bounded repository housekeeping.

Each completed repository registration will record controller-validated command
declarations, baseline failures, protected paths, resource limits, and a
review-only branch/PR policy. Those declarations are configuration inputs, not
authority to execute. A future worker run must prove no outside-worktree writes
and no false green.

Worker cells use a pluggable isolation contract and observed pre/post
attestation. Once containment is proven, an implementer may use a general
in-cell shell, exact task-specific proxy egress, locked dependencies and
lifecycle scripts, and verified read-only content-addressed caches. Host shell,
shared Git authority, credentials, control sockets, and undeclared network
remain unavailable. Repository and connector registrations also pin scoped
project instructions and versioned source-of-truth/freshness rules.

## Phase 3 — bounded local loop

- Extend the implemented dispatch-disabled foreground tracer into an
  authorized worker loop only after its exact dispatch/tool boundaries have
  authoritative ABAC enforcement and Phase 2 repository containment exists.
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
