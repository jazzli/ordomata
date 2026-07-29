# Ordomata

**A local control plane for governed autonomous work.**

Pronounced **or-doh-MAH-tuh**: four syllables, with the primary stress on
“MAH” (IPA: `/ˌɔːr.doʊˈmɑː.tə/`).

Ordomata is a local, single-operator control plane for running neutral tasks through first-party AI coding-harness subscriptions without using purchased product credits, subscription overage, separately billed model APIs, or cloud inference routes. The current tracer bullet is **Chief of Staff Lite**: sanitized local sources become an immutable context snapshot, a structured local draft, and transparent deterministic evaluation.

Source, tests, plans, fixtures, and deliberately sanitized configuration are
published at [`jazzli/ordomata`](https://github.com/jazzli/ordomata) for
provenance and portability. This public repository must never contain private
inputs, credentials, account or billing attestations, local databases, logs,
workspaces, run artifacts, or other sensitive operator data. Those remain local
and ignored, and Ordomata does not push them automatically.

The repository is intentionally conservative about execution while remaining extensible. Codex and Claude Code adapters exist, but normal development and tests use the deterministic mock. Cursor and repository-maintenance workflows are planned next.

## Rename compatibility

The canonical import package and CLI are both `ordomata`, and new local state
uses `.ordomata/`. If a checkout contains only the former `.agentops/` state
root, Ordomata continues using it in place so append-only records and stored
absolute paths remain intact. If both state roots exist, startup fails closed
instead of merging or splitting audit history.

`ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1` is the canonical live-run opt-in. The
former `AGENTOPS_ALLOW_SUBSCRIPTION_RUNS=1` spelling remains a narrow
compatibility alias; when both variables are present they must both equal
exactly `1`, otherwise live execution remains disabled. This alias does not
bypass any billing, authorization, identity, capacity, isolation, or circuit
check.

The renamed distribution intentionally does not install legacy `agentops`
import-package or CLI aliases. Before starting Ordomata, stop and remove any
pre-rename installed runtime or background process; old code cannot participate
in the new dual-root integrity check. An existing legacy state root remains
selected in place: normal versioned SQLite initialization may append migration
metadata, but moving that root or rewriting existing records requires a
separately designed and verified offline migration.

Several pre-rename v1 identifiers remain frozen protocol provenance: account-
fingerprint and supervisor-migration domain separators, authorization shadow
bundle/source IDs, schema `$id` URIs, and the Codex billing-probe client label.
They are not current product names and must not be rewritten inside historical
records.

## What works now

- strict, versioned, runner-neutral task contracts;
- local SQLite FTS5 ingestion, hashing, deduplication, retrieval, and bounded context packs;
- explicit untrusted-source boundaries and credential-shaped input rejection;
- structured output schemas and eight raw evaluation dimensions;
- subscription-only Codex and Claude Code adapters with fail-closed route and account-identity checks;
- narrow child environments that exclude credential and cloud-route variables;
- Billing Hard-Stop v2: separate route, included-capacity, paid-continuation, and paid-balance observations plus short-lived account-bound attestations;
- an interactive `billing-attest` workflow that independently probes the selected harness, requires an exact operator statement, and atomically stores only private semantic evidence;
- an exact live-run gate that is necessary but cannot override billing, evidence, environment, profile, isolation, or circuit failures;
- versioned harness/model/role/settings profiles and billing-lane-aware routing;
- immutable, privacy-safe execution-selection evidence for profile-backed
  Chief-of-Staff attempts, including canonical candidates, fixed rejection
  codes, raw metric tiers, policy/profile/configuration refs, and the selected
  overrides digest;
- pure repository-registration validation for frozen schemas v1 through v4,
  plus the separate library-only schema-v1 direct-executable resolver that
  freshly revalidates exact v4 and returns only bounded, sequential,
  aggregate evidence without authority or execution;
- controller-owned, dispatch-disabled repository-proposal evidence: the
  `bind_repository_proposal_attempt` library API freshly revalidates one
  registration, requires an explicit canonical proposal digest for an existing
  `repository-proposal-disabled` run, and exactly reads back one content-
  addressed `repository_registration_selection` event followed by one
  `repository_proposal_attempt_binding` event while the run remains `CREATED`;
- independent, library-only repository-proposal inspection: the
  `inspect_repository_proposal_evidence` API proves one caller-named run from a
  single read-only SQLite snapshot and returns only bounded, privacy-safe
  coverage, linkage, digest, sequence, and fixed-code findings;
- controller-owned, library-only repository-proposal admission shadow: the
  `evaluate_repository_proposal_admission_shadow` API freshly invokes that
  inspector, evaluates only exact clean and complete Class 0/1 evidence against
  a fixed class-specific ABAC policy, and returns a privacy-safe, explicitly
  non-authoritative observation without persistence or effect;
- independent, library-only admission-shadow verification: the
  `verify_repository_proposal_admission_shadow_mapping` API validates a bounded
  detached exact-dict snapshot with fixed value-free findings; internal
  consistency is not authenticity, freshness, durable truth, or authority;
- isolated per-run workspaces, wall timeouts, terminal-event checks, and output validation;
- append-only SQLite runs, events, artifacts, capacity observations, billing circuits, scheduler claims, and expiring leases, with capacity checked inside the atomic dispatch reservation; baseline creation and exact legacy adoption are transactional, and every ordinary open verifies the frozen, contiguous v1-v4 migration prefix before use;
- a versioned additive SQLite migration for a durable supervisor control-plane
  tracer: immutable mock-only flow admission, append-only optimistic control/
  flow/attempt revisions, sticky cancellation, fenced multi-resource claim
  library APIs, an internal local completion outbox with receipts, and
  append-only non-enforcing ABAC shadow observations at flow admission,
  attempt claim, operator control transitions, and sticky cancellation;
- read-only supervisor status/audit, including independent shadow-digest,
  parity, coverage, ordering, schema, and migration-ledger verification;
  digest-bound reconciliation preview/apply; explicit control commands; and a
  foreground `ordomata supervise` loop whose worker dispatch is deliberately
  disabled;
- post-run billing assessment that quarantines paid or unknown outcomes, suppresses promotion, and opens a durable circuit when required;
- optional typed task-effect authorization intent, independent of the legacy
  numeric class, plus three non-enforcing Chief-of-Staff shadow decisions at
  admission, runner/model dispatch intent, and local-candidate publication;
- the first three authoritative ABAC enforcement points: new profile-backed
  ordinary Class 1 attempts using the exact controller-owned in-memory
  `MockRunner` implementation first require a fixed-policy task-admission
  permit and durable succeeded admission receipt before the admission shadow,
  billing preflight, dispatch, or `RUNNING`; the run record and private
  directories created earlier are inert controller scaffolding. The full task
  consequence vector is inherited, so Class 0, unsafe/high-impact, non-permit,
  stale, malformed, or unprovable admission evidence stops before billing. A
  separate fixed-policy permit is then required for the exact mock
  `runner.execute` action. The immutable execution selection, task-attempt
  binding, mock billing assessment, enforcing decision, and `RUNNING`
  transition each require exact durable readback. Before `RUNNING`
  and again immediately before invocation, the controller rebuilds the permit
  from current authoritative inputs, requires the current resolved task intent
  to equal the bounded canonical lineage in the durable binding, independently
  constructs the canonical wrapper for equality with the retained persisted
  payload, replays the fixed policy, rejects non-finite or stale action times,
  and rechecks exact runner ownership, including unchanged shipped class and
  instance boundaries. Its
  content-addressed terminal action receipt and execution accounting also
  require exact readback before publication may proceed; an unprovable receipt
  after execution quarantines the attempt. Accepted, credential-clean output
  then requires a separate fixed-policy Class 1 permit for the owner-private
  local candidate. That PEP reuses the schema-v6 binding lineage, compares it
  with the captured shipped task-intent resolver, and independently replays the
  shipped evaluator and fixed policy. Its decision and enforcing pre-effect
  record read back exactly; immediately before the first staging mutation, the
  binding, decision, and pre-effect record read back again, the authorization is
  rebuilt, and a new post-replay action time must still be fresh. The existing
  reconciled action receipt records the result. Every non-permit, stale permit,
  authority-ceiling mismatch, or
  uncertain required write blocks before its governed action, and only a
  validated identity-matched no-process result can receive a succeeded
  dispatch receipt, while live, comparison, supervisor, shared publication,
  and promotion paths remain non-enforcing or disabled;
- privacy-bounded ordinary task-attempt bindings that cover the typed
  authorization intent and, for profile-backed attempts, the immutable
  execution selection, profile version, and configuration; current enforced
  mock attempts use a schema-v6 binding that retains admission, dispatch, and
  local-candidate publication coverage while adding the canonical task-intent
  preimage, its controller-owned source, and exact digests needed for
  authoritative replay. Schema-v5 retains the same three enforcement chains
  without the self-contained lineage, schema-v4 is frozen as dispatch plus
  publication, historical schema-v3 bindings declare dispatch only, and
  unprofiled schema-v1 plus live or historical schema-v2 histories retain their
  prior meaning;
  schema-v2 execution accounting, billing-bound dispatch, and schema-v3
  enforcing pre-effect/action receipts around the schema-v5 local-candidate
  publication shadow for schema-v4/v5/v6 enforcing paths, with exact metadata,
  filesystem, and receipt reconciliation; schema-v1-v3 paths retain schema-v2
  non-enforcing receipts;
- append-only schema-v2 Class 0 comparison-trial bindings, lifecycle/accounting
  evidence, schema-v3 admission/dispatch shadows, and a separate schema-v4
  non-enforcing Class 1 private review-artifact publication shadow with
  schema-v2 pre-effect and action-receipt records;
- a strictly read-only `auth-inspect` command that checks baseline schema and
  run-history integrity plus the frozen migration ledger, then recomputes
  legacy and authority-ceiling parity from persisted run state and independently
  derived typed request attributes, canonical digests, evidence authenticity/
  freshness, boundary coverage/order, billing linkage, artifact metadata, and
  ordinary/comparison receipt outcomes; enforcing mock non-permits require
  their exact controller terminal, and a claimed pre-effect stop cannot
  coexist with a dispatch receipt;
- bound histories that reach billing or accounting without a controller-owned
  terminal record are reported as incomplete, while pre-billing attempts may
  remain in progress;
- deterministic controlled comparisons with one immutable snapshot, randomized repetition blocks, fresh adapters/sessions/workspaces, and Class 0 permissions;
- proposal-only self-improvement policy with held-out regression protection;
- typed execution accounting that keeps subscription capacity, paid-capacity consumption, incremental AI charge, and the narrower API-charge field distinct;
- privacy-bounded ordinary accounting that stores runner versions only as
  content references and accepts execution-mode labels only from a fixed
  controller vocabulary;
- an operator CLI and a deterministic, live-model-free test suite.

The authoritative lineage slices advance only the current built-in-mock attempt
binding from schema v5 to v6; they change no enforcing decision-event or action-
receipt schema and grant no new authority. The binding carries one strict,
bounded canonical task-intent lineage; prompts, task inputs, paths, approver
values, and credentials remain omitted. The final dispatch and publication PEPs
reuse that lineage, compare it with the captured shipped resolver, and replay
the shipped evaluator and fixed policy independently of patchable entry points.
Publication additionally requires exact binding, decision, and pre-effect
readback before post-replay action-time freshness and the first staging
mutation. Read-only inspection replays schema v6 without a shadow preimage.
Schema-v1 through v5 histories keep their frozen meanings. Dispatch remains
limited to Class 0/1 requests for the exact profile-backed controller-owned
`MockRunner`, publication remains an owner-private Class 1 local write, and no
live, shared, promotion, API, credit, overage, or cloud path is enabled.

The repository-registration boundary now has frozen schema-v1 through
schema-v3 contracts and a separate additive schema-v4 contract. The pure read-
only
`repository_registration`
validator accepts a controller-supplied ordinary Git root, derives stable
repository and filesystem references, validates format, lint, type-check, test,
and build as exact argv-array (not shell-text) declarations, canonicalizes
protected and allowed repository-relative POSIX paths, enforces mandatory
protection for `.git`, `.ordomata`, and `.agentops`, and validates bounded
resource, fixed local-container/network-disabled isolation, and patch-only
review declarations. Case-insensitive aliases of controller-owned paths,
traversal, and symlink escapes fail closed. Registration versions are bounded
canonical SemVer; credential/billing option names, known shell launchers, and
protected relative executables are rejected. Schema v2 additionally requires
bounded `generated_paths` and `vendor_paths` arrays under `path_policy`.
They are canonical literal deny/classification roots strictly below allowed
paths, never glob or ignore rules. Cross-category nesting, case aliases,
protected or sensitive overlap, symlinks, special files, traversal, and
expansion syntax fail closed; missing leaves remain valid and are not created.
The declarations attest neither generation nor vendor provenance and cannot
hide a diff or authorize a change. Schema v3 retains those path-policy rules
and additionally requires controller-supplied baseline command-result
attestations. Every declared command is covered exactly once by its kind,
identifier, and digest of the exact canonical declaration, and every result is
bound to one shared opaque snapshot digest. Results contain only bounded
integer timing and an exact tagged `exited`, `signaled`, or `timed_out`
observation; a timeout must carry the controller-supplied
`termination_confirmed: true` assertion. They contain no supplied success
claim, output or output hash, environment, path, message, or arbitrary metadata; success is
derived only from an exited zero code. Canonicalization binds the ordered
observations, repository reference, and verification-command digest into one
aggregate baseline digest. The privacy-bounded v3 evidence adds only
`baseline_attestation_source: "controller_supplied"`,
`baseline_command_results_digest`, bounded `baseline_result_count`,
`baseline_authenticity_verified: false`, and
`baseline_freshness_verified: false`. It does not expose the snapshot or
individual command results.

The v3 validator checks internal structure and linkage only. It does not
authenticate the supplied observations, compare their timestamps with the
clock, recompute the snapshot, resolve an executable or toolchain, or establish
reproducibility. Schema v4 preserves the v3 contract and additionally requires
one controller-supplied executable/toolchain identity claim for every declared
command. Each claim carries the exact command kind, identifier, and command
digest plus opaque `executable_identity_digest` and
`toolchain_identity_digest` values. Canonicalization follows declaration order
and derives a syntax-only, command-context-bound declared-executable reference,
the repository reference, the complete verification-command digest, and the
exact baseline aggregate digest. These bindings make the resulting aggregate
context-specific; they neither standardize nor verify the opaque digests'
preimages or provenance. A claim block transplanted into another valid context
can validate with a different aggregate, and same-context replay is
indistinguishable. The baseline binding proves co-declaration only, not that the
baseline process used the claimed executable or toolchain bytes.

Schema-v4 evidence exposes only the fixed controller-supplied source, aggregate
identity digest, and bounded identity count. It fixes
`executable_toolchain_authenticity_verified`,
`executable_toolchain_freshness_verified`,
`executable_toolchain_resolution_verified`,
`executable_toolchain_content_verified`, `toolchain_completeness_verified`, and
`executable_toolchain_execution_correspondence_verified` to `false`. It exposes
no individual identity, declared-executable reference, path, argv, environment,
output, version, or package metadata. Validation of the v4 identity block adds
no PATH or environment lookup, executable stat or content read, symlink or
shebang inspection, interpreter, launcher, module, plugin, dynamic-loader, or
package discovery and executes nothing. Existing registration root and
repository-relative path/executable safety checks are unchanged. The validator
remains pure: it creates no run, state/event record, authorization, worktree,
command, worker, route, or live-model eligibility and authorizes or executes
nothing.

The separate library-only
`ordomata.repository_executable_resolution` API implements a schema-v1 direct-
executable measurement receipt. It accepts only an exact schema-v4 registration,
freshly revalidates it, and uses the fixed `controller_measured` source and
`posix_nofollow_v1` scope. Bare executable names are resolved only through at
most 32 controller-supplied absolute search directories; ambient `PATH`, empty
or relative entries, suffix expansion, and current-directory fallback are
absent. A slash-containing `argv[0]` initially requires command `cwd` to be `.`
and resolves from the registered repository root. Directory descriptors,
descriptor-relative traversal, exact entry spelling, no-follow opens, complete
bounded reads, metadata comparison, namespace reopen, and final registration
revalidation bind each direct file to its command and resolution context.
Symlinks, special files, sparse files, missing execute bits, and detected
drift/races fail closed. Measurement is capped at 64 MiB per unique file and
256 MiB in total.

The outward projection exposes only aggregate receipt/context digests and
bounded measurement, unique-file, and byte counts. It fixes
`sequential_resolution_measurement_complete: true` and
`atomic_snapshot_verified: false`: the point-in-time receipt is sequential and
non-reusable, not an atomic filesystem snapshot. Current freshness,
authenticity or provenance, effective
invocability, shebang/interpreter/launcher and dependency coverage, toolchain
completeness, repository-snapshot or baseline correspondence, and future
execution correspondence remain false. It grants no authority, dispatch,
action receipt, route, billing/capacity fact, or live eligibility and adds no
CLI, persistence, subprocess, or execution path.

Separately, `ordomata.repository_proposal.bind_repository_proposal_attempt`
freshly revalidates one registration, requires an explicit canonical
`proposal_digest`, and accepts only an existing immutable Class 0/1
`repository-proposal-disabled` run whose sole prior event is `CREATED`. It
appends exactly two schema-v1, statusless, content-addressed events in order:
`repository_registration_selection`, then
`repository_proposal_attempt_binding`. Each append atomically requires current
status `CREATED` and the exact ordered predecessor event IDs, so an unrelated
concurrent event blocks before proposal evidence is appended. The selection
records the controller-owned privacy-bounded registration evidence and exact
proposal digest; the binding repeats that digest and carries only privacy-
bounded digest/version links, bounded attempt controls, fixed disabled facts,
and privacy-safe references to the existing run. Commit failures are rolled
back before reconciliation. Exact retries and a selection-only interrupted
append reconcile only after one transactionally consistent read of the exact
event IDs, types, payloads, order, and current status.
The persisted evidence fixes `validation_mode: "read_only"`,
`dispatch_enabled: false`, and `authority_granted: false`; the returned
projection reports `persistence_mode: "append_only_exact_readback"` and
`run_status_at_readback: "created"`.

This evidence layer reuses existing append-only `run_events`; it adds no
SQLite migration and does not persist a registration document or any raw
repository path, argv, workspace, run directory, proposal identifier, proposal
content, or artifact content. It has no CLI or sample registration and creates
no run or status transition,
authorization decision or action receipt, worktree, Git or subprocess call,
worker or supervisor dispatch, profile route, billing/capacity/circuit fact, or
live eligibility. Proposal lineage remains pinned to frozen registration
evidence v1, so schema-v2 through schema-v4 registrations fail before any
proposal event append. The separate point-in-time executable-resolution receipt
is not proposal evidence and does not widen that lineage. Complete interpreter,
dependency, and toolchain manifests plus any future `shell=False` action-
boundary execution remain deferred. Only Class 0/1 effects remain enabled.

The third slice is the library-only `ordomata.repository_proposal_inspection`
API `inspect_repository_proposal_evidence(database_path, *, run_id)`. It
independently inspects one caller-named durable proposal run and returns a
`RepositoryProposalInspectionReport` with
fixed `inspection_scope: "single_run"`, privacy-safe `run_ref`, `clean`,
`coverage`, `truncated`, a capped inspected-event count, permission class and
current status, optional validated proposal/registration/repository references
and version, optional selection/binding digests and sequences, and a bounded
tuple of `RepositoryProposalInspectionFinding` objects containing fixed codes
only. Its mapping also fixes read-only inspection/validation, no repair,
disabled dispatch, and no granted authority, and reports `evidence_complete`
and the finding count. This is an exact single-run proof, never a claim of
whole-database coverage. `coverage: "incomplete"` is reserved for an otherwise
exact, protocol-recoverable `CREATED`-only or `CREATED`-plus-selection evidence
prefix;
`coverage: "complete"` requires the exact clean three-event chain; every other
history is `invalid`. `clean` requires complete, untruncated evidence with no
findings. Inspection sets `truncated` when more than four events exist and its
capped read cannot cover the history.

The inspector stages the exact signed main file and optional WAL into owner-
private temporary storage under a fixed controller-owned 512 MiB combined
ceiling; oversized state fails before copying. A no-WAL snapshot opens through
an immutable read-only URI, while an in-budget WAL pair opens read-only. SQLite
opens only the staged identity, and before/after source signatures detect
concurrent changes. One query-only snapshot then covers the immutable run and
ordered events. It never instantiates `SQLiteStateStore`,
creates source schema or sidecars, or repairs state. It
independently replays event cardinality and order, content-addressed identifiers
and canonical payload digests, durable-run and registration-component links,
the repeated proposal digest, and fixed Class 0/1, runner, `CREATED`, read-only,
dispatch-disabled, and no-authority semantics. It does not revalidate the
registration against the live filesystem. Its fixed findings and errors expose
no raw identifiers, SQLite diagnostics, paths, argv, registration documents,
proposal content, workspace/run-directory values, or artifact content. The
proof is not an external tamper anchor.

A missing database or caller-named run raises a fixed `RecordNotFoundError`;
an invalid run request raises a fixed `ValidationError`; and unreadable,
malformed, schema-incompatible, or concurrently changed state raises a fixed
`ConfigurationError`. None includes the rejected value or SQLite diagnostic.

Inspection has no CLI, creates no source database/schema/sidecar or migration,
persists no run, status, event, authorization decision, or action receipt, and
creates no worktree. It performs no Git/subprocess call, worker or supervisor
dispatch, profile route, billing/capacity/circuit change, harness/network
action, or live eligibility.

The fourth slice is the library-only
`ordomata.repository_proposal_admission` API
`evaluate_repository_proposal_admission_shadow(database_path, *, run_id,
evaluated_at)`. The controller supplies only the durable state path, run
identifier, and evaluation time. The API freshly invokes the independent
inspector on every call and accepts no caller-supplied inspection report,
permission class, authorization request, policy, or evaluator. It evaluates
only a clean, evidence-complete, complete, untruncated, finding-free exact
three-event inspection. Every other inspection returns an inert
`not_evaluated` result with an `indeterminate` effect and the fixed
`inspection_not_clean_complete` block code; run-binding, evaluation, or replay
failures likewise return fixed failed/indeterminate results rather than a
decision.

The controller derives exactly two local shadow projections. Class 0 is a
`READ` observation with its fixed read-only operation, resource type, policy,
and unenforced audit-receipt plus read-only obligations. Class 1 is a `CREATE`
nomination of a local draft with its fixed local-draft operation, resource type,
policy, and unenforced audit-receipt plus isolated-local-only obligations. Each
class-specific policy admits only that class and projection,
the controller role, local control-plane trust boundary, disabled network, and
local non-AI route. The request binds a canonical digest of the privacy-safe
inspection mapping and its validated proposal/registration/repository lineage;
it never imports raw repository paths, identifiers, proposal content, argv,
workspace/run-directory values, SQLite diagnostics, or artifact content. The
built-in shadow evaluator is replayed through a captured built-in boundary and
must exactly match the controller's expected decision.

An exact observational `permit` and `shadow_eligible: true` still grant no
authority. The result mapping fixes `decision_authoritative`,
`enforcement_enabled`, `authority_granted`, `admission_performed`,
`action_performed`, `action_receipt_created`, `evidence_persisted`,
`repair_performed`, `dispatch_enabled`, `route_selected`, `billing_assessed`,
and `obligations_enforced` to false. The API has no CLI or persistence path and
creates no source state, event, durable authorization record, receipt,
worktree, Git/subprocess/command invocation, worker or supervisor dispatch,
route/profile choice, billing/capacity/circuit fact, harness/network action, or
live eligibility.

The fifth slice is the library-only
`ordomata.repository_proposal_admission_verification` API
`verify_repository_proposal_admission_shadow_mapping(value)`. It accepts only
an exact built-in `dict`, takes a bounded detached JSON snapshot, and
independently mirrors the inspection contract. Evaluated inputs replay the
Class 0/1 request, policy, manual expected decision, and captured built-in
evaluator; inert inputs must match an exact state-machine branch, and a reported
replay failure must still have a constructible replay boundary. It emits only
fixed value-free findings. `contract_valid` proves internal consistency
only: it establishes no authenticity, durable reinspection or source truth,
current freshness, or authority. A coherent forgery or replay remains
indistinguishable without a trusted anchor. Verification persists or repairs
nothing, enforces or authorizes nothing, and has no worker, repository, command,
route, billing, network, harness, dispatch, or live effect.

The sixth bounded Phase 3 slice is the schema-v2 generated/vendor exclusion
contract described above. Nonempty categories are bound into the canonical
path-policy and registration digests; privacy-safe evidence continues to expose
only bounded digest references, bounded version metadata, and fixed read-only,
dispatch-disabled, and no-authority facts. Schema v1 and its proposal-evidence
meaning remain unchanged. There is no automatic exclusion discovery,
ignore-file inference, persistence, repair, execution, worker, route, billing,
network, harness, dispatch, or live effect.

The seventh bounded Phase 3 slice is the schema-v3 baseline contract described
above. It validates only controller-supplied, exactly linked, snapshot-bound
command-result observations and emits aggregate-only evidence with authenticity
and freshness explicitly unverified. It performs no snapshot computation,
command resolution or execution, persistence, repair, worker, route, billing,
network, harness, dispatch, authorization, or live effect. Schema v1 and v2
retain their exact meanings, and proposal evidence remains v1-only.

The eighth bounded Phase 3 slice is the schema-v4 executable/toolchain identity
claim contract described above. It validates only bounded opaque digest claims
and their exact command coverage, then emits aggregate-only evidence with
authenticity, freshness, resolution, content, completeness, and execution
correspondence explicitly false. It performs no additional identity lookup or
inspection and no execution, persistence, dispatch, authorization, or live
effect. Existing registration path-safety checks remain unchanged. Frozen schemas v1
through v3 retain their exact meanings, and proposal evidence remains v1-only.

The ninth bounded Phase 3 slice is the separate schema-v1 executable-resolution
receipt described above. It freshly revalidates only schema v4 and measures the
direct `argv[0]` files under bounded explicit search roots and descriptor-based
`controller_measured` / `posix_nofollow_v1` semantics. Aggregate-only evidence
is point-in-time and non-reusable; it creates no authority, persistence,
proposal lineage, command execution, route, billing, or live effect. Complete
interpreter and dependency/toolchain coverage, action-time remeasurement, and
execution remain future boundaries.

## Quick start

Python 3.12+ is required. There are no runtime dependencies outside the standard library.

```sh
PYTHONPATH=src python3 -m ordomata task-validate
PYTHONPATH=src python3 -m ordomata context-inspect
PYTHONPATH=src python3 -m ordomata profiles
PYTHONPATH=src python3 -m ordomata route --lane mock
PYTHONPATH=src python3 -m ordomata demo
PYTHONPATH=src python3 -m ordomata auth-inspect
```

The demo does not invoke a model. It writes its accepted artifact and append-only state under `.ordomata/`, which is ignored by Git.

For new demo attempts, the local candidate write requires a separate exact
Class 1 ABAC permit in addition to the existing Class 0/1 gate, then is
bracketed by a digest-only pre-effect and enforcing action-receipt chain. The
controller retains verified parent-directory and inode descriptors through
receipt reconciliation, checks that only the expected hard link exists,
reconciles commit-then-raise metadata and receipt writes, and quarantines any
unprovable final effect. The non-enforcing shadow remains audit evidence only.

`auth-inspect` never initializes or changes the state database. With no state it
returns a clean empty report without creating `.ordomata`; after a run it can
be narrowed with `--run-id` or `--mismatches-only`, and exits nonzero for a
parity mismatch, integrity finding, coverage gap, or truncated inspection.
Schema and migration findings are fixed, value-free codes; inspection reports
damage but never recreates a missing guard or repairs history. An exact legacy
baseline that predates the migration ledger remains readable without being
adopted by this command.
The inspector reports a derived class above the persisted task class as a
migration mismatch even when both old and shadow paths would otherwise permit
the action; it does not enforce or repair that mismatch.

Inspect local harness readiness without executing a model:

```sh
PYTHONPATH=src python3 -m ordomata doctor
PYTHONPATH=src python3 -m ordomata route --lane subscription
```

After checking the same authenticated account in the official provider UI,
create or refresh its short-lived local evidence from a real terminal:

```sh
PYTHONPATH=src python3 -m ordomata billing-attest --runner codex
PYTHONPATH=src python3 -m ordomata billing-attest --runner claude
PYTHONPATH=src python3 -m ordomata doctor
```

`billing-attest` never starts a model and has no `--yes` or piped-input mode.
It machine-verifies the route and account identity before prompting for the
exact statement shown on screen. Codex additionally requires machine-verified
available capacity and a zero paid-credit category. The ignored output file is
owner-private and contains only the account fingerprint and schema-controlled
semantic evidence, never an identity, numeric balance, token, or free-text
diagnostic.

Create a controlled comparison plan without running its trials:

```sh
PYTHONPATH=src python3 -m ordomata compare-plan \
  --runners codex claude --repetitions 3 --seed 20260726
```

`compare-run` is also implemented. It does not make an unsafe runner eligible: before writing a comparison record or starting a trial, `doctor`, profile routing, Billing Hard-Stop v2, durable capacity state, and every applicable billing circuit must all pass.

Inspect one schedule slot without claiming it or installing an OS schedule:

```sh
PYTHONPATH=src python3 -m ordomata schedule-inspect \
  --interval-seconds 3600
```

Inspect the durable supervisor tracer without creating state:

```sh
PYTHONPATH=src python3 -m ordomata supervisor status --json
PYTHONPATH=src python3 -m ordomata supervisor audit --json
PYTHONPATH=src python3 -m ordomata supervisor reconcile --json
```

Exercise its mock-only control plane explicitly:

```sh
PYTHONPATH=src python3 -m ordomata supervisor enqueue \
  --admission-key demo-flow --flow-id demo-flow --json
PYTHONPATH=src python3 -m ordomata supervisor start --json
PYTHONPATH=src python3 -m ordomata supervise --once --json
PYTHONPATH=src python3 -m ordomata supervisor pause --json
PYTHONPATH=src python3 -m ordomata supervisor stop --json
```

`start`, `pause`, `resume`, `drain`, and `stop` append control intent; they do
not install or launch a background service. `supervise` runs only in the
foreground. It currently claims no work and starts no runner, model,
subprocess, network action, repository worker, or Class 2/3 action because
its exact claim/worker/tool boundaries lack authoritative ABAC coverage and
verified repository containment; the narrow ordinary mock PEPs grant neither.
`reconcile` is a read-only
preview unless `--apply` is supplied with the exact digest from a current
preview.
Sticky cancellation remains an operator safety path, but its truthful shadow
is irreversible on the original flow and therefore derives disabled Class 3.
`supervisor audit` reports that legacy-parity mismatch; the non-enforcing
observation neither blocks cancellation nor enables Class 2/3 authority.

## Live subscription runs

A live run requires all of these conditions:

1. the selected first-party CLI is installed and supports the required safe flags;
2. its local diagnostic proves first-party subscription authentication and a stable account-identity fingerprint;
3. included subscription capacity is currently `available` for the exact account;
4. a current, matching attestation proves paid continuation is disabled for the entire requested run window: Codex requires a zero usable paid-credit balance plus automatic top-up disabled, and Claude requires extra usage disabled;
5. the child environment, profile, capabilities, and isolation mode all pass validation;
6. no applicable durable capacity stop or billing circuit is open;
7. the operator explicitly sets `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1` for that process.

The environment gate is necessary, never sufficient. Authentication alone is also insufficient. Stale, missing, contradictory, mismatched, or unknown evidence blocks the run.

Example syntax—run only when `doctor` reports the exact profile ready now:

```sh
ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1 \
PYTHONPATH=src python3 -m ordomata run \
  --profile codex.subscription.local-draft-synthesis
```

There is no `allow-api` option and no automatic fallback from a subscription lane to an API, cloud provider, unknown route, or mock. A model identifier is optional in a profile; `null` uses the harness's current subscription-backed default. Provider settings are translated through a per-adapter allowlist.

Purchased product credits and subscription overage are blocked routes, not cost-saving fallbacks. Included-capacity exhaustion becomes a durable blocked-until-reset outcome. A restart cannot clear it: only strictly newer verified available-capacity evidence after any recorded reset can supersede it. Paid, changed-account, or unresolvable post-run evidence quarantines the attempt and artifacts and opens the applicable billing circuit; it is never retried or promoted automatically.

For this first workflow, the harness sees only an isolated empty run workspace and receives context through stdin. Codex runs ephemerally in a read-only sandbox with user config ignored. Claude Code runs in safe mode with all built-in tools disabled; the deterministic controller writes the artifact only after validation. No connector, email, calendar, GitHub, deployment, or other external action is available.

## Controlled comparison

When every selected profile is eligible, run the planned three-by-two Class 0 experiment with:

```sh
ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1 \
PYTHONPATH=src python3 -m ordomata compare-run \
  --profiles codex.subscription.local-draft-synthesis \
             claude.subscription.local-draft-synthesis \
  --repetitions 3 --seed 20260726
```

The command binds named, versioned profiles to the same immutable sanitized snapshot, randomizes profile order inside each repetition block, and creates a fresh adapter, session, and empty workspace for every trial. This small Class 0 experiment uses the same two-minute ceiling for every trial plus a one-minute whole-run evidence margin, keeping the six-trial envelope inside Claude's 15-minute capacity attestation. Every dispatch still rechecks current evidence independently. Outputs are private per-trial review artifacts and are never fed into later trials. The report under `.ordomata/comparisons/<comparison-id>/report.json` contains raw automated dimensions only; `.ordomata/comparisons/<comparison-id>/human-review-template.json` keeps review time, corrections, quality, safety, and capacity observations separate. No winner or profile promotion is produced until human review. A stopped run retains a partial report.

The workflow exists, but no live Codex-versus-Claude comparison has been completed or scored in this repository.

Every started comparison trial now has an append-only Class 0 run/event stream.
A schema-v2 digest-only binding ties its plan, snapshot, controls, profile
configuration, runner settings, billing assessment, and trial identity to
schema-v3 non-enforcing admission and immediate pre-dispatch shadows. The
separate owner-private artifact write has a schema-v4 non-enforcing Class 1
publication shadow followed by schema-v2 pre-effect and action-receipt records
that bind the exact proposed and observed local artifact and its sanitized
post-run billing-disposition digest back to durable execution accounting.
Publication stages and fsyncs private bytes, durably syncs namespace changes,
and reconciles the deterministic action-receipt identifier before treating an
append error as missing evidence; unprovable cleanup or persistence quarantines
the trial.
Runner events retain only ordinals; these audit records retain bounded
controller facts and digests, never prompt, output, provider diagnostics, raw
paths, or raw account identity. `auth-inspect` independently checks their
cardinality, bindings, source facts, and order. Binding and report coverage
labels declare the expected instrumentation; only inspection of the observed
event history establishes completeness or reports a gap.
Historical schema-v1 bindings and artifact intent/observation records remain
valid partial-coverage evidence and retain their explicit publication gap; they
are not reinterpreted as the newer receipt contract.
Post-run subscription evidence is reconciled by the controller before any
review output is retained: unknown, changed, interrupted, or incompletely
persisted billing state quarantines the trial, stops the comparison, withholds
usable output, and opens the applicable account/profile and broad runner
circuits.

This is audit migration, not runtime ABAC enforcement. The runner request,
comparison snapshot, profile ceiling, and `RunRecord` remain Class 0; only the
controller-owned, local, reversible private-artifact effect derives Class 1.
No Class 2/3, external, shared, promotion, or live-model authority is added.

## Verification

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests
git diff --check
```

See [architecture](docs/architecture.md), [runtime authorization model](docs/authorization-model.md), [billing policy](docs/subscription-only-policy.md), [routing](docs/routing.md), [roadmap](docs/roadmap.md), [implementation plan](docs/ordomata-implementation-plan.md), and [implementation status](docs/implementation-status.md).

## Adopted target design and narrow active slice

The v1 design interview is decision-complete. The pure Phase 1C ABAC evaluator
has distinct `permit`, `defer`, `deny`, and `indeterminate` outcomes, and its
first narrow authoritative enforcement slice now gates profile-backed ordinary
in-memory mock dispatch and the resulting owner-private local-candidate
publication.
The current task contract now carries explicit action, resource, and
consequence intent, while `PermissionClass` remains an independent runtime
ceiling and defense-in-depth gate.
Class 0-3 is only a derived impact summary: future Class 3 work may run through exact,
revocable standing envelopes and fresh per-action permits, including narrowly
defined irreversible effects, while a root-authority kernel remains
non-delegable. Class 2/3 execution is still disabled.

Later phases add attested disposable worker cells, controller-mediated egress
and dependencies, adaptive promoted-profile routing and bounded recovery,
broader evidence-backed task admission, durable outbox/credential executors for
consequential effects, tainted-data and isolated-memory handling, and staged
soak gates. The orchestrator may propose improvements to its own repository but
cannot activate them. These are documented constraints and roadmap items, not
claims about commands available today.

## Current limits

- the foreground supervisor is a dispatch-disabled control-plane tracer, not
  a worker daemon; no `launchd`, cron, or other OS schedule is installed;
- no production inbox, calendar, Drive, Slack, or other connectors;
- no Cursor Agent adapter yet (the desktop launcher alone is insufficient);
- no repository worktree maintenance workflow yet; the implemented repository-
  proposal records are inert evidence for an existing `CREATED` sentinel run,
  not admission or dispatch;
- no automatic outcome-to-router learning or retry/failover controller yet;
- no general runtime ABAC coverage yet: only Class 1 admission of a new
  profile-backed exact built-in-mock attempt, its mock dispatch, and its
  owner-private local-candidate publication have authoritative decisions and
  action receipts; live, comparison, unprofiled, supervisor, and general task
  admission, shared publication or promotion, and mediated tools remain
  shadow-only or disabled, while current Class 0/1 and deterministic
  eligibility gates stay authoritative defense in depth;
- no standing-envelope evaluator, worker-cell shell/egress backend,
  consequential-action outbox/executor, trusted-memory promotion, or adaptive
  unattended scheduler yet;
- no live comparison has been run;
- no autonomous promotion, merge, push, deploy, or external action.

Those are deliberate phase boundaries, not hidden fallbacks.
