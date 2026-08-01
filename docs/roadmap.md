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
- The standalone schema-v1 repository-registration contract remains frozen,
  schema v2 adds generated/vendor exclusions, schema v3 adds controller-supplied
  baseline command-result attestations, and schema v4 adds opaque controller-
  supplied executable/toolchain identity claims; schemas v1 through v3 remain
  frozen. Pure version-dispatched validation is implemented. The validator
  derives stable repository/filesystem references
  from a controller-supplied ordinary Git root; validates exact argv-array (not
  shell-text) verification declarations, canonical protected/allowed paths,
  bounded resource limits, fixed local-container/network-disabled isolation,
  and patch-only review policy; and returns digest-only evidence that explicitly
  grants no authority or dispatch. Mandatory `.git`, `.ordomata`, and
  `.agentops` protection plus traversal/symlink rejection fail closed. V2
  exclusions are bounded canonical literal carve-outs strictly below allowed
  paths, pairwise non-overlapping and disjoint from protected/sensitive paths.
  They are deny/classification metadata only, attest no generation or vendor
  provenance, and cannot hide changes.
- V3 requires exact one-to-one linkage from every declared verification command
  to one controller-supplied result under a single opaque snapshot digest.
  Results admit only bounded integer timing and tagged exited, signaled, or
  timed-out observations; a timeout carries the controller-supplied
  `termination_confirmed: true` assertion. They accept no supplied success,
  output or output hash, environment, path, message, or arbitrary metadata. Canonical
  aggregate evidence reports authenticity and freshness as unverified and
  exposes neither the snapshot nor individual results. Validation does not
  compare the clock, recompute the snapshot, resolve an executable/toolchain,
  execute a command, persist state, or grant authority.
- V4 requires one exact kind-, identifier-, and command-digest-linked identity
  claim per declared command. Each carries bounded opaque executable and
  toolchain identity digests. Declaration-order canonicalization derives a
  syntax-only, command-context-bound declared-executable reference and binds the
  aggregate to the repository, complete command set, and exact v3 baseline
  aggregate. The digests have no standardized or trusted preimage or
  provenance. Cross-context transplantation can validate but changes the
  aggregate, same-context replay is indistinguishable, and baseline binding
  proves co-declaration rather than which bytes executed. Evidence is
  aggregate-only and explicitly reports authenticity, freshness, resolution,
  content, toolchain completeness, and execution correspondence as false.
  V4 identity-block validation adds no PATH/environment lookup, stat/content
  read, symlink, shebang, interpreter, launcher, module, plugin, loader,
  package, or version inspection and executes nothing. Existing registration
  root and repository-relative path/executable safety checks are unchanged.
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
- Independent admission-shadow contract verification is implemented in the
  library-only `ordomata.repository_proposal_admission_verification` API
  `verify_repository_proposal_admission_shadow_mapping(value)`. It accepts only
  an exact built-in `dict`, takes a bounded detached JSON snapshot, and mirrors
  the inspection contract independently. Evaluated inputs replay the Class 0/1
  request/policy, manual expected decision, and captured evaluator; inert inputs
  must match an exact state-machine branch, and a reported replay failure must
  retain a constructible replay boundary. Findings are fixed and value-free.
  `contract_valid` proves internal consistency only, not authenticity,
  durable reinspection/source truth, current freshness, or authority; a
  coherent forgery or replay remains indistinguishable without a trusted
  anchor. The verifier persists or repairs nothing, enforces or authorizes
  nothing, and has no worker, repository, command, route, billing, network,
  harness, dispatch, or live effect.
- Repository-registration schema v2 now requires bounded `generated_paths`
  and `vendor_paths`. Nonempty categories are digest-bound while raw paths
  remain absent from evidence; missing leaves are not created, and globbing,
  automatic exclusion discovery, ignore behavior, persistence, execution, and
  authority remain absent.
- Repository-registration schema v3 now requires the bounded controller-
  supplied baseline contract described above. Its observations are exactly
  command-linked and snapshot-bound, but their authenticity and freshness are
  explicitly unverified. Frozen schemas v1 and v2 retain their prior meanings,
  and schema v1 remains the only proposal-lineage version; schemas v2 through
  v4 fail before a proposal event append.
- Repository-registration schema v4 now requires the bounded opaque identity-
  claim contract described above. Frozen schemas v1 through v3 retain their
  prior meanings. It adds no trusted resolution, content or completeness fact,
  execution, persistence, dispatch, eligibility, or authority. Only Class 0/1
  effects remain enabled.
- The ninth bounded Phase 3 slice implements a separate library-only schema-v1
  direct-executable receipt for freshly revalidated exact schema-v4
  registrations. Its fixed `controller_measured` / `posix_nofollow_v1`
  resolver uses at most 32 explicit absolute search directories for bare names
  and initially requires `cwd: "."` for repository-root-relative executables.
  Descriptor-pinned no-follow lookup hashes the complete direct file, rejects
  symlinks, special/sparse/non-executable entries and detected drift/races, and
  caps unique files at 64 MiB each and 256 MiB total. Aggregate-only evidence
  fixes `sequential_resolution_measurement_complete: true` and
  `atomic_snapshot_verified: false`; it is point-in-time and non-reusable, not
  an atomic filesystem snapshot. Current freshness, provenance/authenticity, effective
  invocability, interpreter/dependency coverage, toolchain completeness,
  snapshot/baseline and future-execution correspondence, authority, dispatch,
  action-receipt status, routing/billing/capacity facts, and live eligibility
  remain false. It adds no schema change, proposal lineage, CLI, persistence,
  subprocess, or execution path.
- The tenth bounded Phase 3 slice implements the separate library-only
  schema-v1 `ordomata.repository_executable_staging` lease. It requires an
  exact typed expected resolver receipt under fixed `controller_copied` /
  `posix_unlinked_readonly_v1` semantics and captures immutable process-local
  chunks from the same still-pinned descriptor for each source during a fresh
  action pass. Expected and action receipts must match before mutation, and a full
  post-stage resolution must match both. The caller-created staging root must
  be an exact absolute, empty, no-follow, effective-user-owned mode-`0700`
  directory dedicated to one controller process and one lease, without
  concurrent use. Overlap checks are lexical containment plus exact-root inode
  equality only; exclusion of other mount aliases remains false.
  Per-unique-file and aggregate limits remain 64 MiB and 256 MiB.
  Each random O_EXCL mode-`0600` name is unlinked and its parent fsynced before
  captured bytes are written; the resulting inode is read back, set to
  non-executable mode `0400`, and retained only through a read-only,
  close-on-exec descriptor. Cleanup reports `removed`,
  `already_absent_verified`, or `unverifiable`, retaining still-verified
  handles on uncertain cleanup without retrying an ambiguously closed
  descriptor number. It does not restore root timestamps or prove secure erasure.
  Aggregate evidence explicitly leaves kernel/filesystem immutability,
  same-UID exclusion, ACL privacy, external-writer absence, atomic snapshot,
  current freshness, future-execution correspondence, authority,
  authorization, action-receipt status, dispatch, durable control-plane persistence,
  proposal lineage, routing/billing/capacity/circuit facts, live eligibility,
  and execution false. It adds no CLI, state, proposal, runner, worker,
  subprocess, or harness integration. Same-UID adversarial interference is
  outside V1 protection, and the lease must never reach an untrusted same-UID
  worker.
- The eleventh bounded Phase 3 slice implements the separate library-only
  schema-v1 `ordomata.repository_executable_runtime_manifest` boundary.
  `inspect_staged_executable_runtime_manifest(expected_staging, *, lease)`
  requires the exact typed staging receipt and its active, same-PID, exactly
  anchored lease under fixed `controller_inspected` /
  `posix_staged_runtime_header_v1` semantics. It fully remeasures each private
  retained descriptor before and after reading at most 4,096 header bytes and
  classifies only `elf`, `mach_o`, `posix_shebang`, `unsupported_shebang`, or
  `unknown`; accepted ASCII shebang directives are capped at 255 bytes. Runtime
  files and command bindings contain digest/reference and bounded
  classification metadata only, and outward evidence is aggregate-only. The
  Class 0 inspection opens no path and neither mutates nor cleans up the lease.
  Effective invocability, interpreter resolution or identity, dependency and
  runtime/toolchain closure, completeness, authority, authorization, action-
  receipt status, proposal/worktree integration, dispatch, routing, billing/
  capacity/circuit, live eligibility, CLI/state/runner integration,
  subprocesses, and execution remain false or absent.
- The twelfth bounded Phase 3 slice implements the separate library-only
  schema-v1 `ordomata.repository_executable_shebang_requirements` boundary.
  `inspect_staged_executable_shebang_requirements(expected_runtime, *,
  expected_staging, lease)` accepts only exact typed runtime-manifest and
  staging receipts plus their active same-PID, exactly anchored lease. Under
  fixed `controller_inspected` / `posix_staged_shebang_requirements_v1`
  semantics, it freshly reproduces the runtime manifest, requires exact
  correspondence, and remeasures the private leased descriptors without
  opening a path or changing lease state. Independent frozen staging-v1 and
  runtime-manifest-v1 canonical mirrors validate exact lease anchoring and
  runtime shape. A local frozen-v1 mirror derives header, shebang/directive-
  reference, and native ELF/Mach-O classification without dynamically trusting
  upstream helpers. Every full descriptor remeasurement recomputes bounded
  header length and digest, runtime bindings exactly correlate with staging
  bindings, and the independent descriptor proof repeats after final runtime
  reproduction. Fixed dispositions are
  `native_binary_no_shebang` for ELF/Mach-O,
  `absolute_interpreter_token` or `non_absolute_interpreter_token` for a valid
  POSIX shebang, `unsupported_shebang`, and `unknown_runtime_format`. In this
  syntax-only taxonomy, `absolute_interpreter_token` means only that the first
  token byte is `/`; it claims no canonicality, usability, compatibility, or
  resolution, so `/`, repeated or trailing slashes, and dot components remain
  absolute syntax. A valid directive is split only at the first contiguous
  ASCII space/tab boundary run. The whole run is consumed, only its first byte
  determines the separator
  kind, and neither the run nor the remaining opaque argument tail is
  interpreted; token and tail remain digest-only with bounded byte counts.
  The Class 0 call resolves or interprets no interpreter, `env`, `PATH`,
  argument tail, or kernel/launcher semantics; mutates or cleans up no lease;
  and adds no authority, authorization, action receipt, persistence,
  proposal/worktree integration, dispatch, routing, billing/capacity/circuit,
  live eligibility, CLI/state/runner integration, subprocess, harness, or
  execution path.
- The thirteenth bounded Phase 3 slice implements the separate library-only
  schema-v1 `ordomata.repository_executable_shebang_target_resolution`
  boundary. `inspect_staged_executable_shebang_targets(expected_requirements,
  *, expected_runtime, expected_staging, lease, expected_target_paths)` accepts
  only exact typed upstream receipts, their active same-PID exactly anchored
  lease, and the controller's exact tuple of used canonical ASCII absolute
  target paths in first-use order. Under fixed `controller_measured` /
  `posix_absolute_shebang_target_nofollow_v1` semantics, native ELF/Mach-O
  requirements yield only `native_not_applicable`, while every shebang must
  yield `direct_absolute_target_measured`. A non-absolute, non-canonical,
  not-exactly-expected, unsupported, or unknown requirement fails the whole
  call.
  Unique targets are opened through exact-spelling no-follow component walks
  and must match across two sequential full bounded measurements and namespace/
  identity/metadata rechecks. Receipts and evidence expose no raw target paths
  or target bytes; they contain only digest/reference fields, bounded command
  identifiers/kinds and counts/sizes, fixed classifications/dispositions, and
  schema-bounded evidence booleans/metadata. An exactly expected `/usr/bin/env` is only
  the direct target;
  its opaque tail and downstream selection remain uninterpreted. The Class 0
  call mutates or cleans up no lease and adds no semantic interpreter,
  dependency/toolchain, authority, authorization, action-receipt, proposal,
  worktree, route, live, subprocess, harness, or execution capability.
- The fourteenth bounded Phase 3 slice implements the separate library-only
  schema-v1 `ordomata.repository_executable_shebang_target_staging` Class 1
  primitive. `stage_repository_executable_shebang_target_bytes` requires exact
  expected/action/post-stage target-resolution equality, the complete typed
  upstream chain, and the exactly anchored active same-PID executable lease.
  Registration, exact search directories and target paths are revalidated;
  action-boundary bytes are captured through the same pinned descriptor used
  for measurement. The dedicated caller-owned target root must be exact,
  absolute, owner-mode-`0700`, empty, and disjoint from authoritative protected
  roots derived from the registration, search directories, target paths, and
  executable source-stage root.
  Each unique script target is created exclusively without following links,
  unlinked with a target-root directory sync before bytes are written, fixed at
  mode `0400`, synchronized, independently read back, and retained only through
  a non-inheritable `O_RDONLY` descriptor. Shared targets are staged once; a
  native-only target set produces a zero-file lease without touching the target
  root. The receipt and outward evidence expose no raw target paths, target
  bytes, temporary names, or descriptor numbers; the process-local lease holds
  the caller-supplied root and private descriptor state, and explicit cleanup
  releases only that lease.
  This temporary Class 1 staging effect grants no authority, authorization or
  action receipt and has no persistence, proposal/worktree, routing, billing,
  capacity, circuit, dispatch, CLI/state/runner, subprocess, harness, or
  execution integration. It establishes no interpreter/`env`/`PATH`/argument,
  recursive-interpreter, loader, or dependency semantics and no immutability,
  same-UID/external-writer or fork exclusion, external-hardlink or mount-alias
  exclusion, atomic or current freshness, authenticity or provenance,
  effective invocability, crash cleanup, or secure erasure. The Class 0/1
  ceiling is unchanged.
- The fifteenth bounded Phase 3 slice implements the separate library-only
  schema-v1
  `ordomata.repository_executable_shebang_target_runtime_manifest` Class 0
  inspection. `inspect_staged_executable_shebang_target_runtime_manifest(
  expected_target_staging, *, lease)` accepts only the exact target-staging
  receipt object and its active same-PID target-stage lease. Under fixed
  `controller_inspected` /
  `posix_staged_shebang_target_runtime_header_v1` semantics, an independent
  frozen staging-v1 mirror validates the receipt, digest/file-reference and
  receipt/retained-tuple object anchors, untouched lifecycle and cleanup state,
  and stored target-root context without reopening a path. Used-root metadata
  must reproduce its owner-mode-`0700` context; native-only input must reproduce
  the no-op context and retain nonempty requirements and command bindings with
  zero files.
  Each retained mode-`0400`, link-count-zero, non-inheritable `O_RDONLY`
  descriptor is fully remeasured before an at-most-4,096-byte `pread` header
  inspection. After an exact lease snapshot, it is fully remeasured again;
  receipt validation is followed by a closing exact lease snapshot before
  return. Immutable files, requirements, bindings, and the receipt preserve
  exact correspondence while classifying targets as `elf`, `mach_o`,
  `posix_shebang`, `unsupported_shebang`, or `unknown`; direct requirements become
  `direct_absolute_target_runtime_inspected` and native requirements remain
  `native_not_applicable`. Records and evidence expose no paths, bytes,
  directives, temporary names, or descriptor numbers.
  The call opens no source, target, or staging-root path, mutates or cleans up
  no lease, and invokes no model or live harness. It establishes no recursive
  shebang/interpreter/`env`/`PATH`/argument semantics, dependency/loader/
  environment/runtime/toolchain closure, current freshness, atomicity,
  authenticity, provenance, invocability, authority, authorization, action
  receipt, proposal/worktree lineage, persistence, routing, billing, capacity,
  circuit, live, subprocess, harness, or execution capability. The Class 0/1
  ceiling remains unchanged.
- The sixteenth bounded Phase 3 slice implements the separate library-only
  schema-v1 `ordomata.repository_executable_shebang_target_requirements` Class
  0 inspection. `inspect_staged_executable_shebang_target_requirements(
  expected_target_runtime, *, expected_target_staging, lease)` accepts the
  exact typed target-runtime manifest and the exact target-staging receipt held
  by its active same-PID lease. Under fixed `controller_inspected` /
  `posix_staged_shebang_target_requirements_v1` semantics, frozen independent
  mirrors validate both canonical proofs and complete lineage. Fresh target-
  runtime reproduction occurs before and after extraction; exact lease
  snapshots bracket two independent full descriptor passes, their derived
  records must match, and output validation is followed by a closing snapshot
  and path-free descriptor identity/metadata/flags anchor check.
  The immutable receipt has one
  `RepositoryExecutableShebangTargetShebangRequirement` per upstream target-
  runtime requirement and one exact binding per upstream binding. Each unique
  target is parsed once per descriptor pass; shared rows reuse token/tail
  references, and terminal requirement references remain lineage-distinct. The
  fixed dispositions are
  `native_not_applicable`, `native_binary_no_shebang`,
  `absolute_interpreter_token`, `non_absolute_interpreter_token`,
  `unsupported_shebang`, and `unknown_runtime_format`; leading `/` remains a
  syntactic fact only. Native-only input preserves nonempty rows/bindings with
  zero files and no descriptor reads. `unique_target_count`,
  `target_posix_shebang_requirement_count`, `argument_tail_requirement_count`,
  `total_interpreter_token_bytes`, and `total_argument_tail_bytes` count unique
  extractions; `requirement_count`, `direct_target_requirement_count`, and
  `native_not_applicable_count` count upstream rows, and `command_count` counts
  bindings.
  Canonical output is digest/reference/count-only and evidence is aggregate-
  only, excluding paths, bytes, directives, tokens, tails, temporary names,
  and descriptors. Digest equality and lengths remain visible and potentially
  guessable, so secrecy and unlinkability are not claimed. The call opens no
  path, mutates no lease, and supplies no recursive resolution/staging,
  interpreter/`env`/`PATH`/launcher/argument semantics, dependency/loader/
  runtime/toolchain closure, freshness, atomicity, immutability, alias/writer/
  fork exclusion, authenticity, provenance, invocability, authority,
  authorization, action receipt, proposal/worktree lineage, persistence,
  routing, billing, capacity, circuit, live, subprocess, harness, model, or
  execution capability. The Class 0/1 ceiling remains unchanged.
- The seventeenth bounded Phase 3 slice implements the separate library-only
  schema-v1
  `ordomata.repository_executable_shebang_nested_target_resolution` Class 0
  inspection. `inspect_staged_executable_shebang_nested_targets(
  expected_target_requirements, *, expected_target_runtime,
  expected_target_staging, lease, expected_nested_target_paths)` requires the
  exact staged-target shebang-requirements/runtime/staging chain, its
  exactly anchored active same-PID target-stage lease, and the controller's
  exact first-use-ordered canonical ASCII absolute depth-2 target paths. It
  measures exactly one additional hop under fixed `controller_measured` /
  `posix_absolute_shebang_nested_target_nofollow_v1` and
  `immediate_target_reentry_v1` controls. The three successful dispositions are
  `source_native_not_applicable`, `target_native_not_applicable`, and
  `direct_absolute_nested_target_measured`; every unique selected path must
  match across two exact-spelling no-follow content/identity/metadata/namespace
  passes and a closing namespace check. Known depth-1 path or identity re-entry
  and descent through the anchored target-stage root fail closed. Source-native
  input performs no descriptor or path read; a native depth-1 target is freshly
  reproduced from its staged descriptor but performs no nested-path lookup or
  measurement.
  Receipt totals are `requirement_count`, `command_count`,
  `nested_target_requirement_count`, `target_native_not_applicable_count`,
  `source_native_not_applicable_count`, `unique_nested_target_count`, and
  `total_measured_bytes`.
  Privacy-bounded canonical records contain digest/reference lineage, fixed
  outcomes, bounded command identifiers, counts, and byte totals; outward
  evidence is aggregate-only, excluding raw paths, target/token bytes,
  temporary names, and descriptors. The boundary does not inspect or follow a
  measured depth-2
  target, recurse further, stage bytes, change or clean up a lease, or execute.
  It supplies no semantic interpreter/`env`/`PATH`/launcher/argument
  resolution, source-chain or generic cycle closure, broader protected-root
  closure, dependency/toolchain/loader closure, freshness, immutability,
  authority, authorization, action receipt, proposal/worktree lineage,
  persistence, routing, billing, capacity, circuit, live, subprocess, harness,
  model, or execution capability. The Class 0/1 ceiling remains unchanged.
- Complete interpreter/dependency/runtime/toolchain closure and command
  execution remain future boundaries before any proposal-lineage or
  operational widening.
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
