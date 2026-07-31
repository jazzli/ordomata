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

The frozen schema-v1 through schema-v3 and separate schema-v4 repository-
registration contracts plus pure version-dispatched validation are implemented. They
validate a controller-supplied ordinary Git
root, stable repository/filesystem references, exact verification argv-array
(not shell-text) declarations, canonical protected/allowed paths, bounded
resource limits, fixed local-container/network-disabled isolation, and patch-
only review policy, then return digest-only evidence declaring
`dispatch_enabled: false` and `authority_granted: false`. V2 adds bounded,
canonical literal generated/vendor deny roots strictly below allowed paths;
they select no profile or route and provide no ignore or eligibility behavior.
V3 retains those rules and adds controller-supplied baseline command results.
Every declared command is covered exactly once by kind, identifier, and command
digest under one shared opaque snapshot digest. Results contain bounded integer
timing and exactly one tagged exited, signaled, or timed-out observation; a
timeout carries the controller-supplied `termination_confirmed: true`
assertion. No supplied success, output or output hash, environment, path,
message, or arbitrary metadata is accepted. Canonical aggregate evidence binds
the repository and complete command references while exposing no snapshot or
individual result. It adds only fixed controller-supplied source, aggregate
digest, bounded result count, `baseline_authenticity_verified: false`, and
`baseline_freshness_verified: false`. The validator remains pure and creates no
state.

V4 preserves v3 and requires one opaque controller-supplied executable/
toolchain identity claim for every declared command. Exact command kind,
identifier, and command-digest linkage is mandatory. The canonical aggregate
derives a syntax-only, command-context-bound declared-executable reference and
binds the claims to the repository, complete verification-command digest, and
exact v3 baseline aggregate. These values have no standardized or trusted
preimage or provenance. Cross-context transplantation can validate but changes
the aggregate; same-context replay remains indistinguishable. Baseline binding
proves co-declaration, not that its process used the claimed bytes. Aggregate-
only evidence fixes authenticity, freshness, resolution, content, toolchain
completeness, and execution correspondence to false. V4 identity-block
validation adds no PATH, PATHEXT, environment, runtime-cwd, stat, content,
symlink, shebang, interpreter, launcher, module, plugin, loader, package, or
version inspection and executes nothing. Existing registration root and
repository-relative path/executable safety checks are unchanged.

The separate library-only schema-v1 receipt in
`ordomata.repository_executable_resolution` now freshly revalidates only an
exact schema-v4 registration and measures its direct `argv[0]` files under the
fixed `controller_measured` / `posix_nofollow_v1` profile. Bare names search
only at most 32 ordered controller-supplied absolute directories; there is no
ambient `PATH`, empty/relative entry, implicit cwd, or suffix expansion. Slash-
containing declarations initially require `cwd: "."` and resolve from the
registered repository root. Pinned directory descriptors, no-follow
descriptor-relative lookup, complete file hashing, metadata/namespace/
precedence rechecks, and final registration revalidation reject symlinks,
special or sparse files, missing execute bits, and detected drift/races. The
content limits are 64 MiB per unique file and 256 MiB total.

Receipt evidence is aggregate-only and fixes
`sequential_resolution_measurement_complete: true` with
`atomic_snapshot_verified: false`. It is a sequential, point-in-time,
non-reusable observation, not an atomic filesystem snapshot. It does
not verify current freshness, provenance/authenticity, effective invocability,
interpreter or dependency identity, complete toolchain, repository-snapshot or
baseline correspondence, or future execution correspondence. In particular,
it is not route/profile eligibility, authorization, dispatch, action-receipt,
billing/capacity, circuit, or live-run evidence and creates no CLI,
persistence, subprocess, or execution path.

The separate library-only schema-v1
`ordomata.repository_executable_staging` boundary does not turn resolution
evidence into a route. It accepts one exact typed expected resolver receipt
and a new process-local lease under fixed `controller_copied` /
`posix_unlinked_readonly_v1` semantics. Its action resolver pass rereads every unique
source into immutable chunks through the same still-pinned descriptor and must
equal the expected canonical receipt before the first filesystem mutation. A
full post-stage resolver pass must equal both receipts. This detects ordinary
source, namespace, registration, and search-precedence drift while continuing
to deny atomic-snapshot and current-freshness claims.

The caller-created staging root must be an exact concrete absolute, empty,
no-follow, effective-user-owned mode-`0700` directory that does not overlap the
repository or any search directory. V1 checks lexical containment and exact-
root inode equality only; it does not verify exclusion of other mount aliases.
The root is dedicated to one controller process and one lease, without
concurrent use. Within the existing 64 MiB-per-unique-file and 256 MiB-total
bounds, random zero-length mode-`0600` entries are created
exclusively, opened, unlinked, and parent-fsynced before captured bytes are
written. The anonymous inodes are hashed, fsynced, changed to non-executable
mode `0400`, read back, and retained only by read-only close-on-exec
descriptors after all writers close. The root is empty again before success.

The staging receipt binds the expected/action/post-stage resolution and staged
command/file correspondence, but outward evidence remains aggregate-only.
Cleanup reports `removed`, `already_absent_verified`, or `unverifiable` and
preserves still-verified handles on uncertainty without retrying an ambiguously
closed descriptor number; it restores neither root timestamps nor
physical media and proves no secure erasure.

This temporary Class 1 local staging effect cannot choose or admit a profile,
satisfy routing or subscription eligibility, or authorize a later action.
Kernel/filesystem immutability, same-UID exclusion, ACL privacy, external-
writer absence, atomicity, current freshness, future-execution correspondence,
authority, authorization, action-receipt status, dispatch, durable control-
plane persistence,
proposal-lineage extension, billing, capacity, circuit, live eligibility, and
execution remain false. It adds no CLI, state, proposal, runner, worker,
subprocess, or harness integration. Same-UID adversarial interference is
outside V1 protection; the lease must never be handed to or integrated with an
untrusted same-UID worker.

The separate library-only schema-v1
`ordomata.repository_executable_runtime_manifest` boundary also cannot make a
route eligible. `inspect_staged_executable_runtime_manifest(expected_staging,
*, lease)` requires an exact typed staging receipt and its active, same-PID,
exactly anchored process-local lease. Under fixed `controller_inspected` /
`posix_staged_runtime_header_v1` semantics it fully remeasures each private
retained descriptor before and after reading at most 4,096 header bytes,
without opening any source path. The classifier emits only `elf`, `mach_o`,
`posix_shebang`, `unsupported_shebang`, or `unknown`; accepted shebang
directives are ASCII and limited to 255 bytes, but are neither exposed nor
interpreted.

Runtime files and command bindings contain digest/reference, classification,
and bounded-count metadata only; outward evidence is aggregate-only. The Class
0 inspection neither mutates nor cleans up the lease. Effective invocability,
interpreter resolution or identity, dependency/environment/runtime/toolchain
closure, manifest completeness, current source freshness, future execution
correspondence, route/profile eligibility, authority, authorization, action-
receipt status, proposal lineage, worktree integration, dispatch, billing,
capacity, circuit, live eligibility, and execution remain false. It adds no
CLI, state, runner, worker, subprocess, or harness path.

The separate library-only schema-v1
`ordomata.repository_executable_shebang_requirements` boundary likewise cannot
make a route eligible.
`inspect_staged_executable_shebang_requirements(expected_runtime, *,
expected_staging, lease)` accepts only exact typed runtime-manifest and staging
receipts plus their active same-PID lease exactly anchored to the staging
receipt. Fixed `controller_inspected` /
`posix_staged_shebang_requirements_v1` semantics freshly reproduce the runtime
manifest, require exact correspondence, and remeasure the private leased
descriptors without opening a path or changing lease state. Independent frozen
staging-v1 and runtime-manifest-v1 canonical mirrors validate exact lease
anchoring and runtime shape. A local frozen-v1 mirror derives header,
shebang/directive-reference, and native ELF/Mach-O classification rather than
dynamically trusting upstream helpers. Every full descriptor remeasurement
recomputes bounded header length and digest, runtime bindings must exactly
correlate with staging bindings, and the same independent descriptor proof must
repeat after final runtime reproduction. Its fixed
dispositions are `native_binary_no_shebang` for ELF/Mach-O,
`absolute_interpreter_token` or `non_absolute_interpreter_token` for a valid
POSIX shebang, `unsupported_shebang`, and `unknown_runtime_format`. In this
syntax-only taxonomy, `absolute_interpreter_token` means only that the first
token byte is `/`; it claims no canonicality, usability, compatibility, or
resolution, so `/`, repeated or trailing slashes, and dot components remain
absolute syntax. The valid directive is split only at the first contiguous
ASCII space/tab boundary run. The whole run is consumed, only its first byte
determines the separator kind,
and neither the run nor the remaining opaque argument tail is interpreted;
token and tail remain digest-only with bounded byte counts.

None of this resolves or interprets an interpreter, `env`, `PATH`, the opaque
tail, or kernel/launcher semantics, or establishes invocability, dependency or
complete runtime/toolchain closure. The Class 0 call neither mutates nor cleans
up the lease and cannot enter candidate ranking, profile/route eligibility,
proposal/worktree, dispatch, billing/capacity/circuit, live-run, subprocess,
harness, or execution decisions. It supplies no authority, authorization,
action receipt, persistence, or CLI/state/runner integration. Complete
interpreter, dependency, and toolchain closure remains required before any
routing or operational widening.

The thirteenth bounded Phase 3 slice, the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_resolution` boundary, likewise
cannot make a route eligible.
`inspect_staged_executable_shebang_targets(expected_requirements, *,
expected_runtime, expected_staging, lease, expected_target_paths)` accepts only
exact typed upstream receipts, their active same-PID exactly anchored lease,
and the controller's exact used canonical ASCII absolute target paths in
first-use order. Fixed `controller_measured` /
`posix_absolute_shebang_target_nofollow_v1` semantics admit only
`native_not_applicable` and `direct_absolute_target_measured`; any
non-absolute, non-canonical, not-exactly-expected, unsupported, or unknown
requirement fails the entire call. Exact-spelling no-follow component walks and two
sequential full measurements require matching namespace, identity, metadata,
and content results. Records and evidence expose no raw target paths or target
bytes; they contain only digest/reference fields, bounded command identifiers/
kinds and counts/sizes, fixed classifications/dispositions, and schema-bounded
evidence booleans/metadata.

An exactly expected `/usr/bin/env` is measured only as the direct shebang
target; the opaque tail and downstream program remain uninterpreted. This is
not semantic interpreter resolution, invocability, or dependency/environment/
runtime/toolchain closure. It neither mutates nor cleans up the lease and
cannot affect candidate ranking, routing, dispatch, billing, capacity, circuit,
live eligibility, proposal/worktree state, authorization, subprocess, harness,
or execution decisions.

The fourteenth bounded Phase 3 slice, the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_staging` Class 1 primitive,
also cannot make a route eligible. `stage_repository_executable_shebang_target_bytes`
requires the exact expected target-resolution receipt, full typed upstream
chain, and exactly anchored active same-PID executable lease. It freshly
revalidates the registration, exact search directories, and target paths. Its
action measurement captures each unique target through the same still-pinned
descriptor and must reproduce the expected receipt before mutation. The
dedicated caller-owned target root must be exact, absolute, owner-mode-`0700`,
empty, and disjoint from authoritative protected roots derived from the
revalidated registration, search directories, target paths, and executable
source-stage root.

Every unique script target is exclusively staged without following links,
unlinked with a target-root directory sync before bytes are written, fixed at
mode `0400`, synchronized, independently read back, and retained only through a
non-inheritable `O_RDONLY` descriptor. Post-stage target resolution and the
full upstream chain must still match exactly. Shared targets are staged once;
native-only input yields an active zero-file lease without inspecting or
mutating the target root. Receipts and outward evidence expose no raw target
paths, target bytes, temporary names, or descriptor numbers. The process-local
lease retains the caller-supplied root and private descriptor state; explicit
cleanup releases only that lease.

This temporary Class 1 byte staging creates no authority, authorization or
action receipt and cannot enter candidate ranking, dispatch, billing, capacity,
circuit, live, proposal/worktree, persistence, CLI/state/runner, subprocess,
harness, or execution decisions. It establishes no interpreter, `env`, `PATH`,
argument, recursive-interpreter, loader, or dependency semantics and no
immutability, same-UID/external-writer or fork exclusion, external-hardlink or
mount-alias exclusion, atomic or current freshness, authenticity or provenance,
effective invocability, crash cleanup, or secure erasure. The Class 0/1 ceiling
remains unchanged.

The fifteenth bounded Phase 3 slice, the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_runtime_manifest` Class 0
inspection, also cannot make a route eligible.
`inspect_staged_executable_shebang_target_runtime_manifest(
expected_target_staging, *, lease)` accepts only the exact target-staging
receipt object and its active same-PID target-stage lease. An independent
frozen staging-v1 mirror, under fixed `controller_inspected` /
`posix_staged_shebang_target_runtime_header_v1` semantics, validates canonical
receipt shape, digest and file-reference anchors, receipt and retained-file
tuple object anchors, untouched
lifecycle and cleanup state, and the stored root context. Used-root metadata
must reproduce its owner-mode-`0700` context digest without reopening it;
native-only input must match the no-op context and retain exact nonempty
requirements and command bindings with zero target files.

Every retained mode-`0400`, link-count-zero, non-inheritable `O_RDONLY`
descriptor is fully remeasured before an at-most-4,096-byte `pread` header is
accepted; the bounded read must equal the header captured by the full pass.
After an exact lease snapshot, all descriptors are fully remeasured again;
receipt construction and canonical validation are followed by a closing exact
lease snapshot before return. Immutable target-runtime files, requirements,
bindings, and the receipt preserve exact correspondence while fixing `elf`,
`mach_o`, `posix_shebang`,
`unsupported_shebang`, or `unknown` classification. Direct requirements become
`direct_absolute_target_runtime_inspected`, native requirements remain
`native_not_applicable`, and shared targets appear once. Records and evidence
expose no path, target/header bytes, directive, temporary name, or descriptor
number.

This inspection opens no source, target, or staging-root path, mutates or
cleans up no lease, and invokes no model or live harness. It cannot enter
candidate ranking, route eligibility, dispatch, billing, capacity, circuit,
live, proposal/worktree, persistence, subprocess, harness, or execution
decisions. It establishes no recursive shebang, interpreter, `env`, `PATH`,
argument, dependency, loader, environment, runtime, or toolchain semantics and
no current freshness, atomicity, authenticity, provenance, effective
invocability, authority, authorization, or action receipt. The Class 0/1
ceiling remains unchanged.

The sixteenth bounded Phase 3 slice, the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_requirements` Class 0
inspection, likewise cannot make a route eligible.
`inspect_staged_executable_shebang_target_requirements(
expected_target_runtime, *, expected_target_staging, lease)` requires the exact
typed target-runtime manifest and exact target-staging receipt anchored by its
active same-PID lease. Frozen independent canonical mirrors validate both
proofs and lineage under `controller_inspected` /
`posix_staged_shebang_target_requirements_v1`. Fresh runtime reproduction
occurs before and after extraction; exact lease snapshots bracket two
independent complete descriptor passes, both derived results must agree, and a
closing snapshot plus path-free descriptor identity/metadata/flags anchor check
follow output validation.

The receipt preserves one target-shebang requirement and binding per upstream
target-runtime row. Every unique target is parsed once per descriptor pass;
shared rows reuse its token/tail references while terminal requirement
references remain lineage-distinct. The six fixed dispositions are
`native_not_applicable`,
`native_binary_no_shebang`, `absolute_interpreter_token`,
`non_absolute_interpreter_token`, `unsupported_shebang`, and
`unknown_runtime_format`. Leading `/` is syntax, never path resolution.
Native-only input stays nonempty in requirements/bindings but has zero files
and performs no descriptor read. `unique_target_count`,
`target_posix_shebang_requirement_count`, `argument_tail_requirement_count`,
`total_interpreter_token_bytes`, and `total_argument_tail_bytes` count unique
extractions; `requirement_count`, `direct_target_requirement_count`, and
`native_not_applicable_count` count upstream rows, and `command_count` counts
bindings.

Records remain digest/reference/count-only and evidence aggregate-only; no
path, byte, directive, token, tail, temporary name, or descriptor is exposed.
Digest equality and lengths remain visible and potentially guessable, not
secret or unlinkable. The API opens no path, mutates no lease, and cannot enter
candidate ranking, route eligibility, dispatch, billing, capacity, circuit,
live, proposal/worktree, persistence, subprocess, harness, model, or execution
decisions. It establishes no recursive resolution/staging, interpreter/`env`/
`PATH`/launcher/argument semantics, dependency/loader/environment/runtime/
toolchain closure, freshness, atomicity, immutability, writer/alias/fork
exclusion, authenticity, provenance, invocability, authority, authorization,
or action receipt. The Class 0/1 ceiling is unchanged.

The separate
`ordomata.repository_proposal.bind_repository_proposal_attempt` API records a
**repository-registration selection**, not an execution-profile or model
selection. For an existing immutable Class 0/1
`repository-proposal-disabled` run with only its initial `CREATED` status, it
freshly revalidates one registration, requires an explicit canonical
`proposal_digest`, and appends the content-addressed, statusless
`repository_registration_selection` event followed by the content-addressed,
statusless `repository_proposal_attempt_binding` event. Each append atomically
requires current status `CREATED` and the exact ordered predecessor event IDs.
Commit failures roll back before reconciliation, and the exact identifiers,
payloads, order, links, and status must read back from one consistent SQLite
snapshot before the API succeeds.

These events are proposal lineage, not routing or admission evidence. They
cannot change route candidates, score or choose a profile, make billing or
capacity evidence eligible, satisfy a live gate, authorize a command, or enable
supervisor dispatch. They reuse existing `run_events`, add no SQLite migration
or run creation/status transition, and persist no registration body or raw
proposal content, path, argv, workspace, run directory, or artifact content.
They create no worktree, Git/command/process invocation, or worker. The chain
remains pinned to frozen registration evidence v1; schema-v2 through schema-v4
registrations fail before an event append. Baseline or identity claims cannot
select a profile or make route, billing, capacity, identity, environment,
isolation, circuit, or live-gate evidence eligible.

The third slice is the library-only `ordomata.repository_proposal_inspection`
API `inspect_repository_proposal_evidence(database_path, *, run_id)`. Its
privacy-bounded `RepositoryProposalInspectionReport` fixes
`inspection_scope: "single_run"` and exposes `run_ref`, permission class,
current status, `clean`, `coverage`, `truncated`, capped event count, optional
validated proposal/registration/repository references and version, optional
selection/binding digests and sequences, and bounded fixed-code findings. Its
mapping also fixes read-only inspection/validation, no repair, disabled
dispatch, and no granted authority, and reports evidence completeness and
finding count. An exact protocol-recoverable `CREATED`-only or
`CREATED`-plus-selection evidence prefix is incomplete; only the exact clean three-event
chain is complete; every other history is invalid. `clean` requires complete,
untruncated, finding-free
evidence. More than four events sets `truncated` because the capped inspection
cannot cover the history, and one result never claims whole-database coverage.

The exact signed main file and optional WAL are staged into owner-private
temporary storage under a fixed controller-owned 512 MiB combined ceiling;
oversized state fails before copy. A no-WAL snapshot opens through an immutable
read-only URI, while an in-budget WAL pair opens read-only. SQLite opens only
the staged identity, and before/after source signatures detect concurrent
changes. One query-only SQLite snapshot independently replays
cardinality/order, content-addressed identifiers and canonical
payload digests, durable-run, proposal, and registration-component links, and
fixed Class 0/1, runner, `CREATED`, read-only, dispatch-disabled, and
no-authority facts. It never instantiates `SQLiteStateStore`, creates source
schema or sidecars, repairs state, revalidates registration against the live
filesystem, or acts as an external tamper anchor. Fixed findings and errors
expose no raw identifiers, SQLite diagnostics, paths, argv, registration or
proposal content, workspace/run-directory values, or artifact content.

A clean inspection cannot alter candidates, rank or choose a profile, make
billing/capacity evidence eligible, satisfy a live gate, or enable dispatch.
Inspection creates no source database/schema/sidecar or migration and persists
no run/status/event or authorization evidence. It creates no worktree and
performs no Git/command/process invocation, worker/supervisor dispatch, route,
billing, harness/network, or live effect.

The fourth slice is the controller-owned, library-only
`ordomata.repository_proposal_admission` shadow. It accepts only a durable
database path, caller-named run, and controller evaluation time, then freshly
invokes the independent inspector; callers cannot supply a report, class,
request, policy, or evaluator. Only a clean, evidence-complete, complete,
untruncated, finding-free exact three-event Class 0/1 inspection is evaluated.
A nonclean inspection is `not_evaluated` and `indeterminate`, with no request,
policy, or decision. Run-binding, evaluator, or replay failures are likewise
inert failed/indeterminate observations.

Class 0 projects exactly to a local `READ` observation with a fixed read-only
operation/resource, class-specific policy, and unenforced audit-receipt plus
read-only obligations. Class 1 projects exactly to a local `CREATE` nomination
with a fixed local-draft operation/resource, class-specific policy, and
unenforced audit-receipt plus isolated-local-only obligations.
Each request digest-binds the privacy-safe inspection mapping and validated
lineage, and both the active shadow evaluation and captured built-in replay
must equal the controller's expected decision. Routing is not consulted: the
fixed environment is network-disabled and local non-AI, and no profile or
runner candidate is selected or made eligible.

Even an exact shadow permit grants no authority and is not a route or dispatch
input. The mapping fixes authority, enforcement, admission/action, receipt,
evidence persistence, repair, dispatch, route selection, billing assessment,
and obligation enforcement to false. The API persists nothing and creates no
source state, event, durable decision/receipt, worktree, Git/command/process
invocation, worker/supervisor dispatch, profile selection,
billing/capacity/circuit fact, harness/network action, or live eligibility.

The fifth slice is the library-only
`ordomata.repository_proposal_admission_verification` API
`verify_repository_proposal_admission_shadow_mapping(value)`. It accepts only
an exact built-in `dict`, snapshots it as bounded detached JSON, and
independently mirrors the inspection contract. Evaluated inputs replay the
Class 0/1 request, policy, manual expected decision, and captured evaluator;
inert inputs must match an exact state-machine branch, and a reported replay
failure must retain a constructible replay boundary. It emits fixed value-free
findings. `contract_valid` establishes internal consistency only, not
authenticity, durable reinspection or source truth, current freshness, route or
dispatch eligibility, or authority. A coherent forgery or replay is
indistinguishable without a trusted anchor. The verifier persists or repairs
nothing, enforces or authorizes nothing, and has no worker, repository, command,
route, billing, network, harness, dispatch, or live effect.

The sixth bounded Phase 3 slice adds the separate repository-registration
schema-v2 contract. Its required `generated_paths` and `vendor_paths` are
bounded, canonical literal deny/classification roots strictly below allowed
paths. They are pairwise non-overlapping, disjoint from protected/sensitive
paths, and reject case aliases, traversal, glob/expansion syntax, symlinks, and
special files. Nonempty categories are digest-bound, but raw paths remain
absent from evidence. They do not choose routes, suppress changes, attest
provenance, or enable execution. Schema v1 and proposal lineage remain frozen.

The seventh bounded Phase 3 slice adds the schema-v3 baseline contract described
above. It does not authenticate results, compare the clock, recompute a
snapshot, resolve an executable/toolchain, execute a command, choose a route,
or establish eligibility or authority. Schemas v1 and v2 retain their prior
meanings, and proposal lineage remains v1-only.

The eighth bounded Phase 3 slice adds the schema-v4 opaque executable/toolchain
identity-claim contract described above. It adds no executable resolution,
content or dependency-chain inspection, command execution, route choice, or
establish eligibility or authority. Frozen schemas v1 through v3 retain their
prior meanings, proposal lineage remains v1-only, and only Class 0/1 effects
remain enabled.

The ninth bounded Phase 3 slice adds the separate schema-v1 direct-executable
receipt described above. Its fresh schema-v4 revalidation and bounded
descriptor measurement produce only aggregate, point-in-time, non-reusable PIP
evidence. Routing cannot consume it as eligibility, and it changes no
registration schema, proposal lineage, persistence, authority, billing, live
gate, or execution path. The separate tenth slice supplies bounded action-
boundary capture and staging; complete interpreter/dependency manifests and
execution remain future boundaries.

The tenth bounded Phase 3 slice adds the separate executable-staging lease
described above. Its exact expected/action/post-stage correspondence and
namespace-detached read-only descriptor copies remain local evidence only.
They cannot enter candidate ranking, route eligibility, dispatch, billing,
capacity, circuit, live-run, proposal-lineage, or execution decisions, and no
CLI/state/runner path consumes them.

The eleventh bounded Phase 3 slice adds the separate schema-v1 staged-
executable runtime-manifest inspection described above. An active same-PID
lease exactly anchored to the expected staging receipt is required; complete
descriptor remeasurement and at most 4,096 header bytes yield only digest/
reference entries and aggregate ELF, Mach-O, bounded ASCII shebang,
unsupported-shebang, or unknown classification evidence. None of this can
enter candidate ranking, route eligibility, dispatch, billing, capacity,
circuit, live-run, proposal/worktree, or execution decisions. Invocability,
interpreter and dependency/runtime closure, and completeness remain false; the
Class 0 call does not mutate or clean up the lease and has no CLI/state/runner
integration.

The twelfth bounded Phase 3 slice adds the separate schema-v1 staged-
executable shebang-requirements inspection described above. Exact typed runtime
and staging receipts plus their active same-PID anchored lease are mandatory.
Fresh runtime-manifest reproduction and descriptor remeasurement fix five
classification-derived dispositions; a valid POSIX shebang yields only
digest-only interpreter-token and opaque argument-tail requirements split at
the first contiguous ASCII space/tab boundary run. Only the run's first byte
determines the separator kind, and neither the run nor tail is interpreted.
None of this can enter candidate ranking,
route eligibility, dispatch, billing, capacity, circuit, live-run,
proposal/worktree, subprocess, harness, or execution decisions. It opens no
path, mutates or cleans up no lease, interprets or resolves no interpreter,
`env`, `PATH`, arguments, or kernel semantics, and supplies no authority,
authorization, action receipt, persistence, or CLI/state/runner integration.
Complete interpreter/dependency/toolchain closure remains required before
widening.

The thirteenth bounded Phase 3 slice adds the separate schema-v1 direct
shebang-target measurement described above. It requires the exact upstream
receipt chain, active lease, and complete first-use target-path expectation.
Native entries are not applicable; every script target must match across two
sequential full measurements and final exact-namespace revalidation. The
raw-path/raw-byte-free historical receipt cannot enter candidate ranking,
routing, dispatch, billing, live eligibility, subprocess, or execution
decisions.

The fourteenth bounded Phase 3 slice adds the separate schema-v1 direct
shebang-target staging lease described above. Exact expected/action/post-stage
resolution, the complete active upstream chain, same-descriptor capture, and a
dedicated protected-root contract produce only unlinked mode-`0400` read-only
descriptors; native-only input is a zero-file no-op. This Class 1 library
primitive cannot affect ranking, route eligibility, dispatch, billing,
capacity, circuit, live, subprocess, harness, or execution decisions.

The fifteenth bounded Phase 3 slice adds the separate schema-v1 staged
shebang-target runtime-header inspection described above. Exact active receipt,
lease, object-anchor and stored-root-context validation occurs without a path
reopen; complete descriptor remeasurement brackets at most 4,096 header bytes
of five-way classification; and native-only zero-file requirements and command
bindings remain exact. This Class 0 library result cannot affect ranking,
route eligibility, dispatch, billing, capacity, circuit, live, proposal/
worktree, subprocess, harness, model, or execution decisions.

The sixteenth bounded Phase 3 slice adds the separate schema-v1 staged-target
shebang-requirements inspection described above. It freshly reproduces the
exact runtime proof around two matching full descriptor passes, parses each
unique shared target once, and preserves a lineage-distinct requirement and
binding per upstream row; native-only input remains zero-file and zero-read.
This Class 0 digest-only result cannot affect ranking, route eligibility,
dispatch, billing, capacity, circuit, live, proposal/worktree, subprocess,
harness, model, or execution decisions.

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
