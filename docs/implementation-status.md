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
`schemas/repository-registration-v2.schema.json` and
`schemas/repository-registration-v3.schema.json`, all frozen, plus
`schemas/repository-registration-v4.schema.json`. The pure
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
change. Schema v3 retains the v2 path policy and requires controller-supplied
baseline results covering every declared command exactly once by kind,
identifier, and command digest under one shared opaque snapshot digest. Each
result contains bounded integer timing plus one tagged exited, signaled, or
timed-out observation; a timeout must carry the controller-supplied
`termination_confirmed: true` assertion. It accepts no supplied success,
output or output hash, environment, path, message, or arbitrary metadata. Canonical
ordering follows the command declarations, and one aggregate baseline digest
binds those observations with the repository and verification-command
references. Outward evidence exposes only aggregate baseline evidence with
fixed controller-supplied source, bounded result count,
`baseline_authenticity_verified: false`, and
`baseline_freshness_verified: false`, not the snapshot or individual
observations. The validator neither authenticates the claims, consults the
clock, recomputes the snapshot, resolves an executable/toolchain, nor proves
reproducibility. It remains pure, creates no state, and authorizes or executes
nothing.

Schema v4 preserves v3 and requires exactly one controller-supplied executable/
toolchain identity claim for every declared command. Each claim is linked by
the exact command kind, identifier, and domain-separated command digest and
contains only bounded opaque `executable_identity_digest` and
`toolchain_identity_digest` values. Canonicalization follows declaration order
and derives a syntax-only declared-executable reference bound to the exact
command context, the repository reference, complete verification-command
digest, and exact v3 baseline aggregate digest. No standardized or trusted
preimage or provenance exists for the supplied identity digests. The derived
links make the aggregate context-specific, but cross-context transplantation
can still validate with a different aggregate and same-context replay remains
indistinguishable. Baseline binding proves co-declaration, not that the baseline
process used the claimed bytes.

V4 evidence remains aggregate-only: fixed controller-supplied source, aggregate
digest, bounded identity count, and explicit false authenticity, freshness,
resolution, content, toolchain-completeness, and execution-correspondence facts.
It exposes no individual identities or declared-executable refs. V4 identity-
block validation adds no PATH, PATHEXT, environment, runtime-cwd, stat, content,
symlink, shebang, interpreter, launcher, module, plugin, dynamic-loader,
package, or version inspection and executes nothing. Existing registration
root and repository-relative path/executable safety checks are unchanged.
Frozen schemas v1 through v3 retain their exact meanings.

Implemented separately, the library-only
`ordomata.repository_executable_resolution` schema-v1 receipt accepts only a
freshly revalidated exact schema-v4 registration. Its fixed
`controller_measured` / `posix_nofollow_v1` resolver searches bare executable
names only in at most 32 explicit controller-supplied absolute directories;
ambient `PATH`, empty or relative entries, implicit cwd, and suffix expansion
are absent. Slash-containing declarations initially require `cwd: "."` and
resolve from the registered repository root. Pinned directory descriptors,
exact-spelling and no-follow lookup, descriptor-relative traversal, complete
direct-file hashing, metadata/namespace/search-precedence rechecks, and final
registration revalidation reject symlinks, special or sparse files, missing
execute bits, and detected drift/races. Measurements are bounded to 64 MiB per
unique file and 256 MiB total.

The receipt binds the exact registration, repository, command, baseline,
schema-v4 opaque-identity aggregate, and resolution-context digests. Evidence
exposes only aggregate digests and bounded measurement, unique-file, and byte
counts. It is point-in-time and non-reusable, with current freshness,
authenticity/provenance, effective invocability, interpreter and dependency
coverage, toolchain completeness, repository-snapshot/baseline correspondence,
and future execution correspondence all false. Authority, dispatch, action-
receipt status, persistence, route/billing/capacity facts, live eligibility,
CLI exposure, and execution are also absent. Evidence fixes
`sequential_resolution_measurement_complete: true` and
`atomic_snapshot_verified: false`; completion describes the sequential
measurement only, not an atomic filesystem snapshot.

Implemented separately, the library-only schema-v1
`ordomata.repository_executable_staging` API accepts an exact typed expected
resolver receipt and a caller-created one-shot lease under fixed
`controller_copied` / `posix_unlinked_readonly_v1` semantics. During its fresh
action-boundary resolver pass, an internal consumer rereads each unique executable
through the same still-pinned descriptor into immutable process-local chunks.
The complete expected and action canonical receipts must match before the
first staging mutation; after staging, a second full resolver pass must match
both. These checks fail closed on detected source, registration, namespace, or
search-precedence drift but remain sequential rather than atomic and do not
prove current freshness.

The staging root must already exist as an exact concrete absolute, empty,
effective-user-owned mode-`0700` directory reached without symlinks. It must be
lexically nonoverlapping with the repository and explicit search directories;
exact-root inode aliases are rejected, while mount-alias exclusion remains
false. The root is dedicated to one controller process and one lease, without
concurrent use. For every unique source, a random zero-length mode-`0600` file
is created with O_EXCL and no-
follow flags, opened for read, unlinked, and its parent fsynced before any
captured byte is written. The anonymous inode is written and hashed within the
existing 64 MiB-per-file and 256 MiB-total bounds, fsynced, normalized to non-
executable mode `0400`, and read back exactly. The writer closes before
success; only a non-inheritable read-only descriptor remains in the active
lease, and the root is empty at final observation.

The immutable staging receipt binds expected/action/post-stage resolution
digests, registration and resolution context, staged-file facts, and command
bindings. Its evidence exposes only aggregate digests and counts. Explicit
cleanup returns a schema-v1 receipt with `removed`,
`already_absent_verified`, or `unverifiable`, retaining still-verified handles
for conservative retry while never retrying an ambiguously closed descriptor
number. Namespace absence and descriptor release neither restore
the root's timestamps nor prove secure erasure.

This library primitive is a temporary Class 1 local staging effect, not
authority or an authorization/action receipt. Kernel/filesystem immutability,
same-UID tamper exclusion, mount-alias exclusion, ACL privacy, absence of
external writable descriptors, atomic snapshot, current freshness, future execution
correspondence, dispatch, durable control-plane persistence, proposal-lineage
extension, route, billing/capacity/circuit evidence, live eligibility, and
execution all remain false. There is no CLI, SQLite/state, proposal, runner,
worker, subprocess, or harness integration. Same-UID adversarial interference
is outside V1 protection, and the lease must never be passed to or integrated
with an untrusted same-UID worker.

Implemented as the eleventh bounded Phase 3 slice, the separate library-only
schema-v1 `ordomata.repository_executable_runtime_manifest` API exposes
`inspect_staged_executable_runtime_manifest(expected_staging, *, lease)` and
the immutable `RepositoryExecutableRuntimeFile`,
`RepositoryExecutableRuntimeBinding`, and
`RepositoryExecutableRuntimeManifestReceipt` records. It accepts only an exact
typed staging receipt and the active `RepositoryExecutableStageLease` created
by the current PID and exactly anchored to that receipt. Fixed
`controller_inspected` / `posix_staged_runtime_header_v1` semantics fully
remeasure each private retained descriptor before and after a bounded header
read, without reopening a source path. Headers are capped at 4,096 bytes and
classified only as `elf`, `mach_o`, `posix_shebang`,
`unsupported_shebang`, or `unknown`; accepted shebang directives are ASCII and
capped at 255 bytes.

Runtime-file and command-binding entries expose only digest/reference,
classification, and bounded-count metadata. Aggregate evidence reports the
fixed classifier and staged-byte remeasurement but keeps current lease activity
and source freshness false after the historical measurement. The Class 0 call
does not change lease state or clean up descriptors. It establishes no
effective invocability, interpreter/launcher/loader/library/module/plugin/
package/environment/dependency identity or resolution, complete runtime or
toolchain manifest, baseline/future-execution correspondence, authority,
authorization, action receipt, proposal lineage, worktree, durable
persistence, dispatch, routing, billing/capacity/circuit, live eligibility, or
execution. There is no CLI, SQLite/state, runner, worker, subprocess, or
harness integration.

Implemented as the twelfth bounded Phase 3 slice, the separate library-only
schema-v1 `ordomata.repository_executable_shebang_requirements` API exposes
`inspect_staged_executable_shebang_requirements(expected_runtime, *,
expected_staging, lease)` and the immutable
`RepositoryExecutableShebangRequirement`,
`RepositoryExecutableShebangRequirementBinding`, and
`RepositoryExecutableShebangRequirementsReceipt` records. It accepts only
exact typed runtime-manifest and staging receipts plus their active same-PID
lease exactly anchored to the staging receipt. Fixed `controller_inspected` /
`posix_staged_shebang_requirements_v1` semantics freshly reproduce the runtime
manifest, require exact correspondence with `expected_runtime`, and remeasure
the private leased descriptors without opening a path or changing lease state.
Independent frozen staging-v1 and runtime-manifest-v1 canonical mirrors
validate exact lease anchoring and runtime shape. A local frozen-v1 mirror
derives header, shebang/directive-reference, and native ELF/Mach-O
classification rather than dynamically trusting upstream helpers. Every full
descriptor remeasurement recomputes bounded header length and digest, runtime
bindings must exactly correlate with staging bindings, and the same independent
descriptor proof must repeat after final runtime reproduction.

Fixed dispositions are `native_binary_no_shebang` for ELF/Mach-O,
`absolute_interpreter_token` or `non_absolute_interpreter_token` for a valid
POSIX shebang, `unsupported_shebang`, and `unknown_runtime_format`. In this
syntax-only taxonomy, `absolute_interpreter_token` means only that the first
token byte is `/`; it claims no canonicality, usability, compatibility, or
resolution, so `/`, repeated or trailing slashes, and dot components remain
absolute syntax. The valid directive is split only at the first contiguous
ASCII space/tab boundary run. The whole run is consumed, only its first byte
determines the separator kind,
and neither the run nor the remaining opaque argument tail is interpreted;
token and tail stay digest-only with bounded byte counts. Aggregate
evidence does not interpret or resolve the token, `env`, `PATH`, the tail, or
kernel/launcher semantics. The Class 0 call proves no invocability,
interpreter identity, availability or compatibility, dependency coverage, or
complete runtime/toolchain closure; mutates or cleans up no lease; and creates
no authority, authorization, action receipt, persistence, proposal/worktree
integration, dispatch, route, billing/capacity/circuit, live eligibility,
CLI/state/runner integration, subprocess, harness, or execution path.

Implemented as the thirteenth bounded Phase 3 slice, the separate library-only
schema-v1 `ordomata.repository_executable_shebang_target_resolution` API
exposes `inspect_staged_executable_shebang_targets(expected_requirements, *,
expected_runtime, expected_staging, lease, expected_target_paths)`. It accepts
only exact typed requirements, runtime, and staging receipts, their exactly
anchored active same-PID lease, and an exact tuple of used canonical ASCII
absolute target paths in first-use order. Fixed `controller_measured` /
`posix_absolute_shebang_target_nofollow_v1` semantics allow only
`native_not_applicable` and `direct_absolute_target_measured`; any
non-absolute, non-canonical, not-exactly-expected, unsupported-shebang, or
unknown-runtime requirement invalidates the whole call.

Each unique target is opened component-by-component with exact spelling and no
symlink following, then accepted only after two sequential complete bounded
measurements with matching namespace, identity, metadata, and content results.
Canonical records and outward evidence expose no raw target paths or target
bytes; they contain only digest/reference fields, bounded command identifiers/
kinds and counts/sizes, fixed classifications/dispositions, and schema-bounded
evidence booleans/metadata. An exactly expected `/usr/bin/env` establishes only
that direct target's
measurement; its opaque argument tail and downstream selection are not parsed.
The Class 0 result is not semantic interpreter resolution, invocability,
dependency/environment/runtime/toolchain closure, authority, authorization, an
action receipt, proposal lineage, worktree, dispatch, routing, billing,
capacity, circuit, live eligibility, subprocess creation, harness use, or
execution, and the call neither mutates nor cleans up the lease.

Implemented as the fourteenth bounded Phase 3 slice, the separate library-only
schema-v1 `ordomata.repository_executable_shebang_target_staging` API exposes
`stage_repository_executable_shebang_target_bytes(registration, *,
search_directories, expected_target_resolution, expected_requirements,
expected_runtime, expected_staging, executable_lease,
expected_target_paths, lease)`. It requires the exact target-resolution
receipt and full typed upstream chain plus the exactly anchored active same-PID
executable lease. It freshly revalidates the registration, exact search
directories, and expected target paths; immediately before mutation, it
captures each unique target through the same still-pinned descriptor used by
the action measurement and must reproduce the expected resolution exactly.
The caller constructs the `RepositoryExecutableShebangTargetStageLease` with a
dedicated exact concrete absolute, owner-mode-`0700`, empty staging root.
Authoritative protected roots derived from the revalidated registration, exact
search directories and targets, and executable source-stage root must remain
disjoint from it.

For each unique script target, the function creates an exclusive no-follow
temporary regular file, unlinks it and synchronizes the staging directory
before writing target bytes, then fixes mode `0400`, synchronizes, independently
reads back the complete content, closes the writer, and retains only a non-
inheritable `O_RDONLY` descriptor. Shared targets are staged once with exact
ordered command correspondence. Native-only input succeeds with a zero-file
receipt and active lease without inspecting or mutating the target root. A
complete post-stage target resolution must equal both expected and action
receipts, and all upstream receipts and the executable lease must still
validate. The immutable `RepositoryExecutableShebangTargetStagingReceipt` and
outward evidence expose no raw target paths, target bytes, temporary names, or
descriptor numbers. The lease retains the caller-supplied root and private
descriptor state process-locally and is not canonical evidence;
`cleanup_repository_executable_shebang_target_stage(lease)` releases only the
target lease.

This is a temporary Class 1 local staging effect with no authority,
authorization decision, action receipt, persistence, proposal/worktree
lineage, dispatch, routing, billing, capacity, circuit, live eligibility,
CLI/state/runner integration, subprocess, harness, or execution integration.
It interprets no interpreter, `env`, `PATH`, argument, recursive interpreter,
loader, or dependency semantics and proves no immutability, same-UID/external-
writer or fork exclusion, external-hardlink or mount-alias exclusion, atomic
or current freshness, authenticity or provenance, effective invocability,
crash cleanup, or secure erasure. The Class 0/1 ceiling is unchanged.

Implemented as the fifteenth bounded Phase 3 slice, the separate library-only
schema-v1
`ordomata.repository_executable_shebang_target_runtime_manifest` API exposes
`inspect_staged_executable_shebang_target_runtime_manifest(
expected_target_staging, *, lease)`. This Class 0 call accepts only the exact
target-staging receipt object and its active same-PID target-stage lease. A
frozen independent staging-v1 mirror validates the receipt, digest and file-
reference anchors, original receipt and retained-file tuple object anchors,
untouched lifecycle and cleanup state, and stored root context. Nonempty input
must reproduce the owner-mode-`0700` target-root context from retained metadata
without reopening it; native-only input must reproduce the fixed no-op context
and retain exact nonempty requirements and command bindings with zero files.

The inspector verifies each retained target as a mode-`0400`, link-count-zero,
non-inheritable `O_RDONLY` descriptor and fully remeasures it. It reads at most
4,096 header bytes with `pread`, requires that bounded read to equal the header
captured by the complete pass, revalidates the exact lease snapshot, and fully
remeasures every descriptor again. Under fixed `controller_inspected` /
`posix_staged_shebang_target_runtime_header_v1` semantics it emits immutable
target-runtime file, requirement, binding, and manifest-receipt records with
`elf`, `mach_o`, `posix_shebang`, `unsupported_shebang`, or `unknown`
classification. Direct requirements become
`direct_absolute_target_runtime_inspected`; native requirements remain
`native_not_applicable`; shared targets appear once. Canonical records and
outward evidence contain only digest/reference and aggregate metadata, not
paths, bytes, directives, temporary names, or descriptor numbers.

The call opens no source, target, or staging-root path, mutates or cleans up no
lease, and performs no model or live-harness invocation. It adds no recursive
shebang, interpreter, `env`, `PATH`, argument, dependency, loader, environment,
runtime, or toolchain semantics; current freshness, atomicity, authenticity,
provenance, or effective-invocability proof; authority, authorization, action
receipt, persistence, proposal/worktree lineage, dispatch, routing, billing,
capacity, circuit, live eligibility, CLI/state/runner path, subprocess,
harness, or execution integration. The Class 0/1 ceiling is unchanged.

Implemented as the sixteenth bounded Phase 3 slice, the separate library-only
schema-v1 `ordomata.repository_executable_shebang_target_requirements` API
exposes `inspect_staged_executable_shebang_target_requirements(
expected_target_runtime, *, expected_target_staging, lease)`. The Class 0 call
accepts an exact typed target-runtime manifest and the exact target-staging
receipt held by its active same-PID lease. Under fixed `controller_inspected` /
`posix_staged_shebang_target_requirements_v1` semantics, frozen independent
canonical mirrors validate both receipts and the full lineage. The target-
runtime manifest is freshly reproduced from the lease before and after
extraction. Exact lease snapshots bracket two independent complete descriptor
passes, the derived results must be identical, and canonical receipt
validation is followed by a closing exact snapshot and path-free descriptor
identity/metadata/flags anchor check.

The immutable `RepositoryExecutableShebangTargetRequirementsReceipt` contains
one `RepositoryExecutableShebangTargetShebangRequirement` per upstream target-
runtime requirement and one
`RepositoryExecutableShebangTargetShebangRequirementBinding` per upstream
binding. Unique target-runtime files are parsed once per descriptor pass;
shared rows reuse token and opaque-tail references, but each terminal
requirement reference remains lineage-distinct. Its six fixed dispositions are
`native_not_applicable`,
`native_binary_no_shebang`, `absolute_interpreter_token`,
`non_absolute_interpreter_token`, `unsupported_shebang`, and
`unknown_runtime_format`. Leading `/` is only a syntactic token classification.
Native-only input preserves nonempty requirements and bindings with zero files
and no descriptor read. `unique_target_count`,
`target_posix_shebang_requirement_count`, `argument_tail_requirement_count`,
`total_interpreter_token_bytes`, and `total_argument_tail_bytes` count unique
target-file extractions; `requirement_count`,
`direct_target_requirement_count`, and `native_not_applicable_count` count
upstream rows, and `command_count` counts bindings.

Canonical records contain only bounded counts and digest/reference lineage;
outward evidence is aggregate-only. Raw path, file/header/directive/token/tail
bytes, temporary names, and descriptor numbers are absent, but digest equality
and lengths remain visible and potentially guessable. This is not a secrecy or
unlinkability guarantee. The call opens no path, mutates or cleans up no lease,
and adds no recursive resolution or staging, interpreter/`env`/`PATH`/launcher/
argument semantics, dependency/loader/environment/runtime/toolchain closure,
freshness, atomicity, immutability, alias/writer/fork exclusion, authenticity,
provenance, or invocability. It supplies no authority, authorization, action
receipt, persistence, proposal/worktree lineage, dispatch, routing, billing,
capacity, circuit, live eligibility, CLI/state/runner path, subprocess,
harness, model, or execution integration. The Class 0/1 ceiling is unchanged.

Implemented as the seventeenth bounded Phase 3 slice, the separate library-only
schema-v1 `ordomata.repository_executable_shebang_nested_target_resolution`
API exposes `inspect_staged_executable_shebang_nested_targets(
expected_target_requirements, *, expected_target_runtime,
expected_target_staging, lease, expected_nested_target_paths)`. This Class 0
call accepts the exact staged-target shebang-requirements/runtime/staging
receipt chain, the exactly anchored active same-PID target-stage lease, and the
controller's exact first-use-ordered tuple of canonical ASCII absolute nested-
target paths. Its controller-measured depth is fixed at 2, exactly one
additional hop, under `posix_absolute_shebang_nested_target_nofollow_v1`
measurement and `immediate_target_reentry_v1` controls. Successful rows are
fixed as `source_native_not_applicable`, `target_native_not_applicable`, or
`direct_absolute_nested_target_measured`. Every unique selected path is opened
component by component with exact spelling and no symlink following and must
produce identical full
content, filesystem-identity, metadata, and namespace results across two
measurements and a closing namespace check. Re-entry into any known depth-1
target by path reference or measured identity is rejected, as is descent
through the anchored target-stage-root identity. Source-native input has no
target files and performs no descriptor or path read; a native depth-1 target
is still freshly reproduced from its staged descriptor but performs no nested-
path lookup or measurement.

The receipt fixes `requirement_count`, `command_count`,
`nested_target_requirement_count`, `target_native_not_applicable_count`,
`source_native_not_applicable_count`, `unique_nested_target_count`, and
`total_measured_bytes`.

The immutable receipt and aggregate evidence contain only digest/reference
lineage, fixed outcomes, bounded identifiers, counts, and byte totals. Raw
paths, content, token/tail bytes, temporary names, and descriptors are absent,
though deterministic digests and lengths remain potentially guessable. The API
does not inspect or follow the measured depth-2 target's own shebang, recurse
beyond depth 2, stage bytes, mutate or clean up a lease, invoke a model or
harness, create a subprocess, or execute. It proves no semantic interpreter,
`env`, `PATH`, launcher, or argument resolution; source-chain or generic cycle
closure; broader protected-root closure; dependency, loader, environment,
runtime, or toolchain closure; freshness, atomicity, immutability, authenticity,
provenance, authority, authorization, action receipt, proposal/worktree
lineage, persistence, dispatch, routing, billing, capacity, circuit, live
eligibility, CLI/state/runner, or execution capability. Only Class 0/1 effects
remain enabled.

Implemented as the eighteenth bounded Phase 3 slice, the separate library-only
schema-v1
`ordomata.repository_executable_shebang_nested_target_chain_guard` API exposes
`inspect_staged_executable_shebang_nested_target_chain_guard(
expected_nested_resolution, *, expected_target_requirements,
expected_target_runtime, expected_target_staging, target_lease,
expected_source_staging, source_lease, expected_nested_target_paths)`. This
Class 0 call requires the exact expected nested-resolution receipt and exact
path expectation, the exact staged-target requirements/runtime/staging chain
and active same-PID target lease, and the exact source-staging receipt and
active same-PID source lease. Frozen source-staging mirrors and active target-
stage snapshots validate the complete receipt, object-anchor, retained-file,
root-metadata, lifecycle, identity-set, and same-process lineage before and
around receipt construction.

Under fixed `controller_inspected` /
`known_source_chain_identity_and_staging_root_identity_v1` semantics, the call
freshly reproduces the expected fixed-depth nested resolution with a private
guard active inside the exact-spelling no-follow measurement engine. Its known
identity sets include both the original and namespace-detached staged identity
of every source executable and every direct shebang target. Its protected-root
identity set contains the source staging root and the target staging root when
the latter exists. A candidate walk fails before reading leaf bytes when `/`
or any directory component matches any protected staging-root identity or
when the leaf matches any known original or staged source/target identity.
Those checks remain active across both complete measurements, descriptor reopen checks,
and closing namespace validation. The freshly reproduced receipt must exactly
equal the expected nested-resolution receipt. Source and target snapshots are
checked before and after receipt construction; the final guarded reproduction
checks target descriptor anchors, re-anchors the source lease, and then
performs its final guarded namespace validation.

Fixed dispositions are `source_native_not_applicable`,
`target_native_not_applicable`, and `known_chain_guard_verified`. Source-native
and target-native input preserves exact requirement/binding correspondence
with no guarded measurement and no nested-target or staging-root path lookup;
a native depth-1 target still receives the upstream descriptor validation
needed to reproduce the nested resolution. The receipt contains
`RepositoryExecutableShebangNestedTargetChainGuardedMeasurement`,
`RepositoryExecutableShebangNestedTargetChainGuardRequirement`, and
`RepositoryExecutableShebangNestedTargetChainGuardBinding` rows and fixes
`requirement_count`, `command_count`, `known_chain_guard_verified_count`,
`target_native_not_applicable_count`, `source_native_not_applicable_count`,
`guarded_measurement_count`, `known_source_identity_count`,
`known_target_identity_count`, `protected_staging_root_identity_count`, and
`total_guarded_bytes`. The deterministic unkeyed `guard_summary_ref` binds the
identity-set digests, counts, nested receipt digest, and byte total for internal
consistency only; authenticity remains explicitly unverified.

The immutable
`RepositoryExecutableShebangNestedTargetChainGuardReceipt` and aggregate
evidence expose only digest/reference lineage, fixed outcomes, bounded
identifiers, identity-set digests, counts, and byte totals; raw paths, content,
device/inode numbers, temporary names, and descriptors are absent. This API
makes no source-path or staging-root-path exclusion claim, generic-cycle claim,
or broader-protected-root claim. It stages or writes nothing, mutates or cleans
up no lease, invokes no subprocess, harness, or model, and executes nothing. It
grants no authority, authorization, action receipt, proposal/worktree lineage,
persistence, dispatch, routing, billing, capacity, circuit, live eligibility,
or CLI/state/runner integration. The seventeenth resolver's narrower schema-v1
contract is unchanged. Separate Class 1 nested-target staging remains next,
and only Class 0/1 effects remain enabled.

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
registration evidence v1 and rejects v2 through v4 before any event append.
The separate executable-resolution, staging, runtime-manifest, shebang-
requirements, and shebang-target-resolution receipts are not proposal evidence
and do not widen this chain.
Complete interpreter, dependency, and runtime/toolchain closure and future
`shell=False` execution remain deferred. Only Class 0/1 effects remain enabled.

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

The seventh bounded Phase 3 slice is the schema-v3 baseline contract described
above. It performs no snapshot computation, executable resolution, command
execution, persistence, repair, worker, route, billing, network, harness,
dispatch, authority, or live effect. Schemas v1 and v2 retain their exact
canonical/evidence meanings, and proposal lineage remains v1-only.

The eighth bounded Phase 3 slice is the schema-v4 opaque executable/toolchain
identity-claim contract described above. It performs no additional resolution,
stat or content inspection, dependency discovery, command execution,
persistence, repair, worker, route, billing, network, harness, dispatch,
authority, or live effect. Frozen schemas v1 through v3 retain their exact
canonical/evidence meanings, and proposal lineage remains v1-only.

The ninth bounded Phase 3 slice is the separate schema-v1 executable-resolution
receipt described above. It freshly revalidates only schema v4, measures direct
`argv[0]` files under bounded descriptor-based
`controller_measured` / `posix_nofollow_v1` semantics, and emits aggregate-only
point-in-time evidence. It changes no registration schema or proposal lineage
and adds no persistence, authority, dispatch, action receipt, route, billing,
live eligibility, or execution. The separate tenth slice supplies bounded
action-boundary capture and staging; complete interpreter/dependency manifests
and execution remain future boundaries.

The tenth bounded Phase 3 slice is the separate schema-v1 executable-staging
lease described above. It requires exact expected/action/post-stage resolver
equality and produces only namespace-detached, non-executable mode-`0400`
read-only descriptor leases from same-descriptor process-local captures. It
adds no authority, authorization, action receipt, durable control-plane
persistence, proposal lineage, CLI/state/runner integration, route, billing,
live eligibility, or execution. Complete interpreter/dependency manifests and
any consumer that mutates or executes staged bytes remain future boundaries;
the existing lifecycle cleanup only releases the lease, and only the eleventh
through thirteenth slices' Class 0 inspections and the fourteenth slice's
separate Class 1 target staging otherwise read it.

The eleventh bounded Phase 3 slice is the separate schema-v1 staged-executable
runtime-manifest inspection described above. It accepts only an active
same-PID, exactly anchored lease, fully remeasures its descriptors, and emits a
digest/reference-only receipt plus aggregate evidence for at most 4,096 bytes
of fixed ELF, Mach-O, bounded ASCII shebang, unsupported-shebang, or unknown
classification. It neither resolves an interpreter nor proves dependency/
runtime closure, invocability, completeness, authority, authorization, action-
receipt status, proposal/worktree integration, dispatch, routing, billing,
live eligibility, or execution. It does not mutate or clean up the lease, and
no CLI/state/runner path consumes it.

The twelfth bounded Phase 3 slice is the separate schema-v1 staged-executable
shebang-requirements inspection described above. Exact typed runtime and
staging receipts plus their active same-PID anchored lease are mandatory. It
freshly reproduces the runtime manifest, remeasures the descriptors, fixes the
five classification-derived dispositions, and emits digest-only interpreter-
token plus opaque argument-tail requirements for valid POSIX shebangs split at
the first contiguous ASCII space/tab boundary run. Only the run's first byte
determines the separator kind, and neither the run nor tail is interpreted. It
opens no path, mutates or cleans up no lease, and interprets or resolves no
interpreter, `env`, `PATH`, argument tail, or kernel semantics. It adds no
authority, authorization, action receipt,
persistence, proposal/worktree integration, dispatch, route, billing, live
eligibility, CLI/state/runner path, subprocess, harness, or execution.
Complete interpreter/dependency/toolchain closure remains required before
widening.

The thirteenth bounded Phase 3 slice is the separate schema-v1 direct shebang-
target measurement described above. It requires the exact upstream receipt
chain, active lease, and complete first-use target-path expectation. Native
entries are not applicable; each script target must match across two sequential
full measurements and final exact-namespace revalidation. Its raw-path/raw-
byte-free historical receipt adds no authority, proposal lineage, routing,
live eligibility, subprocess, harness, or execution capability.

The fourteenth bounded Phase 3 slice is the separate schema-v1 direct shebang-
target staging lease described above. It requires exact expected/action/post-
stage target resolution and the complete active upstream chain, retains each
unique script target only as an unlinked mode-`0400` read-only descriptor under
the dedicated protected-root contract, and treats native-only input as a zero-
file no-op. The Class 1 library primitive is non-authorizing and has no
persistence, routing, billing, subprocess, harness, or execution integration.

The fifteenth bounded Phase 3 slice is the separate schema-v1 staged shebang-
target runtime-header inspection described above. It validates the exact
active same-PID receipt, lease and object anchors plus stored root context
without opening any path; fully remeasures retained descriptors around an at-
most-4,096-byte five-way classification; and preserves native-only zero-file
requirements and command bindings. The Class 0 library result is non-
authorizing and has no persistence, proposal/worktree, routing, billing, live,
subprocess, harness, model, or execution integration.

The sixteenth bounded Phase 3 slice is the separate schema-v1 staged-target
shebang-requirements inspection described above. It independently validates
and freshly reproduces the exact target-runtime proof, compares two complete
descriptor passes with closing snapshots, parses each unique shared target once
per pass, and preserves a lineage-distinct requirement and binding for every
upstream row. Native-only input remains zero-file and zero-read. This Class 0
digest-only result is non-authorizing and has no recursive resolution,
staging, persistence, proposal/worktree, routing, billing, live, subprocess,
harness, model, or execution integration.

The seventeenth bounded Phase 3 slice is the separate schema-v1 nested
shebang-target measurement described above. Exact active target-stage lineage
and exact ordered canonical absolute depth-2 paths are required; two matching
no-follow measurements and a closing namespace check must agree. Immediate
depth-1 path/identity re-entry and target-stage-root descent fail closed.
Source-native input is zero-file and zero-read; a native depth-1 target still
validates its staged descriptor but makes no nested-path read. The privacy-
bounded Class 0 result contains digest/reference lineage, fixed outcomes,
bounded command identifiers, counts, and byte totals; it stops after one
additional hop and supplies no generic cycle/protected-root closure, staging,
persistence, proposal/worktree, routing, billing, live, subprocess, harness,
model, or execution integration.

The eighteenth bounded Phase 3 slice is the separate schema-v1 nested-target
known-chain guard described above. It requires exact active source- and target-
stage lineages and freshly reproduces the expected depth-2 resolution while
excluding original and staged source/target identities and the one or two
staging-root identities present before candidate reads and throughout closing
checks.
Native-only input performs no nested-target or staging-root path lookup. The
privacy-bounded Class 0 result has no source-path/root-path, generic-cycle,
broader-protected-root, staging, write, persistence, proposal/worktree,
routing, billing, live, subprocess, harness, model, or execution integration.
The seventeenth resolver remains unchanged; Class 1 nested-target staging is
next.

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
  frozen schema v1 and separate schemas v2/v3; v2 adds bounded literal
  generated/vendor carve-outs, while v3 adds exact command-linked, opaque-
  snapshot-bound controller-supplied baseline observations. Evidence remains
  aggregate-only with authenticity and freshness explicitly unverified; neither
  version adds ignore, execution, persistence, or authority behavior.
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

The current subprocess-lifecycle hardening is implemented for non-model
diagnostics, the read-only Codex app-server billing probe, and existing
first-party harness execution. It provides cancellation-safe new-session
launch, immediate leader identity checks, bounded output/JSONL/error retention,
direct-child exit observation independent of inherited-pipe EOF, shared
idempotent original-group TERM/KILL cleanup, fail-closed probe receipts, and
bounded descriptor-relative output-file inspection. Run-directory descriptors
are pinned only after verifying an effective-user-owned mode-`0700` directory;
raw output is unlinked from that anchored namespace before decoding. Event
capture accepts only the exact sealed, fixed-ceiling, count-only controller
sink; arbitrary callbacks fail before reservation or launch, and production
SQLite receives only ordinal observations after runner execution finishes.
Unverified explicit cancellation is reported as a fixed failure. Timeouts,
explicit cancellation, cleanup uncertainty, stream limits, event-limit and
deferred event-persistence faults, output-name and ancestor swaps, direct-parent
exit with lingering original-group descendants, and cancellation during launch
have deterministic tests.
After a possible live launch, uncertainty is converted to sanitized UNKNOWN
billing evidence, output withholding, quarantine, and a broad circuit before
reservation release. Diagnostic timeout receipts remain unusable even when
TERM produces a clean exit, and containment-specific probe failures abort
capability discovery. The Codex billing probe applies separate aggregate,
per-line, message-count, and stderr ceilings, keeps stdout and stderr draining
through cleanup so late output can invalidate a completed reply, and returns
only sanitized evidence after original-group cleanup and task settlement are
proven.

Live evidence is rechecked after atomic reservation acquisition. Reservation
and completion clocks are sampled after the SQLite write lock is acquired. The
lease margin is composed from bounded cleanup, a hard postflight-inspection budget,
durable finalization including one retry, and scheduling slack. A postflight
overrun fails closed as missing evidence and cannot release a safe result.

This is explicitly not completed process-tree or repository containment.
`CleanupResult.verified` means only that the originally verified POSIX process
group is absent and its direct child was reaped; a descendant can escape with
`setsid()` or `setpgid()`. Deterministic coverage records that limitation rather
than masking it. Cancellation also waits for an in-progress operating-system
spawn to resolve so a later-returned child cannot be orphaned, which means a
wedged spawn remains an acknowledged hard-wall limitation. A non-escapable
worker-cell backend and post-run tree reconciliation are still prerequisites
for supervisor repository-worker dispatch. No authority, permission class,
route, connector, recurring schedule, model fallback, or live eligibility was
added by this slice. The current child-facing output-schema argument remains a
pathname protected by the adapter sandbox, not an immutable adversarial-worker
handoff.

The controlled comparison machinery has been implemented and tested with deterministic fixtures. No claim is made that the planned three-runs-per-profile live experiment has run, passed automated checks, received human scores, or produced a winner.
