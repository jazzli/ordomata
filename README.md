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
- isolated per-run workspaces, terminal-event checks, and output validation;
- controller-owned POSIX process-group lifecycle for diagnostics and current
  first-party harness subprocesses, with separate-session launch, wall
  timeouts, bounded
  stdout/stderr and JSONL retention, bounded cancellation/TERM/KILL cleanup,
  fail-closed cleanup evidence, sealed fixed-ceiling count-only event capture,
  post-execution ordinal event persistence, and
  descriptor-relative bounded output reads that unlink raw output before
  decoding;
- append-only SQLite runs, events, artifacts, capacity observations, billing circuits, scheduler claims, and expiring leases, with capacity checked inside the atomic dispatch reservation and reservation/completion time sampled only after the SQLite write lock is acquired; baseline creation and exact legacy adoption are transactional, and every ordinary open verifies the frozen, contiguous v1-v4 migration prefix before use;
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

The separate library-only schema-v1
`ordomata.repository_executable_staging` boundary implements
`stage_repository_executable_bytes`. It accepts an exact typed resolver
receipt and a one-shot `RepositoryExecutableStageLease` under fixed
`controller_copied` / `posix_unlinked_readonly_v1` semantics. During a fresh
action-boundary resolver pass, each unique source is reread into bounded,
immutable process-local chunks through the same still-pinned descriptor that
the resolver measured. The complete expected and action-time canonical
receipts must match before the first staging mutation. A second full resolver
pass after staging must match both receipts, so detected source, namespace, or
search-precedence drift fails closed without claiming an atomic snapshot or
current freshness.

The caller must create an exact concrete absolute staging root in advance. It
must be empty, owned by the effective user, mode `0700`, reached without
following symlinks, and lexically nonoverlapping with the repository and every
search directory; exact-root inode aliases are also rejected. Mount-alias
exclusion remains explicitly unverified. The root is dedicated to one
controller process and one lease, without concurrent use. Each unique file is
bounded by 64 MiB and the aggregate by 256 MiB.
The controller briefly creates a random zero-length mode-`0600` file with
exclusive no-follow creation, opens its read lease, unlinks and fsyncs its name
before writing any captured bytes, then writes, hashes, fsyncs, and normalizes
the anonymous inode to non-executable mode `0400`. It closes the writer and
retains only a read-only, close-on-exec descriptor. Consequently no staged
executable bytes have a pathname, and the staging root must still be empty at
the final check.

The staging receipt binds the expected, action-time, and post-stage resolver
digests, registration and resolution context, command-to-staged-file bindings,
and bounded staged-file measurements. Its outward evidence is aggregate-only.
Lease cleanup returns a schema-v1 cleanup receipt with `removed`,
`already_absent_verified`, or `unverifiable`; uncertainty preserves still-
verified handles for conservative retry, but never retries an ambiguously
closed descriptor number. Cleanup proves only owned namespace
absence and descriptor release. It explicitly does not restore staging-root
timestamps or prove secure erasure.

This is a temporary Class 1 local staging effect whose caller must separately
authorize it; the receipt is neither authority nor an authorization or action
receipt. Kernel/filesystem immutability, same-UID tamper exclusion, mount-alias
exclusion, ACL privacy, absence of external writable descriptors, atomic
snapshot, current freshness, future-execution correspondence, dispatch,
durable control-plane persistence, proposal-lineage extension, routing,
billing, capacity, circuit,
live eligibility, and execution all remain false. The slice adds no CLI,
state-store, runner, worker, subprocess, or harness integration. Same-UID
adversarial interference is outside V1 protection, so the lease must never be
given to or integrated with an untrusted same-UID worker.

The separate library-only schema-v1
`ordomata.repository_executable_runtime_manifest` boundary implements
`inspect_staged_executable_runtime_manifest(expected_staging, *, lease)`. It
accepts only an exact typed staging receipt and its exactly anchored active
`RepositoryExecutableStageLease` in the same process that created the lease.
Under fixed `controller_inspected` / `posix_staged_runtime_header_v1`
semantics it rejects a PID, lifecycle-state, receipt, binding, or retained-file
mismatch, fully rehashes every private staged descriptor before and after
reading at most 4,096 header bytes, and opens no source path. Its fixed
classifications are `elf`, `mach_o`, `posix_shebang`,
`unsupported_shebang`, and `unknown`; accepted shebang directives are ASCII
and capped at 255 bytes. Classification is syntax and magic-byte measurement
only; the shebang directive is not interpreted or resolved.

Manifest entries contain digest/reference and bounded classification metadata
only; raw paths, argv, file bytes, header bytes, and shebang directives remain
private. Outward evidence is aggregate-only. Inspection is read-only and does
not mutate or clean up the lease. It verifies neither effective invocability
nor interpreter resolution, identity, provenance, authenticity, compatibility,
dependencies, loaders, packages, environment, or complete runtime/toolchain
closure. Completeness, execution correspondence, authority, authorization,
action-receipt, dispatch, routing, billing/capacity/circuit, and live-eligibility
facts remain false. The boundary adds no CLI, state/store, runner, proposal,
worktree, worker, subprocess, harness, or execution integration.

The separate library-only schema-v1
`ordomata.repository_executable_shebang_requirements` boundary implements
`inspect_staged_executable_shebang_requirements(expected_runtime, *,
expected_staging, lease)`. It accepts only exact typed runtime-manifest and
staging receipts plus their active, same-PID lease exactly anchored to the
staging receipt. Under fixed `controller_inspected` /
`posix_staged_shebang_requirements_v1` semantics, the Class 0 call freshly
reproduces the runtime manifest, requires exact correspondence with
`expected_runtime`, and remeasures the private leased descriptors without
opening any path or changing lease state. Independent frozen staging-v1 and
runtime-manifest-v1 canonical mirrors validate exact lease anchoring and runtime
shape. A local frozen-v1 mirror derives header, shebang/directive-reference,
and native ELF/Mach-O classification instead of dynamically trusting upstream
helpers. Every full descriptor remeasurement recomputes the bounded header
length and digest, runtime bindings must exactly correlate with staging
bindings, and the same independent descriptor proof must repeat after the final
runtime reproduction. Immutable
`RepositoryExecutableShebangRequirement`,
`RepositoryExecutableShebangRequirementBinding`, and
`RepositoryExecutableShebangRequirementsReceipt` records use fixed
`native_binary_no_shebang` for ELF/Mach-O, `absolute_interpreter_token` or
`non_absolute_interpreter_token` for a valid POSIX shebang,
`unsupported_shebang`, and `unknown_runtime_format` dispositions. In this
syntax-only taxonomy, `absolute_interpreter_token` means only that the first
token byte is `/`; it claims no canonicality, usability, compatibility, or
resolution, so `/`, repeated or trailing slashes, and dot components remain
absolute syntax. A valid directive is split at the first contiguous ASCII
space/tab boundary run. The
whole run is consumed, only its first byte determines the separator kind, and
neither the run nor the remaining opaque argument tail is interpreted; token
and tail remain digest-only with bounded byte counts.

This requirement extraction does not resolve or interpret an interpreter,
`env`, `PATH`, an argument tail, or kernel/launcher semantics, and it does not
claim effective invocability, interpreter availability or identity,
compatibility, dependencies, or complete runtime/toolchain closure. It neither
mutates nor cleans up the lease and adds no authority, authorization decision,
action receipt, persistence, proposal lineage, worktree, dispatch, route,
billing, capacity, circuit, live eligibility, CLI/state/runner integration,
subprocess, harness, or execution path. Complete interpreter, dependency, and
toolchain closure remains required before any operational widening.

The thirteenth bounded Phase 3 slice adds the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_resolution` boundary.
`inspect_staged_executable_shebang_targets(expected_requirements, *,
expected_runtime, expected_staging, lease, expected_target_paths)` accepts the
exact typed requirements, runtime, and staging receipts, their active same-PID
lease, and an exact tuple of used canonical ASCII absolute target paths in
first-use order. Under fixed `controller_measured` /
`posix_absolute_shebang_target_nofollow_v1` semantics, native ELF/Mach-O files
produce only `native_not_applicable`; every shebang must produce
`direct_absolute_target_measured`. A non-absolute, non-canonical, not-exactly-
expected, unsupported, or unknown requirement fails the whole call. Each unique
target
is opened component-by-component with exact spelling and no symlink following,
then fully measured in two sequential passes whose identity, metadata,
namespace, and content results must match. Canonical records and outward
evidence expose no raw target paths or target bytes; they contain only digest/
reference fields, bounded command identifiers/kinds and counts/sizes, fixed
classifications/dispositions, and schema-bounded evidence booleans/metadata.

This is direct shebang-target measurement, not semantic interpreter
resolution. An exactly expected `/usr/bin/env` measures only that direct
target; its opaque argument tail is not parsed and any interpreter it might
select remains unresolved. The Class 0 call neither mutates nor cleans up the
lease and proves no argument, launcher, kernel, dependency, environment,
runtime/toolchain, effective-invocability, future-execution, authority,
authorization, action-receipt, proposal, worktree, routing, billing, capacity,
circuit, live-eligibility, subprocess, harness, or execution fact.

The fourteenth bounded Phase 3 slice adds the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_staging` Class 1 primitive.
`stage_repository_executable_shebang_target_bytes` requires the exact expected
target-resolution receipt, its complete requirements/runtime/staging receipt
chain, and the exactly anchored active same-PID executable-source lease. It
freshly revalidates the registration and exact search directories and target
paths. Immediately before its first mutation, the action-boundary target
inspection captures each unique target through the same still-pinned
descriptor that it measures and must exactly reproduce the expected receipt.
The dedicated caller-owned target root must be an exact concrete absolute,
owner-mode-`0700`, empty directory. Authoritative protected roots derived from
the revalidated registration, exact search directories and targets, and source
staging root must remain disjoint from it.

For a script target, staging creates an exclusive no-follow temporary regular
file, unlinks it and synchronizes the target-root directory before writing any
captured bytes, fixes mode `0400`, synchronizes and independently reads back
the complete content, closes the writer, and retains only a non-inheritable
`O_RDONLY` descriptor. Shared targets are staged once with exact ordered
command correspondence. A native-only target set succeeds with zero files and
does not inspect or mutate the target root. A complete post-stage target
resolution must again equal both prior receipts, and the full upstream chain
and source lease must still validate. The immutable
`RepositoryExecutableShebangTargetStagingReceipt` and outward evidence expose
no raw target paths, target bytes, temporary names, or descriptor numbers. The
`RepositoryExecutableShebangTargetStageLease` keeps the caller-supplied root
and private descriptor state process-locally and is not canonical evidence.
Explicit
`cleanup_repository_executable_shebang_target_stage` releases only that lease.

This temporary Class 1 byte-staging effect creates no authority,
authorization decision, action receipt, persistence, proposal/worktree
lineage, dispatch, route, billing, capacity, circuit, live eligibility,
CLI/state/runner integration, subprocess, harness, or execution path. It does
not interpret interpreter, `env`, `PATH`, argument, recursive interpreter,
loader, or dependency semantics, and does not establish immutability,
same-UID or external-writer exclusion, fork exclusion, external-hardlink or
mount-alias exclusion, atomic or current freshness, authenticity or
provenance, effective invocability, crash cleanup, or secure erasure.
Only the existing Class 0/1 ceiling remains enabled.

The fifteenth bounded Phase 3 slice adds the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_runtime_manifest` Class 0
boundary. `inspect_staged_executable_shebang_target_runtime_manifest(
expected_target_staging, *, lease)` accepts only the exact
`RepositoryExecutableShebangTargetStagingReceipt` object held by its active,
same-PID `RepositoryExecutableShebangTargetStageLease`. Under fixed
`controller_inspected` /
`posix_staged_shebang_target_runtime_header_v1` semantics, an independent
frozen target-staging-v1 canonical mirror validates the receipt, digest and
file-reference anchors, the original receipt and retained-file tuple object
anchors, untouched lifecycle and cleanup state, and the stored target-root
context. A nonempty stage must reproduce the owner-mode-`0700` root-context
digest from retained metadata without reopening the root; native-only input
must reproduce the fixed no-op context and keep exact nonempty requirements
and command bindings while containing zero target files.

Every retained mode-`0400`, link-count-zero, non-inheritable `O_RDONLY`
descriptor is fully remeasured, then read with `pread` for at most 4,096 header
bytes; the bounded read must equal the header captured by the full pass. After
an exact lease snapshot, every descriptor is fully remeasured again; the
constructed receipt is canonically validated, then a closing exact lease
snapshot must still match before return. The fixed classifications are `elf`,
`mach_o`, `posix_shebang`,
`unsupported_shebang`, and `unknown`. Immutable target-runtime file,
requirement, binding, and manifest-receipt records preserve exact staged-target
and command correspondence; direct targets become
`direct_absolute_target_runtime_inspected`, native requirements remain
`native_not_applicable`, and shared targets are classified once. Canonical
records and outward evidence remain digest/reference- and aggregate-only and
expose no paths, file or header bytes, shebang directives, temporary names, or
descriptor numbers.

This inspection opens no source, target, or staging-root path, mutates or
cleans up no lease, and makes no model or live-harness call. It performs no
recursive shebang resolution and interprets no interpreter, `env`, `PATH`, or
argument semantics. Dependency, loader, environment, runtime, and toolchain
closure; current freshness, atomicity, authenticity, provenance, and effective
invocability; authority, authorization, action receipts, proposal/worktree
lineage, durable persistence, dispatch, routing, billing, capacity, circuit,
live eligibility, CLI/state/runner integration, subprocesses, harnesses, and
execution all remain absent or explicitly unverified. The Class 0/1 ceiling is
unchanged.

The sixteenth bounded Phase 3 slice adds the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_requirements` Class 0
boundary. `inspect_staged_executable_shebang_target_requirements(
expected_target_runtime, *, expected_target_staging, lease)` accepts an exact
`RepositoryExecutableShebangTargetRuntimeManifestReceipt`, the exact
`RepositoryExecutableShebangTargetStagingReceipt` held by its active same-PID
lease, and no path or byte input. Under fixed `controller_inspected` /
`posix_staged_shebang_target_requirements_v1` semantics, frozen independent
target-staging and target-runtime canonical mirrors validate the complete
lineage. The expected target-runtime manifest is freshly reproduced from the
lease before and after extraction. Exact lease snapshots bracket two
independent complete descriptor passes; both passes must reproduce the same
bounded headers, classifications, directive references, tokens, opaque tails,
and derived records. Receipt validation is followed by a closing exact lease
snapshot and path-free descriptor identity/metadata/flags anchor check before
return.

The receipt contains one
`RepositoryExecutableShebangTargetShebangRequirement` for every upstream
target-runtime requirement and one exact
`RepositoryExecutableShebangTargetShebangRequirementBinding` for every
upstream binding. Each unique target-runtime file is parsed once per descriptor
pass; shared rows reuse its token and tail references while their terminal
requirement references remain lineage-distinct. The six fixed dispositions are
`native_not_applicable`, `native_binary_no_shebang`,
`absolute_interpreter_token`, `non_absolute_interpreter_token`,
`unsupported_shebang`, and `unknown_runtime_format`. Absolute means only that
the first opaque token starts with `/`; no path resolution follows. A native-
only chain preserves its nonempty requirements and bindings with zero target
files and performs no descriptor read. `unique_target_count`,
`target_posix_shebang_requirement_count`, `argument_tail_requirement_count`,
`total_interpreter_token_bytes`, and `total_argument_tail_bytes` are computed
over unique target-file extractions; `requirement_count`,
`direct_target_requirement_count`, and `native_not_applicable_count` are per
upstream row, and `command_count` is per binding.

Canonical records remain digest/reference- and bounded-count-only, while
outward evidence is aggregate-only. Neither exposes raw paths, target/header/
directive/token/tail bytes, temporary names, or descriptor numbers. Digest
references still disclose equality and bounded lengths and may be guessable;
they are privacy minimization, not secrecy or unlinkability. The call opens no
source, target, staged-target, or staging-root path, mutates or cleans up no
lease, and performs no recursive resolution, target staging, subprocess,
harness, model, or execution. It establishes no interpreter, `env`, `PATH`,
launcher, argument, loader, dependency, environment, runtime, or toolchain
semantics; no current freshness, atomicity, immutability, same-UID/external-
writer/fork/hardlink/mount-alias exclusion, authenticity, provenance, or
effective invocability; and no authority, authorization, action receipt,
proposal/worktree lineage, persistence, dispatch, routing, billing, capacity,
circuit, live eligibility, or CLI/state/runner integration. The Class 0/1
ceiling is unchanged.

The seventeenth bounded Phase 3 slice adds the separate library-only schema-v1
`ordomata.repository_executable_shebang_nested_target_resolution` Class 0
boundary. `inspect_staged_executable_shebang_nested_targets(
expected_target_requirements, *, expected_target_runtime,
expected_target_staging, lease, expected_nested_target_paths)` accepts the exact
staged-target shebang-requirements/runtime/staging receipt chain, its
exactly anchored active same-PID target-stage lease, and the controller's exact
ordered tuple of canonical ASCII absolute nested-target paths. It terminates at
the one additional hop, fixed depth 2. Fixed `controller_measured` /
`posix_absolute_shebang_nested_target_nofollow_v1` measurement and
`immediate_target_reentry_v1` controls produce only
`source_native_not_applicable`, `target_native_not_applicable`, or
`direct_absolute_nested_target_measured`. Every selected path is walked with
exact spelling and no symlink following and must match across two complete
controller-measured content, identity, metadata, and namespace passes plus a
closing namespace check. A path or measured identity that re-enters any known
depth-1 target fails closed, as does descent through the anchored target-stage
root. Native-only input preserves its nonempty requirement and binding
correspondence while source-native input performs zero descriptor or
filesystem-path reads. A native depth-1 target is still freshly reproduced
from its staged descriptor but causes no nested-path lookup or measurement.

The receipt fixes `requirement_count`, `command_count`,
`nested_target_requirement_count`, `target_native_not_applicable_count`,
`source_native_not_applicable_count`, `unique_nested_target_count`, and
`total_measured_bytes`.

The immutable receipt and aggregate evidence expose only digest/reference
lineage, fixed classifications/dispositions, bounded command identifiers,
counts, and byte totals; no raw path, target byte, token, temporary name, or
descriptor number is emitted. This is one bounded token-named target
measurement, not recursive or semantic interpreter resolution. It neither
resolves nor interprets `env`, `PATH`, launchers, arguments, or a measured
target's own shebang, and it
does not recurse beyond depth 2, stage bytes, mutate or clean up a lease, or
execute anything. Source-chain or generic cycle closure, broader protected-root
closure, dependency/toolchain/loader closure, current freshness, immutability,
authority, authorization, action receipts, proposal/worktree lineage,
persistence, dispatch, routing, billing, capacity, circuit, live eligibility,
CLI/state/runner integration, subprocesses, harnesses, models, and execution
remain absent or explicitly unverified. Only Class 0/1 effects remain enabled.

The eighteenth bounded Phase 3 slice adds the separate library-only schema-v1
Class 0 `ordomata.repository_executable_shebang_nested_target_chain_guard`
boundary. `inspect_staged_executable_shebang_nested_target_chain_guard(
expected_nested_resolution, *, expected_target_requirements,
expected_target_runtime, expected_target_staging, target_lease,
expected_source_staging, source_lease, expected_nested_target_paths)` requires
the exact expected nested-resolution receipt, exact staged-target
requirements/runtime/staging chain and active same-PID target lease, and the
exact source-staging receipt and active same-PID source lease. Under fixed
`controller_inspected` /
`known_source_chain_identity_and_staging_root_identity_v1` semantics it
freshly reproduces the fixed-depth nested resolution with a private guard
active during measurement. Source and target snapshots are checked before and
after receipt construction. In the final guarded reproduction, target
descriptor anchors run first, the source lease is re-anchored next, and guarded
namespace validation remains the closing proof action.

The guard derives bounded sets containing both the original and detached
staged identities of every source executable and direct shebang target, plus
the source staging-root identity and the target staging-root identity when
that root exists. A guarded directory walk rejects any protected staging-root
identity at the root or any component, and rejects a leaf matching any known
original or staged source/target identity before candidate bytes are read;
the same exclusions remain active during both complete measurements, reopen
checks, and closing namespace validation. Fixed dispositions are
`source_native_not_applicable`, `target_native_not_applicable`, and
`known_chain_guard_verified`. Source-native and target-native chains preserve
their exact requirement/binding correspondence with zero guarded
measurements and no nested-target or staging-root path lookup; a native
depth-1 target still receives the upstream descriptor validation required to
reproduce its nested-resolution input.

The immutable
`RepositoryExecutableShebangNestedTargetChainGuardReceipt` contains exact
`RepositoryExecutableShebangNestedTargetChainGuardedMeasurement`,
`RepositoryExecutableShebangNestedTargetChainGuardRequirement`, and
`RepositoryExecutableShebangNestedTargetChainGuardBinding` records. They
contain only digest/reference lineage, fixed outcomes, bounded command
identifiers, identity-set digests, counts, and byte totals. Totals are
`requirement_count`, `command_count`,
`known_chain_guard_verified_count`, `target_native_not_applicable_count`,
`source_native_not_applicable_count`, `guarded_measurement_count`,
`known_source_identity_count`, `known_target_identity_count`,
`protected_staging_root_identity_count`, and `total_guarded_bytes`. Raw paths,
bytes, identity numbers, temporary names, and descriptor numbers are absent.
`guard_summary_ref` binds the three identity-set digests to their counts, the
guarded-measurement count, the nested receipt digest, and the byte total for
internal consistency only; it is deterministic and unkeyed, so receipt
authenticity remains explicitly unverified.
This proves only exact identity-domain re-entry exclusion for the known source
chain and the one or two anchored staging-root identities present in the
inputs. It makes no source-path or staging-root-path claim, generic cycle
claim, or broader protected-root claim;
performs no staging, write, cleanup, lease mutation, subprocess, harness,
model, or execution; and grants no authority, authorization, action receipt,
proposal/worktree lineage, persistence, dispatch, routing, billing, capacity,
circuit, live eligibility, or CLI/state/runner capability. The seventeenth
resolver retains its narrower schema-v1 meaning. The nineteenth slice consumes
this proof freshly at its own separate Class 1 effect boundary; the guard
itself remains Class 0 and unchanged.

The nineteenth bounded Phase 3 slice adds the separate library-only schema-v1
Class 1 `ordomata.repository_executable_shebang_nested_target_staging`
primitive. `stage_repository_executable_shebang_nested_target_bytes(
registration, *, search_directories, expected_chain_guard,
expected_nested_resolution, expected_target_requirements,
expected_target_runtime, expected_target_staging, target_lease,
expected_source_staging, source_lease, expected_nested_target_paths, lease)`
requires the exact expected nested-resolution and known-chain-guard receipts,
their complete active same-PID source- and target-stage receipt/lease lineages,
the controller's exact nested-target path expectation, a freshly revalidated
schema-v4 registration and search context, and a new caller-owned
`RepositoryExecutableShebangNestedTargetStageLease`. Under fixed
`controller_copied` / `posix_shebang_nested_target_unlinked_readonly_v1`
semantics, the action-boundary guard replay captures every unique depth-2
target through the same still-pinned guarded descriptor used for measurement.
The action replay must exactly equal the expected guard, and a complete
post-stage guarded replay must equal both before the effect is accepted.
Only the first guarded action measurement invokes the capture sink; its later
measurement, closing reproduction, and the post-stage replay are consumer-free.
Capture is capped at 80 unique targets, 64 MiB per target, and 256 MiB total;
the receipt admits at most 80 requirements and 80 command bindings.

The nested-target staging root must be an exact concrete absolute,
effective-user-owned mode-`0700`, empty directory. It must remain path- and
identity-disjoint from the freshly revalidated repository and search roots,
the active source and direct-target staging roots, and every expected nested-
target path and ancestor. Each unique guarded target is copied once through an
exclusive no-follow temporary regular file whose name is unlinked and whose
directory is synchronized before captured bytes are written. The file is
fixed at mode `0400`, synchronized, independently read back, and retained only
through a non-inheritable `O_RDONLY` descriptor after its writer closes.
Shared targets preserve exact ordered requirement and command correspondence.
Source-native and target-native input produce an active zero-file lease without
inspecting or mutating the caller's nested-target staging root.

The immutable `RepositoryExecutableShebangNestedTargetStagingReceipt` contains
exact `RepositoryExecutableShebangNestedTargetStagedFile`,
`RepositoryExecutableShebangNestedTargetStageRequirement`, and
`RepositoryExecutableShebangNestedTargetStageBinding` records. It binds the
expected, action, and post-stage guard digests; all upstream receipt and
identity-set lineage; the staging context; and bounded
`requirement_count`, `command_count`, `known_chain_guard_staged_count`,
`target_native_not_applicable_count`, `source_native_not_applicable_count`,
`unique_nested_target_count`, and `total_staged_bytes` totals. Canonical data
and aggregate evidence expose no raw path, content, device/inode number,
temporary name, or descriptor number. Deterministic digest equality and byte
lengths remain visible and potentially guessable, so this is privacy
minimization rather than secrecy or unlinkability.
The lease is same-PID, one-shot, noncopyable, nonserializable process-local
state rather than canonical evidence.

`cleanup_repository_executable_shebang_nested_target_stage` is explicit and
idempotent for the owned lease. Its bounded cleanup receipt distinguishes
`removed`, `already_absent_verified`, and `unverifiable`; cleanup uncertainty
fails closed, and neither staging-root metadata restoration nor secure erasure
is claimed. This temporary Class 1 byte-staging effect is not authority, an
authorization decision, or an action receipt. It adds no persistence,
proposal/worktree lineage, dispatch, route,
billing, capacity, circuit, live eligibility, worker, CLI/state/runner
integration, subprocess, harness, model, or execution path. It neither parses nor follows
the copied target, recurses beyond depth 2, nor establishes interpreter,
`env`, `PATH`, launcher, argument, dependency, loader, runtime, or toolchain
semantics; generic original-source-path or staging-root-path-domain exclusion
beyond the explicit disjointness above; generic cycle or broader protected-root
closure; current freshness, atomicity, immutability, authenticity, provenance,
effective invocability, same-UID/external-writer/fork/hardlink/
mount-alias exclusion, crash cleanup, or secure erasure. Only Class 0/1 effects
remain enabled.

The twentieth bounded Phase 3 slice adds the separate library-only schema-v1
Class 0 `ordomata.repository_executable_shebang_nested_target_runtime_manifest`
PIP. `inspect_staged_executable_shebang_nested_target_runtime_manifest(
expected_nested_target_staging, *, lease)` accepts only the exact nested-
target staging receipt held by its active same-PID lease. It independently
validates the receipt digest and object anchors, the retained-file tuple and
staged-file identities, the owner-mode-`0700` staging context, and every
non-inheritable, link-count-zero, mode-`0400` `O_RDONLY` descriptor without
opening a path or mutating or cleaning the lease.

Each retained descriptor is fully remeasured while its first at most 4,096
bytes are captured, read again with position-independent bounded `pread`, and
fully remeasured again before a closing active-lease snapshot. Fixed byte-level
classification reports only `elf`, `mach_o`, `posix_shebang`,
`unsupported_shebang`, or `unknown`; a valid bounded ASCII shebang directive
is represented only by a digest reference. Exact runtime-file, requirement,
and command-binding rows preserve the complete nested staging and known-chain
lineage. Source-native and target-native input produces zero runtime files and
performs no descriptor read. Canonical receipts and aggregate evidence expose
no raw path, header, content, filesystem identity number, temporary name, or
descriptor number; deterministic digests, classifications, counts, and byte
lengths remain visible and potentially guessable.

This historical Class 0 inspection is neither authority nor freshness for a
future action. It adds no write, cleanup, persistence, proposal/worktree,
dispatch, route, billing, capacity, circuit, live, network, worker, subprocess,
harness, model, or execution capability. It does not follow the retained
shebang, recurse beyond depth 2, or establish interpreter, `env`, `PATH`,
launcher, argument, dependency, loader, runtime, toolchain, immutability,
authenticity, provenance, invocability, writer/fork/alias, containment, or
future-execution semantics. Only Class 0/1 effects remain enabled.

The twenty-first bounded Phase 3 slice adds the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_shebang_nested_target_requirements` PIP.
`inspect_staged_executable_shebang_nested_target_requirements(
expected_nested_target_runtime, *, expected_nested_target_staging, lease)`
requires the exact runtime and staging receipts plus their active same-PID
lease. It validates their complete correspondence, reproduces the runtime
manifest before and after extraction, independently remeasures each detached
descriptor twice, and closes with exact lease and descriptor anchors.

Each unique retained nested target is parsed once into only fixed
source-/target-native, native-binary, absolute-token, non-absolute-token,
unsupported-shebang, or unknown-format dispositions. POSIX interpreter tokens
and opaque argument tails are represented only by digest references, byte
counts, a fixed separator kind, and an absolute-token boolean. Shared targets
retain distinct upstream requirement and command bindings; native-only input
performs no descriptor read. Canonical records expose no raw path, header,
content, token, argument tail, filesystem identity number, temporary name, or
descriptor.

This syntax receipt is historical descriptive evidence, not authority,
authorization, a path resolution, or an action receipt. It performs no path or
environment lookup, shebang following, recursion beyond depth 2, write,
cleanup, persistence, proposal/worktree, dispatch, route, billing, live,
network, worker, subprocess, harness, model, or execution. Interpreter,
`env`/`PATH`/launcher/argument, dependency/loader/toolchain, freshness,
immutability, authenticity, provenance, invocability, alias, containment, and
future-execution semantics remain unproved. Only Class 0/1 effects remain
enabled.

The twenty-second bounded Phase 3 slice adds the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_native_loader_requirements` PIP.
`inspect_staged_executable_native_loader_requirements(expected_runtime, *,
expected_staging, lease)` requires the exact direct-executable runtime and
staging receipts plus their active same-PID lease. It reproduces the runtime
manifest before and after inspection, performs matching bounded extraction
passes bracketed by full detached-descriptor remeasurement, and finishes with
exact closing lease anchors.

For each unique direct staged ELF file it parses only the bounded program-
header table and an optional single `PT_INTERP`; for each thin Mach-O file it
parses only the bounded load-command table and an optional single
`LC_LOAD_DYLINKER`. Fat Mach-O architecture selection and malformed or
unsupported native layouts produce a fixed `unsupported_native_layout`
disposition. Supported native records report only format class, byte order,
image kind, declared/absent disposition, a digest reference and byte count for
a canonical absolute loader path, and exact file/command lineage. Non-native
files produce the fixed descriptive `non_native_not_applicable` outcome.

Canonical records expose no raw loader path, header, content, filesystem
identity number, temporary name, or descriptor. This syntax receipt is
historical descriptive evidence, not authority, authorization, path
resolution, shared-library closure, or an action receipt. It performs no
loader lookup, architecture selection, dependency traversal, write, cleanup,
persistence, proposal/worktree, dispatch, route, billing, live, network,
worker, subprocess, harness, model, or execution. Loader identity,
dependency/runtime/toolchain completeness, freshness, authenticity,
provenance, invocability, containment, and future-execution semantics remain
unproved. Only Class 0/1 effects remain enabled.

The twenty-third bounded Phase 3 slice adds the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_native_loader_target_resolution` PIP.
`inspect_staged_executable_native_loader_targets(expected_requirements, *,
expected_runtime, expected_staging, lease, expected_loader_paths)` requires the
exact native-loader requirements/runtime/staging chain and its active same-PID
lease. The caller supplies one exact ordered unique tuple of canonical ASCII
absolute paths; every path must cryptographically reproduce a merged
`PT_INTERP` or `LC_LOAD_DYLINKER` digest reference before any target lookup.
Absent, unsupported, fat, and non-native declarations require no path.

Each unique declaration-bound target is measured twice through exact-spelling,
component-by-component no-follow traversal. Only bounded, non-sparse, regular,
executable files are accepted; duplicate filesystem identities, content or
metadata drift, symlinks, case aliases, and closing namespace drift fail
closed. The receipt retains digest-only path, identity, metadata, content, and
requirement/command lineage plus counts and byte totals. Raw target paths and
bytes remain outside canonical records and aggregate evidence. Deterministic
digests and byte lengths remain correlatable and potentially guessable, so
this is privacy minimization rather than secrecy.

This point-in-time target measurement is historical descriptive evidence, not
loader authenticity, authorization, shared-library or dependency closure, or
an action receipt. It performs no fat-image architecture selection, staging,
write, cleanup, persistence, proposal/worktree, dispatch, route, billing,
live, network, worker, subprocess, harness, model, loader invocation, or
execution. Current freshness, provenance, invocability, dependency/runtime/
toolchain completeness, containment, and future-execution semantics remain
unproved. Only Class 0/1 effects remain enabled.

The twenty-fourth bounded Phase 3 slice adds the separate library-only
schema-v1 Class 1
`ordomata.repository_executable_native_loader_target_staging` primitive.
`stage_repository_executable_native_loader_target_bytes(registration, *,
search_directories, expected_target_resolution, expected_requirements,
expected_runtime, expected_staging, executable_lease,
expected_loader_paths, lease)` requires the exact target-resolution chain,
active same-PID source lease, freshly revalidated schema-v4 registration and
search context, and a fresh caller-scoped target-stage lease. The Class 1
caller supplies an existing empty owner-controlled mode-0700 directory outside
the repository, search roots, source staging root, and loader-target paths.

The action-bound remeasurement hands each still-pinned unique loader descriptor
to a bounded copy sink. Each copy is written under an unpredictable private
name, synchronized, reopened and fully read back, changed to mode 0400, then
unlinked while its non-inheritable read-only descriptor remains leased. Shared
targets are copied once. The controller replays the complete target-resolution
chain after staging and rechecks protected directories and retained descriptors
before issuing the receipt. A chain with no declared target creates an active
empty lease without inspecting or mutating the supplied target-stage root.
Cleanup is explicit and idempotent; an unproved namespace or descriptor release
becomes fixed-redacted cleanup uncertainty rather than success.

The canonical receipt exposes digest/reference/count/byte-total lineage only;
raw paths, bytes, names, descriptors, and filesystem identity numbers remain
private. Deterministic digests remain correlatable and potentially guessable.
The retained descriptors are read-only, not immutable: same-UID writers,
external descriptors, hardlink or mount aliases, crash cleanup, and secure
erasure are not excluded. This primitive does not authenticate, parse, or
invoke a loader; select a fat-image architecture; traverse shared libraries or
dependencies; persist controller state; dispatch a worker; call a network or
model; or execute repository code. It grants no authority and does not raise
the Class 0/1 ceiling.

The twenty-fifth bounded Phase 3 slice adds the separate library-only schema-v1
Class 0
`ordomata.repository_executable_native_loader_target_runtime_manifest` PIP.
`inspect_staged_executable_native_loader_target_runtime_manifest(
expected_target_staging, *, lease)` accepts only the exact target-staging
receipt and its active same-PID lease. It validates the receipt, object and
digest anchors, stored staging-root context, retained tuple identity, and every
requirement and command binding before inspecting detached bytes.

Each retained loader descriptor is fully remeasured while capturing at most
4,096 header bytes, read separately with bounded position-independent
`pread`, then fully remeasured again before a closing lease snapshot. Fixed
ELF, Mach-O, valid bounded ASCII POSIX-shebang, unsupported-shebang, and
unknown classifications preserve exact staged-file, requirement, command,
resolution, and staging lineage. A no-target stage produces a zero-file,
zero-read manifest. Canonical records expose no raw path, header, content,
filesystem identity number, temporary name, or descriptor; deterministic
digests and byte lengths remain correlatable and potentially guessable.

This point-in-time runtime classification is historical Class 0 evidence, not
loader identity, authenticity, compatibility, invocability, authorization,
shared-library/dependency closure, or an action receipt. It opens no path,
mutates or cleans up no lease, selects no fat-image architecture, persists no
state, creates no worker or subprocess, calls no network or model, invokes no
loader, and executes nothing. Current freshness, containment, runtime/toolchain
completeness, and future-execution correspondence remain unproved. Only Class
0/1 effects remain enabled.

The twenty-sixth bounded Phase 3 slice adds the separate library-only schema-v1
Class 0
`ordomata.repository_executable_native_loader_target_loader_requirements`
PIP. `inspect_staged_executable_native_loader_target_loader_requirements(
expected_target_runtime, *, expected_target_staging, lease)` accepts only the
exact target-runtime manifest, exact target-staging receipt, and its active
same-PID lease. It freshly reproduces the target-runtime manifest before and
after inspection, requires exact runtime/staging/file/requirement/command
correspondence, and repeats the complete syntax measurement before closing on
the same retained tuple.

For each unique detached loader target, two complete descriptor
remeasurements bracket bounded ELF32/ELF64 `PT_INTERP` or thin Mach-O32/
Mach-O64 `LC_LOAD_DYLINKER` parsing. Fat Mach-O and deliberately unsupported
layouts receive fixed unsupported outcomes; non-native targets receive a
fixed not-applicable outcome. Shared loader targets are parsed once while
every upstream requirement and command retains exact lineage. A no-target
chain produces zero target-loader requirements and performs no descriptor
read. Public records expose only digest-bound loader-path references, bounded
path byte lengths, fixed syntax attributes, counts, and lineage. Raw paths,
headers, content, identity numbers, names, and descriptors remain private,
while deterministic digests remain correlatable and potentially guessable.

This one-hop loader-of-loader syntax evidence neither resolves a newly
declared loader nor proves compatibility, authenticity, identity,
invocability, dependency/shared-library closure, authorization, or an action
receipt. It opens no path, mutates or cleans up no lease, selects no fat-image
architecture, persists no state, creates no proposal/worktree/route/worker or
subprocess, calls no network or model, invokes no loader, and executes
nothing. Recursion beyond this syntax hop, freshness, containment,
runtime/toolchain completeness, and future-execution correspondence remain
unproved. Only Class 0/1 effects remain enabled.

The twenty-seventh bounded Phase 3 slice adds the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_native_loader_nested_target_resolution` PIP.
`inspect_staged_executable_native_loader_nested_targets(...)` accepts only the
exact loader-of-loader requirements receipt, target-runtime manifest,
target-staging receipt, first-hop target-resolution receipt, active same-PID
target-stage lease, exact ordered current-loader paths, and exact ordered newly
declared nested-loader paths. It reproduces the loader-of-loader receipt on
each of three chain snapshots and requires the exact retained target-stage
tuple through a closing snapshot.

Every declared canonical absolute nested-loader path must reproduce its
digest-only declaration before two complete guarded no-follow measurements.
Shared declarations are measured once while exact target, source, requirement,
lineage, and command bindings are retained. Exact current-loader path re-entry,
original first-hop target identity re-entry, detached staged-target identity
re-entry, and traversal into the target staging root fail before leaf bytes are
read. Absent, unsupported/fat, and non-native loader declarations require no
nested path; a no-target chain performs no nested lookup or read. Public
records expose only digest-bound path, identity, metadata, content, byte-count,
disposition, count, and lineage evidence. Raw paths, content, identity numbers,
temporary names, and descriptors remain private, while deterministic digests
remain correlatable and potentially guessable.

Resolution stops at depth two: newly measured bytes are not parsed, staged,
followed, invoked, or executed. Source-path and source-staging-root re-entry,
general cycle detection, broader protected-root closure, loader identity,
authenticity, compatibility, invocability, shared-library/dependency closure,
current freshness, authorization, and future-execution correspondence remain
unproved. The PIP mutates no lease, persists no state, creates no proposal,
worktree, route, worker, or subprocess, calls no network or model, invokes no
loader, and executes nothing. Only Class 0/1 effects remain enabled.

The twenty-eighth bounded Phase 3 slice adds the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_native_loader_nested_target_chain_guard` PIP.
`inspect_staged_executable_native_loader_nested_target_chain_guard(...)`
consumes the exact depth-two native-loader resolution plus its complete target-
resolution, target-runtime, target-staging, source-staging, active-lease, and
ordered-path proof chain. It reproduces the nested resolution under a stronger
controller-owned guard, brackets receipt construction with exact source/target
stage snapshots, and finishes with another exact reproduction whose closing
source anchor makes guarded namespace validation the final proof action.

The stronger guard adds every original and detached staged source-executable
identity plus the anchored source staging-root identity to the original and
staged target identities and target staging-root identity already protected by
the depth-two resolver. An exact source identity, any hardlink alias, or any
candidate below the source staging-root identity is rejected before leaf bytes
are read. Shared declarations remain measured once, fixed absent/unsupported/
non-native outcomes add no lookup, and a no-target chain retains source lineage
with zero nested reads. Public evidence contains only digest-bound identity-set,
root-set, measurement, requirement, lineage, binding, count, and byte-total
facts; raw paths, content, identity numbers, temporary names, and descriptors
remain private, while deterministic digests remain correlatable and potentially
guessable.

The boundary remains historical depth-two evidence. Newly measured bytes stay
opaque and are not parsed, staged, followed, invoked, or executed. General
cycles, source path-spelling re-entry beyond exact anchored identities, broader
protected-root closure, loader identity/authenticity/compatibility/invocability,
dependency/shared-library closure, current freshness, authorization, and future
execution correspondence remain unproved. It mutates or cleans up no lease,
persists no state, creates no proposal/worktree/route/worker or subprocess,
calls no network, harness, or model, invokes no loader, and executes nothing.
Only Class 0/1 effects remain enabled.

The twenty-ninth bounded Phase 3 slice adds the matching library-only schema-v1
Class 1
`ordomata.repository_executable_native_loader_nested_target_staging`
primitive. It requires the exact depth-two resolution, known-chain guard,
complete source and target proof chain, both active same-PID leases, both
ordered loader-path sets, and a caller-selected private mode-`0700` staging
directory. At the action boundary it reproduces the known-chain guard while a
private consumer copies every unique guarded target through the same pinned
measurement descriptor. Each copy is fully read back, changed to mode `0400`,
reopened read-only and non-inheritable, unlinked from its temporary name, and
retained by a process-bound noncopyable lease. A second exact guard reproduction
must match the expected and action receipts before activation.

Shared targets produce one detached file while requirements, source lineages,
and commands remain distinct. Absent, unsupported/fat, non-native, and no-
target outcomes retain exact disposition and command lineage without opening a
staging directory. Public receipts are digest-only; raw paths, bytes,
filesystem numbers, temporary names, and descriptors remain private. Cleanup
uncertainty is explicit and fails closed. This primitive does not authorize its
own Class 1 effect: separate controller authorization remains required. The
copied bytes are not parsed, recursively followed, invoked, executed, or
persisted. General cycles, broader protected-root closure, dependency/shared-
library closure, freshness, future correspondence, crash cleanup, secure
erasure, and external descriptor absence remain deferred. No proposal,
worktree, route, billing, network, worker, subprocess, harness, model, loader,
or permission widening is added. Only Class 0/1 effects remain enabled.

The thirtieth bounded Phase 3 slice adds the matching library-only schema-v1
Class 0
`ordomata.repository_executable_native_loader_nested_target_runtime_manifest`
primitive. It consumes one exact active nested-target staging receipt and
same-PID lease, fully remeasures each detached descriptor before and after a
separate position-independent header read, and applies the fixed bounded ELF,
Mach-O, POSIX shebang, unsupported-shebang, or unknown classification. Runtime
requirements and source lineages remain distinct even when staged files are
deduplicated; empty outcomes preserve command lineage without descriptor reads
or a staging root.

Canonical records expose only digests, classifications, bounded counts, and
byte totals. Raw headers, file content, paths, filesystem numbers, descriptors,
and staging names remain private. Inspection opens no path and does not mutate
or clean up the lease. It does not follow a newly discovered declaration,
recurse beyond depth two, resolve dependencies, invoke a loader, execute,
persist, route, authorize, call a network/model/subprocess, or widen
permissions. Only Class 0/1 effects remain enabled.

The thirty-first bounded Phase 3 slice adds the matching library-only
schema-v1 Class 0
`ordomata.repository_executable_native_loader_nested_target_loader_requirements`
primitive. It consumes the exact nested-target runtime manifest, exact staging
receipt, and same-PID lease; freshly reproduces the runtime evidence before and
after extraction; and requires two matching complete descriptor/parser passes.
Bounded byte-level parsing reports ELF32/ELF64 `PT_INTERP`, thin
Mach-O32/Mach-O64 `LC_LOAD_DYLINKER`, absent declarations, unsupported native
layouts, or non-native non-applicability. Shared files remain deduplicated
without collapsing the complete target-loader, nested-target, guard, staging,
runtime, source-requirement, or command lineage. Terminal source lineages that
never produced a nested target retain exact dispositions and perform no
descriptor reads.

Canonical records expose only digests, fixed classifications and dispositions,
bounded counts, absolute-path booleans, and byte totals. Raw loader paths,
headers, content, filesystem numbers, descriptors, and staging names remain
private. This inspection resolves or follows no newly declared loader path,
opens no path, mutates or cleans up no lease, invokes no loader, and adds no
recursive or dependency/shared-library closure, execution, persistence,
routing, authorization, network, subprocess, harness, model, or permission
widening. Only Class 0/1 effects remain enabled.

The thirty-second bounded Phase 3 slice adds the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_native_dependency_requirements` primitive. It
consumes the exact direct native-loader, runtime, and staging receipts plus the
active same-PID lease; freshly reproduces native-loader evidence before and
after extraction; and requires two matching complete descriptor/parser passes.
Bounded byte-level parsing records ordered ELF32/ELF64 `DT_NEEDED` entries and
thin Mach-O32/Mach-O64 required, weak, re-export, upward, and lazy dylib load
commands. Each declaration contains only a context-bound digest reference, byte count,
fixed path style, load kind, and—for Mach-O—version integers. Shared direct
executables remain deduplicated without collapsing command lineage.

Canonical records expose no raw dependency names, paths, headers, content,
filesystem numbers, descriptors, or staging names. Unsupported layouts and
non-native inputs have fixed fail-closed dispositions. This inspection does
not look up, resolve, stage, open, or execute a dependency; mutate or clean up
the lease; select a fat Mach-O architecture; or establish shared-library,
recursive dependency, loader, runtime, or toolchain closure. It adds no
persistence, routing, authorization, network, subprocess, harness, model, or
permission widening. Only Class 0/1 effects remain enabled.

The thirty-third bounded Phase 3 slice adds the separate library-only schema-v1
Class 0
`ordomata.repository_executable_native_dependency_target_resolution`
primitive. It consumes the exact direct dependency/runtime/staging chain and
active same-PID lease, freshly reproduces dependency evidence on three chain
snapshots, and measures an exactly expected ordered set of canonical ASCII
absolute dependency paths twice with no-follow traversal and closing namespace
validation. Shared absolute targets are measured once without collapsing
declaration, file, or command lineage. Bare, relative, `@rpath`,
`@loader_path`, and `@executable_path` declarations remain explicit unresolved
outcomes and perform no target read.

Canonical records contain only digest-bound path, identity, metadata, content,
declaration, requirement, and command references plus bounded counts and byte
totals. Raw dependency names, paths, content, filesystem numbers, and
descriptors remain private. This boundary applies no loader search semantics,
stages no dependency, mutates or cleans up no lease, invokes no loader, and
proves no recursive dependency/shared-library/runtime/toolchain closure. It
adds no execution, persistence, routing, authorization, network, subprocess,
harness, model, or permission widening. Only Class 0/1 effects remain enabled.

The thirty-fourth bounded Phase 3 slice adds the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_native_dependency_manifest` primitive. It
freshly reproduces the exact dependency/runtime/staging/active-lease chain
three times and requires one ordered controller-supplied mapping for every
bare, relative, `@rpath`, `@loader_path`, or `@executable_path` declaration.
Each mapping cryptographically reproduces its private declaration spelling and
binds it to a canonical ASCII absolute target-path reference; absolute
declarations remain outside this manifest boundary. The receipt contains only
digest-bound mappings and lineage. It consults no host loader environment,
cache, RPATH/RUNPATH, or token-expansion semantics, opens no target path,
stages no target, and proves no dependency closure or execution eligibility.

The thirty-fifth bounded Phase 3 slice adds the separate library-only schema-v1
Class 0 `ordomata.repository_executable_native_dependency_manifest_targets`
primitive. It re-proves the explicit manifest three times, then measures only
its exact canonical targets twice with no-follow traversal and closing namespace
checks. Shared manifest targets deduplicate their measurement without
collapsing declaration or command lineage. It still consults no host loader
state, expands no token, stages no target, invokes no loader, and proves no
dependency closure or execution eligibility.

The thirty-sixth bounded Phase 3 slice adds the separate library-only schema-v1
Class 1
`ordomata.repository_executable_native_dependency_manifest_target_staging`
primitive. It re-proves the upstream manifest-target receipt, copies only from
the still-pinned no-follow descriptor, and requires action measurement plus
post-stage reinspection equality. Its caller supplies a pre-existing, empty,
owner-owned mode-`0700` root outside every target; each randomized no-follow
name is unlinked before data is written, and only a read-only descriptor
remains on a one-shot same-PID lease. Evidence is digest-only. It neither
authorizes nor performs search, loading, execution, persistence, network,
subprocess, model, or higher-class effects.

The thirty-seventh bounded Phase 3 slice adds the separate library-only
schema-v1 Class 0
`ordomata.repository_executable_native_dependency_manifest_target_runtime_manifest`
primitive. It validates that active detached target-stage lease, fully
remeasures each unlinked read-only descriptor with `pread`, and records only a
bounded byte-level ELF, Mach-O, shebang, unsupported-shebang, or unknown
classification. It opens no path and leaves the lease unchanged. It does not
parse dependencies, invoke loader behavior, establish recursive closure, or
enable execution, persistence, network, subprocess, model, or higher-class
effects.

The thirty-eighth bounded Phase 3 slice adds the separate library-only schema-v1
Class 0
`ordomata.repository_executable_native_dependency_manifest_target_loader_requirements`
primitive. It validates the runtime receipt and active detached descriptor
lease, then reports only direct ELF interpreter or Mach-O dylinker declaration
syntax. It does not look up, open, load, or execute a declared name and leaves
the lease unchanged. Dependency parsing and closure, loader behavior,
authority, persistence, network, subprocess, model, and higher-class effects
remain out of scope.

The thirty-ninth bounded Phase 3 slice adds the separate library-only schema-v1
Class 0
`ordomata.repository_executable_native_dependency_manifest_target_dependency_requirements`
primitive. It validates the runtime receipt and active detached descriptor
lease, then records only bounded ELF `DT_NEEDED` and thin Mach-O dylib-load
syntax as digest-only declarations. It never resolves a declaration, opens a
path, loads a target, proves recursive/shared-library closure, or enables
execution, authority, persistence, network, subprocess, model, or higher-class
effects.

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
proposal event append. The separate executable-resolution, staging, runtime-
manifest, shebang-requirements, and shebang-target-resolution receipts are not
proposal evidence and do not widen that lineage. Complete interpreter,
dependency, and runtime/toolchain
closure plus any future `shell=False` action-boundary execution remain
deferred. Only Class 0/1 effects remain enabled.

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
proposal lineage, command execution, route, billing, or live effect. The
receipt itself remains non-reusable; the separate tenth slice supplies bounded
action-boundary capture and staging. Complete interpreter and dependency/
toolchain coverage and execution remain future boundaries.

The tenth bounded Phase 3 slice is the separate schema-v1 executable-staging
lease described above. Exact expected/action/post-stage resolution equality,
same-descriptor process-local chunk capture, and namespace-detached mode-`0400`
read-only descriptors establish only bounded temporary Class 1 byte staging.
It adds no authority, authorization decision, action receipt, proposal
lineage, durable control-plane persistence, CLI/state/runner integration,
routing, billing, live eligibility, or execution. Complete dependency/toolchain
coverage and any consumer that mutates or executes staged bytes remain future
boundaries; the existing lifecycle cleanup only releases the lease, and only
the eleventh through thirteenth slices' Class 0 inspections and the fourteenth
slice's separate Class 1 target staging otherwise read it.

The eleventh bounded Phase 3 slice is the separate schema-v1 staged-executable
runtime-manifest inspection described above. It requires an active same-PID,
exactly anchored lease, fully rehashes each retained descriptor, and emits only
digest/reference entries plus aggregate evidence for bounded ELF, Mach-O,
ASCII-shebang, unsupported-shebang, or unknown header classification. It does not
resolve an interpreter, establish dependency or runtime closure, prove
invocability or completeness, mutate or clean up the lease, or add any
authority, authorization, action receipt, proposal/worktree integration,
dispatch, routing, billing, live, CLI/state/runner, subprocess, or execution
path.

The twelfth bounded Phase 3 slice is the separate schema-v1 staged-executable
shebang-requirements inspection described above. Exact typed runtime and
staging receipts plus their active same-PID anchored lease are mandatory. The
call freshly reproduces the runtime manifest, remeasures the leased
descriptors, and fixes `native_binary_no_shebang`,
`absolute_interpreter_token`, `non_absolute_interpreter_token`,
`unsupported_shebang`, or `unknown_runtime_format` as appropriate. It turns a
valid POSIX shebang into digest-only interpreter-token and opaque argument-tail
requirements by splitting at the first contiguous ASCII space/tab boundary
run; only the run's first byte determines the separator kind, and neither the
run nor tail is interpreted. It opens no path, mutates or cleans up no lease,
resolves or interprets no
interpreter, `env`, `PATH`, arguments, or kernel semantics, and adds no
authority, authorization, action receipt, persistence, proposal/worktree
integration, dispatch, route, billing, live, CLI/state/runner, subprocess,
harness, or execution path. Complete interpreter/dependency/toolchain closure
remains required before widening.

The thirteenth bounded Phase 3 slice is the separate schema-v1 direct shebang-
target measurement described above. It requires the exact upstream receipt
chain, active lease, and complete first-use target-path expectation. Native
entries are not applicable; every script target must pass two sequential full
measurements plus final exact-namespace revalidation. The raw-path/raw-byte-
free receipt remains historical, non-authorizing, outside proposal lineage,
and unusable for routing, live eligibility, subprocess creation, or execution.

The fourteenth bounded Phase 3 slice is the separate schema-v1 direct shebang-
target staging lease described above. It binds exact expected/action/post-stage
target resolution and the complete active upstream chain, stages each unique
script target into an unlinked mode-`0400` read-only descriptor under a
dedicated protected-root contract, and leaves a native-only target set as a
zero-file no-op. This Class 1 library primitive is non-authorizing and has no
persistence, routing, billing, subprocess, harness, or execution integration.

The fifteenth bounded Phase 3 slice is the separate schema-v1 staged shebang-
target runtime-header inspection described above. It validates the exact
active same-PID target-stage receipt, object anchors, retained descriptors, and
stored root context without reopening a path; fully remeasures every target
descriptor around an at-most-4,096-byte five-way header classification; and
preserves native-only zero-file correspondence through nonempty requirements
and bindings. This Class 0 library inspection adds no authority, persistence,
proposal/worktree lineage, routing, billing, live, subprocess, harness, model,
or execution capability.

The sixteenth bounded Phase 3 slice is the separate schema-v1 staged-target
shebang-requirements extraction described above. It validates and freshly
reproduces the exact target-runtime manifest from the active target-stage
lease, compares two independent complete descriptor passes, parses each unique
target once per pass under a fixed one-hop byte grammar, and preserves one
lineage-distinct requirement and binding per upstream row. Native-only input remains
a zero-file, zero-read result. This digest-only Class 0 library evidence adds
no recursive resolution, staging, authority, persistence, routing, billing,
live, subprocess, harness, model, or execution capability.

The seventeenth bounded Phase 3 slice is the separate schema-v1 nested
shebang-target measurement described above. It accepts the exact active target-
stage receipt chain and exact ordered absolute depth-2 paths, reproduces the
staged-target syntax proof, and requires two matching no-follow measurements.
Immediate depth-1 path or identity re-entry and target-stage-root descent fail
closed. Source-native input remains zero-file and zero-read; a native depth-1
target still validates its staged descriptor but makes no nested-path read. Its
privacy-bounded Class 0 receipt contains digest/reference lineage, fixed
outcomes, bounded command identifiers, counts, and byte totals; it stops after
one additional hop and adds no broader cycle or protected-root closure,
staging, authority, routing, live, subprocess, harness, model, or execution
capability.

The eighteenth bounded Phase 3 slice is the separate schema-v1 nested-target
known-chain guard described above. It requires the exact expected nested
resolution plus the exact active source- and target-stage receipt/lease
lineages, then reproduces the depth-2 measurement with original and staged
source/target identities and the one or two staging-root identities present
excluded before candidate reads. Native-only input performs no nested-target
or root-path lookup. Its privacy-bounded Class 0 receipt remains non-authorizing and
makes no source-path, root-path, generic-cycle, broader-protected-root,
staging, write, routing, live, subprocess, harness, model, or execution claim.
The seventeenth resolver and public guard remain unchanged.

The nineteenth bounded Phase 3 slice is the separate schema-v1 Class 1 nested-
target staging primitive described above. It captures each unique depth-2
target through the same still-pinned descriptor used by an exact guarded
action replay, keeps exact active source/target lease lineage, and requires a
matching post-stage guard replay. Each copied target is retained only as an
unlinked mode-`0400`, non-inheritable read-only descriptor under a protected
caller-owned staging root; native-only input is a zero-file, no-root-touch
no-op. Its privacy-bounded receipt and explicit fail-closed cleanup evidence
grant no authority, persistence, proposal/worktree, routing, billing, live,
subprocess, harness, model, or execution capability.

The twentieth slice adds the matching Class 0 nested-target runtime-header
inspection described above. It remeasures only the active detached descriptors,
returns fixed privacy-bounded classifications and exact lineage, and preserves
native-only zero-read behavior without adding freshness, authority, routing,
worker, subprocess, harness, model, or execution capability.

The twenty-first slice adds matching Class 0 nested-target shebang syntax
requirements. It reproduces the runtime evidence twice, independently
remeasures detached bytes twice, and emits only digest-bound token/tail syntax
and exact lineage without resolving or executing anything.

The twenty-second slice adds matching Class 0 direct native-loader declaration
syntax. It inspects only bounded ELF `PT_INTERP` and thin Mach-O
`LC_LOAD_DYLINKER` declarations, emits digest-only path references and exact
lineage, and performs no loader resolution, shared-library traversal, fat-
binary architecture selection, subprocess, model, or execution.

The twenty-third slice adds matching Class 0 declaration-bound loader-target
measurement. Exact caller-supplied paths must reproduce the digest-only
declarations before two no-follow file measurements; raw paths stay private,
and no loader, shared library, dependency, subprocess, model, or executable is
invoked.

The twenty-fourth slice adds matching Class 1 native-loader target staging.
Each unique target is copied through its still-pinned action-measurement
descriptor into an unlinked mode-`0400` read-only lease, followed by exact
post-stage correspondence checks and explicit fail-closed cleanup. Raw paths
and bytes remain private, and no loader, dependency, subprocess, model, or
executable is invoked.

The twenty-fifth slice adds matching Class 0 runtime-header inspection of the
detached loader copies. Two full descriptor remeasurements surround one
bounded position-independent header read and emit fixed privacy-bounded
classifications without opening a path, mutating a lease, invoking a loader,
or executing anything.

The twenty-sixth slice adds matching Class 0 loader-of-loader declaration
inspection. Fresh runtime reproduction and repeated descriptor measurements
bind bounded ELF `PT_INTERP` or thin Mach-O `LC_LOAD_DYLINKER` syntax to every
target and command without resolving a newly declared path, invoking a loader,
or executing anything.

The twenty-seventh slice adds matching Class 0 measurement of exactly one
newly declared native-loader hop. Exact declaration/path reproduction, two
guarded no-follow measurements, and immediate current-target, hardlink, staged-
target, and target-staging-root re-entry exclusions extend digest-only lineage
to depth two without parsing the new bytes, invoking a loader, or executing
anything.

The twenty-eighth slice adds a separate Class 0 known-chain guard over that
depth-two receipt. It reproduces the same measurement with original/staged
source identities and the source staging-root identity added to the existing
target protections, then closes on the exact source and target leases. Source
identity, hardlink, staged-copy, and source-stage-root re-entry now fail before
leaf reads without parsing the measured bytes or adding staging, loader,
subprocess, model, or execution capability.

The twenty-ninth slice adds matching Class 1 descriptor staging for the exact
guarded depth-two bytes. Each unique target is copied through its pinned action-
measurement descriptor into an unlinked mode-`0400`, read-only, non-inheritable
process-bound lease, followed by exact post-stage guard replay. Empty outcomes
retain command lineage without touching a staging root. Separate authorization
is still required, and no parsing, recursion, loader invocation, execution,
persistence, routing, or permission widening is added.

The thirtieth slice adds matching Class 0 runtime-header evidence for those
detached depth-two descriptors. Full descriptor remeasurement surrounds one
bounded position-independent read, fixed byte-level classification preserves
requirement, source-lineage, and command correspondence, and empty stages
perform no descriptor reads. It opens no path, mutates no lease, follows no
further declaration, invokes no loader, and executes nothing.

The thirty-first slice adds matching Class 0 loader-declaration evidence for
those classified depth-two files. Fresh runtime reproduction and two complete
matching descriptor/parser passes extract only bounded ELF `PT_INTERP` or thin
Mach-O `LC_LOAD_DYLINKER` syntax and preserve the complete digest lineage.
Terminal lineages remain zero-read. It does not resolve or follow the declared
path, invoke a loader, mutate a lease, or execute anything.

The thirty-second slice adds separate Class 0 direct-native dependency-
declaration evidence. Exact direct native-loader/runtime/staging/lease lineage,
fresh native-loader reproduction, and two matching descriptor/parser passes
produce digest-only ordered ELF `DT_NEEDED` and thin Mach-O dylib-load syntax.
It performs no dependency lookup, resolution, staging, path open, or execution
and proves no shared-library or recursive dependency closure.

The thirty-third slice adds separate Class 0 measurement for only those direct
dependency declarations that are already canonical absolute paths. Exact
caller expectations, three fresh dependency-chain snapshots, two matching
no-follow measurements, and closing namespace checks produce digest-only
evidence. Non-absolute declarations remain unresolved and zero-read; no loader
search semantics, dependency staging, or closure is claimed.

The thirty-fourth slice adds separate Class 0 explicit controller-manifest
binding for every non-absolute direct dependency declaration. Ordered private
name-to-canonical-path inputs reproduce the existing digest-bound declarations,
then yield only digest-bound mapping evidence after three fresh chain snapshots.
It neither consults ambient loader search state nor expands Mach-O tokens, and
opens or stages no mapped path; target measurement and dependency closure remain
future boundaries.

The thirty-fifth slice adds separate Class 0 no-follow measurement for the
already controller-bound manifest targets. It repeats the manifest proof around
two matching target measurements and closing namespace checks, while keeping
raw names, paths, content, and filesystem identifiers private. No host loader
search, target staging, loading, or closure is added.

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
