# Subscription-only billing policy

## Invariant

The project must not cause separately billed AI inference during development, tests, comparison, scheduled operation, self-improvement, or normal use. An unavailable or exhausted included subscription is a blocked/deferred state; it never authorizes another billing lane.

Allowed routes:

- `subscription_included`, but only with all current Billing Hard-Stop v2 evidence described below;
- `local_non_ai`;
- `mock`.

Blocked routes:

- `purchased_product_credit`;
- `subscription_overage`;
- `separately_billed_api`;
- `cloud_provider_billing`;
- `unknown`.

There is no API-key, product-credit, overage, cloud, or mock fallback from a requested subscription run.

## Billing Hard-Stop v2

Billing safety is not one boolean. The controller keeps these observations separate:

- `billing_route`: where inference would be charged;
- `capacity_state`: `available`, `limit_reached`, `blocked_until_reset`, `cooldown`, `unknown`, or `not_applicable` for the included pool;
- `paid_continuation_protection`: whether spillover is provider-disabled or, for Codex, a zero paid balance and disabled automatic top-up have both been verified;
- `paid_credit_balance`: a value-free category (`zero`, `positive`, `unlimited`, `unknown`, or `not_applicable`).

A live AI run is eligible only when every independent gate agrees:

```text
billing_route == subscription_included
capacity_state == available
route confidence == high
account identity fingerprint == verified and matching
capacity evidence == current through the requested run window
paid-continuation attestation == current, matching, and provider-valid
paid-continuation protection == safe for that runner
profile/capability/isolation/environment checks == passed
durable billing circuit == closed
ORDOMATA_ALLOW_SUBSCRIPTION_RUNS == 1
```

The former `AGENTOPS_ALLOW_SUBSCRIPTION_RUNS` name is a temporary compatibility
alias. It enables the same gate only when its value is exactly `1`. If both
names are present, both must equal exactly `1`; any disagreement or malformed
value disables live execution. Neither variable is inherited by worker
processes, and neither can override another eligibility check.

The live gate and first-party subscription authentication are necessary, never sufficient. Missing, stale, contradictory, mismatched, or unknown evidence fails closed.

## Account-bound attestations

When a provider setting cannot be read safely by the harness diagnostic, a short-lived local attestation may record operator-observed provider UI state. The attestation is schema-validated, owner-private, tied to a non-secret one-way account fingerprint, and must remain valid for the requested run duration plus the safety margin. It cannot override unsafe machine-readable evidence.

- Codex requires current included capacity, a usable paid-credit balance classified as `zero`, and operator-observed automatic top-up disabled. A positive, unlimited, or unknown paid balance blocks execution.
- Claude requires a positively identified paid Claude subscription, current included capacity, and operator-observed extra usage/usage credits disabled. Free, null, contradictory, or unknown subscription identity blocks execution.

Attestations contain semantic evidence codes, not account names, addresses, tokens, numeric balances, screenshots, or credential material. The ignored local file is `.ordomata/billing-attestations.json`; `doctor` reports only sanitized status categories.

The supported lifecycle command is `ordomata billing-attest --runner codex|claude`. It is terminal-interactive only, exposes no `--yes` or noninteractive bypass, probes an adapter configured without prior file evidence, and requires the operator to type the exact provider-specific statement shown. Codex's operator-observed automatic-recharge setting expires after at most one hour; its capacity and paid-credit balance are still machine-probed afresh before every dispatch. Claude UI evidence expires after at most 15 minutes. The command replaces the selected runner's record atomically, preserves other current strict records, and enforces a non-symlinked mode-`0700` parent plus a mode-`0600` file. Run `doctor` afterward; successful creation alone does not make the runner eligible.

The six-trial Class 0 comparison applies a uniform two-minute trial timeout and reserves an additional one-minute evidence margin. All selected attestations and capacity windows must cover that full envelope before any comparison record is created, and every individual dispatch checks them again.

## Post-run enforcement and durable state

The adapter performs a bounded post-run billing assessment even when model execution raises or fails. Deterministic policy then classifies the result:

- a verified safe, matching postflight may record no paid capacity and no incremental AI charge;
- verified included-capacity exhaustion records `blocked_until_reset`, stops remaining controlled trials, and does not switch lanes or retry immediately;
- `limit_reached`, `blocked_until_reset`, `cooldown`, and `unknown` remain durable across controller restarts; dispatch resumes only when a policy-valid `available` observation is strictly newer than both the blocking event and any recorded reset;
- a paid route, paid-consumption signal, changed account, missing postflight, or otherwise unknown post-run state quarantines the attempt and artifacts;
- paid or unknown evidence opens an append-only account/profile billing circuit, which prevents later live dispatch until an explicit, separately reviewed close event exists.

Quarantined output cannot be promoted. Capacity and circuit events are append-only so a later process cannot erase the evidence that caused a stop. Reservation completion writes the postflight capacity observation before releasing its account/profile lease, preventing a second worker from slipping between capacity detection and persistence.

## Execution accounting

The controller records independent, typed fields rather than inventing a dollar cost:

```text
subscription_capacity_consumed: yes | no | unavailable
paid_capacity_consumed: yes | no | unknown | not_applicable
incremental_ai_charge: none | possible | confirmed | unknown
incremental_api_charge: none | unknown
```

`incremental_api_charge` is the narrower API-specific compatibility field. It must never be used to infer `incremental_ai_charge: none`: product credits or subscription overage can create an AI charge without being an API charge. Missing telemetry remains `unknown` or `unavailable`, never zero.

## Credential handling

Preflight reports environment-variable names but never their values. Child processes receive a newly constructed, narrow environment. Prohibited API and cloud-provider credentials are excluded without modifying the operator's parent environment. Credential-shaped approved names and values are rejected; diagnostics retain only names and fixed error categories.

Examples of prohibited or high-risk variables include:

- `OPENAI_API_KEY`
- `CODEX_API_KEY`
- `ANTHROPIC_API_KEY`
- `ANTHROPIC_AUTH_TOKEN`
- `CLAUDE_CODE_USE_BEDROCK`
- `CLAUDE_CODE_USE_VERTEX`
- `CLAUDE_CODE_USE_FOUNDRY`
- `AZURE_OPENAI_API_KEY`
- `GOOGLE_API_KEY`
- `OPENROUTER_API_KEY`

Subscription authentication remains owned by the installed first-party harness. Credential values are never passed as command-line arguments, logged, stored in SQLite, or committed.

## Runner-specific execution policy

Codex execution uses the documented first-party headless CLI/app-server boundary. It is eligible only after the diagnostic proves ChatGPT subscription identity and current capacity and a matching attestation proves zero usable paid credits plus disabled automatic top-up. User configuration is ignored during execution so it cannot inject a different provider or MCP route.

Claude Code execution uses its documented first-party headless mode. It is eligible only after structured diagnostics jointly prove a paid Claude subscription/OAuth route and matching identity, current capacity is attested, and extra usage is attested disabled. API-key authentication and Bedrock, Vertex, Foundry, third-party, contradictory, free, or unknown routes are blocked. Safe mode and strict MCP isolation prevent project/user customizations from changing the effective workflow.

Other harnesses remain blocked until their billing route, account identity, included capacity, paid-continuation protection, safe headless controls, and post-run evidence can all be verified and encoded in a reviewed adapter.

## Testing and controlled comparisons

The full suite uses deterministic mocks, sanitized event fixtures, and simulated route, credit, overage, capacity, identity, circuit, timeout, and postflight failures. Normal tests never invoke a model or network service.

The schema-v6 task-attempt binding is limited to the exact controller-owned
in-memory mock path. Its bounded canonical task-intent lineage is reused by the
final dispatch and owner-private publication PEPs, which compare it with the
captured shipped resolver and independently replay the shipped evaluator and
fixed policy. Publication exactly rereads the binding, decision, and pre-effect
record before post-replay action-time freshness and staging. These checks add
authorization provenance only: they change no event or receipt schema, allowed
billing route, or live gate; invoke no harness; and enable no credit, overage,
API, cloud, comparison, supervisor, or external-action fallback. Schema-v1
through v5 histories retain their prior billing and authorization meanings.

The frozen schema-v1 through schema-v3 and separate schema-v4 repository-
registration contracts plus pure version-dispatched validation deterministically validate
and hash a controller-supplied ordinary Git
identity, stable filesystem reference, exact verification argv-array (not
shell-text) declarations, canonical protected/allowed paths, bounded resource
limits, fixed local-container/network-disabled isolation, and patch-only review
policy. Their digest-only evidence explicitly declares read-only use, disabled
dispatch, and no granted authority. The validator invokes no Git command,
subprocess, worker, harness, or network service; creates no state or worktree;
and changes no authorization, billing gate, circuit, capacity, or live-route
eligibility. V2 adds bounded canonical literal generated/vendor deny roots
strictly below allowed paths; they provide no billing, route, harness, ignore,
or execution evidence. V3 retains those path rules and requires exact
one-to-one linkage between every declared command and a controller-supplied
baseline result under one shared opaque snapshot digest. Results admit only
bounded integer timing and tagged exited, signaled, or timed-out observations;
a timeout carries the controller-supplied `termination_confirmed: true`
assertion. They contain no supplied success, output or output hash,
environment, path, message, credential, billing fact, or arbitrary metadata.
Outward evidence adds only fixed controller-supplied source, aggregate digest,
bounded result count, `baseline_authenticity_verified: false`, and
`baseline_freshness_verified: false`; it exposes no snapshot or individual
result.

V4 preserves v3 and adds one bounded controller-supplied executable/toolchain
identity claim for each declared command. Claims are exactly command-linked and
carry only opaque executable and toolchain identity digests. Canonicalization
derives a syntax-only, command-context-bound declared-executable reference and
binds the aggregate to the repository, complete verification-command set, and
exact v3 baseline aggregate. The supplied digests have no standardized or
trusted preimage or provenance. Cross-context transplantation can validate but
changes the aggregate, same-context replay remains indistinguishable, and the
baseline link proves co-declaration rather than the executable/toolchain bytes
used by the process. Aggregate-only evidence explicitly reports authenticity,
freshness, resolution, content, completeness, and execution correspondence as
false. V4 identity-block validation adds no PATH or environment lookup,
runtime-cwd or symlink resolution, stat/content read, shebang/interpreter/
launcher/module/plugin/dynamic-loader/package/version inspection, or execution.
Existing registration root and repository-relative path/executable safety
checks are unchanged.

The separate library-only `ordomata.repository_executable_resolution`
schema-v1 receipt accepts only a freshly revalidated exact schema-v4
registration. Under fixed `controller_measured` / `posix_nofollow_v1`
semantics it searches bare names only in at most 32 explicit controller-
supplied absolute directories; ambient `PATH`, empty or relative entries,
implicit cwd, and suffix expansion are absent. Slash-containing declarations
initially require `cwd: "."` and resolve from the registered repository root.
Pinned descriptors, no-follow descriptor-relative lookup, complete direct-file
hashing, metadata/namespace/precedence rechecks, and final registration
revalidation reject symlinks, special or sparse files, missing execute bits,
and detected drift/races. The bounds are 64 MiB per unique file and 256 MiB
total.

Its evidence exposes only aggregate digests and bounded counts. The receipt is
point-in-time and non-reusable and keeps current freshness,
authenticity/provenance, effective invocability, interpreter/dependency
coverage, toolchain completeness, repository-snapshot or baseline
correspondence, and future execution correspondence false. It supplies no
subscription identity, paid-continuation protection, capacity, billing route,
circuit, live-gate, authorization, dispatch, action receipt, or live
eligibility and adds no CLI, persistence, subprocess, or execution path.
Evidence fixes `sequential_resolution_measurement_complete: true` and
`atomic_snapshot_verified: false`; completion is sequential and does not prove
an atomic filesystem snapshot.

The separate library-only schema-v1
`ordomata.repository_executable_staging` boundary consumes an exact typed
expected resolver receipt, not subscription, identity, capacity, or billing
evidence. Its staging source/scope is fixed to `controller_copied` /
`posix_unlinked_readonly_v1`. During a fresh action resolver pass it rereads each unique executable
into immutable process-local chunks through the same still-pinned descriptor.
The expected and action canonical receipts must match before the first staging
mutation, and a complete post-stage resolver pass must match both. This
bracketing detects ordinary drift but does not prove an atomic snapshot,
current freshness, or future execution correspondence.

Its caller must pre-create an exact concrete absolute staging root that is
empty, no-follow traversable, owned by the effective user, exactly mode `0700`,
and nonoverlapping with the repository and explicit search directories. The
overlap check is lexical containment plus exact-root inode equality only;
exclusion of other mount aliases remains false. The root is dedicated to one
controller process and one lease, without concurrent use. The 64 MiB-per-
unique-file and 256 MiB-total limits remain fixed. Each random zero-
length mode-`0600` entry is created exclusively, opened, unlinked, and parent-
fsynced before captured bytes are written. The resulting anonymous inode is
hashed, fsynced, normalized to non-executable mode `0400`, read back, and
retained only through a read-only close-on-exec descriptor after the writer is
closed. The successful root contains no staged byte name.

The receipt binds expected/action/post-stage resolution and staged file/command
correspondence; outward evidence is aggregate-only. Cleanup returns `removed`,
`already_absent_verified`, or `unverifiable`, preserving still-verified handles
for retry without retrying an ambiguously closed descriptor number. It proves
neither root-timestamp restoration nor secure erasure.

This temporary Class 1 local staging primitive cannot satisfy route, capacity,
identity, paid-continuation, environment, isolation, circuit, or live-gate
requirements and performs no inference. Kernel/filesystem immutability,
same-UID exclusion, ACL privacy, absence of external writable descriptors,
authority, authorization, action-receipt status, dispatch, durable control-
plane persistence, proposal-lineage extension, routing, billing/capacity/
circuit eligibility, live eligibility, and execution remain false. It has no
CLI, state, proposal, runner, worker, subprocess, or harness integration.
Same-UID adversarial interference is outside V1 protection, and the lease must
never be passed to or integrated with an untrusted same-UID worker.

The separate library-only schema-v1
`ordomata.repository_executable_runtime_manifest` boundary reads the active
lease only for Class 0 measurement; it supplies no subscription evidence.
`inspect_staged_executable_runtime_manifest(expected_staging, *, lease)`
requires an exact typed staging receipt and its active same-PID, exactly
anchored lease. Fixed `controller_inspected` /
`posix_staged_runtime_header_v1` semantics open no source path, fully remeasure
every private retained descriptor before and after reading at most 4,096 header
bytes, and classify only `elf`, `mach_o`, `posix_shebang`,
`unsupported_shebang`, or `unknown`. Accepted shebang directives are ASCII and
limited to 255 bytes, but their content is neither exposed nor interpreted.

Runtime-file and command-binding entries contain digest/reference,
classification, and bounded-count metadata only, with aggregate-only outward
evidence. The inspection neither changes lease state nor cleans up a
descriptor. It establishes no effective invocability, interpreter identity or
resolution, dependency/environment/runtime/toolchain closure, complete
manifest, authority, authorization, action receipt, proposal lineage,
worktree, dispatch, route, billing, capacity, paid-continuation, circuit, live-
gate, or execution fact. It cannot satisfy any subscription-only prerequisite
and adds no CLI, state, runner, worker, subprocess, network, harness, or live
integration.

The separate library-only schema-v1
`ordomata.repository_executable_shebang_requirements` boundary is also Class 0
local measurement and supplies no subscription evidence.
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
repeat after final runtime reproduction. Fixed
dispositions are `native_binary_no_shebang` for ELF/Mach-O,
`absolute_interpreter_token` or `non_absolute_interpreter_token` for a valid
POSIX shebang, `unsupported_shebang`, and `unknown_runtime_format`. In this
syntax-only taxonomy, `absolute_interpreter_token` means only that the first
token byte is `/`; it claims no canonicality, usability, compatibility, or
resolution, so `/`, repeated or trailing slashes, and dot components remain
absolute syntax. A valid directive is split at the first contiguous ASCII
space/tab boundary run. The whole run is consumed, only its first byte
determines the separator kind, and
neither the run nor the remaining opaque argument tail is interpreted; token
and tail stay digest-only with bounded byte counts.

The boundary interprets or resolves no interpreter, `env`, `PATH`, argument
tail, or kernel/launcher semantics. It establishes no dependency or complete
runtime/toolchain closure and cannot satisfy route, capacity, identity, paid-
continuation, environment, isolation, circuit, or live-gate requirements. It
neither mutates nor cleans up the lease and adds no authority, authorization,
action receipt, persistence, proposal/worktree integration, dispatch, route,
billing, capacity, paid continuation, circuit, live eligibility,
CLI/state/runner integration, subprocess, network, harness, or execution path.
Complete interpreter/dependency/toolchain closure remains required before any
subscription-gated or operational widening.

The thirteenth bounded Phase 3 slice, the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_resolution` boundary, is also a
Class 0 local measurement and supplies no subscription evidence.
`inspect_staged_executable_shebang_targets(expected_requirements, *,
expected_runtime, expected_staging, lease, expected_target_paths)` requires the
exact typed upstream receipts, their exactly anchored active same-PID lease,
and the controller's exact used canonical ASCII absolute target paths in
first-use order. Under fixed `controller_measured` /
`posix_absolute_shebang_target_nofollow_v1` semantics, the only successful
dispositions are `native_not_applicable` and
`direct_absolute_target_measured`; any non-absolute, non-canonical,
not-exactly-expected, unsupported, or unknown requirement invalidates the whole
call.
Exact-spelling no-follow component walks and two sequential full measurements
require matching namespace, identity, metadata, and content results. Canonical
records and outward evidence expose no raw target paths or target bytes; they
contain only digest/reference fields, bounded command identifiers/kinds and
counts/sizes, fixed classifications/dispositions, and schema-bounded evidence
booleans/metadata.

An exactly expected `/usr/bin/env` measures only the direct target; its
opaque argument tail and downstream selection remain uninterpreted. This is not
semantic interpreter resolution and establishes no dependency, environment,
runtime/toolchain, or effective-invocability fact. It neither mutates nor cleans
up the lease and cannot satisfy route, capacity, identity, paid-continuation,
isolation, circuit, or live gates. It adds no authority, authorization, action
receipt, proposal/worktree integration, dispatch, route, billing, network,
subprocess, harness, or execution path.

The fourteenth bounded Phase 3 slice, the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_staging` boundary, is a Class 1
local byte-staging effect and supplies no subscription evidence.
`stage_repository_executable_shebang_target_bytes` requires the exact expected
target-resolution receipt, complete typed upstream chain, and exactly anchored
active same-PID executable lease. It freshly revalidates the registration,
exact search directories, and target paths. At the action boundary, each unique
target is measured and captured through the same still-pinned descriptor and
must reproduce the expected receipt before mutation. The dedicated caller-
owned target root must be exact, absolute, owner-mode-`0700`, empty, and
disjoint from authoritative protected roots derived from the revalidated
registration, search directories, target paths, and executable source-stage
root.

Each unique script target is exclusively staged without following links,
unlinked with a target-root directory sync before bytes are written, fixed at
mode `0400`, synchronized, independently read back, and retained only through a
non-inheritable `O_RDONLY` descriptor. Post-stage target resolution and the
complete upstream chain must still match exactly. Shared targets are staged
once; native-only input creates an active zero-file lease without inspecting or
mutating the target root. Receipts and outward evidence disclose no raw target
paths, target bytes, temporary names, or descriptor numbers. The process-local
lease retains the caller-supplied root and private descriptor state; explicit
cleanup releases only that lease.

This primitive establishes no entitlement, paid-continuation, route, billing,
capacity, circuit, identity, isolation, or live-gate fact and adds no authority,
authorization decision, action receipt, persistence, proposal/worktree,
dispatch, CLI/state/runner, subprocess, network, harness, or execution path. It
interprets no interpreter, `env`, `PATH`, argument, recursive-interpreter,
loader, or dependency semantics and proves no immutability, same-UID/external-
writer or fork exclusion, external-hardlink or mount-alias exclusion, atomic
or current freshness, authenticity or provenance, effective invocability,
crash cleanup, or secure erasure. Only Class 0/1 remains enabled.

The fifteenth bounded Phase 3 slice, the separate library-only schema-v1
`ordomata.repository_executable_shebang_target_runtime_manifest` Class 0
boundary, supplies no subscription evidence.
`inspect_staged_executable_shebang_target_runtime_manifest(
expected_target_staging, *, lease)` accepts only the exact target-staging
receipt object and its active same-PID target-stage lease. A frozen independent
staging-v1 mirror, under fixed `controller_inspected` /
`posix_staged_shebang_target_runtime_header_v1` semantics, validates the
canonical receipt, digest and file-reference
anchors, receipt and retained-file tuple object anchors, untouched lifecycle
and cleanup state, and stored root context. Used-root owner-mode-`0700`
metadata must reproduce the context digest without reopening it; native-only
input must match the no-op context and preserve exact nonempty requirements
and command bindings with zero files.

Every mode-`0400`, link-count-zero, non-inheritable `O_RDONLY` target
descriptor is fully remeasured before an at-most-4,096-byte `pread` header is
accepted; the bounded read must equal the header captured by the complete pass.
The exact lease snapshot and all descriptors are verified again afterward.
Immutable target-runtime files, requirements, bindings, and the receipt fix
`elf`, `mach_o`, `posix_shebang`, `unsupported_shebang`, or `unknown`
classification. Direct requirements become
`direct_absolute_target_runtime_inspected`, native requirements remain
`native_not_applicable`, and shared targets appear once. Canonical records and
aggregate evidence expose no path, bytes, directive, temporary name, or
descriptor number.

This call opens no source, target, or staging-root path, mutates or cleans up no
lease, and makes no model or live-harness call. It establishes no entitlement,
identity, isolation, paid-continuation, route, billing, capacity, circuit, or
live-gate fact; no recursive shebang/interpreter/`env`/`PATH`/argument semantics
or dependency/loader/environment/runtime/toolchain closure; no current
freshness, atomicity, authenticity, provenance, or effective invocability; and
no authority, authorization, action receipt, persistence, proposal/worktree,
dispatch, CLI/state/runner, network, subprocess, harness, or execution path.
Only Class 0/1 remains enabled.

Separately, `ordomata.repository_proposal.bind_repository_proposal_attempt`
freshly revalidates one registration and binds it plus an explicit canonical
`proposal_digest` to an existing immutable Class 0/1
`repository-proposal-disabled` run. It appends exactly one content-addressed,
statusless `repository_registration_selection` event and then one content-
addressed, statusless `repository_proposal_attempt_binding` event. Each append
atomically requires the run to remain `CREATED` and the exact ordered
predecessor event IDs. Commit failures roll back before reconciliation; exact
event identifiers, payloads, ordering, digest/component links, and status must
read back from one consistent SQLite snapshot. These privacy-bounded events
store no raw proposal content, registration document, path, argv, workspace,
run directory, credential, or artifact content.

The proposal evidence reuses existing `run_events` and adds no SQLite
migration, run creation/status transition, authorization decision/action
receipt, route/profile selection, billing assessment, capacity/circuit event,
worktree, Git/command/process invocation, worker/supervisor dispatch, harness
call, network request, or live eligibility. It cannot satisfy route, capacity,
identity, paid-continuation, environment, isolation, circuit, or explicit live-
gate prerequisites. The chain remains pinned to frozen registration evidence
v1 and rejects schema-v2 through schema-v4 registrations before any event
append. Baseline observations and executable/toolchain identity claims cannot
satisfy route, capacity, identity, paid-continuation, environment, isolation,
circuit, or explicit live-gate evidence.

The third slice is the library-only `ordomata.repository_proposal_inspection`
API `inspect_repository_proposal_evidence(database_path, *, run_id)`. Its
privacy-bounded `RepositoryProposalInspectionReport` fixes
`inspection_scope: "single_run"` and returns `run_ref`, permission class,
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
cannot cover the history. One result proves only its caller-named run, never
the whole database.

The exact signed main file and optional WAL are staged into owner-private
temporary storage under a fixed controller-owned 512 MiB combined ceiling;
oversized state fails before copy. A no-WAL snapshot opens through an immutable
read-only URI, while an in-budget WAL pair opens read-only. SQLite opens only
the staged identity, and before/after source signatures detect concurrent
changes. One query-only SQLite snapshot independently replays
cardinality/order, event and payload digests, durable-run, proposal,
registration-component linkage, and fixed Class 0/1, runner, `CREATED`,
read-only, dispatch-disabled, and no-authority semantics. It never instantiates
`SQLiteStateStore`, creates source schema or sidecars, repairs state,
revalidates registration against the live filesystem, or provides an external
tamper anchor. Fixed findings and errors expose no raw identifiers, SQLite
diagnostics, paths, argv, registration/proposal content, workspace/run-directory
values, or artifact content.

Inspection creates no source database/schema/sidecar or migration and persists
no run/status/event or authorization evidence. It creates no worktree and
performs no Git/command/process invocation, worker/supervisor dispatch,
route/profile selection, billing assessment, capacity/circuit event,
harness/network action, or live eligibility. A clean report cannot satisfy
route, capacity, identity, paid-continuation, environment, isolation, circuit,
or explicit live-gate prerequisites.

The fourth slice is the controller-owned, library-only
`ordomata.repository_proposal_admission` shadow. Its public API accepts only a
durable database path, caller-named run, and controller evaluation time, then
freshly invokes the independent inspector. It accepts no caller-supplied
inspection report, class, authorization request, policy, or evaluator. Only a
clean, evidence-complete, complete, untruncated, finding-free exact three-event
Class 0/1 result reaches shadow evaluation. A nonclean result is
`not_evaluated` and `indeterminate` with no request, policy, or decision; fixed
failed/indeterminate results cover run-binding, evaluator, or replay failure.

The fixed Class 0 projection is a local `READ` observation with a read-only
operation/resource, class-specific policy, and unenforced audit-receipt plus
read-only obligations. The fixed Class 1 projection is a local `CREATE`
nomination with a local-draft operation/resource, class-specific policy, and
unenforced audit-receipt plus isolated-local-only obligations.
The request digest-binds the privacy-safe inspection mapping and validated
lineage. The active evaluator and captured built-in replay must exactly match
the controller's expected decision. Its environment is fixed to disabled
network and `LOCAL_NON_AI`; capacity and paid-continuation fields are
`NOT_APPLICABLE`, not evidence that can satisfy any subscription or live-run
gate.

An exact observational permit grants no authority and cannot select a billing
lane, route, profile, or runner. The mapping fixes authority, enforcement,
admission/action, receipt, evidence persistence, repair, dispatch, route,
billing assessment, and obligation enforcement to false. The API has no CLI
and persists nothing; it creates no source state, event, durable decision or
receipt, worktree, Git/command/process invocation, worker/supervisor dispatch,
profile selection, billing/capacity/circuit fact, harness/network action, or
live eligibility. It cannot satisfy route, capacity, identity,
paid-continuation, environment, isolation, circuit, or live-gate evidence.

The fifth slice is the library-only
`ordomata.repository_proposal_admission_verification` API
`verify_repository_proposal_admission_shadow_mapping(value)`. It accepts only
an exact built-in `dict`, takes a bounded detached JSON snapshot, and
independently mirrors the inspection contract. Evaluated inputs replay the
Class 0/1 request, policy, manual expected decision, and captured evaluator;
inert inputs must match an exact state-machine branch, and a reported replay
failure must retain a constructible replay boundary. Findings remain fixed and
value-free. `contract_valid` reports internal consistency only; it supplies no
authenticity, durable reinspection or source truth, current freshness, billing
or route evidence, or authority. A coherent forgery or replay remains
indistinguishable without a trusted anchor. Verification persists or repairs
nothing, enforces or authorizes nothing, and creates no worker, repository,
command, route, billing, network, harness, dispatch, or live effect. It cannot
satisfy any subscription or live-run prerequisite.

The sixth bounded Phase 3 slice adds the separate repository-registration
schema-v2 contract. Its required, bounded `generated_paths` and
`vendor_paths` are canonical literal deny/classification roots strictly below
allowed paths. They are pairwise non-overlapping and disjoint from
protected/sensitive paths; aliases, traversal, glob/expansion syntax, symlinks,
and special files fail closed. Nonempty categories are digest-bound, but their
raw paths remain absent from evidence. These declarations provide no route,
capacity, identity, billing, paid-continuation, or live-gate evidence and do not
enable or invoke a harness. Frozen schema v1 remains the only proposal-lineage
version.

The seventh bounded Phase 3 slice adds the schema-v3 baseline contract described
above. It does not authenticate the observations, compare the clock, recompute
the snapshot, resolve an executable/toolchain, execute a command, invoke a
harness, or create subscription, billing, capacity, or route evidence. Schemas
v1 and v2 retain their prior meanings, and frozen schema v1 remains the only
proposal-lineage version.

The eighth bounded Phase 3 slice adds the schema-v4 opaque executable/toolchain
identity-claim contract described above. It creates no trusted identity,
resolution, content, completeness, execution, subscription, billing, capacity,
route, or live-gate evidence. Frozen schemas v1 through v3 retain their prior
meanings, frozen schema v1 remains the only proposal-lineage version, and only
Class 0/1 effects remain enabled.

The ninth bounded Phase 3 slice adds the separate schema-v1 direct-executable
receipt described above. Fresh schema-v4 revalidation and bounded descriptor-
based measurement produce only aggregate, point-in-time, non-reusable local
evidence. It cannot satisfy any subscription-only gate and changes no
registration schema, proposal lineage, persistence, authority, route, billing,
capacity, circuit, live eligibility, or execution path. The separate tenth
slice supplies bounded action-boundary capture and staging; complete
interpreter/dependency manifests and execution remain future boundaries.

The tenth bounded Phase 3 slice adds the separate executable-staging lease
described above. Exact expected/action/post-stage resolution equality and
namespace-detached read-only copies establish no subscription entitlement,
capacity, paid-continuation, route, billing, circuit, or live-run fact. Nothing
in the CLI, state store, runner, harness, proposal lineage, or execution path
consumes the receipt or lease; only the separate Class 0 runtime-manifest,
shebang-requirements, and shebang-target inspections plus the separate Class 1
target-staging primitive below read the active lease.

The eleventh bounded Phase 3 slice adds that separate schema-v1 staged-
executable runtime-manifest inspection. Its exact active same-PID lease
anchoring, full descriptor remeasurement, and at-most-4,096-byte ELF, Mach-O,
bounded ASCII shebang, unsupported-shebang, or unknown classification produce
digest/reference-only local receipt entries and aggregate evidence. They
establish no subscription entitlement, invocability, interpreter or
dependency/runtime closure, completeness, authority, authorization, action
receipt, proposal/worktree integration, dispatch, route, billing, capacity,
paid-continuation, circuit, live-gate, or execution fact. The Class 0 call does
not mutate or clean up the lease and has no CLI/state/runner integration.

The twelfth bounded Phase 3 slice adds the separate schema-v1 staged-
executable shebang-requirements inspection. Exact typed runtime and staging
receipts plus their active same-PID anchored lease are mandatory. Fresh
runtime-manifest reproduction and descriptor remeasurement fix five
classification-derived dispositions; a valid POSIX shebang yields only digest-
only interpreter-token and opaque argument-tail requirements split at the
first contiguous ASCII space/tab boundary run. Only the run's first byte
determines the separator kind, and neither the run nor tail is interpreted.
This establishes no subscription entitlement,
interpreter or `env`/`PATH`/argument/kernel semantics, dependency/toolchain
closure, authority, authorization, action receipt, persistence,
proposal/worktree integration, dispatch, route, billing, capacity, paid-
continuation, circuit, live-gate, subprocess, harness, or execution fact. The
Class 0 call opens no path, mutates or cleans up no lease, and has no
CLI/state/runner integration. Complete interpreter/dependency/toolchain closure
remains required before widening.

The thirteenth bounded Phase 3 slice adds the separate schema-v1 direct
shebang-target measurement described above. Exact upstream receipts, the
active lease, and the complete first-use target-path expectation are mandatory.
Native entries are not applicable; every script target must match across two
sequential full measurements and final exact-namespace revalidation. The
raw-path/raw-byte-free historical receipt supplies no subscription evidence and
cannot satisfy routing, billing, capacity, paid-continuation, circuit, live,
subprocess, harness, or execution gates.

The fourteenth bounded Phase 3 slice adds the separate schema-v1 direct
shebang-target staging lease described above. Exact expected/action/post-stage
target resolution, the complete active upstream chain, same-descriptor capture,
and a dedicated protected-root contract yield only unlinked mode-`0400` read-
only descriptors; native-only input is a zero-file no-op. The Class 1 library
primitive supplies no subscription, persistence, routing, billing, capacity,
paid-continuation, circuit, live, subprocess, harness, or execution evidence.

The fifteenth bounded Phase 3 slice adds the separate schema-v1 staged
shebang-target runtime-header inspection described above. It validates the
exact active receipt, lease, object anchors and stored root context without
opening a path, fully remeasures retained descriptors around an at-most-4,096-
byte five-way classification, and preserves native-only zero-file requirement
and command correspondence. The Class 0 result supplies no subscription,
identity, isolation, paid-continuation, routing, billing, capacity, circuit,
live, subprocess, harness, model, or execution evidence.

`compare-run` is an opt-in execution workflow, not a bypass. It requires the same live gate and current evidence for every selected profile before creating comparison records. Trials use one immutable sanitized Class 0 snapshot, randomized repetition blocks, fresh sessions and workspaces, no shared outputs, and no external actions. Reports expose raw automated dimensions and separate human-review fields; they do not declare a winner or auto-promote a profile.

No live Codex-versus-Claude comparison has yet been completed in this repository.
