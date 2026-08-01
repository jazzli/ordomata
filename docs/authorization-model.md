# Runtime authorization model

Status: target architecture adopted; profile-backed exact built-in-mock Class 1 admission, dispatch, and local-candidate publication PEPs implemented; broader enforcement planned

Date: 2026-07-28

This document defines the target authorization model for the local,
single-operator orchestrator. It does not widen current authority. The runtime
still enforces its existing Class 0/1 checks. Three separate ABAC enforcement
points now gate only new profile-backed ordinary Class 1 attempts that use the
exact controller-owned in-memory mock implementation: task admission, mock
dispatch, and the resulting owner-private local-candidate publication. Classes
2 and 3 remain disabled.

## Normative project decision

The target runtime authorization model is attribute-based access control
(ABAC), aligned with NIST SP 800-162. A deterministic controller evaluates an
authenticated subject, a concrete action, a canonical resource, and current
environment attributes against a versioned policy before an action may occur.
The controller also evaluates a project-specific consequence vector. That
vector is an extension built from action, resource, and environment facts; it
is not presented as a fifth canonical NIST ABAC category.

NIST SP 800-162 is architectural guidance, not an executable policy language
or a ready-made policy bundle. This project must therefore define and test its
own small, versioned, deterministic policy schema and evaluator. No external
policy engine is selected at this stage.

The supporting standards have distinct roles:

- ANSI/INCITS RBAC concepts define versioned controller, planner,
  implementer, verifier, reviewer, and recovery roles. Effective roles are
  controller-established, provenance-bearing subject attributes and support
  static and dynamic separation of duties; requested roles and current routing
  strings are not authoritative. RBAC does not replace contextual ABAC
  evaluation.
- FIPS 199 Low, Moderate, and High confidentiality, integrity, and
  availability impact concepts inform a per-request consequence vector. This
  is an adaptation: FIPS 199 categorizes information and information systems,
  not individual agent actions, so the project makes no claim that an action
  has received a FIPS 199 categorization or that this design establishes FIPS
  compliance.
- NIST SP 800-53 Rev. 5 supplies control objectives and traceability for
  AC-3 access enforcement, AC-5 separation of duties, AC-6 least privilege,
  AC-16 security/privacy attributes, AC-25 reference-monitor properties,
  selected AC-3 enhancements for dual authorization and revocation, and AU
  audit controls. It is a control catalog, not the runtime policy-decision
  procedure. Continuous mediation is a project design invariant informed by
  the applicable controls, not a claim that every SP 800-53 baseline requires
  AC-25. Dual authorization is applied only to actions whose reviewed policy
  requires it; it is not a blanket substitute for least privilege.
- The NIST AI RMF supplies lifecycle governance, risk tolerances, measurement,
  monitoring, incident response, and current-to-target profiles. It informs
  runtime requirements and evidence, but it is not the permission engine. The
  project version-pins its profile and control crosswalk because the framework
  and supporting guidance can change.
- MCP tool annotations such as `readOnlyHint`, `destructiveHint`,
  `idempotentHint`, and `openWorldHint` are provider claims. They are never
  authorization guarantees. Even claims from an authenticated, version-pinned
  server remain insufficient without local policy and effective containment.

## Authority and enforcement architecture

The target follows the familiar policy administration, information, decision,
and enforcement split:

- **Policy administration point (PAP):** operator-controlled, versioned policy
  bundles, schemas, role assignments, and promotion history.
- **Policy information point (PIP):** deterministic collectors for identity,
  repository registration, isolation, billing, capacity, network, approvals,
  circuits, and other attributes. Every value carries source, freshness, and
  confidence metadata where applicable.
- **Policy decision point (PDP):** a pure, deny-by-default evaluator over a
  canonical request and an exact policy digest.
- **Policy enforcement points (PEPs):** controller-owned boundaries at task
  admission, claim and dispatch, each mediated command/tool invocation,
  artifact publication, policy activation, and any future external action.

A prior permit is not a reusable bearer token. The enforcement point binds the
decision to the exact subject, action parameters, resource version, evidence,
policy digest, and expiry, then re-evaluates when a relevant attribute changes.
Missing, stale, contradictory, unauthenticated, or unrecognized evidence fails
closed. Evaluation uses deny-overrides semantics: a known class, operation,
resource, flow, circuit, network, isolation, or billing prohibition remains
`deny` even when some other evidence is unknown. Unknown evidence cannot mask a
known hard stop.

Billing restrictions remain mandatory, non-overridable deny rules. ABAC may
consume validated billing-route, capacity, paid-continuation, account, and
circuit evidence, but no lower-precedence policy or approval can waive the
subscription-only invariant.

## Current compatibility map and known gap

The current runtime is deliberately conservative but class-based:

- `PermissionClass` is stored on task, run, routing, profile, evaluation, and
  comparison objects;
- task schemas and contract loading accept only Classes 0 and 1;
- `ApprovalPolicy` and the orchestrator decide executable-now status from the
  class;
- routing compares the task class to the profile maximum and uses numeric
  class headroom in risk ranking;
- harness requests, SQLite constraints, deterministic evaluation, and the
  controlled comparison validate or assume the current class representation;
- current profile roles are routing strings, not authenticated RBAC
  assignments or enforced separation-of-duty constraints.

These are real authority and validation points, not display-only fields. They
must remain in place until a backward-compatible migration and parity tests
prove the new PDP cannot widen behavior.

New profile-backed ordinary Class 1 attempts using the exact built-in
`MockRunner` pass three narrow controller-owned PEPs at task admission,
`runner.execute`, and owner-private local-candidate publication. A schema-v6
attempt binding declares all three chains and commits a bounded canonical task-
intent lineage; frozen schema-v5 declares the same chains without that self-
contained lineage, schema-v4 declares dispatch plus publication, and historical
schema-v3 declares dispatch only. The run
record and private directories created before admission are inert controller
scaffolding. After required selection and binding evidence, the controller
builds a fixed admission CREATE request over the isolated worktree, inherits
the task's full consequence vector, persists its decision, rebuilds from
current authoritative inputs, compares the exact persisted wrapper,
independently replays policy, checks freshness, and requires a durable
succeeded receipt. Class 0, unsafe/high-impact, non-permit, stale, evaluation,
or evidence failures stop before the admission shadow, billing, dispatch, or
`RUNNING`. After admission and required billing evidence, the controller builds
an exact mock-only execute request, evaluates a fixed versioned policy, and
requires exact readback of the selection, task-attempt binding, mock billing
assessment, and decision. Before `RUNNING`, the PEP rebuilds the authorization
from current controller inputs, requires the resolved task intent and digest to
equal the lineage committed by the durable binding,
independently constructs the canonical wrapper for exact comparison with the
retained persisted payload, independently replays the fixed policy, requires
finite current time, a derived class no greater than the persisted run class or
Class 1, exact supported obligations, the independent legacy gate, and the
unchanged shipped controller-owned runner class and instance boundaries. The
`RUNNING` record must then read back
exactly. The PEP repeats the binding, fixed-policy, finite-freshness, and
runner-ownership checks immediately before the call. A linked terminal action
receipt is required once invocation begins, and both it and execution
accounting must read back exactly before publication can proceed; unprovable
receipt persistence after the effect quarantines the attempt.
After a succeeded, accepted, credential-clean mock result, a separate exact
Class 1 CREATE request binds that receipt, accounting, billing disposition, and
candidate metadata. It reuses the schema-v6 lineage, requires equality with the
captured shipped resolver, and independently replays the shipped evaluator and
fixed policy. Its decision and enforcing pre-effect record must read back
exactly. Immediately before staging, the binding, decision, and pre-effect
record read back again; the controller rebuilds the permit and checks a newly
captured post-replay action time for freshness. The existing reconciliation
chain embeds its action receipt. Non-permits and
uncertain decision persistence perform no governed action. Unprofiled
schema-v1, live or historical schema-v2, and historical schema-v3/v4/v5 histories
remain valid under their frozen semantics, and live, comparison, supervisor,
or general-admission paths do not inherit this authority.
The lineage slices advance only current exact-mock attempt bindings to schema v6
and change no enforcing decision-event or action-receipt schema. They grant no
new authority.
For v6, read-only inspection validates the task-intent preimage, source, and
digests from the authoritative binding and never from a shadow; v1-v5 retain
their historical interpretation. The dispatch PEP remains limited to Class 0/1
requests for the exact
profile-backed controller-owned `MockRunner`; new attempts still require the
existing Class 1 admission permit before they can reach dispatch.

The first task contract now distinguishes the owner-private local candidate
action from future active/shared promotion. Independently, the publication
boundary always uses a controller-owned `artifact.publish_local_candidate`
projection so a Class 0 task intent cannot misdescribe an actual local write.
That effect is local, reversible, and bounded, derives at least Class 1, and
inherits task protection, sensitivity, and confidentiality/integrity/
availability impact so higher impact is never relabeled as low;
`required_before_promotion` does not apply to that private candidate write.
New task attempts bind immutable run inputs and the controller-resolved typed
authorization intent before admission. Schema-v6 exact-mock attempts also bind
the strict canonical intent lineage and the separate admission enforcement
coverage before the admission decision and
receipt. Dispatch also binds the persisted
preflight billing assessment, while schema-v2 execution accounting links to the
schema-v5 publication shadow. On schema-v4/v5/v6 exact-mock attempts, schema-v3
pre-effect/action receipts carry the enforcing decision and canonical action
receipt; older paths retain schema-v2 non-enforcing receipts. The shadow never
becomes authority, and the existing Class 0/1 gate remains independently
required.
Policy activation, Git/remote publication, deployment, and other shared effects
remain separate unimplemented typed actions whose exact resource version and
digest must receive fresh authorization and any required approval.

The repository-registration boundary preserves frozen schemas v1 through v3
and adds separate schema v4. Its pure read-only validator dispatches on an exact
integer version and validates a controller-supplied ordinary Git
root, stable repository/filesystem references, exact argv-array (not shell-
text) verification declarations, canonical protected/allowed paths with
mandatory Git and Ordomata state protection, bounded resource limits, a fixed
local-container/network-disabled isolation requirement, and a patch-only
review policy. Traversal and symlink escapes fail closed. The resulting
privacy-bounded evidence contains only bounded digest references, version
metadata, and fixed declarations that validation is read-only, dispatch is
disabled, and no authority is granted. The validator remains a pure PIP
collector: it creates no state and is not a permit. V2 adds bounded, canonical
literal generated/vendor deny roots strictly below allowed paths. Those
declarations are digest-bound but provide no provenance, ignore, authorization,
or enforcement fact. V3 retains the v2 rules and adds controller-supplied
baseline command-result attestations. Every declared command must have exactly
one kind-, identifier-, and command-digest-linked observation under one shared
opaque snapshot digest. Only bounded integer timing and a tagged `exited`,
`signaled`, or `timed_out` termination are accepted; a timeout must carry the
controller-supplied `termination_confirmed: true` assertion. Pass is derived
only from exited zero. No supplied success, output or output hash, environment,
path, message, or arbitrary metadata enters the result block. Its canonical
aggregate binds the repository reference, complete command digest, snapshot,
and declaration-ordered observations.

The baseline block is descriptive PIP input, not authenticated evidence or an
ABAC grant. Validation neither compares the claimed observation times with the
clock nor recomputes the snapshot, resolves an executable/toolchain, or proves
reproducibility. Outward evidence exposes only the aggregate baseline digest and
bounded result count with fixed controller-supplied source,
`baseline_authenticity_verified: false`, and
`baseline_freshness_verified: false`. The snapshot and individual results
remain absent. These facts cannot satisfy
an authorization, freshness, containment, command, execution, or action-receipt
predicate.

Schema v4 adds bounded executable/toolchain identity claims as descriptive PIP
input. Every declared command has exactly one kind-, identifier-, and command-
digest-linked claim carrying opaque executable and toolchain identity digests.
The controller derives a syntax-only declared-executable reference bound to the
exact command context and binds the canonical aggregate to the repository,
complete verification-command set, and exact v3 baseline aggregate. This is
context binding, not provenance: the opaque digests have no standardized or
trusted preimage, and the baseline link proves only co-declaration, not that the
observed process used those bytes. Cross-context transplantation can validate
but changes the aggregate; same-context replay remains indistinguishable.

V4 evidence exposes only the fixed controller-supplied source, aggregate digest,
and bounded count, with authenticity, freshness, resolution, content,
toolchain completeness, and execution correspondence all explicitly false. It
contains no individual identity or declared-executable reference. The v4
identity-block validator adds no PATH, PATHEXT, environment, runtime-cwd,
executable metadata or content, symlink, shebang, interpreter, launcher,
module, plugin, dynamic-loader, package, or version inspection and does not
execute a command. Existing registration root and repository-relative path/
executable safety checks are unchanged. These facts cannot satisfy an ABAC
attribute, authorization, command PEP, action receipt, or Class 2/3 effect;
only Class 0/1 remains enabled.

The separate library-only schema-v1 receipt in
`ordomata.repository_executable_resolution` is a bounded Class 0 PIP
measurement, not a new registration schema or executable PEP. It rejects
schemas v1 through v3 before resolution inspection, freshly revalidates exact
schema v4, and binds the registration, repository, commands, baseline,
schema-v4 opaque-identity aggregate, and resolution context. Under the fixed
`controller_measured` / `posix_nofollow_v1` profile, bare names use only
bounded controller-supplied absolute search directories. Slash-containing
declarations initially require repository-root `cwd: "."`. Pinned directory
descriptors, no-follow descriptor-relative traversal, complete direct-file
hashing, metadata and namespace rechecks, and final registration revalidation
fail closed on symlinks, special or sparse files, missing execute bits, and
detected drift/races. The limits are 64 MiB per unique file and 256 MiB total.

Its outward evidence is aggregate-only and fixes
`sequential_resolution_measurement_complete: true` plus
`atomic_snapshot_verified: false`. The receipt is explicitly a sequential,
point-in-time, non-reusable measurement, not an atomic filesystem snapshot. It
does not verify current freshness, executable
authenticity/provenance, effective invocability, interpreter, launcher,
dependency or environment identity, toolchain completeness, repository-
snapshot or baseline correspondence, or future execution correspondence.
Those false facts cannot satisfy authorization, dispatch, action-receipt,
routing, billing/capacity, or live-run predicates. The API adds no CLI,
persistence, subprocess, execution, or proposal-lineage consumption.

The separate schema-v1
`ordomata.repository_executable_staging.stage_repository_executable_bytes`
boundary is a bounded Class 1 local filesystem primitive, not an authorization
decision or executable PEP. It accepts only an exact typed resolver receipt,
uses fixed `controller_copied` / `posix_unlinked_readonly_v1` staging
semantics, freshly performs the complete resolver measurement, and rereads each unique
source through that same pinned descriptor into immutable process-local
chunks. The expected and action receipts must be canonically identical before
the first filesystem mutation. A complete post-stage resolver pass must then
equal both receipts. This sequential bracketing rejects detected drift while
leaving atomic-snapshot and current-freshness facts false.

The caller supplies a pre-existing exact concrete absolute root that is empty,
owned by the effective user, mode `0700`, no-follow traversable, and lexically
nonoverlapping with every repository and search root; exact-root inode aliases
are rejected, while mount-alias exclusion remains false. The root is dedicated
to one controller process and one lease, without concurrent use. For each
unique file, exclusive creation produces only a random zero-length mode-`0600`
name. The
controller opens its reader and removes and fsyncs that name before writing any
captured byte. It then writes, hashes, fsyncs, sets non-executable mode `0400`,
reads back, and closes the writer. A successful one-shot lease retains only
read-only, close-on-exec descriptors to unlinked inodes. The established bounds
remain 64 MiB per unique file and 256 MiB total.

The staging receipt binds expected/action/post-stage resolution, staging
context, staged-file measurements, and command bindings, while its evidence
exposes only aggregate digests and counts. Cleanup yields `removed`,
`already_absent_verified`, or `unverifiable`; uncertainty retains still-
verified handles for retry and never retries an ambiguously closed descriptor
number. Even verified cleanup does not restore root timestamps or prove secure
erasure. The receipt establishes neither present lease activity nor an ABAC
attribute that can authorize a later consumer.

Accordingly, kernel/filesystem immutability, same-UID exclusion, mount-alias
exclusion, ACL privacy, external-writer absence, atomicity, current freshness,
and future-execution correspondence remain false, as do authority,
authorization, action-receipt,
dispatch, durable control-plane persistence, proposal-lineage, routing,
billing/capacity/circuit, live-eligibility, and execution facts. The caller
remains responsible for separate Class 1 authorization before invocation. No
CLI, state store,
runner, worker, subprocess, harness, or proposal integration exists. Same-UID
adversarial interference is outside V1 protection; the lease must never be
passed to or integrated with an untrusted same-UID worker.

The separate library-only schema-v1
`ordomata.repository_executable_runtime_manifest` boundary is a Class 0 PIP
measurement over that already-established staging effect, not a PEP. Its
`inspect_staged_executable_runtime_manifest(expected_staging, *, lease)` API
accepts only an exact typed staging receipt and its exactly anchored active
`RepositoryExecutableStageLease` in the creating PID. Under fixed
`controller_inspected` / `posix_staged_runtime_header_v1` semantics, it fully
remeasures every private retained descriptor before and after reading at most
4,096 header bytes. The fixed classifier emits only `elf`, `mach_o`,
`posix_shebang`, `unsupported_shebang`, or `unknown`; a valid shebang directive
must be bounded to 255 ASCII bytes. This is byte-level syntax classification,
not interpreter interpretation or resolution.

The immutable runtime-file and command-binding entries contain only digests,
privacy-safe references, classifications, and bounded counts. Outward evidence
is aggregate-only and reports the bounded measurement and staged-byte
correspondence, while current lease activity remains unverified after the
historical inspection. The call opens no path, mutates no lease, and performs
no cleanup. Runtime-manifest and toolchain completeness, effective
invocability, interpreter/launcher/loader/library/module/plugin/package/
environment/dependency identity or closure, source freshness, baseline or
future-execution correspondence, authority, authorization, action-receipt,
dispatch, durable persistence, proposal-lineage, worktree, routing, billing,
capacity, circuit, live-eligibility, and execution facts all remain false. No
CLI, state store, runner, worker, subprocess, or harness integration exists.

The separate library-only schema-v1
`ordomata.repository_executable_shebang_requirements` boundary is another
Class 0 PIP measurement, not a PDP decision or PEP. Its
`inspect_staged_executable_shebang_requirements(expected_runtime, *,
expected_staging, lease)` API accepts only exact typed runtime-manifest and
staging receipts plus the active same-PID lease exactly anchored to the staging
receipt. It freshly reproduces the runtime manifest, requires exact
correspondence with `expected_runtime`, and remeasures the private leased
descriptors while opening no path. Independent frozen staging-v1 and runtime-
manifest-v1 canonical mirrors validate exact lease anchoring and runtime shape
instead of trusting projection helpers. A local frozen-v1 mirror derives
header, shebang/directive-reference, and native ELF/Mach-O classification
rather than dynamically trusting upstream helpers. Every full descriptor
remeasurement recomputes the bounded header length and digest, runtime bindings
must exactly correlate with staging bindings, and the same independent
descriptor proof must repeat after the final runtime reproduction. Under fixed
`controller_inspected` /
`posix_staged_shebang_requirements_v1` semantics, the immutable
`RepositoryExecutableShebangRequirement`,
`RepositoryExecutableShebangRequirementBinding`, and
`RepositoryExecutableShebangRequirementsReceipt` records fix
`native_binary_no_shebang` for ELF/Mach-O, `absolute_interpreter_token` or
`non_absolute_interpreter_token` for a valid POSIX shebang,
`unsupported_shebang`, or `unknown_runtime_format`. In this syntax-only
taxonomy, `absolute_interpreter_token` means only that the first token byte is
`/`; it claims no canonicality, usability, compatibility, or resolution, so
`/`, repeated or trailing slashes, and dot components remain absolute syntax.
A valid private directive is split at the first contiguous ASCII space/tab
boundary run. The whole run
is consumed, only its first byte determines the separator kind, and neither
the run nor the remaining opaque argument tail is interpreted; only digest
references plus bounded byte counts are exposed for the token and tail.

This syntax extraction interprets or resolves no interpreter, `env`, `PATH`,
argument tail, or kernel/launcher semantics. It establishes no interpreter
identity, availability, compatibility, dependency coverage, effective
invocability, or complete runtime/toolchain closure. The Class 0 call neither
mutates nor cleans up the lease and grants no authority or authorization,
enforces no effect, and creates no action receipt, persistence, proposal
lineage, worktree, dispatch, route, billing, capacity, circuit, live
eligibility, CLI/state/runner integration, subprocess, harness, or execution
path. Complete interpreter, dependency, and toolchain closure remains required
before any authorization or operational widening.

The thirteenth bounded Phase 3 slice adds a further Class 0 PIP, not a PDP or
PEP: `ordomata.repository_executable_shebang_target_resolution` exposes
`inspect_staged_executable_shebang_targets(expected_requirements, *,
expected_runtime, expected_staging, lease, expected_target_paths)`. It requires
the exact typed upstream receipts and active same-PID lease, while the
controller supplies the exact used canonical ASCII absolute target paths in
first-use order. Under fixed `controller_measured` /
`posix_absolute_shebang_target_nofollow_v1` semantics, the only successful
dispositions are `native_not_applicable` and
`direct_absolute_target_measured`; a non-absolute, non-canonical,
not-exactly-expected, unsupported, or unknown non-native requirement fails the
whole call. Exact-spelling component walks reject symlinks, and two sequential
full target measurements must produce matching namespace, identity, metadata,
and content results.

The historical receipt and outward evidence expose no raw target paths or
target bytes; they contain only digest/reference fields, bounded command
identifiers/kinds and counts/sizes, fixed classifications/dispositions, and
schema-bounded evidence booleans/metadata. They authorize nothing and do not establish
current freshness or future execution correspondence. An exactly expected
`/usr/bin/env` is measured only as the direct
shebang target; its opaque tail and selected downstream program remain
uninterpreted. Interpreter/launcher/argument semantics, dependencies,
environment and toolchain closure, effective invocability, proposal lineage,
worktree, dispatch, routing, billing, capacity, circuit, live eligibility,
subprocesses, harnesses, and execution all remain absent or false. The call
does not mutate or clean up the lease and issues no action receipt. Two expected
paths selecting the same inode fail, but external hardlink or mount aliases,
same-UID tampering, absence of external writable descriptors, filesystem
immutability, atomicity, and current freshness remain unverified.

The fourteenth bounded Phase 3 slice adds a separate Class 1 local staging
primitive, not a PDP or PEP:
`ordomata.repository_executable_shebang_target_staging` exposes
`stage_repository_executable_shebang_target_bytes`. It requires the exact
expected target-resolution receipt, its complete requirements/runtime/staging
receipt chain, and the exactly anchored active same-PID executable-source
lease. The registration, exact search directories, and expected target paths
are freshly revalidated. Immediately before the first effect, an action-bound
inspection measures and captures each unique target through the same
still-pinned descriptor and must exactly reproduce the expected resolution.
The caller-owned target root must be a dedicated exact concrete absolute,
owner-mode-`0700`, empty directory disjoint from authoritative protected roots
derived from the revalidated registration, exact search directories and
targets, and source staging root.

Each unique script target is staged once through an exclusive no-follow
temporary regular file. Its pathname is unlinked and the target-root directory
is synchronized before target bytes are written; after mode `0400`, file
synchronization, and independent complete readback, the writer closes and only
a non-inheritable `O_RDONLY` descriptor remains. Command correspondence is
exact and ordered. Native-only input produces a zero-file receipt and active
lease without inspecting or mutating the target root. Full post-stage target
resolution must equal expected and action receipts, and the complete upstream
chain and source lease must still validate. The immutable
`RepositoryExecutableShebangTargetStagingReceipt` and outward evidence expose
no raw target paths, target bytes, temporary names, or descriptor numbers. The
`RepositoryExecutableShebangTargetStageLease` retains the caller-supplied root
and private descriptor state process-locally and is not canonical evidence;
explicit cleanup releases only the target lease.

The receipt is evidence of a temporary Class 1 byte-staging effect, not
authority, authorization, or an action receipt. Nothing consumes it for
persistence, proposal/worktree lineage, dispatch, routing, billing, capacity,
circuit, live eligibility, CLI/state/runner integration, subprocess, harness,
or execution. It establishes no interpreter, `env`, `PATH`, argument,
recursive-interpreter, loader, or dependency semantics and no immutability,
same-UID/external-writer or fork exclusion, external-hardlink or mount-alias
exclusion, atomic or current freshness, authenticity or provenance, effective
invocability, crash cleanup, or secure erasure. The implemented authorization
ceiling remains Class 0/1.

The fifteenth bounded Phase 3 slice adds a further Class 0 PIP, not a PDP or
PEP: `ordomata.repository_executable_shebang_target_runtime_manifest` exposes
`inspect_staged_executable_shebang_target_runtime_manifest(
expected_target_staging, *, lease)`. It accepts only the exact target-staging
receipt object and its active same-PID target-stage lease. An independent
frozen schema-v1 mirror validates the target-staging receipt, digest and file-
reference anchors, original receipt and retained-file tuple object anchors,
untouched lifecycle and cleanup state, and stored root context. A used root's
owner-mode-`0700` metadata must reproduce the target-staging context digest
without a path reopen; native-only input must match the fixed no-op context and
retain exact nonempty requirements and command bindings with zero files.

Each mode-`0400`, link-count-zero, non-inheritable `O_RDONLY` target descriptor
is fully remeasured before its bounded header is accepted. The inspector reads
at most 4,096 bytes with `pread`, requires equality with the header captured by
the complete pass, revalidates the exact lease snapshot, and fully remeasures
every descriptor again. It emits immutable target-runtime files,
requirements, bindings, and a manifest receipt under fixed
`controller_inspected` / `posix_staged_shebang_target_runtime_header_v1`
semantics. The five classifications are `elf`, `mach_o`, `posix_shebang`,
`unsupported_shebang`, and `unknown`; direct requirements become
`direct_absolute_target_runtime_inspected`, native requirements remain
`native_not_applicable`, and shared targets are classified once. Canonical
records and aggregate evidence disclose no path, bytes, directive, temporary
name, or descriptor number.

The receipt is historical syntax evidence, not authority, authorization, a
decision, or an action receipt. The call opens no source, target, or staging-
root path, mutates or cleans up no lease, and invokes no model or live harness.
It supplies no recursive shebang, interpreter, `env`, `PATH`, argument,
dependency, loader, environment, runtime, or toolchain semantics; no current
freshness, atomicity, authenticity, provenance, or effective invocability; and
no proposal/worktree lineage, persistence, dispatch, route, billing, capacity,
circuit, live eligibility, CLI/state/runner integration, subprocess, harness,
or execution capability. The implemented authorization ceiling remains Class
0/1.

The sixteenth bounded Phase 3 slice adds another Class 0 PIP, not a PDP or
PEP: `ordomata.repository_executable_shebang_target_requirements` exposes
`inspect_staged_executable_shebang_target_requirements(
expected_target_runtime, *, expected_target_staging, lease)`. It accepts the
exact typed target-runtime manifest and the exact target-staging receipt held
by its active same-PID lease. Frozen independent mirrors validate both
canonical proofs and their complete lineage under `controller_inspected` /
`posix_staged_shebang_target_requirements_v1`. A fresh target-runtime
reproduction from the anchored lease occurs before and after extraction; exact
lease snapshots bracket two independent full descriptor passes, their derived
records must match, and output validation is followed by a closing snapshot and
path-free descriptor identity/metadata/flags anchor check.

One immutable `RepositoryExecutableShebangTargetShebangRequirement` is emitted
per upstream target-runtime requirement and one
`RepositoryExecutableShebangTargetShebangRequirementBinding` per upstream
binding. Each unique target file is parsed once per descriptor pass, so shared
rows reuse its directive/token/tail references while their terminal
requirement references remain distinct and bound to their own upstream
lineage. The fixed dispositions are `native_not_applicable`, `native_binary_no_shebang`,
`absolute_interpreter_token`, `non_absolute_interpreter_token`,
`unsupported_shebang`, and `unknown_runtime_format`; leading `/` is a bounded
syntactic fact only. Native-only chains preserve nonempty requirements and
bindings with zero files and no descriptor reads. `unique_target_count`,
`target_posix_shebang_requirement_count`, `argument_tail_requirement_count`,
`total_interpreter_token_bytes`, and `total_argument_tail_bytes` count unique
target extractions; `requirement_count`, `direct_target_requirement_count`,
and `native_not_applicable_count` count upstream rows, and `command_count`
counts bindings.

`RepositoryExecutableShebangTargetRequirementsReceipt` is historical PIP
syntax evidence only. Canonical data is digest/reference- and bounded-count-
only and outward evidence is aggregate-only; paths, bytes, directives, tokens,
tails, temporary names, and descriptors are absent. Digest equality and length
leakage remain and low-entropy values may be guessable, so no secrecy or
unlinkability is claimed. The call opens no path, changes or cleans up no
lease, and performs no recursive resolution/staging. It verifies no
interpreter/`env`/`PATH`/launcher/argument semantics, dependency or runtime
closure, freshness, atomicity, immutability, alias/writer/fork exclusion,
authenticity, provenance, or invocability. It is not authority, authorization,
a decision, or an action receipt and cannot enter proposal lineage,
persistence, dispatch, routing, billing, capacity, circuit, live eligibility,
CLI/state/runner, subprocess, harness, model, or execution. The Class 0/1
ceiling remains unchanged.

The seventeenth bounded Phase 3 slice adds another Class 0 PIP, not a PDP or
PEP: `ordomata.repository_executable_shebang_nested_target_resolution`
exposes `inspect_staged_executable_shebang_nested_targets(
expected_target_requirements, *, expected_target_runtime,
expected_target_staging, lease, expected_nested_target_paths)`. It requires the
exact staged-target shebang-requirements/runtime/staging receipt chain, the
exactly anchored active same-PID target-stage lease, and a controller-supplied
exact first-use-ordered tuple of canonical ASCII absolute nested-target paths.
That tuple is a closed measurement expectation, not authority or a search
root. The boundary permits exactly one additional hop at fixed depth 2 under
`controller_measured` /
`posix_absolute_shebang_nested_target_nofollow_v1` and
`immediate_target_reentry_v1` controls. Its only successful dispositions are
`source_native_not_applicable`, `target_native_not_applicable`, and
`direct_absolute_nested_target_measured`. Each
unique selected path must match across two exact-spelling, descriptor-relative,
no-follow full measurements and a closing namespace check. A candidate path
reference or measured identity that re-enters the known depth-1 target set is
rejected, as is a candidate directory chain that descends through the anchored
target-stage root. Source-native input has no target files and performs no
descriptor or filesystem-path read; a native depth-1 target is still freshly
reproduced from its staged descriptor but performs no nested-path lookup or
measurement.

Its bounded totals are `requirement_count`, `command_count`,
`nested_target_requirement_count`, `target_native_not_applicable_count`,
`source_native_not_applicable_count`, `unique_nested_target_count`, and
`total_measured_bytes`.

The immutable receipt and aggregate evidence contain only digest/reference
lineage, fixed outcomes, bounded command identifiers, counts, and byte totals.
They disclose no raw path, content, token, temporary name, or descriptor number
and grant no authority. This PIP does not inspect or follow the measured depth-
2 target's own shebang, recurse beyond depth 2, stage bytes, mutate or clean up
a lease, or execute. It establishes no semantic interpreter, `env`, `PATH`,
launcher, or argument resolution; source-chain or generic cycle closure;
broader protected-root closure; dependency/toolchain/loader closure; current
freshness, immutability, authenticity, provenance, or invocability;
authorization, an
action receipt, proposal/worktree lineage, persistence, dispatch, routing,
billing, capacity, circuit, live eligibility, CLI/state/runner, subprocess,
harness, model, or execution capability. The implemented authorization ceiling
remains Class 0/1.

The eighteenth bounded Phase 3 slice adds a separate Class 0 PIP, not a PDP or
PEP: `ordomata.repository_executable_shebang_nested_target_chain_guard`
exposes `inspect_staged_executable_shebang_nested_target_chain_guard(
expected_nested_resolution, *, expected_target_requirements,
expected_target_runtime, expected_target_staging, target_lease,
expected_source_staging, source_lease, expected_nested_target_paths)`. It
requires the exact expected nested-resolution receipt and path expectation,
the exact staged-target requirements/runtime/staging receipt chain and active
same-PID target lease, and the exact source-staging receipt and active same-PID
source lease. These inputs are PIP evidence and process-local proof anchors,
not authority. Fixed `controller_inspected` /
`known_source_chain_identity_and_staging_root_identity_v1` semantics freshly
reproduce the depth-2 nested resolution while an identity guard remains active
inside every measurement and namespace check.

The exact known-source set contains the original and detached staged identity
of every source executable; the exact known-target set contains the original
and detached staged identity of every direct shebang target. The source-stage
root and, when used, target-stage root form a separate protected identity set.
A no-follow walk rejects any protected root identity at any directory
component and rejects any known source/target identity before leaf bytes are
read, with the same exclusions on reopen and closing namespace validation.
Source and target
lease snapshots are required before and after receipt construction; the final
guarded reproduction checks target descriptor anchors, re-anchors the source
lease, and then performs its final guarded namespace validation. Fixed dispositions are
`source_native_not_applicable`,
`target_native_not_applicable`, and `known_chain_guard_verified`. Native-only
input preserves the exact requirement/binding lineage with zero guarded
measurements and no nested-target or staging-root path lookup.

`RepositoryExecutableShebangNestedTargetChainGuardReceipt` contains exact
`RepositoryExecutableShebangNestedTargetChainGuardedMeasurement`,
`RepositoryExecutableShebangNestedTargetChainGuardRequirement`, and
`RepositoryExecutableShebangNestedTargetChainGuardBinding` records. They are
digest/reference-, identity-set-digest-, bounded-count-, and byte-total-only
and expose no path, content, device/inode number, temporary name, or
descriptor. Its deterministic unkeyed `guard_summary_ref` establishes only
internal digest/count/byte-total consistency; receipt authenticity remains
explicitly unverified. This narrow PIP verifies
only known original/staged source and target identity re-entry exclusion and
the one or two staging-root identities present. It does not verify a source
path or staging-root path, generic cycle closure, or broader protected-root closure;
perform staging, a write, cleanup, or lease mutation; or grant authority,
authorization, an action receipt, proposal/worktree lineage, persistence,
dispatch, routing, billing, capacity, circuit, live eligibility, CLI/state/
runner, subprocess, harness, model, or execution capability. The seventeenth
resolver remains a separate narrower PIP. The nineteenth slice freshly
consumes this evidence at its own separate Class 1 effect boundary; neither
the guard nor its exact result becomes authority.

The nineteenth bounded Phase 3 slice adds a separate Class 1 local staging
primitive, not a PDP or PEP:
`ordomata.repository_executable_shebang_nested_target_staging` exposes
`stage_repository_executable_shebang_nested_target_bytes(
registration, *, search_directories, expected_chain_guard,
expected_nested_resolution, expected_target_requirements,
expected_target_runtime, expected_target_staging, target_lease,
expected_source_staging, source_lease, expected_nested_target_paths, lease)`.
It requires the exact nested-resolution and known-chain-guard receipts, exact
active same-PID source- and target-stage receipt/lease lineages, the exact
nested-target path expectation, a freshly revalidated schema-v4 registration
and search context,
and a new caller-owned nested-target stage lease. Fixed `controller_copied` /
`posix_shebang_nested_target_unlinked_readonly_v1` semantics replay the private
guard at the action boundary and capture every unique depth-2 target through
the same still-pinned guarded descriptor used for measurement. The action
guard must exactly reproduce the expected guard; a complete post-stage guard
replay must reproduce both. These are PIP evidence checks around a local
effect, not an authorization decision or reusable permit.
Only the first guarded action measurement invokes the capture sink; its later
measurement, closing reproduction, and the post-stage replay are consumer-free.
Capture is capped at 80 unique targets, 64 MiB per target, and 256 MiB total;
the receipt admits at most 80 requirements and 80 command bindings.

The caller-owned staging root must be exact, concrete, absolute,
effective-user-owned, mode `0700`, empty, and path- and identity-disjoint from
the freshly pinned repository/search roots, active source/target stage roots,
and expected nested targets and their ancestors. Each unique nested target is
copied once through an exclusive no-follow temporary regular file. Its name is
unlinked and its directory synchronized before captured bytes are written;
mode `0400`, synchronization, independent complete readback, writer closure,
and retention only by a non-inheritable `O_RDONLY` descriptor follow. Exact
ordered requirement and command lineage is preserved for shared targets.
Source-native and target-native inputs create an active zero-file lease without
inspecting or mutating the nested staging root.

`RepositoryExecutableShebangNestedTargetStagingReceipt` carries exact staged-
file, stage-requirement, and stage-binding records and binds expected, action,
and post-stage guard digests, upstream receipt and identity-set lineage, the
staging context, and bounded counts and byte totals. Canonical records and
aggregate evidence disclose no raw path, content, identity number, temporary
name, or descriptor. Digest equality and bounded sizes remain visible and can
be guessable, so secrecy and unlinkability are not claimed. The process-local
`RepositoryExecutableShebangNestedTargetStageLease` is same-PID, one-shot,
noncopyable, nonserializable, and not canonical evidence.
Explicit `cleanup_repository_executable_shebang_nested_target_stage` is
idempotent, emits bounded `removed`, `already_absent_verified`, or
`unverifiable` cleanup evidence, and fails closed on uncertainty; it never
claims staging-root metadata restoration or secure erasure.

The receipt records a temporary Class 1 local byte copy, not authority,
authorization, or a PEP action receipt. No persistence, proposal/worktree
lineage, dispatch, routing, billing, capacity, circuit, live eligibility,
worker, CLI/state/runner, subprocess, harness, model, or execution capability
is added. Copied bytes are not parsed or followed and no recursion beyond depth 2,
interpreter/`env`/`PATH`/launcher/argument semantics, dependency/loader/
runtime/toolchain closure, generic original-source-path or staging-root-path-
domain exclusion beyond the explicit disjointness above, generic cycle or
broader protected-root closure, freshness, immutability, authenticity,
atomicity, provenance, invocability, same-UID/external-writer/fork/hardlink/
mount-alias exclusion, crash cleanup, or secure erasure is established. The current Class
0/1 ceiling is unchanged.

The twentieth bounded Phase 3 slice adds a separate Class 0 PIP, not a PDP or
PEP: `ordomata.repository_executable_shebang_nested_target_runtime_manifest`.
Its `inspect_staged_executable_shebang_nested_target_runtime_manifest(
expected_nested_target_staging, *, lease)` boundary requires the exact nested-
stage receipt anchored by an active same-PID lease and independently validates
the immutable receipt/object anchors, retained-file tuple, stored root context,
and every detached mode-`0400`, link-count-zero, non-inheritable `O_RDONLY`
descriptor. It opens no path and performs no lease mutation or cleanup.

The PIP fully rehashes each retained descriptor around a separate bounded
at-most-4,096-byte header read and then requires a closing active-lease
snapshot. Its fixed ELF, Mach-O, POSIX-shebang, unsupported-shebang, and unknown
classifications are descriptive attributes only. A valid bounded ASCII
directive is exposed only as a digest reference. Exact runtime-file,
requirement, and binding records retain the complete nested-staging and known-
chain lineage; source-native and target-native cases return zero files without
reading a descriptor.

Neither a clean receipt nor its Class 0 evidence grants authority, satisfies
fresh authorization, or becomes an action receipt. Raw paths, headers, content,
identity numbers, temporary names, and descriptors remain absent from canonical
evidence. The boundary adds no write, persistence, proposal/worktree, dispatch,
route, billing, live, network, worker, subprocess, harness, model, or execution
capability and establishes no recursive interpreter or dependency semantics,
immutability, authenticity, provenance, invocability, containment, or future-
action correspondence. The current Class 0/1 ceiling is unchanged.

The twenty-first bounded Phase 3 slice adds another separate Class 0 PIP, not
a PDP or PEP:
`ordomata.repository_executable_shebang_nested_target_requirements`. It accepts
only the exact nested-target runtime/staging receipts and their active same-PID
lease, checks complete correspondence, reproduces runtime evidence before and
after extraction, independently remeasures retained descriptors twice, and
requires closing lease and descriptor anchors.

Its fixed syntax attributes distinguish source-/target-native no-ops, native
binaries, absolute and non-absolute tokens, unsupported shebangs, and unknown
formats. Token and opaque argument-tail bytes become only digest references,
bounded byte counts, a separator kind, and an absolute-token boolean. Shared
targets preserve distinct complete lineage; native-only input performs no
descriptor read. These remain untrusted descriptive attributes until a future
PDP evaluates them under fresh policy.

The receipt grants no authority and is neither authorization nor an action
receipt. It exposes no raw path/header/content/token/tail/identity/descriptor,
performs no path or environment lookup, and adds no recursion beyond depth 2,
write, cleanup, persistence, proposal/worktree, dispatch, route, billing,
network, worker, subprocess, harness, model, or execution capability. Complete
interpreter, launcher, argument, dependency/toolchain, containment, and future-
action semantics remain deferred. The current Class 0/1 ceiling is unchanged.

The twenty-second bounded Phase 3 slice adds another separate Class 0 PIP, not
a PDP or PEP: `ordomata.repository_executable_native_loader_requirements`.
Its inspector accepts only exact direct-executable runtime/staging receipts
and their active same-PID lease, verifies complete lineage, reproduces the
runtime manifest before and after extraction, brackets bounded parsing with
full descriptor remeasurement, and requires exact closing lease anchors.

Only direct declaration syntax becomes an attribute: ELF32/ELF64
`PT_INTERP`, or thin Mach-O32/Mach-O64 `LC_LOAD_DYLINKER`. Supported records
carry fixed format, byte-order, image-kind, declared/absent, path-length, and
canonical-absolute-path facts plus a digest-only path reference. Fat Mach-O,
duplicate, malformed, or out-of-scope layouts collapse to a fixed unsupported
outcome; non-native files receive a fixed not-applicable outcome. These remain
untrusted descriptive attributes until a future PDP evaluates exact current
facts under policy.

The receipt grants no authority and is neither authorization nor an action
receipt. It exposes no raw path/header/content/identity/descriptor, performs
no path or loader resolution, shared-library traversal, dependency closure, or
fat-binary architecture selection, and adds no write, cleanup, persistence,
proposal/worktree, dispatch, route, billing, live, network, worker,
subprocess, harness, model, or execution capability. Loader identity,
runtime/toolchain completeness, containment, and future-action semantics
remain deferred. The current Class 0/1 ceiling is unchanged.

The twenty-third bounded Phase 3 slice adds another separate Class 0 PIP, not
a PDP or PEP:
`ordomata.repository_executable_native_loader_target_resolution`. Its
inspector requires the exact loader-requirements/runtime/staging evidence and
active same-PID lease plus an exact ordered unique canonical path expectation.
Each expected path must cryptographically reproduce its precise upstream
`PT_INTERP`/`LC_LOAD_DYLINKER` digest reference before the path is read.
Requirements with absent, unsupported/fat, or non-native outcomes cannot bind
a target path.

The PIP measures each unique matched file twice through exact-spelling no-
follow traversal, rejects aliases and drift, then emits only digest-bound path,
filesystem identity, metadata, content, requirement, and command attributes.
Raw target paths and bytes are absent, while deterministic digests remain
correlatable and potentially guessable. Those attributes describe one
historical point in time; a future PDP must still evaluate freshness,
sensitivity, authority, containment, and intended use for a concrete action.

Neither a matched path nor a clean receipt authorizes a loader or verifies its
authenticity. The boundary is not an action receipt and performs no shared-
library/dependency closure, architecture selection, staging, write, cleanup,
persistence, proposal/worktree, dispatch, routing, billing, network, worker,
subprocess, harness, model, loader invocation, or execution. Runtime/toolchain
completeness and future-action semantics remain deferred. The current Class
0/1 ceiling is unchanged.

The twenty-fourth bounded Phase 3 slice adds a separate Class 1 local-draft
primitive, not a PDP or PEP:
`ordomata.repository_executable_native_loader_target_staging`. A caller that
already holds suitable Class 1 authority must provide the exact loader-target
resolution chain and paths, active source lease, revalidated schema-v4
registration/search context, disjoint empty owner-controlled mode-0700 staging
root, and fresh caller-scoped target lease. None of those inputs grants or
derives authority inside the primitive.

The primitive copies each unique target only through the same pinned descriptor
used by a fresh action-bound measurement. After synchronized write, full
readback, mode reduction, and unlink, the controller retains a non-inheritable
read-only descriptor and replays the complete target-resolution and protected-
root checks. The resulting digest-only receipt binds expected, action, and
post-stage evidence plus every requirement and command. A no-target outcome
creates an active empty lease without touching the candidate root. Explicit
idempotent cleanup issues bounded evidence and treats any unproved namespace or
descriptor release as cleanup uncertainty.

These are historical Class 1 copy facts, not loader authenticity, authorization
for another action, a PEP action receipt, immutability, dependency closure, or
future freshness. Raw paths and bytes remain private, while deterministic
digests can still be correlated or guessed. Same-UID writers, external
descriptors, hardlink/mount aliases, fork/crash cleanup, and secure erasure are
not excluded. No architecture selection, loader parsing or invocation, shared-
library traversal, persistence, dispatch, routing, billing, network, worker,
subprocess, model, or execution authority is introduced. The current Class
0/1 ceiling is unchanged.

The separate second slice records that PIP evidence for a dispatch-disabled
repository proposal. The controller API
`ordomata.repository_proposal.bind_repository_proposal_attempt` freshly
revalidates one registration, requires an explicit canonical
`proposal_digest`, and accepts only an existing immutable Class 0/1
`repository-proposal-disabled` run that remains exactly `CREATED`, then exactly
reads back one content-addressed, statusless
`repository_registration_selection` event followed by one content-addressed,
statusless `repository_proposal_attempt_binding` event. The first records the
controller-owned selection; the second links its evidence and component digests
plus the proposal digest to privacy-safe references for immutable proposal-
attempt facts. Each append atomically requires current status `CREATED` and the
exact ordered predecessor event IDs; no raw proposal content is stored. Commit
failure rolls back before reconciliation, and final proof uses one consistent
SQLite snapshot. The selection itself commits the proposal digest, and the
binding repeats it so a selection-only recovery cannot change proposal content.
Both fix `validation_mode: "read_only"`,
`dispatch_enabled: false`, and `authority_granted: false` semantics.

These records are PIP provenance only. In particular,
`repository_proposal_attempt_binding` is not the authoritative
`task_attempt_authorization_binding`, does not contain or imply a PDP decision,
and establishes no task-admission, execute, publication, command, or tool PEP.
Exact durable readback proves only that the local evidence was stored as
expected; it is not an action receipt or grant. The evidence layer adds no
SQLite migration, run creation or status transition, worktree, Git/command/
process invocation, worker or supervisor dispatch, route/profile selection,
billing/capacity/circuit fact, harness call, or live eligibility. The frozen
registration schema-v1 evidence meaning remains the only version accepted by
this proposal chain. Schema-v2 through schema-v4 registrations fail before any
event append. The separate direct-executable resolution, staging, runtime-
manifest, shebang-requirements, and shebang-target-resolution receipts are not
proposal evidence and do not widen this chain.
Complete interpreter, dependency, and runtime/toolchain closure plus execution
receipts remain deferred.

The third slice is the library-only `ordomata.repository_proposal_inspection`
API `inspect_repository_proposal_evidence(database_path, *, run_id)`. It
returns a privacy-bounded `RepositoryProposalInspectionReport` with fixed
`inspection_scope: "single_run"`, `run_ref`, permission class, current status,
`clean`, `coverage`, `truncated`, capped event count, optional independently
validated proposal/registration/repository references and version, optional
selection/binding digests and sequences, and bounded fixed-code
`RepositoryProposalInspectionFinding` objects. Incomplete coverage is limited
to an exact protocol-recoverable `CREATED`-only or
`CREATED`-plus-selection evidence prefix. The
mapping also fixes read-only inspection/validation, no repair, disabled
dispatch, and no granted authority, and reports `evidence_complete` and finding
count. Complete coverage requires the exact clean three-event chain; every other
history is invalid. A clean result is complete, untruncated, and finding-free.
More than four events sets `truncated` because the capped inspection cannot
cover the history.
This is proof about one caller-named run, not whole-database coverage.

The inspector independently replays the durable run, event/payload digests,
cardinality/order, proposal and registration-component links, and fixed Class
0/1, runner, `CREATED`, read-only, dispatch-disabled, and no-authority facts
from one read-only, query-only SQLite snapshot. The exact signed main file and
optional WAL are staged into owner-private temporary storage under a fixed
controller-owned 512 MiB combined ceiling; oversized state fails before copy.
A no-WAL snapshot opens through an immutable read-only URI, while an in-budget
WAL pair opens read-only. SQLite opens only the staged identity, and
before/after source signatures detect concurrent changes. The inspector never
instantiates `SQLiteStateStore`, creates source schema or sidecars, repairs
evidence, or revalidates the registration against the live filesystem. Fixed
findings and errors expose no raw identifiers, SQLite diagnostics, paths, argv,
registration documents, proposal content, workspace/run-directory values, or
artifact content. A clean report is PIP integrity evidence only: it is not a
PDP decision, permit, obligation result, PEP, pre-effect record, action receipt,
external tamper anchor, or authority grant.

Inspection creates no source database/schema/sidecar or migration and persists
no run, status, event, or authorization evidence. It creates no worktree and
performs no Git/command/process invocation, worker or supervisor dispatch,
route/profile selection, billing/capacity/circuit change, harness/network
action, or live eligibility.

The fourth slice is the controller-owned, library-only
`ordomata.repository_proposal_admission` ABAC shadow. Its public evaluator
accepts only a durable database path, caller-named run, and controller
evaluation time and freshly calls the independent inspector. It accepts no
caller-supplied report, permission class, authorization request, policy, or
evaluator. Only a clean, evidence-complete, complete, untruncated,
finding-free exact three-event Class 0/1 inspection reaches the PDP shadow.
Every nonclean inspection is `not_evaluated` with no request, policy, or
decision, an `indeterminate` effect, and the fixed
`inspection_not_clean_complete` reason. Run-binding, evaluation, and exact
replay failures are also inert failed/indeterminate results.

The PIP-to-PDP projection is closed. Class 0 becomes the exact local `READ`
observation and its fixed read-only operation, resource type, class-specific
policy, and unenforced audit-receipt plus read-only obligations. Class 1 becomes
the exact local `CREATE` nomination and its fixed local-draft operation,
resource type, class-specific policy, and unenforced audit-receipt plus
isolated-local-only obligations. Each policy enables only its one projected
class and the controller role, local control-plane trust boundary, disabled
network, and local non-AI route. The request binds a canonical digest of the
privacy-safe inspection mapping and the validated proposal, registration,
repository, selection, and binding lineage. Both the active shadow evaluator
and a captured built-in replay must equal the controller's exact expected
decision.

A matching shadow `permit` and `shadow_eligible` value are observational only,
not authorization or a PEP input. The mapping fixes authoritative decision,
enforcement, authority, admission/action, receipt, evidence-persistence,
repair, dispatch, route, billing, and obligation-enforcement facts to false.
The API has no CLI and persists nothing; it creates no source state, event,
durable decision or receipt, worktree, Git/command/process invocation, worker
or supervisor dispatch, profile selection, billing/capacity/circuit fact,
harness/network action, or live eligibility. It binds no raw repository path
or identifier, argv, registration/proposal content, workspace/run-directory
value, SQLite diagnostic, or artifact content.

The separate fifth slice is the library-only
`ordomata.repository_proposal_admission_verification` API
`verify_repository_proposal_admission_shadow_mapping(value)`. It accepts only
an exact built-in `dict`, snapshots it through bounded detached JSON, and
independently mirrors the inspection contract. Evaluated inputs replay the
class-specific Class 0/1 request/policy, manual expected decision, and captured
evaluator; inert inputs must match an exact state-machine branch, and a reported
replay failure must retain a constructible replay boundary. Fixed, value-free
findings describe mismatches. `contract_valid` is only an internal-
consistency result, not authenticity, durable reinspection or source truth,
current freshness, authority, or a PIP/PDP/PEP decision. A coherent forgery or
replay cannot be distinguished without a trusted anchor. The verifier persists
or repairs nothing, enforces or authorizes nothing, and creates no worker,
repository, command, route, billing, network, harness, dispatch, or live effect.

The sixth bounded Phase 3 slice adds a separate repository-registration
schema-v2 contract. It requires bounded `generated_paths` and
`vendor_paths` arrays as canonical literal deny/classification roots strictly
beneath allowed paths. They cannot overlap one another, protected or sensitive
paths, or case aliases, and they reject traversal, glob/expansion syntax,
symlinks, and special files. Missing leaves are accepted without creation.
Nonempty categories are digest-bound but raw paths remain absent from evidence.
The declarations provide no generation/provenance attestation, do not suppress
diff or protected-path review, and establish no ABAC attribute, authority, or
effect. Schema v1 remains frozen and proposal evidence remains v1-only.

The seventh bounded Phase 3 slice adds the separate schema-v3 baseline contract
described above. It establishes no authenticated source, current freshness,
ABAC attribute, permission, execution fact, or effect. Schemas v1 and v2 retain
their exact canonical and evidence meanings, and proposal evidence remains
v1-only.

The eighth bounded Phase 3 slice adds the schema-v4 opaque executable/toolchain
identity-claim contract described above. It establishes no authenticated
identity, current freshness, resolution, content, complete toolchain,
execution fact, ABAC attribute, permission, or effect. Frozen schemas v1
through v3 retain their exact canonical and evidence meanings, and proposal
evidence remains v1-only.

The ninth bounded Phase 3 slice adds the separate schema-v1 direct-executable
receipt described above. Exact schema-v4 revalidation and bounded descriptor-
based measurement establish only a point-in-time direct-file observation.
Aggregate evidence grants no ABAC attribute, permission, dispatch, action
receipt, persistence, route, billing, live eligibility, or execution effect;
proposal lineage remains v1-only. The separate tenth slice supplies bounded
action-boundary capture and staging; complete interpreter/dependency manifests
and execution remain future boundaries.

The tenth bounded Phase 3 slice adds the separate executable-staging contract
described above. It establishes a temporary Class 1 read-only descriptor lease
only after exact expected/action/post-stage resolver correspondence. It is not
a PDP decision, PEP enforcement receipt, authority envelope, proposal-lineage
input, or executable action. Durable control-plane persistence, routing,
billing, live eligibility, CLI/state/runner integration, and execution remain
absent.

The eleventh bounded Phase 3 slice adds the separate schema-v1 staged-
executable runtime-manifest PIP described above. It accepts only an active
same-PID lease exactly anchored to the expected staging receipt, fully
remeasures each descriptor, and classifies at most 4,096 header bytes as ELF,
Mach-O, bounded ASCII shebang, unsupported shebang, or unknown. Its digest/
reference-only receipt and aggregate evidence establish no complete manifest,
invocability, interpreter or dependency/runtime closure, authority,
authorization, action receipt, proposal/worktree integration, dispatch,
routing, billing, live eligibility, or execution. The Class 0 call neither
mutates nor cleans up the lease and adds no CLI/state/runner path.

The twelfth bounded Phase 3 slice adds the separate schema-v1 staged-executable
shebang-requirements PIP described above. Exact typed runtime and staging
receipts plus their active same-PID anchored lease are mandatory. Fresh
runtime-manifest reproduction and descriptor remeasurement fix
`native_binary_no_shebang`, `absolute_interpreter_token`,
`non_absolute_interpreter_token`, `unsupported_shebang`, or
`unknown_runtime_format` as appropriate; a valid POSIX shebang yields only
digest-referenced interpreter-token and opaque argument-tail requirements
split at the first contiguous ASCII space/tab boundary run. Only the run's
first byte determines the separator kind, and neither the run nor tail is
interpreted. The Class 0 call opens no path,
mutates or cleans up no lease, resolves or interprets no interpreter, `env`,
`PATH`, arguments, or kernel semantics, and supplies no authority,
authorization, action receipt, persistence, proposal/worktree integration,
dispatch, route, billing, live eligibility, CLI/state/runner path, subprocess,
harness, or execution. Complete interpreter/dependency/toolchain closure
remains mandatory before widening.

The thirteenth bounded Phase 3 slice adds the separate schema-v1 direct
shebang-target measurement PIP described above. Exact upstream receipts, the
active lease, and the complete first-use target-path expectation are mandatory.
Native entries are not applicable; each script target must match across two
sequential full measurements and final exact-namespace revalidation. The
raw-path/raw-byte-free historical receipt is not a PDP decision or PEP receipt,
grants no authority, extends no proposal lineage, and cannot support routing,
live eligibility, subprocess creation, or execution.

The fourteenth bounded Phase 3 slice adds the separate schema-v1 direct
shebang-target staging lease described above. Its exact expected/action/post-
stage resolution chain, active upstream correspondence, same-descriptor
capture, and dedicated protected-root contract produce only unlinked mode-
`0400` read-only descriptors; native-only input is a zero-file no-op. It is a
Class 1 local effect, not authorization or a PEP action receipt, and grants no
proposal, route, billing, live, subprocess, harness, or execution capability.

The fifteenth bounded Phase 3 slice adds the separate schema-v1 staged
shebang-target runtime-header PIP described above. It validates the exact
active target-stage receipt, object anchors and stored root context without
opening a path, fully remeasures retained descriptors around an at-most-4,096-
byte five-way classification, and preserves native-only zero-file requirement
and command correspondence. The Class 0 result is not a PDP decision or PEP
receipt and grants no proposal, route, billing, live, subprocess, harness,
model, or execution capability.

The sixteenth bounded Phase 3 slice adds the staged-target shebang-
requirements PIP described above. Independent target-runtime reproduction,
two matching full descriptor passes, and closing lease snapshots yield one
lineage-distinct row and binding per upstream target-runtime requirement while
parsing each shared target once per pass. Native-only input is zero-file and
zero-read. The digest-only Class 0 result is not a PDP decision or PEP receipt and
grants no recursive resolution, staging, proposal, route, billing, live,
subprocess, harness, model, or execution capability.

The seventeenth bounded Phase 3 slice adds the nested shebang-target resolution
PIP described above. It requires the exact active target-stage proof chain and
exact ordered absolute depth-2 paths, then requires two matching no-follow
measurements and a closing namespace check. Immediate depth-1 path/identity
re-entry and target-stage-root descent fail closed. Source-native input is
zero-file and zero-read; a native depth-1 target still validates its staged
descriptor but performs no nested-path read. The privacy-bounded Class 0 result
contains digest/reference lineage, fixed outcomes, bounded command
identifiers, counts, and byte totals; it stops after one additional hop, is
neither a PDP decision nor PEP receipt, and grants no broader cycle/protected-
root closure, staging, proposal, route, billing, live, subprocess, harness,
model, or execution capability.

The eighteenth bounded Phase 3 slice adds the nested-target known-chain guard
PIP described above. Exact active source- and target-stage lineages anchor
original and staged source/target identities and the one or two staging-root
identities present while the expected depth-2 measurement is freshly
reproduced.
Those exclusions apply before candidate reads and through closing namespace
validation. Native-only input performs no nested-target or root-path lookup.
The privacy-bounded Class 0 result is neither a PDP decision nor PEP receipt
and grants no source-path/root-path, generic-cycle, broader-protected-root,
staging, write, route, live, subprocess, harness, model, or execution
capability. The seventeenth PIP and public guard are unchanged.

The nineteenth bounded Phase 3 slice adds the nested-target Class 1 staging
primitive described above. It requires exact guarded same-descriptor capture,
active source/target lease lineage, a protected owner-private root, unlinked
mode-`0400` read-only descriptors, and matching action/post-stage guard
replays. Native-only input is a zero-file, no-root-touch no-op. Its privacy-
bounded receipt and fail-closed cleanup evidence are neither a PDP decision nor
a PEP receipt and grant no proposal, route, billing, live, subprocess, harness,
model, or execution capability.

The twentieth slice adds the matching Class 0 nested-target runtime-header PIP.
Its exact active-lease remeasurement and privacy-bounded classification receipt
remain descriptive evidence, not a PDP decision or PEP receipt, and grant no
route, worker, subprocess, harness, model, or execution capability.

The twenty-first slice adds the matching Class 0 nested-target shebang-
requirements PIP. Its digest-only token/tail syntax is descriptive evidence,
not a PDP decision or PEP receipt, and grants no resolution or execution
authority.

The twenty-second slice adds the matching Class 0 direct native-loader
declaration PIP. Digest-only `PT_INTERP`/`LC_LOAD_DYLINKER` syntax is
descriptive evidence, not a PDP decision or PEP receipt, and grants no loader,
dependency, shared-library, or execution authority.

The twenty-third slice adds the matching Class 0 declaration-bound loader-
target measurement PIP. Its exact no-follow file facts remain descriptive
evidence, not a PDP decision or PEP receipt, and grant no loader, dependency,
shared-library, or execution authority.

The twenty-fourth slice adds matching Class 1 native-loader target staging.
Its same-descriptor unlinked read-only copies and cleanup facts remain local-
draft evidence, not a PDP decision or PEP action receipt, and grant no loader,
dependency, shared-library, or execution authority.

The durable supervisor now also records non-enforcing controller-bookkeeping
shadows for mock-flow admission and claim, operator control transitions, and
sticky cancellation. Control requests bind the exact previous control revision;
cancellation requests bind the exact source flow revision and the deterministic
local writes that follow, including whether a completion intent is appended.
These bookkeeping projections grant no worker, network, repository, or
external authority. Control transitions are reversible local changes and
currently derive Class 1. Cancellation is irreversible on the original flow;
explicitly admitting a replacement is compensation, not reversal, so it
conservatively derives Class 3. Current policy denies it and the audit reports
the resulting legacy-execution parity mismatch. The existing operator safety
path remains unchanged because these shadows are non-authoritative. Storage
can retain the denied Class 3 evidence, but current policy still enables only
Classes 0/1.

## Canonical request

The canonical request contract is JSON with a stable digest and these typed
groups. Phase 1C implements these groups as immutable standard-library value
types. The Chief-of-Staff contract supplies typed task-effect intent for
non-enforcing admission and dispatch observations, while the controller
supplies the exact local-create intent at publication. For the narrow
profile-backed built-in-mock path, the controller additionally constructs
separate exact admission CREATE, execute, and local-candidate CREATE requests
at their respective boundaries. The admission projection inherits the full
task consequence vector so unsafe intent cannot be relabeled as harmless
controller bookkeeping.

Controlled comparison trials use a distinct controller projection for the
Class 0 effect of reading and evaluating one immutable comparison snapshot. A
schema-v2 digest-only event binds each trial's plan, controls, profile
configuration, runner settings, and billing assessment before schema-v3
admission and dispatch shadows are recorded. The owner-private review artifact
is deliberately not folded into that Class 0 projection: it remains a separate
Class 1 controller effect with a schema-v4 non-enforcing publication shadow and
linked schema-v2 pre-effect/action-receipt evidence. Historical schema-v1
comparison records retain their original partial-coverage meaning. The newer
publication chain also binds its billing-disposition digest to independently
recomputed, sanitized execution-accounting source facts.

- `subject`: operator principal, controller instance, agent session, assigned
  role and role version, execution profile, runner, and authenticated
  harness/account evidence references;
- `action`: typed verb (`read`, `create`, `modify`, `execute`, `delete`, `send`,
  `approve`, or a narrower registered verb), tool or command identity, exact
  parameter/input digest, and intended effect;
- `resource`: canonical type and identifier, path or external object, version
  or content digest, owner, repository registration, protected status,
  sensitivity, and trust boundary;
- `environment`: time, flow state, isolation attestation, network mode,
  billing route and capacity, approval receipts, lease/concurrency state, and
  circuit state;
- `consequences`: confidentiality, integrity, and availability impact
  (`low`, `moderate`, or `high`) plus local/shared/external reach,
  destructiveness, reversibility, sensitivity, and blast radius.

Model-reported attributes, requested roles, requested permission classes, and
tool annotations are untrusted claims until the controller establishes the
effective value from an authoritative source.

## Canonical decision and action receipt

The canonical decision is immutable before enforcement and contains the fields
below. Phase 1C implements the value type, non-authoritative Chief-of-Staff
shadow events, and narrow enforcing decisions for profile-backed built-in-mock
Class 1 admission, dispatch, and owner-private candidate publication. Those
enforcing records are distinct from admission, dispatch-intent, and
publication shadows. Historical ordinary and all controlled-comparison
publication receipts remain non-enforcing; schema-v4 carries dispatch plus
publication permits, schema-v5 adds the admission permit and receipt, and
schema-v6 adds authoritative task-intent lineage without adding a permit:

- decision, request, and policy identifiers and digests;
- an effect, fixed reason codes, and matched rule identifiers;
- evidence references and attribute source/freshness metadata;
- issue and expiry times;
- enforceable obligations such as an isolation backend, no-network mode,
  allowed paths, exact argv, attempt ceiling, fresh independent review,
  approval requirements, audit receipt, or quarantine;
- a conservatively derived Class 0-3 summary for display and compatibility.

A separate append-only action receipt links to the decision and records the
exact enforced object, obligation checks, outcome, resulting artifact or state
transition, and completion time. A receipt never mutates or retroactively
changes the decision that preceded it.

The effect vocabulary is:

- `permit`: the exact action may execute while the decision is current and all
  recorded obligations still hold;
- `defer`: one or more explicitly identified, satisfiable approvals or
  prerequisites are missing, so the workflow may enter a durable waiting
  state;
- `deny`: policy prohibits the action, and a generic approval cannot convert
  it into a permit; and
- `indeterminate`: evidence is missing, stale, contradictory, unrecognized, or
  evaluation failed. It fails closed and cannot be converted into approval.

A decision is immutable. Satisfying a `defer` condition creates a fresh
request and decision bound to the approval, current evidence, resource and
context versions, and policy digest; it never rewrites the deferred decision.

## Standing envelopes and high-impact actions

Class 3 describes consequence, not an automatic target-state prohibition. A
versioned, operator-approved standing authorization envelope is the normal
target path for repeatable high-impact actions. An envelope may remain valid
until explicitly revoked or automatically invalidated, but it is not ambient
authority: every concrete action still requires a fresh, short-lived ABAC
permit for the exact subject, target, parameters, resource version, context,
and current environment.

An envelope defines exact action and target allowlists plus rate, concurrency,
monetary, sensitivity, and blast-radius ceilings. It also defines preflight,
verification, idempotency, rollback or compensating-action requirements, and
circuit conditions. A request outside the envelope returns `defer` only when a
specific permissible approval or policy choice can satisfy it; otherwise it
is denied or indeterminate as appropriate. Material changes to identity,
policy, target registration, tool manifest, isolation, billing, circuit state,
or failure budget invalidate or suspend the envelope automatically.

Inherently irreversible actions such as sending, publishing, or deletion
without guaranteed restoration may be eligible only under an action-specific
envelope with exact targets, strict rate and blast-radius limits,
deterministic preflight checks, independent verification when judgment
remains, duplicate protection where possible, and immediate circuit breaking.
There is no generic `irreversible actions allowed` capability.

The root-authority kernel is permanently non-delegable to agents and ordinary
workflows. It includes activating authorization or billing policy, expanding a
worker's own authority, weakening audit or containment, and reading credential
material. Changes to this kernel require a direct operator-controlled path and
cannot be authorized by a standing worker envelope.

These are adopted target-design decisions only. The current runtime enables
neither Class 2 nor Class 3 actions and has no standing-envelope evaluator.

## Consequential execution and recovery

Every future Class 2/3 state-changing operation is executed from a durable,
controller-owned outbox record created only after authorization. The record
contains the exact authorized intent and idempotency key. A leased,
capability-specific executor performs it and appends an action receipt;
workers and general workflow code may propose an operation but never call a
consequential connector directly.

External effects use an at-least-once model rather than claiming exactly-once
delivery. An ambiguous result is recorded as `unknown`; the controller
reconciles against the authoritative external state before retrying and
returns `defer` when neither idempotency nor reconciliation can establish
whether the first effect occurred. Connector credentials remain behind the
dedicated executor, scoped to the minimum request. Durable state records only
credential references and fingerprints, never values, and response
normalization removes token- or secret-bearing fields.

Verification is risk-adaptive. A complete deterministic executable oracle is
sufficient for a tightly structured operation. When material semantic,
reputational, legal, or ambiguous judgment remains, a reviewer uses a fresh
session, separate role, frozen artifacts, and no hidden implementer
transcript. A different model or provider is required only when the envelope
identifies material correlated-error risk and an eligible included-
subscription route exists.

Objective policy, security, containment, or verification failures are binding
vetoes. A subjective implementer/reviewer disagreement receives at most one
fresh adjudication over frozen evidence; an unresolved result becomes
`defer`, not an unbounded debate or agent vote. Correctable defects may enter a
bounded repair loop with fresh verification, but the goal, resource snapshot,
authority envelope, billing lane, and total attempt ceiling stay fixed.
Policy prohibition, authority expansion, credential exposure, containment
breach, or a circuit trip skips repair and instead denies, quarantines, or
suspends as policy requires.

## RBAC and separation of duties

The target role vocabulary is versioned before multi-agent flows are enabled:

- the controller coordinates and enforces policy; it is not a model role by
  default;
- a planner may propose a bounded flow but cannot authorize it;
- an implementer may change one isolated worktree but cannot verify, approve,
  or promote its own candidate;
- a verifier runs registered checks and cannot edit the candidate;
- a reviewer receives frozen declared artifacts and cannot silently become the
  implementer;
- a recovery worker receives only a classified failure and no more than the
  failed attempt's authority. A deterministic recovery router may select the
  original profile, a specialist, or a stronger versioned profile, but only
  from promoted, pre-approved profiles inside the original billing lane,
  snapshot, envelope, repair ceiling, and total attempt budget. A route or
  settings escalation cannot add tools or permissions.

Agent review is useful separation of duties but is not dual-human
authorization. This single-operator deployment cannot claim two-person
authorization; any action that genuinely requires two independent human
principals remains disabled unless the operating model changes.

## MCP claim handling

MCP annotations are stored separately from authoritative attributes with the
authenticated server identity, tool name, protocol/tool version, and
provenance. Conservative defaults and mismatches may raise risk, but an
annotation cannot lower a controller-derived requirement or grant authority.

In particular, read-only does not mean confidentiality-safe, non-destructive
does not mean reversible or harmless, idempotent does not make every ambiguous
retry safe, and closed-world does not mean trusted. A reviewed local registry
must normalize each concrete invocation and arguments into effective action,
resource, environment, and consequence attributes. Unknown or mismatched tools
fail closed or remain disabled. Sandbox, filesystem, network, and credential
capabilities enforce the decision; metadata and prompts do not.

## Untrusted content, context, and memory

Every connector response, repository artifact, model output, and retrieved
external source remains tainted data even when it came from an authenticated
service. The controller normalizes it into bounded schemas, preserves
provenance and trust-boundary labels, removes credential-bearing fields, and
exposes only task-required projections. Prompt-injection detection is an
additional risk signal, never the security boundary: tainted content cannot
alter policy, instructions, authorization attributes, or executor parameters.

Tainted content may enter append-only evidence storage with namespace,
provenance, confidence, sensitivity, and retention metadata. It cannot become
trusted long-term memory, a skill, or an instruction without deterministic
validation and the normal reviewed promotion path. Retention expiry deletes or
cryptographically erases the payload while preserving a non-sensitive
append-only tombstone containing the disposal authority, reason, time, and
digest metadata. Raw content, prompts, credentials, and private outputs are
not retained merely to make an audit log append-only.

Memory and evidence are isolated by repository, project, role, and trust
domain. Cross-project retrieval is disabled by default and requires an
explicit provenance-preserving, redacted projection into a separate
namespace. Worker sessions are ephemeral: the controller reconstructs each
context from declared, digest-bound inputs and approved projections, never
hidden provider history or unrelated memory.

A worker may request more information by describing the information need, not
an arbitrary host path. The controller enforces scope, sensitivity,
provenance, taint, and context budget, then returns an immutable context-pack
delta with its own digest. Adding a delta invalidates every not-yet-executed
permit based on the old cumulative context and requires future planning,
review, and authorization to bind the new digest. Material contradiction
triggers replanning.

Conflicting sources defer execution only when the disagreement affects a
decision-critical fact, authorization attribute, or expected consequence.
Repository and connector registrations therefore define versioned
source-of-truth rules: authoritative sources, acceptable replicas,
precedence, freshness, and reconciliation per resource type. Agents may report
conflicts but cannot choose or change the authoritative source. A missing
critical source-of-truth rule yields `indeterminate`, or `defer` when a
specific operator choice can resolve it.

Repository-local instructions such as `AGENTS.md`, `CLAUDE.md`, and project
prompts are digest-bound, scoped implementation guidance below operator and
controller policy. They cannot change authorization, billing, isolation,
credential, or promotion policy. An attempt to widen authority is a policy
violation, not an instruction to follow.

## Migration without authority widening

1. **Implemented — documentation and compatibility inventory.** Adopt this
   target model, record current Class 0/1 authority points, preserve all
   existing gates, and add no new runtime capability.
2. **Chief-of-Staff and comparison slices implemented; broader parity planned — shadow model.**
   Standard-library request/decision/receipt types, a versioned current-stage
   policy bundle, conservative class derivation, and adversarial fixtures now
   exist. The task contract independently declares its action, resource, and
   consequence intent. The run path appends non-authoritative canonical
   `task_attempt_admission_only`, `runner_model_dispatch_only`, and
   `local_candidate_publication_only` observations. Shadow build, evaluation,
   and append failures are sanitized and cannot allow or block legacy work.
   Historical paths add required non-enforcing publication receipts. Frozen
   schema-v4 exact-mock attempts add a separate enforcing publication decision
   and schema-v3 pre-effect/action receipts; schema-v5 attempts retain that chain
   and add an enforcing admission decision and durable succeeded receipt; current
   schema-v6 attempts retain all three chains and add the bounded canonical task-
   intent lineage used by the final dispatch PEP and read-only replay.
   Failure to prove those
   audit records or the exact local effect fails closed. A read-only
   inspector recomputes canonical
   digests, evidence authenticity/freshness, legacy executability from the
   persisted run, the class from validated typed request attributes,
   derived-class authority-ceiling parity, and expected boundary coverage and
   controller-event order. Class-ceiling mismatches in shadows are evidence;
   the narrow admission, dispatch, and publication PEPs enforce their
   independent ceilings.
   Ordinary candidates add a privacy-bounded attempt binding,
   receipt-bound billing accounting, and exact metadata/filesystem
   reconciliation. Controlled comparison trials add a versioned Class 0 binding,
   admission/dispatch shadows, and a separately bounded Class 1 private-
   publication shadow with pre-effect/action-receipt evidence. Historical v1
   trials remain valid partial evidence. Other current decision paths remain
   planned.
3. **Partly implemented — initial enforcement.** The first deterministic PEPs
   gate only Class 1 admission of a new profile-backed ordinary exact built-in
   mock attempt, its dispatch, and the resulting owner-private candidate
   publication. Admission requires a persisted decision, exact current-input
   rebuild and persisted-wrapper equality, independent policy replay,
   freshness, and a durable succeeded receipt before shadow or billing.
   Dispatch exactly reads back selection, task-attempt binding, mock billing,
   and decision evidence, rebuilds
   current inputs, independently constructs and compares the canonical
   persisted wrapper, independently replays fixed policy, and checks finite
   freshness and unchanged shipped runner boundaries before `RUNNING`. It exactly reads
   back `RUNNING`, repeats those current checks immediately before invocation,
   and exactly reads back the linked action receipt and execution accounting
   before publication;
   unprovable post-effect receipt persistence quarantines the attempt.
   Publication uses the same v6 binding lineage, captured shipped resolver and
   evaluator replay, its own fixed Class 1 decision, exact binding/decision/pre-
   effect readback, post-replay action-time freshness check, and reconciled
   action receipt. These changes require no schema bump and do not widen the
   exact profile-backed
   `MockRunner` Class 0/1 boundary; new admission remains Class 1.
   General/live/comparison/supervisor
   admission, shared publication or promotion, comparison execution,
   supervisor worker dispatch, live harness,
   approvals/resumption, and mediated commands/tools remain non-enforcing or
   disabled. Retain legacy Class 0/1 checks as defense in depth through the
   migration.
4. **Partly implemented; continuous mediation planned — typed contracts.** The
   first task effect is typed independently of `PermissionClass`, the supervisor
   has focused flow and controller-bookkeeping shadow attributes, and the
   frozen schema-v1 through schema-v3 and separate schema-v4 repository-
   registration contracts produce digest-only, no-authority validation
   evidence; v3 baseline
   evidence is aggregate-only and explicitly unauthenticated and not freshness-
   verified, while v4 identity evidence is aggregate-only with authenticity,
   freshness, resolution, content, completeness, and execution correspondence
   explicitly false. Controller-owned
   durable repository-registration selection and proposal-attempt binding remain
   pinned to v1 evidence and are implemented as two content-addressed,
   statusless PIP events for the fixed dispatch-disabled sentinel run.
   Independent single-run inspection and a fresh-inspection,
   non-authoritative Class 0/1 admission shadow are implemented, along with
   independent value-free verification of an untrusted returned shadow mapping;
   profile-resource authorization, command, and tool coverage remain planned.
   Shadow mismatches are recorded
   rather than rejected because the legacy class is still authoritative. Once
   enforcement migrates, derive the compatibility class from the request and
   mediate exact commands and tools at their point of use.
5. **Planned with multi-agent flows.** Enforce versioned RBAC assignments,
   least-privilege delegation, and separation of duties. Children inherit only
   a strict subset of the parent's effective authority.
6. **Deferred.** Class 2/3 runtime enablement, standing-envelope enforcement,
   external connectors and writes, dual-human workflows, distributed
   identity/PDP infrastructure, a third-party policy engine, and any formal
   NIST/FIPS compliance claim require separate implementation, authorization,
   and evidence. The target semantics above are adopted; capability remains
   disabled.

During migration, the existing numeric class fields remain compatibility
inputs because current schemas, routing, runners, persistence, evaluation, and
comparison depend on them. They become output-only summaries only after parity
tests and enforcement-point coverage demonstrate that removing their authority
cannot widen access.

## Derived operator summaries

Class 0-3 is retained only as a conservative operator-facing summary in the
target model:

- Class 0: read-only;
- Class 1: isolated local changes;
- Class 2: shared but normally reversible changes;
- Class 3: external, destructive, irreversible, or otherwise high-impact
  actions.

The summary is lossy and never overrides the ABAC decision. A read can still
have high confidentiality impact, and an additive external write can still be
consequential. Derivation therefore uses the highest applicable summary: a
read-only operation that is otherwise high-impact displays Class 3 rather than
being forced into Class 0. Operator views should also show the consequence
vector and important obligations alongside the class.

## Primary references

- [NIST SP 800-162, Guide to Attribute Based Access Control](https://csrc.nist.gov/pubs/sp/800/162/upd2/final)
- [NIST Role Based Access Control project and INCITS standard history](https://csrc.nist.gov/Projects/Role-Based-Access-Control)
- [FIPS 199, Standards for Security Categorization](https://csrc.nist.gov/pubs/fips/199/final)
- [NIST SP 800-53 Rev. 5, Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [MCP ToolAnnotations schema](https://modelcontextprotocol.io/specification/2025-11-25/schema#toolannotations)
- [MCP tool-annotation security guidance](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)
