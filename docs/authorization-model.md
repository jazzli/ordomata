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

The first repository-registration slice provides a standalone versioned schema
and pure read-only validator. It validates a controller-supplied ordinary Git
root, stable repository/filesystem references, exact argv-array (not shell-
text) verification declarations, canonical protected/allowed paths with
mandatory Git and Ordomata state protection, bounded resource limits, a fixed
local-container/network-disabled isolation requirement, and a patch-only
review policy. Traversal and symlink escapes fail closed. The resulting
privacy-bounded evidence contains only bounded digest references, version
metadata, and fixed declarations that validation is read-only, dispatch is
disabled, and no authority is granted. The validator remains a pure PIP
collector: it creates no state and is not a permit.

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
billing/capacity/circuit fact, harness call, or live eligibility. Baseline
command results and generated/vendor exclusions remain deferred.

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

The next recommended bounded slice is pure schema/validator support for
generated/vendor exclusions in repository registrations, still with no
execution or worker enablement.

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
   standalone schema-v1 repository-registration contract produces digest-only,
   no-authority validation evidence. Controller-owned durable repository-
   registration selection and proposal-attempt binding are now implemented as
   two content-addressed, statusless PIP events for the fixed dispatch-disabled
   sentinel run. Independent single-run inspection and a fresh-inspection,
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
