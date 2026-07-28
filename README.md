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
  from current authoritative inputs, independently constructs the canonical
  wrapper for equality with the retained persisted payload, replays the fixed
  policy, rejects non-finite or stale action times, and rechecks exact runner
  ownership, including unchanged shipped class and instance boundaries. Its
  content-addressed terminal action receipt and execution accounting also
  require exact readback before publication may proceed; an unprovable receipt
  after execution quarantines the attempt. Accepted, credential-clean output then
  requires a separate fixed-policy Class 1 permit immediately before the first
  local-candidate filesystem mutation and an integrated reconciled action
  receipt. Every non-permit, stale permit, authority-ceiling mismatch, or
  uncertain required write blocks before its governed action, and only a
  validated identity-matched no-process result can receive a succeeded
  dispatch receipt, while live, comparison, supervisor, shared publication,
  and promotion paths remain non-enforcing or disabled;
- digest-only ordinary task-attempt bindings that cover the typed authorization
  intent and, for profile-backed attempts, the immutable execution selection,
  profile version, and configuration; new enforced mock attempts use one
  schema-v5 binding that declares admission, dispatch, and local-candidate
  publication coverage; schema-v4 is frozen as dispatch plus publication,
  historical schema-v3 bindings declare dispatch only, and unprofiled
  schema-v1 plus live or historical schema-v2 histories retain their prior
  meaning;
  schema-v2 execution accounting, billing-bound dispatch, and schema-v3
  enforcing pre-effect/action receipts around the schema-v5 local-candidate
  publication shadow for schema-v4/v5 enforcing paths, with exact metadata,
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

The dispatch hardening changes no event or attempt-binding schema and grants no
new authority. Dispatch remains limited to Class 0/1 requests for the exact
profile-backed controller-owned `MockRunner`; new attempts that reach it still
require the existing Class 1 admission permit. The next narrow authorization
slice should make authoritative dispatch intent lineage self-contained for
read-only replay without depending on non-authoritative shadow preimages,
before any permission expansion.

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
- no repository worktree maintenance workflow yet;
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
