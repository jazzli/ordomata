# Ordomata

**A local control plane for governed autonomous work.**

Pronounced **or-doh-MAH-tuh**: four syllables, with the primary stress on
“MAH” (IPA: `/ˌɔːr.doʊˈmɑː.tə/`).

Ordomata is a local, single-operator control plane for running neutral tasks
through first-party AI coding-harness subscriptions. It prohibits purchased
product credits, subscription overage, separately billed model APIs, and cloud
inference routes. The current tracer bullet is **Chief of Staff Lite**:
sanitized local sources become an immutable context snapshot, a structured
local draft, and transparent deterministic evaluation.

The public repository contains source, tests, plans, fixtures, and deliberately
sanitized configuration for provenance and portability. Private inputs,
credentials, account or billing attestations, local databases, logs,
workspaces, and run artifacts remain local and ignored. Ordomata never pushes
them automatically.

## Mental model

```text
Task + sanitized sources
  -> deterministic validation and authorization
  -> billing, capacity, and containment gates
  -> isolated first-party harness or deterministic mock
  -> schema validation and deterministic evaluation
  -> private local candidate or quarantine
  -> append-only evidence and operator inspection
```

Deterministic controller code owns state, permissions, scheduling, evaluation,
billing gates, circuit breakers, and promotion. An agent cannot widen its own
authority. Only permission classes 0 (read-only) and 1 (local draft) are
enabled; external, shared, irreversible, or high-impact effects remain
disabled.

## Current capabilities

- Strict, versioned task contracts and structured-output schemas.
- Local SQLite FTS5 ingestion, hashing, deduplication, retrieval, and bounded
  provenance-rich context packs.
- Subscription-only Codex and Claude Code adapters plus a deterministic mock
  used by normal development and tests.
- Fail-closed route, account-identity, included-capacity, paid-continuation,
  environment, and containment checks.
- Owner-private, short-lived billing attestations containing only bounded
  semantic evidence and an account fingerprint.
- Versioned execution profiles, deterministic routing, immutable selection
  evidence, controlled comparison plans, and separate human-review templates.
- Append-only SQLite run, event, artifact, capacity, circuit, scheduling,
  supervisor, authorization, and migration records with integrity guards.
- Process-group containment with bounded output, timeout, cancellation,
  TERM/KILL cleanup, and fail-closed cleanup evidence.
- Authoritative Class 1 policy-enforcement points for new profile-backed exact
  built-in mock admission, mock execution, and private local-candidate
  publication, plus reversible local supervisor control transitions. Other
  paths remain shadow-only or disabled.
- Read-only authorization and supervisor inspection that reports fixed,
  privacy-bounded findings without repairing history.
- A foreground, dispatch-disabled supervisor control-plane tracer with
  optimistic revisions, sticky cancellation, claims, reconciliation, and a
  local completion outbox.
- Pure repository-registration validation and a library-only chain for bounded
  executable, shebang, native-loader, and dependency evidence. This chain
  stages only private descriptor-backed bytes and remains explicitly
  non-authoritative and dispatch-disabled.

The exact implemented boundary changes frequently as the tracer advances.
Use the [implementation status](docs/implementation-status.md) for the detailed
capability ledger and [architecture](docs/architecture.md) for component and
failure-flow detail.

## Safety invariants

- A live model run is opt-in with `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1`; that
  gate is necessary and never sufficient.
- The legacy `AGENTOPS_ALLOW_SUBSCRIPTION_RUNS=1` alias is accepted only when
  it does not conflict with the canonical variable.
- API keys, AI API SDKs, metered inference, purchased credits, overage, cloud
  routes, and fallback to any of them are architecturally prohibited.
- Child environments are constructed from a narrow allowlist and never receive
  prohibited credential or cloud-route variables.
- Missing, stale, contradictory, mismatched, low-confidence, paid, or unknown
  billing evidence blocks execution. Paid or unknown post-run evidence
  quarantines output and opens a durable circuit.
- Run, capacity, circuit, and authorization evidence is append-only. Inspection
  reports damage; it does not silently repair or reinterpret history.
- Tests and normal development use deterministic mocks and never make live
  model calls.
- No recurring schedule, external message, calendar change, deployment,
  promotion, merge, or push occurs automatically.

See the [subscription-only policy](docs/subscription-only-policy.md) and
[authorization model](docs/authorization-model.md) for the normative details.

## Requirements

- Python 3.12 or newer.
- A POSIX platform for the descriptor-anchored executable proof modules and
  their full test coverage.
- No runtime dependency outside the Python standard library.

The Codex or Claude Code CLI is needed only for an explicitly authorized live
subscription run. The deterministic mock and all ordinary tests require
neither CLI.

## Quick start

Run read-only validation and inspection directly from a checkout:

```sh
PYTHONPATH=src python3 -m ordomata task-validate
PYTHONPATH=src python3 -m ordomata context-inspect
PYTHONPATH=src python3 -m ordomata profiles
PYTHONPATH=src python3 -m ordomata route --lane mock
PYTHONPATH=src python3 -m ordomata auth-inspect
PYTHONPATH=src python3 -m ordomata doctor
```

Run the deterministic local demo explicitly:

```sh
PYTHONPATH=src python3 -m ordomata demo
```

The demo invokes no model. It writes its accepted private artifact and
append-only state under `.ordomata/`, which Git ignores.

Inspect one schedule slot without claiming it or installing an OS schedule:

```sh
PYTHONPATH=src python3 -m ordomata schedule-inspect \
  --interval-seconds 3600
```

Inspect the supervisor tracer without creating state:

```sh
PYTHONPATH=src python3 -m ordomata supervisor status --json
PYTHONPATH=src python3 -m ordomata supervisor audit --json
PYTHONPATH=src python3 -m ordomata supervisor reconcile --json
```

`supervise` runs only in the foreground and currently dispatches no worker,
runner, model, subprocess, repository action, or external effect. Explicit
supervisor control commands append local control intent; they do not install a
service or recurring schedule.

## Live subscription runs

Before any live run, inspect the same authenticated account in the official
provider UI and create short-lived local evidence from a real terminal:

```sh
PYTHONPATH=src python3 -m ordomata billing-attest --runner codex
PYTHONPATH=src python3 -m ordomata billing-attest --runner claude
PYTHONPATH=src python3 -m ordomata doctor
PYTHONPATH=src python3 -m ordomata route --lane subscription
```

`billing-attest` never starts a model and has no `--yes` or piped-input mode. A
live run is eligible only when all of these are true:

1. The selected first-party CLI is installed and exposes the required safe
   flags.
2. Local diagnostics prove first-party subscription authentication and a
   stable account fingerprint.
3. Included subscription capacity is currently available for that account.
4. Current account-bound evidence proves paid continuation is disabled for the
   whole requested run window. Codex also requires zero usable paid-credit
   balance; Claude requires extra usage disabled.
5. The environment, profile, capabilities, isolation mode, durable capacity
   state, and billing circuits all pass.
6. The operator explicitly sets `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1` for the
   process.

Example syntax—use it only when `doctor` reports the exact profile ready now:

```sh
ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1 \
PYTHONPATH=src python3 -m ordomata run \
  --profile codex.subscription.local-draft-synthesis
```

There is no API or cloud fallback. For Chief of Staff Lite, the harness sees
an isolated empty workspace and receives context through standard input. The
controller validates the output before writing any private candidate.

## Controlled comparison

Create a deterministic comparison plan without running trials:

```sh
PYTHONPATH=src python3 -m ordomata compare-plan \
  --runners codex claude --repetitions 3 --seed 20260726
```

When every selected profile is independently eligible, the corresponding
`compare-run` command executes block-randomized, fresh-session trials against
one immutable sanitized snapshot. It retains raw evaluation dimensions and a
separate human-review template, but produces no automatic winner or profile
promotion. No live Codex-versus-Claude comparison has been completed or scored
in this repository.

## Rename compatibility

The canonical import package and CLI are `ordomata`, and new local state uses
`.ordomata/`. If a checkout contains only the former `.agentops/` state root,
Ordomata continues using it in place so append-only records and stored absolute
paths remain intact. If both roots exist, startup fails closed rather than
merging or splitting audit history.

The renamed distribution intentionally installs no legacy `agentops` package
or CLI alias. Stop and remove any pre-rename installed runtime or background
process before starting Ordomata. Several v1 protocol identifiers retain the
former name as frozen provenance and must not be rewritten inside historical
records.

## Development and verification

The complete local checks are:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests
git diff --check
```

CI runs the compile and test commands on Python 3.12 and 3.14. The suite uses
only deterministic mocks; never enable the live-run gate in tests.

Start with the [documentation map](docs/README.md) to find the canonical
architecture, status, policy, routing, roadmap, plan, and research sources.

## Deliberate current limits

- The supervisor is a dispatch-disabled foreground tracer, not a worker daemon.
- Repository registration and executable-closure evidence grant no route,
  authority, worktree integration, subprocess, or execution capability.
- Only the narrow exact built-in-mock Class 1 admission, dispatch, and private
  publication path has authoritative attribute-based access-control coverage.
  Live, comparison, supervisor, shared publication, promotion, and general
  mediated-tool paths remain shadow-only or disabled.
- No production inbox, calendar, Drive, Slack, deployment, or other connector
  is enabled.
- No Cursor Agent adapter, autonomous learning, retry/failover controller,
  standing-envelope evaluator, worker-cell backend, or consequential-action
  executor exists yet.
- No autonomous promotion, merge, push, deployment, or external action exists.

These are deliberate phase boundaries, not hidden fallbacks. The
[roadmap](docs/roadmap.md) records planned work and explicit deferrals.
