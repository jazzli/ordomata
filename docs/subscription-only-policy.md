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

The standalone schema-v1 repository-registration contract and pure validator
now deterministically validate and hash a controller-supplied ordinary Git
identity, stable filesystem reference, exact verification argv-array (not
shell-text) declarations, canonical protected/allowed paths, bounded resource
limits, fixed local-
container/network-disabled isolation, and patch-only review policy. Their
digest-only evidence explicitly declares read-only use, disabled dispatch, and
no granted authority. They invoke no Git command, subprocess, worker, harness,
or network service; create no worktree, state/event record, or attempt binding;
and change no authorization, billing gate, circuit, capacity, or live-route
eligibility. Baseline results and generated/vendor exclusions remain deferred.

The next recommended bounded slice is controller-owned registration selection
and digest-only attempt binding for a dispatch-disabled repository proposal,
with exact durable readback but still no worktree, command, worker, or authority.

`compare-run` is an opt-in execution workflow, not a bypass. It requires the same live gate and current evidence for every selected profile before creating comparison records. Trials use one immutable sanitized Class 0 snapshot, randomized repetition blocks, fresh sessions and workspaces, no shared outputs, and no external actions. Reports expose raw automated dimensions and separate human-review fields; they do not declare a winner or auto-promote a profile.

No live Codex-versus-Claude comparison has yet been completed in this repository.
