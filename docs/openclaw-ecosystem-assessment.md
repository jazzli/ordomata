# OpenClaw Ecosystem Assessment

**Date:** 2026-07-26

**Status:** Architecture decision record and research snapshot

**Scope:** OpenClaw and projects positioning themselves as smaller, safer, faster, or more operationally complete alternatives and control planes

## Decision summary

OpenClaw should be treated as a **reference implementation and, potentially, an optional frontend or interoperability endpoint**. It should not become this project's runtime dependency, control plane, or fork base.

The ecosystem validates several parts of our direction: durable queues, isolated workspaces, explicit worker identities, parent-to-child capability reduction, restart-safe sessions, append-only events, shared artifacts, deterministic evaluation, and desired-state reconciliation. Those patterns should be implemented behind our own small interfaces and subscription-only billing gate.

The project must retain these non-negotiable boundaries:

- AI inference runs only through a first-party coding harness with verified included-subscription capacity and verified protection against purchased-credit or overage continuation.
- There is no API-key fallback, metered AI API SDK, or cloud-model route.
- Deterministic code owns authorization, scheduling, evaluation, state transitions, and promotion.
- Live harness execution remains opt-in through `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1`, which is necessary but never sufficient.
- Only work inside the current Class 0/1 ceiling is enabled at this stage; the
  target authorization model derives those labels rather than treating them as
  grants. The target permits exactly bounded Class 3 standing envelopes, but
  no Class 2/3 runtime path or envelope enforcement is implemented.
- Tests use deterministic mocks and never make live model calls.

## Evidence and inference convention

Statements labeled **Evidence** summarize official project repositories or documentation as they existed on the assessment date. Statements labeled **Assessment** are conclusions for this project. Project-authored claims about performance, size, safety, or compatibility have not been independently benchmarked unless explicitly stated.

## What OpenClaw is

### Evidence

[OpenClaw](https://github.com/openclaw/openclaw) is a broad, local-first personal-agent platform. Its gateway connects model-backed agents to messaging channels, tools, browser automation, schedules, sessions, and isolated workspaces. It supports multiple named agents and routing among agents, workspaces, and sessions. Tool execution can be placed in per-agent or per-session Docker sandboxes with resource, network, and tool policies. Its gateway protocol exposes session creation, sending, steering, aborting, and subscription, and it provides an [ACP bridge](https://docs.openclaw.ai/tools/acp-agents) for agent-client interoperability.

OpenClaw now includes a native Codex app-server path that can use ChatGPT/Codex OAuth and subscription entitlement. However, the same official [OpenAI provider documentation](https://docs.openclaw.ai/providers/openai) also supports API-key profiles and direct OpenAI Platform services. Its [model-failover documentation](https://docs.openclaw.ai/concepts/model-failover) permits ordered authentication profiles that rotate from a subscription profile to an API-key profile when a subscription limit is reached. Its realtime voice path explicitly requires Platform billing rather than a ChatGPT subscription.

OpenClaw's own [security guidance](https://docs.openclaw.ai/gateway/security) describes execution approvals as operator-intent guardrails rather than hostile multi-tenant isolation. Its [Docker documentation](https://docs.openclaw.ai/install/docker) offers useful execution isolation, but isolation remains configuration-dependent. The project is actively and rapidly evolving, as shown by its [release history](https://github.com/openclaw/openclaw/releases).

### Assessment

OpenClaw is best understood as an expansive personal-agent runtime and gateway, not as a narrow deterministic supervisor for coding workers. Its breadth is valuable for studying channel adapters, session protocols, tool policy, sandboxing, and user experience. The same breadth creates coupling and a large action surface that this project's early phases deliberately avoid.

OpenClaw's subscription-capable Codex route is relevant evidence that first-party harness interoperability is practical. Its mixed billing routes are nevertheless incompatible with our architectural invariant. Preventing API fallback and purchased-credit/overage continuation must be structural, not a prompt, profile convention, or unsupported operator promise. Billing Hard-Stop v2 now encodes that stronger condition, but each live Codex or Claude attempt still remains blocked unless current evidence proves the exact account has available included capacity, provider-appropriate paid-continuation protection, a matching unexpired attestation, and a closed durable circuit for the requested run window.

## Why OpenClaw is a reference and optional frontend

| Concern | OpenClaw characteristic | Project decision |
|---|---|---|
| Billing | Supports subscription-backed Codex, API keys, direct APIs, and ordered auth fallback | The controller permits live AI only with verified included capacity and paid-continuation protection; API, credit, overage, and unknown routes are rejected |
| Authority | A general agent runtime can own tools, schedules, channels, and agent behavior | Deterministic local code owns authority; harnesses only propose or execute bounded work |
| Attack surface | Many providers, plugins, channels, browser tools, and remote integrations | Start with local repositories and work that derives to Class 0/1 under local policy |
| Isolation | Useful Docker policies, but security depends on deployment and configuration | Make isolation and environment filtering controller-enforced invariants |
| Technology fit | Large, fast-moving TypeScript/Node platform | Keep the core Python 3.12 standard-library-first and small |
| Coupling | A fork would inherit upstream product direction and merge burden | Define stable local protocols and adapters instead |
| Promotion | Agent platforms often optimize for direct action | Require deterministic checks and human review before promotion |

A future OpenClaw integration could expose our queue and run state through a constrained local adapter, or submit work through ACP/gateway-compatible boundaries. In that arrangement, OpenClaw would be a replaceable client: it would not receive credentials, choose an inference route, install schedules, expand permissions, promote changes, or execute consequential actions. Messaging-channel integration remains out of scope while only classes 0 and 1 are enabled.

## Ecosystem taxonomy

The projects reviewed fall into four useful groups:

1. **General personal-agent runtime:** OpenClaw combines gateway, agent loop, channels, tools, scheduling, and extensibility.
2. **Small reimplementations:** NanoClaw, PicoClaw, ZeroClaw, IronClaw, FastClaw, and NullClaw trade breadth, language, isolation model, or operational footprint against OpenClaw.
3. **Security and deployment wrapper:** NVIDIA NemoClaw wraps existing agent runtimes with stronger sandbox, network, and credential controls.
4. **Control planes:** AgentTeams and OpenClaw Managed Agents coordinate multiple workers, environments, sessions, queues, artifacts, and lifecycle state above an underlying runtime.

This distinction matters. A compact agent loop does not automatically provide a durable control plane; a secure sandbox does not provide scheduling or evaluation; and a polished multi-agent control plane does not guarantee a permitted inference route.

## Comparison of credible projects

| Project | Category and implementation | Notable evidence | Fit and lesson for this project |
|---|---|---|---|
| [OpenClaw](https://github.com/openclaw/openclaw) | Broad TypeScript/Node personal-agent runtime and gateway | Multi-agent routing, channels, schedules, Docker workspaces, gateway protocol, ACP, subscription-capable Codex route alongside API routes | Strong reference and possible replaceable frontend; unsuitable as the trusted billing and authority boundary |
| [NanoClaw](https://github.com/nanocoai/nanoclaw) | Small TypeScript host with a Bun container runner | Central SQLite state, per-session inbox/outbox databases, one container per active session, sweep/recovery behavior, named agents, schedules, and agent-to-agent work | Adopt its explicit mailboxes, wake deduplication, stale-run recovery, and short-lived container lifecycle; verify any claimed subscription route independently |
| [PicoClaw](https://github.com/sipeed/picoclaw) | Independent Go reimplementation | Event bus, sub-turn hooks, steering, cron, named agents, spawned workers, routing, and workspace restriction | Event-driven seams are useful; application-level path checks are not a substitute for OS isolation, and automatic self-application conflicts with gated promotion |
| [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) | Layered Rust runtime | One daemon with named agents, OS sandbox options, per-agent policies, depth-capped subagents, parent-subset authority, resumable procedures, replay/evaluation foundations, and optional signed tool receipts | Closest conceptual match for capability reduction, provenance, and deterministic replay; avoid its permissive modes and broad environment forwarding |
| [IronClaw](https://github.com/nearai/ironclaw) | Rust reimplementation with durable services | Scheduler, routines, orchestrator, parallel jobs, Postgres, WASM capability tools, host-side credential injection, leak scanning, and endpoint allowlists | Capability-based plugins and keeping secrets outside workers are valuable; its API-oriented onboarding, operational weight, and evolving parity make it a reference only |
| [NemoClaw](https://github.com/NVIDIA/NemoClaw) | Security/deployment wrapper around agent runtimes | OpenShell gateway, L7 proxy, non-root execution, seccomp, filesystem/process/network controls, SSRF defenses, and a credential broker | Adapt the layered deny-by-default model and recovery guidance; do not adopt its inference layer or assume a wrapper replaces deterministic authorization |
| [AgentTeams](https://github.com/agentscope-ai/AgentTeams) | Go multi-worker control plane, formerly HiClaw | Kubernetes-style reconciler, declarative workers/teams/managers/humans, heterogeneous runtimes, artifact storage, credential gateway, and idle sleep/wake | Strong model for desired-state reconciliation, heterogeneous adapters, visible team topology, and shared artifacts; its API-token model is prohibited here |
| [OpenClaw Managed Agents](https://github.com/stainlu/openclaw-managed-agents) | TypeScript service layer over OpenClaw | Typed Agent/Environment/Session/Event resources, immutable versions, durable queues, per-session containers, warm pools, restart adoption, quotas, and audit | Useful resource model and restart-safety reference; not an inference solution and presently coupled to OpenClaw and API-key use |
| [FastClaw](https://github.com/fastclaw-ai/fastclaw) | Go service and TypeScript administration UI | Agent factory, per-agent state, schedules, teams, queues, databases, and optional Docker/E2B sandboxes | Learn from its operational UI; avoid host-shell defaults, API-first routing, and tight upstream/runtime coupling |
| [NullClaw](https://github.com/nullclaw/nullclaw) | Very small Zig runtime | Interface-oriented architecture, named agents, subagents, cron/heartbeat, encrypted secrets, signed audit, and several OS sandbox backends | A useful portability and interface-design reference; pre-1.0 maturity and no verified subscription-only path make it unsuitable as a foundation |

## Adopt, adapt, and avoid

### Adopt as core patterns

- **Durable, explicit work state:** queued work, leases, attempts, sessions, events, artifacts, terminal results, and recovery after process restart.
- **Append-only provenance:** record task input, selected worker profile,
  model-setting intent, harness identity, authorization request/decision and
  derived class, tool outcomes, checks, and promotion decision.
- **Per-run isolation:** a dedicated worktree or workspace, a narrow child-process environment, bounded resources, and no implicit access to host credentials.
- **Capability reduction:** every child receives a subset of the parent's permissions; delegation depth and concurrency are deterministic limits.
- **Desired-state reconciliation:** controllers compare declared work with observed processes and repair stale leases, abandoned sessions, and duplicate wakeups.
- **Artifact-first collaboration:** workers exchange patches, reports, test results, and structured events rather than relying on unbounded conversational memory.
- **Durable effect mediation:** consequential connectors consume exact,
  authorized controller outbox records with idempotency and reconciliation;
  workers never hold connector credentials or call them directly.
- **Tainted ingress and ephemeral context:** authenticated channel content,
  connector data, and model output remain untrusted, provenance-bearing data;
  each worker session is rebuilt from declared digest-bound context.
- **Deterministic evaluation:** formatting, linting, type checking, tests, diff policies, and repository rules decide whether a result is acceptable.
- **Replaceable harness adapters:** route tasks by declared capability and verified availability without letting a model choose billing or authority.

### Adapt behind local interfaces

- OpenClaw's session/gateway concepts and ACP interoperability, but only as an optional client boundary.
- NanoClaw's per-session mailboxes and container lifecycle, expressed in our append-only run model.
- ZeroClaw's tool receipts and resumable procedures, initially using simple signed or hashed records rather than a distributed trust system.
- AgentTeams' Worker, Team, and desired-state abstractions, reduced to the needs of one operator and local repositories.
- NemoClaw's layered network, filesystem, process, and credential controls, introduced incrementally as isolation backends mature.
- Administrative dashboards from FastClaw and managed-agent systems, built from controller state rather than becoming the source of truth.
- Scheduling as durable intents consumed by the deterministic scheduler, never as agent-created cron entries or autonomous external automations.

### Avoid

- API keys, direct model APIs, usage-based cloud inference, provider failover, or any path that can silently become metered.
- Passing a broad inherited environment to a harness, worker, plugin, or container.
- Agent-controlled permission changes, schedule installation, evaluator selection, or self-promotion.
- `YOLO`, unrestricted host-shell, blanket full-access, or auto-apply modes.
- Treating workspace path validation alone as a security boundary.
- Automatically installing skills, plugins, MCP servers, or marketplace packages proposed by an agent.
- Direct agent actions that send messages, change calendars, merge, deploy, push, or mutate external systems.
- Forking a rapidly moving upstream as the core architecture when a small compatibility adapter is sufficient.

## Fit with the current project

The present architecture already has the right trust split: the deterministic controller owns state and policy, while a subscription-backed coding harness is a bounded worker. The ecosystem suggests strengthening that split rather than replacing it.

The lowest-risk progression is:

1. Complete a repository-work tracer bullet: discover work, lease it, create an isolated worktree, invoke a deterministic mock or gated harness, run checks, store artifacts, and stop at a reviewable local draft.
2. Make worker routing explicit with a `WorkerProfile` that names the harness,
   model-setting intent, capability tags, concurrency limit, typed authority
   envelope, and temporary class compatibility ceiling. A live AI route is
   eligible only if its included-subscription transport, available capacity,
   protection against paid continuation, and fresh local authorization all
   agree.
3. Add restart-safe `Environment`, `RunSession`, `Event`, and `Artifact` records where existing state does not already cover them. Preserve append-only history and idempotent recovery.
4. Add parent-subset delegation and bounded parallel workers. Collaboration should flow through structured work items and artifacts.
5. Introduce stronger sandbox backends and deny-by-default egress without changing the controller's policy model.
6. Add an optional local OpenClaw/ACP frontend adapter only after the core protocol is stable. Keep it disabled by default and limited to requests that derive to Classes 0 and 1 until higher-impact policy is separately designed and approved.

The worker-cell target is backend-pluggable and judged by observed isolation
attestation rather than a container label. Within a proven disposable cell an
implementer may eventually receive a general shell, narrowly proxied egress,
locked dependencies, and read-only verified caches; host credentials, control
sockets, shared Git authority, and undeclared network remain unavailable. This
adopts useful claw-ecosystem ergonomics without making prompt-injection
detection, plugin metadata, or a third-party gateway an authorization boundary.

After fail-closed eligibility (which includes capacity availability), model routing should rank correctness and risk first, included-subscription efficiency second, and latency third. It must never optimize by crossing the billing boundary. If every eligible subscription harness is unavailable or exhausted, the correct state is deferred or blocked—not API fallback.

## Caveats and open questions

- This is a source review, not an independent security audit or performance benchmark.
- The ecosystem changes quickly. Version numbers, default settings, product names, and compatibility claims should be rechecked before implementation decisions.
- Binary-size and memory claims are difficult to compare because projects report different feature sets and build modes; they are not selection criteria here.
- “Supports Codex,” OAuth, or ChatGPT subscription does not by itself prove that every execution path is subscription-backed. Each adapter needs an executable billing-route verification and fail-closed behavior.
- Subscription authentication also does not prove included-only usage: Codex can draw from ChatGPT product credits after plan limits, and Claude usage credits can extend Claude Code at separately billed rates. Account-level credit state therefore belongs in the billing gate.
- Container isolation, WASM, Landlock, Bubblewrap, Seatbelt, seccomp, and application allowlists have different threat models. A backend must state what it protects and what remains trusted.
- Multi-agent messaging can create cost and coordination overhead without improving results. Parallelism should be earned through evaluations and bounded by useful, independently checkable work.
- Optional interoperability must not turn a third-party runtime's configuration or database into this project's source of truth.

## Primary sources

### OpenClaw

- [Repository and README](https://github.com/openclaw/openclaw)
- [OpenAI provider and Codex app-server authentication](https://docs.openclaw.ai/providers/openai)
- [Model failover](https://docs.openclaw.ai/concepts/model-failover)
- [Gateway security](https://docs.openclaw.ai/gateway/security)
- [Docker sandboxing](https://docs.openclaw.ai/install/docker)
- [Gateway protocol](https://docs.openclaw.ai/gateway/protocol)
- [ACP bridge](https://docs.openclaw.ai/tools/acp-agents)
- [Releases](https://github.com/openclaw/openclaw/releases)

### Reimplementations and compact runtimes

- [NanoClaw repository](https://github.com/nanocoai/nanoclaw), [introduction](https://docs.nanoclaw.dev/introduction), [architecture](https://docs.nanoclaw.dev/concepts/architecture), and [changelog](https://docs.nanoclaw.dev/changelog)
- [PicoClaw repository](https://github.com/sipeed/picoclaw) and [configuration/security guide](https://github.com/sipeed/picoclaw/blob/main/docs/guides/configuration.md)
- [ZeroClaw repository](https://github.com/zeroclaw-labs/zeroclaw), [architecture](https://github.com/zeroclaw-labs/zeroclaw/blob/master/docs/book/src/architecture/overview.md), [tool receipts](https://github.com/zeroclaw-labs/zeroclaw/blob/master/docs/book/src/security/tool-receipts.md), and [releases](https://github.com/zeroclaw-labs/zeroclaw/releases)
- [IronClaw repository](https://github.com/nearai/ironclaw), [feature parity](https://github.com/nearai/ironclaw/blob/main/FEATURE_PARITY.md), and [releases](https://github.com/nearai/ironclaw/releases)
- [FastClaw repository](https://github.com/fastclaw-ai/fastclaw)
- [NullClaw repository](https://github.com/nullclaw/nullclaw)

### Security and control planes

- [NVIDIA NemoClaw repository](https://github.com/NVIDIA/NemoClaw) and [security best practices](https://docs.nvidia.com/nemoclaw/latest/user-guide/openclaw/security/best-practices)
- [AgentTeams repository](https://github.com/agentscope-ai/AgentTeams) and [releases](https://github.com/agentscope-ai/AgentTeams/releases)
- [OpenClaw Managed Agents repository](https://github.com/stainlu/openclaw-managed-agents)

### Subscription credit behavior

- [OpenAI: using credits for flexible usage in ChatGPT](https://help.openai.com/en/articles/12642688-using-credits-for-flexible-usage-in-chatgpt-freegopluspro-sora)
- [Anthropic: managing usage credits for paid Claude plans](https://support.claude.com/en/articles/12429409-manage-usage-credits-for-paid-claude-plans)

## Related project decisions

- [Architecture](architecture.md)
- [Subscription-only policy](subscription-only-policy.md)
- [Roadmap](roadmap.md)
