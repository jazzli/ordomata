# Worker-dispatch security design

**Status:** operator-approved, non-enabling design with preliminary laboratory
evidence. This document does not authorize a worker, a container backend, a
subprocess, a repository mutation, or a live model run.

## Purpose and current boundary

Repository work must remain a Class 1 local-draft activity: it may produce a
reviewable patch in a disposable private area, but it cannot modify the
operator's checkout, Git metadata, remotes, credentials, networked systems, or
any Class 2/3 resource.

The current supervisor deliberately stops at a durable `dispatching` intent.
Its local bookkeeping permits do not authorize a worker. The existing
[`worker_cell_containment`](../src/ordomata/worker_cell_containment.py) module
is an inert v1 contract seam: its only deterministic backend creates no cell
and permanently reports containment unproven. A shape-complete mock
attestation is not a security proof and cannot be promoted into one.

This design turns the remaining gate into an exact implementation target. It
does not relax any current blocker.

## Proposed containment decision

The recommended production candidate is a **fresh local Linux virtual-machine
boundary containing one unprivileged OCI-compatible container per attempt**.
The virtual machine is the host-isolation boundary; the container provides the
per-attempt filesystem, process, resource, and network boundary. It must be
local to the single operator, have no shared host folders, receive only
controller-created per-job transfer artifacts, and use no remote scheduler or
control plane.

This is a recommendation, not an activation decision. The presence of Docker
on a development machine, a process group, a sandbox flag, or a successful
mock test is insufficient evidence for this design. A concrete backend needs a
separate review of its VM image, runtime version, host integration, and
observed evidence before it can be implemented or enabled.

The following alternatives remain insufficient on their own:

- a host subprocess or POSIX process group, because descendants can escape;
- a container with a Docker or other host-control socket mounted into it;
- a worktree whose `.git` pointer or common Git directory is visible to the
  worker;
- a host path, shared folder, credential store, or live harness-auth store
  passed through as a convenience mount; and
- an unauthenticated backend self-report or a result inferred from an exit
  status.

## Trust boundaries and data flow

```text
Controller
  -> frozen task, registration, source snapshot, and exact command contract
  -> materialized no-Git job tree + bounded immutable input bundle
  -> fresh VM-contained unprivileged worker cell
  -> untrusted candidate tree and structured result bundle
  -> controller-owned postflight verification and review bundle
```

The controller owns every cross-boundary transition. A worker receives only a
materialized source tree for one job, bounded temporary storage, and immutable
task/context inputs. It never receives the primary checkout, a Git worktree
pointer, the shared Git directory, controller state, host shell access,
credentials, control sockets, or implicit network access.

The worker may modify only the job tree. The controller reconstructs a patch
against the frozen source snapshot after the cell exits; it does not trust the
worker to describe the patch, claim success, or select verification commands.
The candidate remains private until independent controller verification and
human review.

## Exact authorization boundary

One future authoritative policy-enforcement point (PEP) must sit immediately
before creating the cell and immediately before launching the worker. It must
not be a general shell permit. The permit must bind all of the following exact,
digest-addressed facts:

- source supervisor flow and `dispatching` attempt event, including current
  leases, cancellation state, deadline, and target running transition;
- task definition, immutable context/input bundle, selected deterministic
  profile, runner, and permission class;
- validated repository-registration version, frozen source snapshot, allowed
  and protected path policies, resource limits, and exact registered argv
  verification commands;
- cell-containment contract, approved backend identity/version, cell image or
  template identity, and observed preflight assessment;
- controller-owned billing, capacity, circuit, identity, and environment facts
  for any later live runner; and
- policy digest, subject identity, action parameters, consequence vector,
  expiry, and a fresh operator approval when the policy requires one.

The PEP must persist and exactly reread its decision before creating a cell,
rebuild the request from current controller state immediately before launch,
and fail closed if any digest, freshness, lease, cancellation, circuit, or
containment fact changes. A prior permit is not reusable. The only initially
eligible result is an isolated Class 1 local draft; Classes 2 and 3 remain
disabled.

The worker never obtains the permit as a bearer capability. It receives a
controller-created cell specification with no authority to widen mounts,
environment names, commands, resource limits, network policy, or task scope.
Every worker-invoked tool or command must have its own controller-mediated
boundary or remain unavailable.

## Required observed evidence

The existing v1 declaration shape is useful vocabulary but cannot be reused as
real proof. A reviewed v2 backend must produce controller-verifiable,
privacy-bounded evidence for the exact attempted cell.

Before launch, that evidence must prove at least:

- a fresh cell and non-root effective user;
- a read-only base and root filesystem where practical, with explicit mounts
  only and a single writable job tree plus bounded temporary storage;
- no visible `.git` pointer, shared Git metadata, host credentials, cloud
  credentials, billing attestations, or host-control socket;
- network namespace disabled by default, with no implicit resolver or proxy
  escape; and
- enforced CPU, memory, process, output, disk, wall, and idle limits.

After launch, controller evidence must prove at least:

- all cell processes and resources are gone;
- no writes occurred outside the job tree and controller-owned run area;
- no network, credential, or control-socket access occurred;
- the frozen source, registration, and command identities remained bound to the
  executed attempt; and
- the returned candidate can be read through a controller-owned, no-follow,
  bounded reconciliation path.

Backend self-reports are inputs to verification, never the only proof. Missing,
stale, contradictory, or unverifiable evidence blocks the attempt, with
partial output quarantined.

## Live harness boundary

The operator's confirmation of included subscription capacity and disabled paid
continuation is necessary for a future live run, but it does not solve worker
credential isolation. An unattended tool-enabled harness remains disabled
until the backend can demonstrate that model tools cannot read, persist, or
exfiltrate the provider-auth store. The first worker-cell integration therefore
uses deterministic mock execution only. A live-harness canary is a later,
separate, explicitly gated decision.

## Implementation sequence and acceptance gates

1. **Backend review and laboratory probe:** select one local VM/container
   runtime, record its exact supported host/runtime versions, and run only
   non-production adversarial probes. No repository worker is enabled.
2. **Controller materialization:** the implemented v1 source-bundle contract
   now binds a bounded controller input to registration policy without I/O; it
   does not make a tree or establish snapshot freshness. Build the remaining
   no-Git, no-symlink job tree and controller-owned patch reconciler. Test that
   the primary checkout and shared Git data remain unchanged on success,
   failure, timeout, and crash.
3. **Authoritative dispatch PEP:** add append-only decision and receipt
   records, exact replay, read-only audit coverage, and cancellation/lease
   rechecks. It remains connected only to a deterministic mock cell until the
   next gate passes.
4. **Verified containment backend:** add the reviewed v2 backend, observed
   preflight/postflight evidence, post-run reconciliation, and adversarial
   isolation tests. It still starts with deterministic mock payloads.
5. **Narrow live canary:** only after separate harness-auth isolation proof,
   fresh billing evidence, explicit live gate, and a human-approved test plan.

Every stage must preserve `dispatch_enabled: false` until its stated
predecessors are demonstrated. No stage installs a daemon, recurring schedule,
network access, Git publication, message delivery, deployment, or automatic
promotion.

The minimum adversarial suite includes traversal and symlink attacks,
job-tree-race attempts, protected-path writes, Git metadata and socket access,
credential-path probes, attempted network access, resource exhaustion,
process-tree escape attempts, cancellation during launch, crash recovery, and
changed argv/cwd/environment/input replay. A single false green, out-of-cell
write, credential disclosure, paid-route start, or escaped process resets the
affected gate.

## Operator decision and remaining implementation boundary

The operator approved the proposed local VM-contained-container direction and
authorized a bounded non-production laboratory probe. The resulting
[`laboratory record`](worker-dispatch-laboratory-probe-2026-08-03.md) shows
that selected Docker Desktop restrictions held for the exact test, but also
that resolver configuration was injected. It is preliminary evidence, not a
containment proof or approval of a production backend.

That approval permits only further deterministic controller and test work. A
real backend still needs its own review of VM configuration, image provenance,
launcher behavior, resolver/proxy suppression, observed preflight/postflight
evidence, and the adversarial suite above. Worker dispatch remains disabled
until every stated predecessor is demonstrated.
