# Worker-dispatch laboratory probe — 2026-08-03

**Status:** bounded, non-production laboratory evidence. This is not a
containment proof, does not enable a worker, and does not change
`dispatch_enabled: false`.

## Purpose and scope

After the operator approved the proposed VM-contained-container direction, a
single disposable Docker Desktop probe checked whether a deliberately
restricted Linux container could expose basic evidence needed for a later
backend review. It received no repository tree, Git metadata, user-supplied
directory mount, controller-provided credential, Docker socket, proxy
environment, network, model command, or worker task.

The observations below describe this exact laboratory run only. They do not
establish a supported production runtime, authenticate an image, prove the
Docker Desktop VM configuration, or confer authority on the current inert
worker-cell contract.

## Recorded environment

| Fact | Observed value |
| --- | --- |
| Container engine | Docker Engine `29.6.1` |
| Guest platform | `linux/arm64` |
| Laboratory image | `busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662` |
| Local image ID | `sha256:b7c873bd97bdc9046fc894e0b216c8aef31e0db4c5b761fb53022e40577ab6c0` |
| Pull/runtime policy | Explicit Linux/arm64 pull; later runs used the recorded digest with `--pull=never` |

BusyBox was selected only as small, disposable laboratory tooling. Its pull
does not approve it as a future worker image or satisfy the provenance review
required for a real backend.

## Baseline probe

The disposable container used all of the following constraints:

- `--network none` and no user-supplied bind mount;
- `--read-only`, with only `/tmp` as a `noexec,nosuid`, 16 MiB tmpfs;
- `--user 65532:65532`, `--cap-drop ALL`, and
  `--security-opt no-new-privileges:true`;
- `--pids-limit 64`, `--memory 128m`, `--memory-swap 128m`, and
  `--cpus 0.50`; and
- `--rm` plus a unique, probe-only container name.

The initial probe observed:

| Check | Observation |
| --- | --- |
| Effective user | `65532` |
| Write to root filesystem | Blocked |
| Write to `/tmp` | Allowed |
| Process limit | `pids.max = 64` |
| Memory limit | `memory.max = 134217728` |
| CPU quota | `cpu.max = 50000 100000` |
| No-new-privileges | Present in `/proc/self/status` |
| Effective capabilities | Empty in `/proc/self/status` |
| Named sensitive paths | No Docker socket, `/run/secrets`, `/root/.docker`, `/.git`, or `/workspace` |
| Proxy environment | No value in the six common HTTP/HTTPS/ALL proxy names |
| Post-run cleanup | Each exact named probe container was absent after its `--rm` run |

The first probe also found that `/sys/class/net` contained kernel virtual
entries in addition to `lo`, so it deliberately did not count as a green
network-isolation result.

## Follow-up network diagnostic

A second disposable container used the same restrictions and made no network
request. It showed:

| Check | Observation |
| --- | --- |
| IPv4 route-table entries | `0` |
| IPv4 default routes | `0` |
| Common proxy environment values | `0` |
| Mount markers matching the probe's repository/socket paths | `0` |
| Resolver configuration | Nonempty: 222 bytes and one nameserver entry |

The absence of a route is useful evidence that this exact `--network none`
run had no ordinary IPv4 egress path. It does not override the resolver
finding: Docker injected resolver configuration despite the disabled network.
Any future backend must explicitly prevent or verify that configuration rather
than treating a container flag as sufficient proof.

## Conclusion and remaining gates

The probe establishes a viable **laboratory substrate** for further,
deterministic containment work: the tested engine honored the selected
unprivileged-user, read-only-root, capability, no-new-privileges, cgroup, and
no-default-route settings, and it removed the disposable test cells. It does
not establish verified repository-worker containment.

In particular, a real backend remains blocked on all of the following:

1. an independently reviewed VM configuration with no shared host folders;
2. controller-owned no-Git job materialization and no-follow patch
   reconciliation;
3. an authoritative dispatch PEP bound to the exact cell, image/template,
   mounts, argv, registration, policy, and current controller state;
4. controller-verifiable preflight and postflight evidence, including resolver
   and proxy suppression, process/cgroup reclamation, and out-of-cell write
   detection; and
5. the full adversarial suite: traversal, symlink and worktree races,
   protected-path writes, credential/control-socket probes, network attempts,
   resource exhaustion, process escapes, cancellation, crash recovery, and
   replay changes.

No live harness, repository worker, repository mutation, networked worker
operation, or promotion was attempted. The next safe implementation step is
the deterministic controller materialization and reconciliation layer, while
worker dispatch remains disabled.
