# Project instructions

This repository implements a local, single-operator agent orchestrator. Preserve these requirements:

- AI-assisted runs must use a verified first-party coding harness, current included-subscription capacity, and current account-bound proof that paid continuation is disabled. Purchased product credits, subscription overage, separately billed APIs, and cloud model routes are architecturally prohibited.
- Never add an API-key fallback, AI API SDK, credit/overage fallback, or option that enables metered AI inference.
- Live harness runs are opt-in and require `AGENTOPS_ALLOW_SUBSCRIPTION_RUNS=1`, but that gate is necessary and never sufficient; normal tests and development must use deterministic mocks.
- Never print, persist, or pass prohibited credential values. Child-process environments must be constructed from a narrow allowlist.
- Deterministic code owns state, permissions, scheduling, evaluation, billing gates, post-run billing disposition, circuit breakers, and promotion. Agents cannot widen their own authority.
- Only permission classes 0 (read-only) and 1 (local draft) are enabled at this stage.
- Do not install recurring schedules, send messages, change calendars, merge, deploy, push, or perform other consequential actions automatically.
- Use Python 3.12+ and the standard library unless a dependency is explicitly justified and approved.
- Keep run, capacity, and billing-circuit records append-only; quarantine artifacts after paid or unknown post-run billing evidence; keep changes reviewable and tests free of live model calls.

Run verification with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests
```
