# Documentation map

Use this page to choose the narrowest authoritative document for a task. The
repository intentionally keeps operator orientation, current implementation
status, durable policy, and future plans separate.

| Document | Canonical purpose |
| --- | --- |
| [`../README.md`](../README.md) | Product boundary, quick start, operator workflow, and deliberate current limits |
| [`../AGENTS.md`](../AGENTS.md) | Durable safety and collaboration rules for coding agents |
| [`architecture.md`](architecture.md) | Implemented component boundaries, control flow, persistence, and failure handling |
| [`implementation-status.md`](implementation-status.md) | Detailed current-capability and evidence-boundary ledger |
| [`authorization-model.md`](authorization-model.md) | Runtime authorization vocabulary, policy decisions, enforcement state, and migration constraints |
| [`subscription-only-policy.md`](subscription-only-policy.md) | Subscription-only billing, credential, attestation, and post-run invariants |
| [`routing.md`](routing.md) | Execution profiles, eligibility, selection evidence, billing lanes, and target routing policy |
| [`roadmap.md`](roadmap.md) | Prioritized delivery phases and explicit deferrals |
| [`ordomata-implementation-plan.md`](ordomata-implementation-plan.md) | Target design, acceptance criteria, and long-form delivery plan |
| [`openclaw-ecosystem-assessment.md`](openclaw-ecosystem-assessment.md) | Non-normative ecosystem research and prior art |
| [`../fixtures/README.md`](../fixtures/README.md) | Sanitized fixture provenance and maintenance rules |

Current code, schemas, fixtures, and tests are the executable source of truth.
If they disagree with prose, investigate the intended contract and update the
stale document rather than duplicating another description elsewhere.

The detailed executable-closure proof modules deliberately repeat some frozen
validation logic so later monkeypatches cannot replace earlier proof
primitives. Do not consolidate that repetition as ordinary deduplication
without a versioned security design and focused compatibility tests.
