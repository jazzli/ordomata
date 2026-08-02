# Project instructions

This repository implements a local, single-operator agent orchestrator. Preserve these requirements:

- AI-assisted runs must use a verified first-party coding harness, current included-subscription capacity, and current account-bound proof that paid continuation is disabled. Purchased product credits, subscription overage, separately billed APIs, and cloud model routes are architecturally prohibited.
- Never add an API-key fallback, AI API SDK, credit/overage fallback, or option that enables metered AI inference.
- Live harness runs are opt-in and require `ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1`; the legacy `AGENTOPS_ALLOW_SUBSCRIPTION_RUNS=1` alias may be accepted only when it does not conflict with the canonical variable. That gate is necessary and never sufficient; normal tests and development must use deterministic mocks.
- Never print, persist, or pass prohibited credential values. Child-process environments must be constructed from a narrow allowlist.
- Deterministic code owns state, permissions, scheduling, evaluation, billing gates, post-run billing disposition, circuit breakers, and promotion. Agents cannot widen their own authority.
- Only permission classes 0 (read-only) and 1 (local draft) are enabled at this stage.
- Do not install recurring schedules, send messages, change calendars, deploy,
  push, or perform other consequential actions automatically. A separate
  explicit merge authorization is not required after the repository owner has
  approved the current pull request and asked to proceed in ordinary language;
  treat that instruction as authorization to merge. Before merging, still
  verify the exact repository and pull request, required checks, mergeability,
  intended merge method, and clean local scope.
- Use Python 3.12+ and the standard library unless a dependency is explicitly justified and approved.
- Keep run, capacity, and billing-circuit records append-only; quarantine artifacts after paid or unknown post-run billing evidence; keep changes reviewable and tests free of live model calls.

## Response clarity and comprehension

**Explain meaning before mechanics.** Make technical work easy for a capable
project owner to evaluate without requiring them to reconstruct the conclusion
from file paths, implementation details, or tool output.

### Lead with the outcome

For every substantial response, begin with a concise plain-English explanation
of the bottom line, its practical effect, whether anything changed, and whether
the owner must act or decide. Do not open with raw logs, long file inventories,
stack traces, commands, code excerpts, or low-level mechanics unless the owner
explicitly asks for those first.

Use progressive disclosure in this general order:

1. conclusion or outcome;
2. practical meaning and impact;
3. concise rationale;
4. supporting evidence;
5. implementation details;
6. exact files, commands, logs, or code when useful.

Apply this structure proportionately. Simple questions and brief status updates
should remain brief; omit inapplicable sections, avoid repeating a conclusion
in different forms, and do not force headings onto short answers. Scale detail
to the complexity, risk, and consequence of the work. Include enough context to
make the answer understandable, but do not reproduce large logs or diffs unless
they are requested or necessary.

### Separate facts, conclusions, and proposals

Keep these epistemic states clear, using labels when they help rather than as a
mandatory template:

- **Observed:** directly verified in code, configuration, documentation, tests,
  logs, tool results, or runtime behaviour.
- **Inferred:** a conclusion derived from observed evidence.
- **Recommended:** a proposed action that has not been performed.
- **Completed:** work actually performed.
- **Unresolved:** unverified, blocked, ambiguous, or awaiting a decision.

Never present a recommendation as completed work, an assumption as a verified
fact, or a hypothesis as a confirmed root cause. Never claim to have inspected
a file or passed a test unless that inspection or successful test run actually
occurred. State material uncertainty instead of concealing it with confident
wording.

Tie important conclusions to concrete evidence: inspected code or
configuration, specific documentation, test output, runtime reproduction,
logs, measurements, tool results, or repository history. When uncertainty is
decision-relevant, state high, medium, or low confidence and explain what is
unknown; do not invent numeric confidence scores. Provide concise,
decision-useful rationale and evidence, not private chain-of-thought, hidden
scratch work, or token-by-token deliberation.

### Explain the kind of work performed

For substantial implementation work, normally cover:

1. the outcome and user-visible or system-visible effect;
2. relevant before-and-after behaviour;
3. changes grouped by purpose and why the approach was selected;
4. validation actually performed and its result;
5. known limitations, risks, or unresolved matters;
6. the next action or decision, if one exists.

Group files by purpose instead of giving an unexplained inventory. Describe an
important file by its role in the change, not merely by its path. Clearly
distinguish user-visible behaviour from internal implementation.

For investigations, debugging, reviews, and audits, normally explain the
bottom line, why it matters, the evidence, the likely cause or interpretation,
important alternatives considered, the recommended action, and remaining
uncertainty. Identify a hypothesized root cause as a hypothesis. Rank or group
findings by practical impact when that helps the owner decide what to address.

For an unfamiliar subsystem or architectural explanation, use these layers
when appropriate:

1. a one-sentence mental model of what the subsystem does;
2. the conceptual flow of data, control, or responsibility;
3. the implementation mapping to components, services, modules, interfaces,
   and files.

Use a small text flow such as `Input -> Validation -> Processing -> Persistence
-> Output` when it makes the system easier to understand. Explain why the major
stages exist, where the boundaries lie, and where failures can occur before
diving into individual functions or files.

### Make recommendations actionable

When several meaningful options exist, recommend one first and explain why it
is preferred. State its most important disadvantage, the strongest
alternatives, and the conditions that would make an alternative preferable.
Say whether the decision is reversible and, when material, what delay would
cost or risk. Do not leave the owner with an undifferentiated list when the
evidence supports a practical recommendation.

Define an unfamiliar technical term or abbreviation on first use, and explain
project-specific concepts when the current exchange does not establish them.
Prefer concrete component, interface, and behaviour names over vague
abstractions. Connect technical changes to their effects on users, maintainers,
reliability, security, performance, operations, or future development. Do not
redefine terms already established in the active conversation.

End every substantial response with a definite status: no further action is
required; one specific next action is recommended; a precise decision is
required; work is blocked by a named dependency; or unresolved matters remain
with an explanation of what would resolve them. Avoid vague endings when a
specific recommendation or question is available.

Run verification with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests
```
