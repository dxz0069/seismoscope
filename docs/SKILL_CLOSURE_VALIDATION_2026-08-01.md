# Skill Closure Validation - 2026-08-01

## Scope And Evidence Boundary

This validation exercised the local Vibe Sec Skill/CLI implementation. The
remote lab host was used only to obtain authorized source snapshots and confirm
that the published lab endpoints were reachable. No live exploit payload,
credential collection, destructive action, or production target was used.

| Asset | Source identity | Local validation result | Claim boundary |
| --- | --- | --- | --- |
| VAmPI | `/root/VAmPI`, commit `f16052d`; exported snapshot SHA-256 `995BBF23DF2035EC34E27EAFAF1C8F321C4799E4B44FE9A84B8742A29D7FEA24` | Skill audit: 1 candidate, 1 `needs_evidence`, 1 remediation package | A small static review queue, not an accuracy or exploitability claim |
| Juice Shop | Authorized source subset excluding `.git`, dependencies, and built output; export SHA-256 `7FD24BA133E3127AAF21D7043D721FB4D09BF09751A5EED0496EEDCCCBD6F68D` | Skill audit: 99 candidates, 1 rejected, 29 `needs_evidence`, 69 deferred by verification budget, 29 remediation packages | Triage queue only; no CVE/challenge ground truth was asserted |
| Agent/MCP fixture | Local fixed fixture and an isolated copied remediation lab | Initial audit: 16 candidates, 2 rejected, 14 `needs_evidence`; one command-execution remediation was fixed and closed | Demonstrates the full local harness loop, not a claim about an external system |

The complete Skill summaries are stored under `.lab-cache/results/`. Full audit
objects are referenced by the corresponding local artifact manifest. The
durable sessions are in `.lab-cache/sessions/`.

## Closed Agent/MCP Loop

The fresh runtime-projection-v4 session `run-3be84ceab7e14d5f` generated
`REMEDIATION-cluster-e6638b678b098573` for the command-execution location in
the local lab copy. The coding-context return changed only:

- `vulnerable_app.py`: replaces direct `shell=True` execution with a bounded
  `status` command allowlist and `shell=False` argument-vector execution;
- `tests/test_smoke.py`: adds a negative assertion for shell interpretation
  and a positive assertion for the allowed command path.

The return package included `state=completed`, `fix_result.status=fixed`, the
declared changed files, and evidence records bound to both
`negative-exploit` and `positive-behavior` control IDs. A local signed approval
was issued for the critical consequential change. `retest` then recorded:

| Gate | Result |
| --- | --- |
| Signed project/session/package-bound confirmation | passed |
| Negative exploit control and positive behavior control | passed with artifact reference |
| Isolated project test | passed: `python -m unittest discover -s tests -q` in `python:3.12-slim`, network disabled, read-only workspace |
| Changed-tree scope | passed: only the required source file and allowed test file changed |
| VRTM post-fix diff | no authority expansion, trust-boundary change, control regression, or review requirement |
| Closure state | `closed_count=1`, `open_count=0` |

The prior v3 run intentionally remained open even though regression passed:
the previous source-location-based graph identities produced a false authority
expansion after an implementation edit. That result was retained as evidence,
not overridden. The fix is the v4 semantic identity scheme described below.

## Product Changes Validated

1. `RunSession` now persists the Skill request, VRTM baseline, dispatched
   package summaries, return checkpoint, retest reports, closure record, and
   post-fix VRTM snapshot.
2. VRTM context travels into remediation packages as surface-node bindings,
   risk-hypothesis IDs, control gaps, evidence predicates, expected surface
   change, and forbidden authority/scope changes.
3. A high-impact package cannot be closed on a coding-agent assertion. It
   needs a local signed approval bound to its project, session, and package.
4. Retest evidence must identify the planned control ID and match the exact
   post-fix predicate. Legacy bare `passed` claims remain visible to regression
   reporting but cannot satisfy the closure gate.
5. VRTM graph identities for code blocks, entry points, and trust boundaries
   now use semantic source anchors instead of line numbers. A pre-v4 model is
   marked as an identity-scheme migration and does not create a false security
   regression; a new baseline is required for future diffs.

## LLM Boundary

The local runtime had no active LLM credential during the lab run, so all three
source audits used the deterministic path. This is intentional: `--use-llm`
fails without explicit configuration and never falls back to a mock provider.
The bounded multi-turn audit/verification state machines, tool evidence
binding, forced finalization, degradation behavior, and immutable finding IDs
are covered by the automated ReAct contract tests. A real-provider acceptance
run remains a separate credentialed validation task and must not be claimed
from these static lab results.
