# LLM Multi-Lab Retest (2026-08-02)

## Scope And ROE

- Objective: validate the local Vibe Sec Platform's bounded LLM review and
  evidence workflow across Python/API, Agent/MCP, and TypeScript/Node fixtures.
- In scope: local source copies only: `.lab-cache/VAmPI`, `tests/fixtures`, and
  `.lab-cache/juice-shop-source`.
- Out of scope: starting a target service, remote target access, exploit
  execution, browser automation, containers, dependency-network inspection,
  target writes, and VRTM persistence.
- Provider: DeepSeek OpenAI-compatible endpoint with `deepseek-v4-flash`.
  The credential was read from the local key file for each process, removed
  from the process environment in `finally`, and never written to source,
  session metadata, reports, or command output.

Every run used `use_llm=True`, ReAct audit and verification enabled, discovery
disabled, `react_review_limit=2`, `max_verification_count=2`,
`verification_fraction=0.0`, `react_max_turns=4`, and source-only tools.

## Runtime Fixes Validated

1. `DeepSeekService` uses `https://api.deepseek.com` and
   `deepseek-v4-flash` by default.
2. DeepSeek accepts normal tool calls but rejects OpenAI's named-function
   `tool_choice` form with HTTP 400. After the evidence budget is reached,
   terminal turns now use a no-tool structured JSON response rather than the
   unsupported named-function hint. The prompt lists concrete completion fields
   and explicitly prevents the model from returning JSON Schema keywords as
   finding values.
3. DeepSeek can return multiple tool calls despite `parallel_tool_calls=False`.
   The ReAct runtime now preserves the whole assistant batch, executes each
   tool serially under the same policy, and returns every matching tool result
   before the next model request.
4. `react_review_limit` is now a global cross-lane budget. Every enabled lane
   first registers static candidates; the shared allocator selects the global
   highest risk candidates by severity, confidence, and stable order. This
   prevents noisy lanes from consuming the LLM budget before critical paths.

The focused regression set for these changes passed:

```text
47 passed in 0.89s
```

Relevant implementation and test coverage:

- `core/agent_runtime/react.py`
- `core/agent_runtime/loop.py`
- `core/audit/review_budget.py`
- `agents/audit_agent.py`
- `core/orchestrator/orchestrator.py`
- `tests/test_agent_runtime.py`
- `tests/test_parallel_finding_review.py`

## Results

| Lab | Static candidates | Merged candidates | LLM audit reviews | LLM verification sessions | Final evidence state | Primary evidence |
| --- | ---: | ---: | --- | --- | --- | --- |
| VAmPI | 1 | 1 | 1 completed, 2 read-only tools | 1 completed, 2 controlled evidence tools | 1 `needs_evidence`; no false confirmation | `.lab-cache/benchmarks-v1-llm/vampi-v3/audit-llm-bounded-v3.json` |
| Agent/MCP fixture | 17 | 16 | 2 completed, 2 tools each; 15 static candidates outside LLM budget | 2 degraded safely to `needs_evidence`; 14 budget-deferred | 0 verified, 0 rejected, 2 `needs_evidence`, 14 `not_reviewed` | `.lab-cache/benchmarks-v1-llm/agent-mcp-v3/audit-llm-bounded-v3.json` |
| OWASP Juice Shop | 98 | 97 | 2 global-priority reviews; 96 static candidates outside LLM budget | 2 degraded safely to `needs_evidence`; 95 budget-deferred | 0 verified, 0 rejected, 2 `needs_evidence`, 95 `not_reviewed` | `.lab-cache/benchmarks-v1-llm/juice-shop-v2/audit-llm-bounded-v2.json` |

`static candidates` is the lane-level candidate total before merge. `merged
candidates` can be lower because de-duplication and a completed LLM
unconfirmed verdict remove non-reportable candidates. It is not a vulnerability
count. The verification result is conserved in every run: every merged finding
is represented as verified, rejected, needs-evidence, or not-reviewed.

## High-Priority Checks

### VAmPI SQL Injection

- Source anchor: `models/user_model.py:72`.
- Fact: the static SQL injection candidate was retained through provider-backed
  review and verification.
- Result: `needs_evidence`, not verified or rejected. The source-only test did
  not start VAmPI or execute a request, so this is deliberately not a dynamic
  confirmation.

### Agent/MCP Fixture

- The current global priority allocator chose two critical candidates in
  `vulnerable_app.py`: command injection and code injection.
- Both audit ReAct sessions completed after two read-only evidence tool calls.
- One remained `needs_evidence`; one was promoted to an audit candidate. Both
  later verification sessions degraded safely instead of claiming a dynamic
  proof. No result is reported as verified.

### Juice Shop B2B Evaluator

- Source anchor: `routes/b2bOrder.ts:23`.
- Fact: after replacing first-come budget allocation with global priority,
  this critical code-injection candidate received one of the two real LLM audit
  review slots.
- The reviewer collected two read-only evidence tool results but did not
  complete a valid terminal action within four turns. It therefore remains
  `needs_evidence`; it was not promoted to verified or silently discarded.
- The second selected critical candidate completed an LLM review with an
  unconfirmed verdict and is not represented as a reportable merged finding.

### Juice Shop B2B Structured-Terminal Follow-up

- Scope: a repeat review of only `routes/b2bOrder.ts:23` against the local
  Juice Shop source copy. No service was started and no request was issued to a
  target.
- Result: the DeepSeek review completed in three model turns after one
  read-only source-tool batch (three tool records). It used the no-tool
  structured-terminal fallback and satisfied `FinalizeFinding` validation.
- Verdict: `potential`. This is intentionally not `verified`: the exercise
  collected source evidence only and did not perform dynamic validation.
- Sanitized artifact:
  `.lab-cache/benchmarks-v1-llm/juice-shop-b2b-json-terminal/runner-output.json`.
  It contains status, turn count, verdict, completion mode, tool count, and
  response-shape telemetry only; it contains no prompt, model text, provider
  error, or credential.

## Limitations And Next Gate

Facts established by this retest:

- The real provider authenticates, answers normal prompts, performs tool calls,
  and can be used in the local audit workflow.
- DeepSeek-specific tool-call compatibility and multi-tool transcript pairing
  are covered by code and regression tests.
- Global LLM review limits are enforced across parallel audit lanes and select
  critical findings ahead of lower-priority prompt-injection noise.
- Conservative state handling works: incomplete sessions become
  `needs_evidence`; they do not erase static candidates or claim verification.

Not established by this retest:

- Dynamic exploitability of VAmPI, Agent/MCP, or Juice Shop findings.
- Precision/recall for Juice Shop: no complete ground-truth mapping was used.
- Stable finalization for every DeepSeek ReAct session at a four-turn limit.
  The focused Juice Shop B2B follow-up demonstrates a successful three-turn
  structured-terminal completion, while the earlier degraded run shows that
  provider output remains variable and must retain conservative fallback states.

Recommended next gate: rerun only the two `needs_evidence` critical paths with
a six-turn ceiling and an explicit per-path cost cap, then compare terminal
completion and evidence quality against this four-turn baseline. Dynamic
validation should remain a separate, explicitly authorized local-lab phase.
