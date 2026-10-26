# LLM Provider Acceptance - 2026-08-02

## Status

The real DeepSeek provider is connected and a bounded local-only acceptance
flow completed successfully:

`VRTM -> LLM Skill audit -> remediation package -> local fix -> signed approval -> isolated retest -> VRTM closure`

This document covers local fixture copies only. It does not assert a
vulnerability in a remote system and no remote source or lab was changed.

## Credential Boundary

- The user-supplied provider credential was placed only in a process-local
  environment variable for the request, then cleared.
- It is absent from source, API state, session snapshots, artifacts, test
  evidence, and this document.
- A fixed minimal `deepseek-chat` request completed with `finish_reason=stop`.
- The connection-test API remains redaction-safe: it returns only a bounded
  connection state and never returns a credential or model response.

## Real Provider Runs

| Run | Local target | Result | Evidence boundary |
| --- | --- | --- | --- |
| `run-de35d133853d43a0` | Agent/MCP closure fixture | 16 candidates; 2 `needs_evidence`; 14 deferred by explicit verification budget; no false confirmation | Session snapshot: `.lab-cache/sessions-llm-v2/run-de35d133853d43a0.jsonl` |
| `run-4cd6773a82d34606` | Code-injection closure fixture | 6 candidates; 2 `needs_evidence`; 4 deferred by budget | Full audit artifact: `.lab-cache/state-llm-closure/artifacts/run-4cd6773a82d34606/artifact-680c0c614d8243c39d4ca2a6732a1296.json` |

Deferred candidates are not reclassified as safe or fixed. They were not
reviewed because the real-provider acceptance profile limits discovery,
finding review, verification, and ReAct turns to keep cost and runtime bounded.

## Verified Remediation Closure

The second run produced one evidence-backed package for a local Flask fixture:

| Field | Value |
| --- | --- |
| Session | `run-4cd6773a82d34606` |
| Package | `REMEDIATION-cluster-0b495a94419165d1` |
| Finding | `code_injection` in `vulnerable_app.py` |
| Fix | Removed dynamic evaluation and added a bounded arithmetic AST evaluator |
| Approval | Signed local approval bound to the project, session, and package |
| Retest evidence | `artifact-4431eca21c784ccb8dc7d9f065eb0cee` |
| Final result | `closed_count=1`, `open_count=0` |

The negative control sent a dynamic-import expression to `/calculate` and
observed HTTP 400 before any dynamic evaluation. The positive control sent
`7 + 5` and observed the intended JSON result. The fixture also contains an
AST assertion that no `eval` or `exec` call remains.

The final platform result is stored at
`.lab-cache/state-llm-closure/code-injection-retest-final.json`.

## Isolation And VRTM Gates

- The project test command completed in `vibe-sec-python-flask:3.1.3` with
  `network=none`, a read-only workspace, dropped capabilities, a non-root
  user, and bounded CPU, memory, PID, and temporary filesystem settings.
- The isolated command ran all 5 fixture tests successfully.
- Changed-tree validation accepted only `vulnerable_app.py` and
  `tests/test_smoke.py`, which are within the package's declared source/test
  scope.
- VRTM preflight found no authority expansion, new boundary crossing, or
  control regression. The post-fix model accepted the remediation observation
  and bound it to the changed runtime code block.
- The fixture VRTM remains `degraded` because other intentionally vulnerable
  routes still have unresolved authentication and boundary facts. That is a
  coverage diagnostic, not a failure of this closed package.

## VAmPI Transfer Validation

The same real-provider workflow was then exercised against a clean local copy
of VAmPI commit `f16052dce83f05847133ec98f01c5193a41de7d8`.

| Field | Value |
| --- | --- |
| Session | `run-4d944501145b449b` |
| LLM result | One SQL injection package at `models/user_model.py:72`; initially `needs_evidence` |
| Package | `REMEDIATION-cluster-49eba828722d6af1` |
| Fix | Replaced raw username SQL construction with `User.query.filter_by(username=username).first()` |
| Controls | Injection-shaped username no longer returns a record; known username still returns its user |
| Isolated tests | 3 of 3 passed in `vibe-sec-vampi-runtime:py311`, with no network and a read-only workspace |
| Closure | `closed_count=1`, `open_count=0` |
| Final result | `.lab-cache/state-llm-vampi-v2/vampi-sql-injection-retest-final.json` |

Before the fix, a one-shot in-memory SQLite probe bound to the actual
`User.get_user` method showed that an injection-shaped username returned a
record. The same probe returned no record after the fix while the valid lookup
continued to succeed. This is controlled local evidence only.

The VAmPI application entrypoint has a separate, pre-existing `app`/`config`
circular-import failure while loading its OpenAPI handlers. The endpoint was
therefore not started or changed. The validation was intentionally bound to the
affected ORM method using an in-memory database, which keeps the finding and
the remediation scope precise. VRTM accepted the post-fix observation and
found no authority expansion, boundary addition, or control regression; its
overall `degraded` state continues to represent unrelated unknown
authentication/boundary facts.

## Juice Shop Evidence-Quality Validation

Juice Shop 20.1.1 was assessed and remediated only in the local working copy
`.lab-cache/juice-shop-llm-closure-v1`. The original snapshot at
`.lab-cache/juice-shop-source` was preserved and was not changed. This
application is intentionally vulnerable, so this closure validates the
platform workflow; it does not claim that the challenge route is an accidental
production defect.

| Field | Value |
| --- | --- |
| Final LLM session | `run-2528bbc8947a4a57` |
| Result artifact | `.lab-cache/state-llm-juice-v5/artifacts/run-2528bbc8947a4a57/artifact-c90086110a5345a3997215d6c0bc6ed2.json` |
| Final candidate count | 96 total; 2 `needs_evidence`; 94 deferred by the explicit verification budget |
| Remediation package | `REMEDIATION-cluster-2b4e565d4c1d4a98` for `routes/b2bOrder.ts:23` |
| Approval | `approval-854495b5bb3f8f70358042cd`, bound to the local project, session, and package |
| Final closure | `closed_count=1`, `open_count=0` |
| Final result | `.lab-cache/state-llm-juice-v5/juice-b2b-retest-final.json` |

The LLM package identified the public B2B route's
`vm.runInContext('safeEval(orderLinesData)', ...)` path, which receives
`body.orderLinesData`. Before the fix, controlled no-side-effect expressions
returned `42` and `7` through that exact evaluator. The evidence run was local
only, network-disabled, read-only, non-root, capability-dropped, resource
limited, and bounded by a VM timeout. It did not use filesystem, network,
shell, or destructive payloads.

The local fix removed `vm`, `notevil`, and request-controlled evaluation from
`routes/b2bOrder.ts`, while retaining the normal B2B JSON response. The added
`test/server/b2bOrder.security.unit.test.ts` asserts both that the evaluator
path is absent and that a normal request still returns its CID, order number,
and a future payment date. The source and test hashes are recorded in
`.lab-cache/juice-evidence/b2b-order-postfix-controls.json`.

The final platform retest passed all three gates: evidence-bound negative and
positive controls, the isolated Node test, and declared changed-tree scope.
The isolated test used `vibe-sec-juice-runtime:node24` with `network=none`, a
read-only workspace, non-root execution, dropped capabilities, and bounded
CPU, memory, PID, and temporary filesystem resources. The local runtime was
built without relying on a public npm registry: its Node dependencies use
`https://registry.npmmirror.com`. `VIBE_SEC_NODE_TEST_IMAGE` selected this
prebuilt local image only for the retest process and does not persist in
project configuration.

VRTM accepted post-fix observation `obs-5a1262dde152dbf5` and recorded the
changed runtime code block without an authority expansion, boundary addition,
or control regression. Its overall status remains `degraded` because this
large intentionally vulnerable application has 246 routes with unknown
authentication facts; that coverage diagnostic is separate from the closed
B2B remediation package.

The run also corrected four JavaScript/TypeScript scanner false-positive
classes: `RegExp.exec()`, identifiers such as `safeEval()`, ordinary
`function (...)` syntax, and fixed `new Function(...)` / VM parser wrappers.
The resulting deterministic Web scan reduced from 44 matches to 8 and retained
the intended code-evaluation surfaces (`b2bOrder`, `captcha`, and
`userProfile`) for this class.

## Product Changes From This Acceptance

1. Python static scan rules for `eval`/`exec` and shell-enabled process calls
   now bind to Python AST call nodes. Test assertion literals and comments no
   longer become critical candidates, while executable calls remain detected.
2. `retest --test-command` now accepts the full argument vector, including
   interpreter flags such as `-m` and test flags such as `-q`.
3. `VIBE_SEC_PYTHON_TEST_IMAGE` can select a pre-prepared Python test image for
   the current process. The default remains `python:3.12-slim`; this override
   does not relax the isolated runtime controls or persist in project config.
4. JavaScript/TypeScript code-injection signals now distinguish global dynamic
   evaluators from `RegExp.exec()`, safe-wrapper identifiers, function syntax,
   fixed constructor wrappers, and non-evaluator VM parser calls. The verifier
   retains direct request-to-VM execution evidence without upgrading indirect
   flows absent an isolated dynamic control.
5. `VIBE_SEC_NODE_TEST_IMAGE` provides a process-local Node image override for
   isolated retests, matching the existing Python image override without
   weakening the container controls or persisting an environment setting.
6. The `retest` CLI accepts UTF-8 JSON with an optional BOM. This preserves the
   payload and makes PowerShell-generated remediation packages usable on
   Windows.

## Verification

- Focused platform regression: `11 passed`
- Closure fixture tests: `5 passed`
- Final isolated retest: 3 of 3 gates passed
- VAmPI local-copy isolated regression: `3 passed`
- VAmPI remediation closure: one closed package, zero open packages
- Full platform test suite: `222 passed, 1 skipped`
- Frontend production build: passed
