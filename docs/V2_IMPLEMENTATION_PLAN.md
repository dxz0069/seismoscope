# V2 Implementation Plan

This plan turns `PRODUCT_ARCHITECTURE_V2.md` into concrete engineering phases.

The guiding rule is conservative migration: preserve the current runnable CLI/Skill path while introducing clearer contracts underneath it. Do not copy large modules from AutoCVE or lz-secure. Rebuild the useful concepts behind stable local interfaces.

## Phase 0: Baseline Cleanup

Goal: make the current project reliable enough to change.

Tasks:

1. Fix version consistency.
   - Align `pyproject.toml`, `core/__init__.py`, API version, README, and docs.

2. Remove generated runtime artifacts from the repository.
   - Remove `__pycache__` and `.pyc` files.
   - Add `.gitignore`.
   - Remove or explain the nested `vibe-sec-platform/knowledge_base` directory.

3. Fix test execution.
   - Convert `tests/test_basic_audit.py` from demo script to real pytest assertions.
   - Ensure async tests work with `pytest-asyncio`.
   - Add a no-cache test command for local Windows environments if needed.

4. Fix report and documentation encoding.
   - Normalize generated-facing text to UTF-8.
   - Keep internal code comments concise and readable.

5. Add a minimal development command set.
   - `python -m pytest`
   - `python -m main audit tests/fixtures --format markdown`
   - `python -m main version`

Exit criteria:

- The current fixture audit still returns findings.
- Tests run reliably.
- The repo no longer depends on checked-in bytecode.

## Phase 1: Harness Schemas

Goal: define stable objects before refactoring behavior.

Add modules:

```text
core/harness/
  __init__.py
  return_protocol.py
  trigger_policy.py
  gates.py

core/session/
  __init__.py
  models.py
  store.py

core/audit/
  __init__.py
  models.py
  lanes.py

core/policy/
  __init__.py
  permission_policy.py
  closure_policy.py
```

Core schema work:

1. `RunSession`
   - `session_id`
   - `project_path`
   - `mode`
   - `status`
   - `started_at`
   - `completed_at`
   - `metadata`

2. `RunEvent`
   - phase event
   - agent event
   - tool event
   - policy event
   - evidence event

3. `Checkpoint`
   - phase
   - state
   - artifact refs
   - resumability metadata

4. `Finding`
   - current dictionary findings should move toward this object.
   - Include `verification_status`, `evidence_refs`, `risk_chain_id`, and `evidence_gaps`.

5. `EvidenceBundle`
   - code snippets.
   - tool traces.
   - browser artifacts later.
   - sha256 and artifact path metadata.

6. `RemediationReturn`
   - finding.
   - evidence summary.
   - risk chain.
   - `ai_patch_prompt`.
   - patch constraints.
   - retest plan.
   - acceptance criteria.

Exit criteria:

- Existing agents can still return dictionaries.
- New schemas can wrap or normalize existing dictionaries.
- Output formatter can render from the normalized schema.
- Runtime modeling, evidence, remediation return, and retest closure all have named schemas instead of ad hoc dictionaries.

## Phase 1.5: Competitive Capability Contracts

Goal: turn the product's core advantages into enforceable engineering contracts.

### Runtime Surface Modeling Contract

Define what counts as a security-relevant runtime surface entity:

- page entry;
- API route;
- prompt;
- agent role or instruction;
- tool;
- MCP resource/tool/server;
- permission profile;
- storage key;
- browser sink;
- external content source;
- workflow node;
- code block.

Every entity should have:

- stable id;
- type;
- source location when available;
- confidence;
- metadata;
- evidence refs.
- threat-modeling metadata when available.

Define graph edge semantics:

- calls;
- renders;
- reads;
- writes;
- authorizes;
- invokes_tool;
- receives_external_content;
- crosses_trust_boundary;
- exposes_capability;
- stores_sensitive_data.

Define threat-modeling fields:

- asset;
- entry point;
- trust boundary;
- data flow;
- privilege level;
- actor;
- threat category;
- candidate attack technique;
- precondition;
- impact hypothesis;
- evidence predicate.

The runtime model should support two complementary views:

1. Microsoft-style threat modeling view:
   - assets;
   - entry points;
   - trust boundaries;
   - data flows;
   - privileged operations;
   - threat categories.

2. ATT&CK-style path view:
   - adversary goal;
   - technique;
   - preconditions;
   - boundary traversal;
   - evidence predicate;
   - likely impact.

Exit criteria:

- A finding can point to one or more runtime-surface node ids.
- A high-risk finding can either produce a `RiskChain` or a clear `evidence_gap`.
- Reports can explain the risk path without exposing raw graph internals.
- The model can distinguish ordinary implementation bugs from cross-surface risk chains involving prompts, tools, MCP, permissions, browser sinks, or workflow nodes.

### Controlled Verification Contract

Define verification as predicate evaluation, not model opinion.

LLM agents are still core to the verification workflow. They can:

- generate hypotheses;
- select likely verification methods;
- draft PoC or harness code;
- interpret logs and artifacts;
- propose fix and retest plans.

The harness controls whether those LLM outputs become trusted state.

Each verification result should include:

- method;
- predicate;
- expected unsafe signal;
- observed result;
- evidence refs;
- confidence;
- status;
- gaps.

Valid statuses:

- `not_attempted`;
- `candidate`;
- `verified`;
- `rejected`;
- `needs_evidence`;
- `blocked`.

Exit criteria:

- Docker or browser execution failure cannot mark a finding verified.
- LLM analysis can raise or lower confidence but cannot close a finding without evidence.
- Retest requires both exploit-negative and positive-control checks when applicable.

### Skill Return Contract

Define the Skill return as the developer-facing security handoff.

It must include:

- concise finding summary;
- evidence summary;
- risk chain summary;
- patch prompt;
- patch constraints;
- retest plan;
- acceptance criteria;
- warning for high-permission agent actions.

Exit criteria:

- The same object can render as Claude Code Skill output, CLI Markdown, or JSON.
- The return object is usable without opening Web UI.

## Phase 2: Session and Event Store

Goal: make audits observable and resumable without adding a central database.

Implementation:

1. Add JSONL session store first.
   - Default path: `.vibe-sec/sessions/<session_id>/events.jsonl`
   - Artifacts: `.vibe-sec/sessions/<session_id>/artifacts/`
   - Checkpoints: `.vibe-sec/sessions/<session_id>/checkpoints/`

2. Add event emission to orchestrator phases.
   - phase started.
   - phase completed.
   - phase failed.
   - finding emitted.
   - evidence stored.
   - remediation returned.

3. Keep API persistence separate.
   - Do not force FastAPI memory DB into the harness core.
   - API can later read the session store.

Exit criteria:

- Running CLI audit creates a session folder.
- The final report includes a session id.
- Failed audits preserve partial state.

## Phase 3: Deterministic Orchestration Upgrade

Goal: make the workflow explicit and gateable.

Tasks:

1. Add `PLAN` and `RETURN` phases.
   - Current flow starts at recon and ends after regression.
   - V2 should explicitly model trigger planning and remediation return.

2. Replace implicit phase payloads with typed phase context.
   - `ProjectProfile`
   - `RuntimeSurface`
   - `FindingSet`
   - `VerificationResultSet`
   - `RemediationReturnSet`

3. Add phase gates.
   - If recon fails, stop.
   - If audit emits high-risk finding without evidence, mark evidence gap.
   - If verification cannot run, do not claim verified.
   - If remediation lacks acceptance criteria, block return.

4. Introduce FinalizeFinding-style contract.
   - Audit lanes must finalize findings through a shared builder/schema.
   - Do not append arbitrary dictionaries directly as final output.

5. Wire ReasoningGuard as a blocking check.
   - Before marking a finding verified.
   - Before returning remediation.
   - Before closing retest.

Exit criteria:

- Orchestrator exposes a clear list of completed phases.
- Failed gates produce useful errors and partial artifacts.
- Reports distinguish `candidate`, `verified`, `rejected`, and `needs_evidence`.

## Phase 4: Audit Lanes

Goal: split the current growing `AuditAgent` into clear lanes.

Suggested files:

```text
agents/audit/
  __init__.py
  web_audit_agent.py
  agent_audit_agent.py
  mcp_audit_agent.py
  secrets_audit_agent.py
  workflow_audit_agent.py
  merge.py
```

Migration path:

1. Extract existing web patterns to `web_audit_agent.py`.
2. Extract prompt/tool/agency patterns to `agent_audit_agent.py`.
3. Extract secret patterns to `secrets_audit_agent.py`.
4. Add MCP-specific lane after schemas stabilize.
5. Add workflow lane after RuntimeSurfaceGraph is present.

Exit criteria:

- Existing fixture still produces expected categories.
- Lanes can be enabled/disabled by audit scope.
- Merge deduplicates across lanes.

## Phase 5: Surface Graph and Risk Chain

Goal: connect findings to runtime relationships, not just files and lines.

Tasks:

1. Strengthen `RuntimeSurface`.
   - Keep current builder.
   - Add stable IDs for entries, prompts, tools, permissions, boundaries, and code blocks.

2. Add `RuntimeSurfaceGraph`.
   - Node types: page, api_route, prompt, tool, permission, storage, browser_sink, external_source, code_block.
   - Edge types: calls, reads, writes, renders, authorizes, invokes_tool, crosses_boundary.

3. Attach `RiskChain` during merge.
   - Source signal.
   - Preconditions.
   - Boundary path.
   - Impact hypothesis.
   - Evidence predicates.

Exit criteria:

- Each high/critical finding has either a risk chain or an explicit gap.
- Reports can show risk path summaries.

## Phase 6: Verification Semantics

Goal: make verification honest and useful.

Tasks:

1. Fix current Docker verification semantics.
   - Execution failure must not automatically mean verified.
   - Verification scripts should assert specific exploit predicates.

2. Add verification levels.
   - `static`
   - `surface_consistency`
   - `sandbox`
   - `browser`
   - `retest`

3. Add evidence gaps.
   - Docker unavailable.
   - Target app cannot start.
   - Browser evidence not applicable.
   - Missing route or line changed.

4. Add positive controls for retest.
   - The exploit should fail.
   - The legitimate path should still work.

Exit criteria:

- Findings are not silently upgraded to verified.
- Reports clearly explain verification method and gaps.

## Phase 7: Remediation Return Loop

Goal: make findings actionable for the coding agent.

Tasks:

1. Normalize `RemediationBundle`.
   - Include package id.
   - Include finding id/title/severity.
   - Include risk chain summary.
   - Include evidence refs.
   - Include patch constraints.
   - Include retest plan.

2. Add return renderers.
   - Claude Code Skill return.
   - CLI Markdown.
   - JSON.

3. Add retest command.
   - Retest by session id.
   - Retest by finding id.
   - Retest all unresolved findings.

Exit criteria:

- A finding can become a returned remediation package.
- The package can drive a coding-agent repair.
- Retest can decide whether it is closed.

## Phase 8: Skill-First UX

Goal: make the harness natural in Vibe Coding.

Skill commands should map to harness actions:

- Audit this project.
- Audit recent changes.
- Audit this feature.
- Audit before commit.
- Generate remediation package.
- Retest after fix.
- Explain evidence.
- Show unresolved high-risk findings.

The Skill should explain when it triggers:

- explicit request.
- sensitive file/code change.
- high-permission tool or agent behavior.
- pre-commit/release checkpoint.
- post-fix retest.

Exit criteria:

- Skill documentation matches the new harness workflow.
- Skill output uses remediation return protocol.

## Deferred Work

These are later product layers:

- Web UI.
- Team accounts.
- Central task database.
- Distributed workers.
- Replay-lab bulk import.
- Enterprise policy dashboard.
- Plugin marketplace.

## First Engineering Sprint Recommendation

The first sprint should be:

1. Baseline cleanup.
2. Harness/session schemas.
3. JSONL session store.
4. Verification semantics fix.
5. RemediationBundle normalization.
6. Real pytest coverage for current fixture flow.

This gives a stable base before moving to lane extraction and deeper verification.
