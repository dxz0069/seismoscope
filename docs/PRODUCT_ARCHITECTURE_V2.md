# Vibe Sec Platform V2 Product Architecture

## 1. Product Positioning

Vibe Sec Platform is an agentic security audit and verification platform for Vibe Coding workflows. It must deliver a mature AutoCVE-class source-audit engine as a first-class product capability, then extend that engine with runtime-surface modeling, controlled execution, tool integration, and development-context remediation.

The platform is not merely a wrapper around an external review engine. The Harness describes the control and integration responsibility; the Agentic Audit Engine remains a core product capability.

The platform sits around the development agent:

```text
Coding agent generates or changes code
  -> Control plane selects an audit policy and starts a session
  -> Agentic audit engine performs deep source and runtime analysis
  -> Tool fabric supplies fast scanners and isolated security tools
  -> Findings are verified and linked to evidence
  -> Remediation guidance is returned to the development context
  -> Coding agent or user applies fixes
  -> Security harness retests and closes the loop
```

The product goal is to make security a normal, evidence-driven part of the Vibe Coding loop, not a late manual review.

The product is composed of:

```text
AutoCVE-class Agentic Code Audit Engine
  + Runtime Surface Security Modeling
  + Fast Scanner and Security Tool Fabric
  + Controlled Verification Environment
  + Remediation Relay and Regression Closure
  + Skill / CLI / later Web UI Control Plane
```

## 2. Target Users

The product serves all Vibe Coding users, with different surfaces for different maturity levels:

- Independent developers and small teams need low-friction security checks during AI-assisted development.
- AI programming users need a harness that constrains high-permission coding agents and turns findings into actionable repair prompts.
- Enterprise security teams need auditable evidence, repeatable workflows, and eventually centralized task visibility.

The first-class entry point is the Claude Code Skill. CLI is also first-class for automation and local workflows. Web UI is useful later for management and visualization, but it is not the first implementation priority.

## 3. Core Product Value

The platform's value is not only detecting vulnerabilities. Its core value is controlling the security loop:

1. Trigger at the right time.
2. Run a fixed security workflow instead of ad hoc model reasoning.
3. Produce evidence-backed findings.
4. Return remediation packages to the active development workflow.
5. Retest fixes and preserve the audit trail.

This means the platform must model both code and runtime relationships: pages, APIs, prompts, tools, permissions, files, browser actions, external content, and agent capabilities.

## 3.1 Core Competitive Advantages

V2 should be built around three defensible capabilities.

### 3.1.1 Runtime Surface Modeling as Risk Analysis Method

Vibe Coding accelerates product creation, but it also accelerates the creation of unclear security boundaries. A generated application may combine ordinary Web code, backend APIs, embedded assistants, prompts, MCP tools, browser actions, workflow nodes, storage, and external content in one product surface.

Traditional source-code audit can find many implementation defects, but it does not naturally model how prompts, tools, UI sinks, permissions, and runtime actions interact. Traditional Web scanning also misses agent-specific risks such as prompt injection, excessive agency, unsafe tool descriptions, and MCP trust-boundary failures.

The platform should therefore provide a Vibe Coding-era security modeling and risk analysis method. The method should be closer to security architecture analysis than to a scanner rule list. It should borrow the spirit of Microsoft-style threat modeling: identify assets, entry points, trust boundaries, data flows, privileged operations, and threat categories before deciding which checks matter. It should also borrow from ATT&CK-style analysis: describe adversary behavior as techniques and paths across a system, not only as isolated bugs.

The method is:

```text
Project code
  -> RuntimeSurface
  -> RuntimeSurfaceGraph
  -> RiskChain
  -> Evidence-backed finding
```

The graph should place traditional Web risks and AI/agent risks on the same runtime surface. This is the theory-level product differentiation: Vibe Sec is not only scanning files, it is modeling the composite runtime system created by AI-assisted development.

The model should answer risk-analysis questions:

- What are the assets and sensitive operations?
- Where does untrusted input enter?
- Where are trust boundaries crossed?
- Which prompts, tools, MCP resources, APIs, browser sinks, storage keys, or workflow nodes can amplify risk?
- Which attack techniques are plausible on this surface?
- Which evidence predicates would prove or disprove the hypothesis?
- Which fix constraints keep the intended business path alive?

Practical requirements:

- Every runtime-surface node must have a stable id.
- Graph edges must describe security-relevant relationships, not generic dependency noise.
- Nodes and edges should carry threat-modeling metadata where possible: asset, entry point, trust boundary, data flow, privilege level, threat category, and candidate technique.
- Findings should attach to graph nodes or explicitly record why graph attachment is unavailable.
- High-risk findings should produce a risk chain that explains source signal, boundary crossing, and impact.
- Reports should show the model in developer terms, not as abstract graph theory.

### 3.1.2 Agent Orchestration and Controlled Verification

The harness must depend on LLM-powered agents to discover issues, reason about context, generate hypotheses, plan verification, interpret evidence, and produce remediation packages. This is central to the product. Without LLM capability, the platform becomes a conventional rule scanner and loses much of its value in Vibe Coding scenarios.

However, the LLM must not be treated as the source of truth. The harness controls the workflow. The model proposes, plans, investigates, and explains; the harness records evidence, applies gates, checks verification predicates, and decides state transitions.

The orchestration layer should follow AutoCVE as closely as practical in the local Skill/CLI product shape:

- deterministic phases;
- explicit state machine;
- task handoff;
- checkpoints;
- controlled tool execution;
- completion contracts;
- nudge and guard mechanisms.

Verification should be evidence-level based:

- static evidence;
- runtime-surface consistency;
- sandbox or Docker proof;
- browser/service evidence;
- post-fix retest with positive and negative controls.

The key product capability is not "the model said this is vulnerable." The key capability is:

```text
Agent hypothesis
  -> Harness-controlled verification
  -> Evidence predicate
  -> Remediation return
  -> Retest closure
```

### 3.1.3 Skill-First Development Integration

The Skill form is a product advantage because it enters the developer's active Vibe Coding context instead of forcing a separate security workflow.

The Skill should make security:

- easy to invoke;
- fast enough to run alongside development;
- structured enough to return actionable remediation;
- light enough for independent developers and small teams;
- deterministic enough to satisfy enterprise security expectations later.

The Skill must return formatted remediation context, not just a detached report. The returned object should be immediately usable by the coding agent and inspectable by the human developer.

Important limitation: a Skill is not automatically omniscient. It can respond to explicit requests and can suggest triggers based on project scans or changed files, but fully automatic trigger integration depends on the host development environment. V2 should state this honestly and start with explicit and suggested triggers.

## 3.2 Product Guardrails

The competitive direction creates several risks that must be controlled:

- Do not overclaim runtime modeling. The graph is useful only if nodes, edges, and risk chains are tied to evidence.
- Do not let LLM agents freely decide the audit workflow. Major phases must remain deterministic.
- Do not let Docker execution become a false verifier. Verification must check specific predicates.
- Do not bury the developer in graph complexity. Reports should explain the risk path plainly.
- Do not make Skill integration depend on a future Web UI. Skill and CLI must remain first-class.
- Do not copy lz-secure's large modules. Rebuild capabilities behind small contracts.

## 4. Scope

The product targets all Vibe Coding outputs, including:

- Traditional Web applications and APIs.
- AI-generated frontend/backend projects.
- AI Agent applications.
- MCP servers and MCP toolchains.
- Workflow apps such as Flowise, n8n, Langflow-like systems.
- Local tools, plugins, scripts, and browser automation flows.
- Lightweight internal tools produced rapidly by AI coding agents.

The platform should not be limited to Web vulnerabilities. Web risks, agent risks, tool permission risks, prompt injection risks, MCP risks, workflow risks, and secret exposure must be represented in one shared workflow.

## 5. Design References

### AutoCVE

AutoCVE is the baseline audit-engine reference, not merely an orchestration reference. Vibe Sec must reproduce and mature the following capabilities:

- Deterministic orchestration.
- Explicit phases.
- Structured task handoff.
- Agent state tracking.
- Checkpoints and resumability.
- FinalizeFinding-style completion contracts.
- Nudge/guard mechanisms to prevent false completion.
- Tool execution audit records.
- Multi-round observe, tool call, evidence reconciliation, and conclusion formation.
- Candidate generation, prioritization, cross-file reasoning, and finding-level review.
- Verification handoff, failure handling, retry/degradation, and remediation feedback.

Vibe Sec should not directly copy AutoCVE's heavy Web platform shape at the beginning. PostgreSQL, Redis queues, and a full realtime management UI are later concerns, not V2 foundations. The behavior and contracts of the audit engine are mandatory; the deployment shape is adapted to local Skill and CLI workflows.

### Cairn

Cairn is referenced for one implementation idea only: package traditional security tools in a container and expose them to the audit agent through a controlled interface.

Vibe Sec does not adopt Cairn's blackboard, Fact/Intent model, multi-agent coordination protocol, or dispatcher architecture. The existing Vibe Sec orchestrator remains responsible for audit tasks and state. By default, the agent runtime stays outside the tool container and invokes approved scanners or verification tools through the Tool Fabric.

The container should be as small as the enabled tool profile permits. Kali is optional and is not an architectural requirement. A focused image containing only selected tools is preferable for the initial implementation.

### lz-secure

lz-secure is the security capability reference. Vibe Sec should borrow:

- RuntimeSurface.
- RuntimeSurfaceGraph.
- RiskChain.
- EvidenceBundle and ArtifactManifest.
- Browser evidence collection.
- PermissionPolicy and verification harness concepts.
- Remediation return protocol.
- Replay-lab and fixture ideas as curated test assets.

Vibe Sec should not inherit lz-secure's implementation shape: giant API files, monolithic database managers, oversized UI pages, and large script dumps should be avoided.

## 6. Core Workflow

The V2 workflow is:

```text
Plan
  -> Recon
  -> Surface
  -> Surface and Threat Model
  -> Audit Lanes and Tool Signals
  -> Merge
  -> Verify
  -> Remediate
  -> Return
  -> Retest
```

### Plan

Determine audit intent, project type, risk-sensitive changes, and required audit lanes.

### Recon

Build a project profile:

- Languages and frameworks.
- Entry points.
- Package and runtime dependencies.
- Sensitive configuration files.
- Existing tests and executable commands.

### Surface

Build the composite runtime surface:

- Page entries.
- API routes.
- Prompt configurations.
- Model invocations.
- Tool profiles.
- MCP servers, tools, resources, transports, and dynamic registrations.
- Permission profiles.
- Trust boundaries.
- Storage keys.
- Browser sinks.
- External content inputs.
- Workflow jobs and steps.
- Code block indexes.

Surface modeling projects these objects into the V3 runtime graph. Python uses AST extraction, JavaScript/TypeScript use Tree-sitter, and workflow/config files use safe JSON/YAML parsing. Graph nodes have stable ids and source provenance. Edges are deduplicated and carry a `security_meaning` such as untrusted input flow, instruction influence, authorization decision, privileged capability access, browser rendering, or data read/write. Same-project presence alone does not create an edge. The Surface phase also emits a deterministic `RuntimeThreatModel` containing techniques, `RiskHypothesis` objects, continuous attack paths, assumptions, coverage metrics, and evidence predicates. A hypothesis is an investigation target, not a confirmed vulnerability.

The executable method currently models nine techniques:

- Prompt injection through untrusted content reaching model context.
- Excessive agency across prompts, tools, and privileged operations.
- Instruction-like MCP/tool descriptions that may influence tool selection.
- Unprotected externally reachable entry points.
- Indirect prompt injection through external content entering model context.
- MCP capability authorization gaps for resources, tools, transports, and privileged operations.
- External content reaching browser rendering or navigation sinks.
- Attacker-influenced workflow inputs reaching code, credential, network, or deployment capability.
- Model-callable access to sensitive storage assets.

### Audit Lanes

Audit should be lane-based rather than one large scanner:

- `web_audit`: Web/API vulnerabilities and business logic trust issues.
- `agent_audit`: prompt injection, excessive agency, unsafe tool use, unsafe output handling.
- `mcp_audit`: MCP resource exposure, tool description injection, auth gaps, host/header boundary issues.
- `secrets_audit`: hardcoded secrets, credentials, tokens, sensitive files.
- `workflow_audit`: workflow automation risks, SSRF, file access, arbitrary code execution, IDOR-like object boundary issues.

The current local runtime executes the enabled Web, agent, MCP, secrets, and workflow lanes as bounded parallel child tasks when more than one lane is enabled. Each child has an isolated audit-agent instance, a parent task id, a completion contract, state-transition history, and session checkpoints. Protocol-specific validators include Python MCP tool/resource decorators, JavaScript/JSX and TypeScript/TSX MCP SDK registrations, consequential handlers, local approval guards, unresolved dynamic identity, remote transport authentication gaps, structured MCP JSON/YAML wildcard capability and description checks, and parsed GitHub Actions run-step injection checks. Additional MCP SDK shapes, deployment-provided gateway policy, host/header enforcement, and non-GitHub workflow engines remain explicit coverage extensions.

In the target architecture, each lane can consume three signal classes:

1. deterministic scanner results, such as Semgrep, CodeQL, Gitleaks, Trivy, Nuclei, Bandit, or package audits;
2. runtime-surface and threat-model hypotheses;
3. the agent's own source exploration and cross-file reasoning.

These signals are inputs to the same Agentic Audit Engine. A scanner finding is not automatically a confirmed vulnerability, and an LLM hypothesis is not automatically a finding. Both must pass evidence binding, deduplication, and verification contracts.

Dependency inventory is offline and always available through `inspect_dependencies`. Exact locked or pinned versions can be matched to OSV through `query_dependency_vulnerabilities` only when the trusted caller explicitly supplies `--osv`. The Tool Gateway fixes the endpoint to `https://api.osv.dev/v1/querybatch`, applies the `api.osv.dev` allowlist, records query time and the absence of a snapshot version, stores raw and normalized artifacts, and reports unpinned packages as coverage gaps. Default review policy remains network-disabled.

When a real LLM provider is enabled, candidate review uses a bounded multi-turn loop: observe the candidate and hypothesis, call read-only evidence tools, append tool results to the transcript, reconcile supporting or contradicting evidence, and call `FinalizeFinding`. Verification has a separate bounded loop with `FinalizeVerification` and controlled static, dynamic, and fuzzing tools. Source reads, surface inspection, hypothesis inspection, and verification calls are permission-checked and recorded. Mock providers intentionally use the deterministic path; `--use-llm` without an explicit key fails fast rather than silently selecting a mock.

### Merge

Deduplicate findings and connect them to runtime surface nodes and risk chains.

### Verify

Verification is level-based:

- Level 1: static evidence only.
- Level 2: static evidence plus runtime surface/risk-chain consistency.
- Level 3: sandbox proof or controlled local execution.
- Level 4: browser/service evidence with screenshots, DOM, network logs, or state diff.
- Level 5: fix retest with positive and negative controls.

The system should record evidence gaps instead of pretending every finding is fully verified.

### Remediate

Generate a remediation package:

- Finding summary.
- Evidence references.
- Risk chain.
- `ai_patch_prompt`.
- Patch constraints.
- Machine-readable required/allowed change scope with explicit approval for production-file expansion.
- Retest plan.
- Acceptance criteria.
- Files likely involved.
- Safety notes for high-permission coding agents.

### Return

Return the remediation package to the Vibe Coding context. The return format must be directly usable by a coding agent and understandable by a developer.

### Retest

Retest after code changes:

- Confirm the original exploit path is blocked.
- Confirm positive business paths still work.
- Detect obvious side effects.
- Preserve evidence and status.

## 7. Trigger Model

Trigger timing is a product-level responsibility. The harness should support explicit and automatic triggers.

### Explicit Triggers

- User asks the Skill to audit the project.
- User asks before commit or release.
- User asks to verify a specific feature or file.
- User asks to retest after a fix.

### Automatic or Suggested Triggers

The harness should suggest or run audits when it detects:

- Authentication or authorization changes.
- File upload or file access logic.
- Network request, SSRF-sensitive, or URL-fetch logic.
- Shell command, subprocess, eval, template, or dynamic code execution.
- Prompt, system instruction, tool description, or agent policy changes.
- MCP server/tool/resource changes.
- Secret/configuration changes.
- New browser sink such as `innerHTML`, markdown rendering, iframe, SVG, or rich-text preview.
- New workflow node with file, network, code execution, database, or credential access.
- High-permission agent behavior or broad tool permissions.

Automatic triggers should start conservative: suggest an audit first, then later allow policy-controlled auto-run.

## 8. High-Permission Agent Risk Model

In Vibe Coding, coding agents often receive broad filesystem, command, dependency, browser, or network permissions. The harness must assume that a development agent can make powerful changes quickly.

The security harness should provide:

- Permission-aware audit triggers.
- Destructive-action awareness.
- Tool-call traceability.
- Patch constraints.
- Human confirmation gates for sensitive fixes.
- Evidence requirements before marking high-risk findings as closed.
- Retest gates before accepting completion.

Default behavior: code changes and destructive operations should require user confirmation unless the project policy explicitly allows autonomous repair.

## 9. Return Protocol

The return payload should be structured and stable.

```json
{
  "finding": {
    "id": "FINDING-001",
    "title": "Unsafe tool permission boundary",
    "severity": "high",
    "vulnerability_type": "excessive_agency",
    "file_path": "agent.py",
    "line_start": 42,
    "line_end": 52
  },
  "evidence": [
    {
      "type": "code_snippet",
      "artifact_ref": "artifact://...",
      "summary": "Tool allows arbitrary command execution without confirmation"
    }
  ],
  "risk_chain": {
    "source_signal": "user-controlled instruction",
    "boundary_path": ["prompt", "tool_selector", "shell_tool"],
    "impact_hypothesis": "User input can influence command execution"
  },
  "remediation": {
    "ai_patch_prompt": "Patch the tool execution path so destructive commands require confirmation...",
    "patch_constraints": [
      "Preserve existing public API",
      "Do not remove legitimate read-only tool calls"
    ],
    "retest_plan": [
      "Attempt dangerous command without approval and verify it is blocked",
      "Run benign command and verify it still works"
    ],
    "acceptance_criteria": [
      "Dangerous actions require confirmation",
      "Tool calls are logged",
      "Existing benign workflow remains functional"
    ]
  }
}
```

Markdown, JSON, and Claude Code-native renderings should be different views over the same object model.

## 10. Core Data Objects

V2 should stabilize these objects before expanding features:

- `RunSession`: one audit or retest session.
- `RunEvent`: phase, tool, policy, and evidence events.
- `Checkpoint`: resumable state snapshot.
- `ProjectProfile`: recon result.
- `RuntimeSurface`: normalized runtime surface.
- `RuntimeSurfaceGraph`: graph of pages, prompts, tools, APIs, storage, browser sinks, and trust boundaries.
- `Finding`: candidate or verified issue.
- `RiskChain`: causal route from source signal to impact.
- `EvidenceBundle`: evidence and artifact manifest.
- `ValidationSession`: verification attempt and outcome.
- `RemediationBundle`: repair package returned to development.
- `RegressionReport`: retest result and closure status.
- `ArtifactRef`: immutable reference to raw tool output, source excerpt, screenshot, trace, or report.
- `ToolSignal`: a normalized scanner or tool observation linked to its execution and artifact.
- `RiskHypothesis`: an attack or misuse hypothesis with evidence predicates and assumptions.
- `ToolSpec` / `ToolRequest` / `ToolExecution`: the versioned tool-fabric contract.

## 11. Proposed Module Boundaries

```text
core/harness/
  trigger policy, return protocol, workflow gates

core/session/
  RunSession, RunEvent, Checkpoint, artifact refs

core/orchestrator/
  deterministic phase orchestration

core/agent_runtime/
  strict task state machine, ReAct loop, tool waits, completion contracts,
  retry/backoff, loop detection, stop hooks, nudge, context compaction,
  parent/child task graphs, permissioned tool execution, and exact-state JSONL resume helpers

core/agents/
  BaseAgent, TaskHandoff, registry

agents/
  concrete agents and audit lanes

core/surface/
  RuntimeSurface, RuntimeSurfaceGraph, RiskChain

core/audit/
  finding schemas, lane contracts, detection rule execution

core/verification/
  static checks, sandbox checks, browser checks, evidence packaging

core/tool_fabric/
  ToolSpec, ToolRequest, ToolExecution, ToolSignal, ArtifactRef, registry,
  scanner adapters, container execution gateway, append-only artifact manifest,
  and explicit retention cleanup

core/remediation/
  RemediationBundle, Skill relay, retest plan, and changed-tree snapshots

core/sanitization.py
  JSON-safe persistence and credential redaction with stable fingerprints

core/policy/
  permission policy, trigger policy, closure gates

core/reporting/
  rendering only; no business logic

api/
  later management API; not the primary V2 path

skill/
  first-class entry for Vibe Coding workflows
```

## 12. MVP Direction

V2 should first deliver a strong local harness:

1. Claude Code Skill entry.
2. Source-package bootstrap plus `setup`, `doctor`, and `update-tools` CLI contracts.
3. Deterministic orchestration.
4. Lightweight session persistence using JSONL or SQLite.
5. RuntimeSurface and RiskChain as stable objects.
6. Executable RuntimeThreatModel and RiskHypothesis contracts.
7. Lane-based audit architecture.
8. Evidence-backed reports.
9. RemediationBundle return protocol.
10. Retest command for fix verification.
11. AutoCVE-style bounded agent runtime with validated terminal actions.
12. Multi-turn finding review with controlled evidence tools.
13. Finding-level child tasks with bounded parallel verification.

Web UI should wait until the core workflow is stable.

## 13. Product Roadmap

### Phase 1: Harness Core

- Define stable schemas.
- Add session/events/checkpoints. (Implemented with JSONL persistence, sanitized payloads, and exact paused-state resume.)
- Add trigger and return protocol. (Implemented with `vibe-sec.skill-audit.v1`, conservative `--suggest-only`, changed-file focus with transitive source context, and `returned_packages`.)
- Keep Skill and CLI as primary entries. (Implemented with validated Skill metadata and `skill-audit`, `audit`, and `retest` commands.)
- Make the source package self-installing for a coding assistant. (Implemented with Windows/Linux bootstrap scripts, editable `vibe-sec` entry point, locked tool-image manifest, checksummed resumable artifacts, image capability preflight, and machine-readable setup/doctor/update contracts.)
- Fix current versioning, test setup, and report encoding. (Implemented for the current local package and Skill files.)

### Phase 2: Deterministic Orchestration

- Refactor current orchestrator into explicit phases and lanes.
- Add phase gates and failure handling.
- Add FinalizeFinding-style contracts. (Implemented in `core/agent_runtime`.)
- Add ReasoningGuard as a blocking gate. (Connected to phase task execution.)
- Add bounded ReAct turns, tool waits, retry/backoff, loop detection, nudge, and
  checkpoint-backed resume. (Implemented for the local runtime.)
- Add parent/child task graph execution and Finding-level parallel verification.
  (Implemented with bounded concurrency.)

### Phase 3: Surface and Evidence

- Strengthen RuntimeSurface.
- Add RuntimeSurfaceGraph and RuntimeThreatModel hypotheses. (Implemented in the local runtime.)
- Add RiskChain attachment to findings.
- Add EvidenceBundle and artifact refs. (Implemented with provenance-preserving scanner merge through final verification, immutable evidence files, and an append-only searchable manifest.)

### Phase 4: Verification Depth

- Improve static verification. (Implemented as location-bound predicates plus framework semantics for Django/FastAPI/Flask, Express/Nest/Next, Spring, and common Go routers. Non-Python framework paths remain bounded provenance, not universal data flow.)
- Add controlled sandbox verification. (Implemented through `vibe-sec.poc-plan.v2`, trusted safety envelopes, source hash binding, Harness-owned oracle controls, stable fingerprints, isolated containers, and internal multi-service reproduction. Unsupported dynamic predicates remain `needs_evidence`.)
- Add browser/service evidence where applicable. (Implemented as an explicitly authorized, allowlisted service lifecycle with loopback-only port publication, health checks, positive/negative Playwright controls, and forced cleanup. Authorization must come from the trusted Harness input as well as the service plan; startup hints never grant it.)
- Record evidence gaps honestly. (Implemented with `needs_evidence` and explicit degraded review status.)
- Expand ReAct finding review from read-only source/surface evidence to controlled runtime probes. (Implemented in the separate verification ReAct loop, including `prepare_poc_plan`, runtime controls, loopback browser probes, and internal multi-service PoC environments. Co-located multi-service browser execution remains future work.)

### Phase 5: Remediation and Retest Loop

- Normalize remediation bundles. (Implemented with a versioned schema, generic fallback, positive/negative retest cases, constraints, and expected runtime-surface change.)
- Return repair packages to Skill/CLI. (Implemented in the stable Skill envelope and Claude Code formatter.)
- Add retest workflow. (Implemented through `run_retest()` and the `retest` CLI. Applied fixes can supply changed files directly, use a Git baseline, or use the hash-validated pre-change tree snapshot emitted with the remediation bundle; applying the patch remains the coding Agent's responsibility.)
- Track closure criteria and regression results. (Regression now reports passed, failed, and skipped instead of simulated passes.)

### Phase 6: Management Layer

- Add local Web UI.
- Add project/task/finding views.
- Add evidence browser.
- Add team and enterprise policy controls.

## 14. Immediate Codebase Implications

The current project already contains useful pieces, but they need sharper boundaries:

- Keep `core/orchestrator`, but make phase execution and gates explicit.
- Keep `core/agents`, but extend TaskHandoff with coverage, artifact refs, evidence gaps, and next actions.
- Keep `core/surface`, with RuntimeSurfaceGraph, RuntimeThreatModel, and stronger graph attachment.
- Keep `core/runtime/permission_policy.py`, but move policy ownership toward `core/policy`.
- Keep `core/remediation/skill_relay.py`, but align RemediationBundle fields with the return protocol.
- Refactor `AuditAgent` into lane-based detection and multi-turn evidence review rather than one expanding scanner.
- Fix verification semantics so sandbox failure does not falsely imply vulnerability confirmation. (Implemented in the verification result binding and completion contracts.)
- Treat reports as renderers over stable schemas, not as the source of truth.

## 15. Non-Goals for the Next Step

These are intentionally deferred:

- Full Web UI.
- Multi-user authentication.
- Central database service.
- Redis/ARQ distributed queue.
- Plugin marketplace.
- Large replay-lab import.
- Enterprise dashboard.

They remain valid product goals, but only after the harness core is stable.
