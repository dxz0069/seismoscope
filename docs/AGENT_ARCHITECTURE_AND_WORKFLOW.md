# Vibe Sec Platform Agent Architecture and Workflow

> This document describes the implementation currently present in the repository. It separates executable behavior from planned extensions so that the architecture remains auditable while the product evolves.

## 1. Product Role

Vibe Sec Platform is a security harness around an AI-assisted development workflow. It is not the coding agent and it is not only a source scanner. The harness controls when security work starts, which stages must run, how evidence is collected, when a finding can be finalized, and how remediation is returned to the coding context.

The current first-class surfaces are:

- Claude Code Skill: the intended low-friction development integration.
- CLI: the executable local entry point in `main.py`.
- Local session/checkpoint storage: JSONL snapshots for inspection and resume.
- Web UI: not implemented in this iteration; the runtime graph projection is designed as its future data contract.

The core product loop is:

```text
trigger
  -> plan
  -> recon
  -> runtime surface modeling
  -> threat modeling
  -> parallel audit lanes
  -> merge and graph attachment
  -> evidence review
  -> controlled verification
  -> remediation bundle
  -> return to coding context
  -> regression / retest
```

The LLM may propose observations, tool calls, hypotheses, and conclusions. The harness owns the phase order, task states, permissions, completion contracts, checkpoints, and final data shape.

## 2. End-to-End Workflow

### 2.1 Plan

The orchestrator creates a `RunSession`, records the trigger and project path, stores the requested `audit_scope`, and fixes the phase order. The model cannot reorder the major phases.

Current phase enum:

```text
INIT -> PLAN -> RECON -> SURFACE -> AUDIT -> MERGE
     -> VERIFICATION -> REMEDIATION -> RETURN -> REGRESSION
     -> COMPLETED | FAILED
```

`REGRESSION` is configurable. The CLI enables it by default, while the orchestrator configuration can disable it for a shorter run.

### 2.2 Recon

`ReconAgent` creates a `ProjectProfile`. It scans the repository for languages, frameworks, file structure, entry points, dependencies, and build/test hints. It produces a `TaskHandoff` for `SurfaceAgent`.

Recon is intentionally mostly deterministic. If an LLM service is configured, it can generate additional insights, but those insights do not replace the scanned profile.

### 2.3 Surface and Threat Model

`SurfaceAgent` builds a `RuntimeSurface` and projects it to a stable `RuntimeSurfaceGraph`. The graph models ordinary Web objects and agent-specific objects in one structure:

- external actors;
- HTTP/API entry points;
- prompts and model context;
- tools and model-callable capabilities;
- MCP servers, tools, resources, transports, and dynamic registrations;
- trust boundaries and permission controls;
- external content inputs and browser sinks;
- workflow jobs and steps;
- storage assets and data operations;
- privileged operations/assets;
- indexed code blocks.

Python objects are extracted with AST, JavaScript/JSX and TypeScript/TSX with Tree-sitter, and workflow/config objects with safe JSON/YAML parsing. Every non-actor node retains file/line provenance. V3 graph edges are deduplicated, have a security meaning, and are created from explicit references or bounded source-local correlation; generic project dependency noise is not represented as data flow.

`RuntimeThreatModelAnalyzer` then creates a versioned `RuntimeThreatModel` containing `RiskHypothesis` objects. The executable techniques are:

- `T-PROMPT-INJECTION`;
- `T-EXCESSIVE-AGENCY`;
- `T-MCP-DESCRIPTION-INJECTION`;
- `T-UNPROTECTED-ENTRY`.
- `T-INDIRECT-PROMPT-INJECTION`;
- `T-MCP-AUTHORIZATION`;
- `T-BROWSER-SINK-INJECTION`;
- `T-WORKFLOW-PRIVILEGE`;
- `T-SENSITIVE-STORAGE-ACCESS`.

A hypothesis is an investigation target. It is not a confirmed vulnerability. Missing permission metadata is an unresolved boundary and not proof of exploitability. The hypothesis must be supported by audit evidence and, where appropriate, controlled verification.

### 2.4 Audit Lanes

The orchestrator maps the audit scope to independent child tasks:

| Lane | Scope key | Current responsibility |
| --- | --- | --- |
| `web_audit` | `web_vulns` | SQL injection, XSS, command injection, path traversal and related source patterns |
| `agent_audit` | `agent_vulns` | Prompt injection, excessive agency, unsafe tool descriptions, broad permissions and agent behavior patterns |
| `mcp_audit` | `mcp_vulns` | MCP tool/resource registration, description injection, broad capability, and local approval boundaries |
| `secrets_audit` | `secret_leaks` | Hardcoded passwords, API keys, tokens, sensitive configuration, and dependency inventory context |
| `workflow_audit` | `workflow_vulns` | Workflow input-to-shell/network/file paths and structured GitHub Actions injection checks |

When more than one lane is enabled, each lane gets a separate `AuditAgent` instance and a child `AgentTask`. The child tasks share a parent task id, run concurrently within `audit_concurrency`, and write checkpoints and state transitions to the session.

MCP-specific and workflow-specific lanes have structured detectors and independent static validators. MCP coverage parses Python tool/resource decorators, JavaScript/JSX and TypeScript/TSX SDK registrations and handlers, consequential tool and resource operations, local approval guards, unresolved dynamic identity, remote transport authentication gaps, JSON/YAML wildcard capabilities, and instruction-override descriptions. Workflow coverage parses GitHub Actions YAML and binds attacker-controlled event expressions to concrete `run` steps. These validators do not claim every MCP SDK, deployment gateway policy, effective host/header enforcement, or non-GitHub workflow engine.

### 2.5 Merge

The orchestrator normalizes and deduplicates lane findings. Each finding is attached to graph nodes by matching its relative source path and line range. If no node matches, the finding includes `surface_attachment_reason` instead of silently pretending it is modeled.

The merged state contains:

```text
merged_findings
lane_findings
runtime_surface_graph
runtime_threat_model
```

### 2.6 Multi-turn Finding Review

With a real non-mock LLM provider, the audit stage can run `ReActFindingReviewer` for bounded candidate review. The loop is:

```text
observe candidate + hypothesis
  -> call a read-only evidence tool
  -> receive tool result
  -> compare supporting and contradicting evidence
  -> collect evidence bundle and gaps
  -> call FinalizeFinding
```

The reviewer is bounded by turn count, timeout, and an evidence budget. It cannot finalize by merely writing a natural-language claim. `FinalizeFindingContract` requires the finding identity, location, severity, type, verdict, and at least one evidence item. After the evidence budget is reached, the handler exposes only `FinalizeFinding` and sends an explicit terminal nudge. Duplicate evidence queries are returned from cache and do not count as new evidence. Tool failures are appended as paired failure observations so the provider transcript remains valid. Terminal actions are consumed locally and never leave an unmatched provider tool call.

Before candidate conclusions, each discovery target must load the built-in source-audit and false-positive methodology. Guidance is marked as non-project evidence and is explicitly excluded from candidate artifact binding. Python, JavaScript/JSX, and TypeScript/TSX candidate files must have a relevant AST-backed semantic trace before the discovery target can complete. Other language paths remain explicit coverage gaps rather than simulated semantic support.

The harness binds immutable finding identity fields back over the model output. `confirmed` and `verified` are not accepted when the evidence bundle has gaps or no successful source read. If the provider does not satisfy the completion contract, the result is explicitly `degraded`, confidence is capped, and the finding is moved to `needs_evidence` or `unconfirmed`; it is never silently treated as confirmed.

The mock provider intentionally follows the deterministic static fallback. This keeps local tests deterministic and prevents a mock response from being mistaken for a real LLM review.

### 2.7 Verification

`VerificationAgent` selects a verification depth from finding severity and confidence. With a real provider it also runs a bounded `FinalizeVerification` ReAct loop. That loop can inspect the finding, read bounded source, run the deterministic static predicate, and request Docker/fuzzing evidence through a permissioned executor. `verified`, `rejected`, and `needs_evidence` are separate outcomes. Without a real provider, the deterministic path remains available and records the evidence limitation. Current evidence paths are:

- static source verification;
- dynamic execution through `DockerExecutor` when available;
- generated fuzzing harnesses in Docker;
- `PlaywrightExecutor` as a reusable browser evidence component.

The verification result is stored as `VerificationEvidence` and folded into an `evidence_bundle`. Docker or Playwright unavailability is recorded as an evidence gap; it must not be reported as successful exploit proof.

Finding-level verification is fanned out into child tasks when multiple findings need verification. The task graph limits concurrency and records each child state.

### 2.8 Remediation

`RemediationAgent` consumes verified or evidence-bearing `needs_evidence` findings and creates `RemediationBundle` objects. It does not directly edit project files. A package contains a repair prompt, patch strategy, constraints, retest steps, acceptance criteria, and affected location metadata. A `needs_evidence` package remains a remediation suggestion and cannot be treated as a closed vulnerability.

This separation is deliberate: the coding agent may apply the patch, but the security harness keeps the repair request explicit and auditable. High-risk changes remain subject to human confirmation and retesting.

### 2.9 Return and Regression

`build_return_packages()` converts verified findings and remediation bundles into a stable return protocol for Skill/CLI consumers. The package preserves evidence, remediation constraints, retest requirements, and closure gates.

`RegressionAgent` consumes remediation packages and produces `RegressionReport` objects. A remediation bundle is only a proposal until the coding agent applies it. The regression agent never reports simulated passes: it executes an explicitly enabled project `pytest` command when a test directory exists, otherwise returns `skipped` with the missing evidence. Vulnerability-fix and side-effect checks likewise require post-fix evidence. A `partial` report therefore means that human or coding-agent action is still required, not that the patch is safe.

## 3. Agent Registry and Dependencies

The registry is created in `main.setup_agent_registry()`:

```text
Orchestrator
  -> ReconAgent
      -> SurfaceAgent
          -> AuditAgent (web / agent / secrets child lanes)
              -> VerificationAgent (finding child tasks)
                  -> RemediationAgent
                      -> RegressionAgent
```

The registry dependency checks prevent a downstream Agent from running before its prerequisite registration has completed. The orchestrator still owns the actual phase order and handoff payload construction.

## 4. Agent Contracts

### 4.1 OrchestratorAgent

**Role**

Owns the deterministic workflow, phase transitions, fan-out/fan-in, state aggregation, session events, and final result. It is the harness controller, not a free-form planning chatbot.

**Input payload**

```json
{
  "project_path": "path/to/project",
  "audit_scope": {
    "web_vulns": true,
    "agent_vulns": true,
    "secret_leaks": true
  },
  "use_llm": false,
  "trigger": "explicit",
  "session_id": "optional"
}
```

**Context assembled by the harness**

- the current `RunSession`;
- prior `TaskHandoff` objects rendered through `to_prompt_context()`;
- project profile from Recon;
- runtime graph and threat model from Surface;
- merged findings for Verification;
- verified findings for Remediation;
- remediation packages for Regression.

**Tools and permissions**

The orchestrator does not expose an unrestricted shell to the LLM. Its operational capabilities are the internal task runtime, registry, task graph, session store, and phase-specific Agent calls. Phase-specific tools are governed by the child Agent.

**Output**

The final `AgentResult.data` includes `findings`, `verified_findings`, `remediation_bundles`, `returned_packages`, `runtime_surface_graph`, `threat_model`, lane summaries, task ids, regression reports, and the serialized session.

**Completion and failure**

Every phase is run through `AgentTaskLoop` unless disabled in configuration. Phase timeout, task failure, dependency failure, and unhandled exceptions move the session to `FAILED` and retain partial results.

### 4.2 ReconAgent

**Role**

Builds a low-cost repository profile that gives later Agents enough project context to select surface and audit work.

**Input**

```json
{
  "project_path": "path/to/project"
}
```

**Context**

Repository files, directory structure, detected language/framework markers, dependency manifests, and the original audit scope. Recon does not consume a prior security finding list.

**Tools**

Current implementation uses internal deterministic filesystem scanning. It does not expose a general-purpose LLM tool schema. LLM use is limited to optional profile insight generation.

**Output**

`project_profile` with `languages`, `frameworks`, `entry_points`, `dependencies`, `sensitive_files`, `commands`, and `insights`, plus a handoff to `surface`.

**Failure behavior**

Missing `project_path` or scan exceptions fail the Agent. A malformed optional handoff is ignored with a warning rather than being treated as trusted instructions.

### 4.3 SurfaceAgent

**Role**

Builds the runtime attack surface, stable graph, high-risk area list, and initial threat hypotheses.

**Input**

```json
{
  "project_path": "path/to/project",
  "recon_handoff": "optional serialized handoff",
  "prior_handoffs": "optional rendered context"
}
```

**Context**

Source files plus Recon output. The builder extracts routes, prompt configurations, tool profiles, permission profiles, trust boundaries, and code blocks.

**Tools**

The current builder uses deterministic source inspection. Optional LLM insight generation calls only the configured LLM service; no write or execution tool is exposed to it.

**Output**

```text
runtime_surface
runtime_surface_graph
runtime_surface_graph.visualization
threat_model
high_risk_areas
summary
```

The handoff to Audit points to the surface summary. The full graph and threat model are passed through the orchestrator payload.

**Important interpretation**

The graph is a risk-analysis representation, not a complete runtime trace. Static extraction can miss dynamic registration, indirect tool loading, external MCP servers, runtime authorization, and deployment configuration.

### 4.4 AuditAgent

**Role**

Generates candidates in separate vulnerability lanes, attaches evidence, and optionally performs LLM-driven multi-turn review.

**Input**

```json
{
  "project_path": "path/to/project",
  "audit_scope": {"web_vulns": true, "agent_vulns": true, "secret_leaks": true},
  "audit_lane": "agent_audit",
  "runtime_surface_graph": {},
  "threat_model": {},
  "changed_files": ["src/changed_file.py"],
  "use_llm": true,
  "enable_react_review": true
}
```

**Context**

The relevant source tree, lane scope, surface graph, threat hypotheses, and the candidate state machine. For a candidate review, the reviewer receives only the candidate and its matched hypothesis plus bounded tool results.

**LLM tools**

Discovery and finding review expose these read-only tools through `ToolGateway`:

| Tool | Purpose | Boundary |
| --- | --- | --- |
| `read_source` | Read a bounded source excerpt | Project-root containment check; no writes |
| `list_source_files` | List bounded source and dependency files | Dependency/build directories excluded |
| `search_code` | Search bounded project source | Result/file limits and artifact provenance |
| `inspect_file_outline` | Parse symbols and imports | Bounded single project file |
| `trace_python_flow` | Trace Python callers, callees, sources, sinks, and guards | Bounded AST index, depth, paths, and files |
| `trace_javascript_flow` | Trace JavaScript/JSX callers, callees, sources, sinks, and guards | Esprima AST; TypeScript is not claimed |
| `trace_typescript_flow` | Trace TypeScript/TSX callers, callees, sources, sinks, and guards | Tree-sitter AST; bounded files, depth, and paths |
| `inspect_dependencies` | Parse manifests, versions, lockfiles, and provenance | Bounded known formats; unsupported locks become gaps |
| `query_dependency_vulnerabilities` | Match exact pinned/locked versions to OSV advisories | Default blocked; trusted `--osv` authorization; fixed `api.osv.dev` endpoint; freshness and gaps recorded |
| `load_audit_guidance` | Load trusted methodology and existing checklists | Fixed trusted roots; guidance cannot become finding evidence |
| `inspect_surface` | Query graph nodes and related edges | In-memory graph only |
| `inspect_hypothesis` | Read one threat hypothesis and predicates | In-memory threat model only |
| `semgrep_scan` | Collect local rule-pack SAST signals | Optional container mode; pinned image/rules, no network, read-only project |
| `gitleaks_scan` | Collect secret-location signals | Optional container mode; persisted output is redacted |
| `bandit_scan` | Collect Python-specific SAST signals | Optional container mode; pinned Bandit 1.8.0, no network |
| `trivy_filesystem_scan` | Collect dependency, configuration, and secret signals | Optional container mode; offline DB with freshness metadata, no network |
| `codeql_database_scan` | Analyze an existing CodeQL database | Exposed only when the CodeQL image passes preflight; currently unavailable locally |

The reviewer cannot call `write_file`, `execute_command`, `shell`, or `run_command`. Every permitted call is passed through `ToolGateway` and recorded as a `ToolExecution`. Scanner schemas are generated from the post-preflight registry, so an absent or version-mismatched image is not shown to the model.

`nuclei_service_scan` is intentionally absent from the normal discovery/review schema. A trusted control plane must register it separately, attach it to an isolated managed service network, and authorize the exact target hostname. Its curated templates, severity profile, rate limit, disabled interactsh, and disabled update checks are fixed by the adapter.

**Output**

`findings`, `findings_by_lane`, `audit_summary`, and a handoff to Verification. Reviewed candidates retain the model verdict, confidence, evidence items, and tool-call audit information.

**Completion and failure**

Static candidates may still be returned when an LLM review is unavailable. A failed ReAct review creates an evidence gap and does not silently convert the model's prose into a validated conclusion.

### 4.5 VerificationAgent

**Role**

Tests whether a candidate is supported by executable or static evidence and assigns verification status.

**Input**

```json
{
  "project_path": "path/to/project",
  "findings_to_verify": [],
  "verification_threshold": 0.5,
  "runtime_surface_graph": {},
  "threat_model": {},
  "enable_react_verification": true,
  "verification_authorization": {"allow_service_start": false},
  "prior_handoffs": "..."
}
```

**Context**

Merged findings, source locations, vulnerability type, severity, confidence, existing evidence, and the runtime environment availability.

**Tools/executors**

- static file and line inspection inside the project path;
- predicate-bound dynamic execution through the hardened `DockerExecutor` compatibility layer;
- explicit fuzz harnesses with a required success marker;
- loopback-only `PlaywrightExecutor` positive/negative controls for browser evidence.
- an allowlisted service-under-test lifecycle with a read-only project mount, health predicate, timeout, logs, and forced cleanup.
- a first-class `vibe-sec.poc-plan.v2` protocol with trusted safety envelope, source target binding, stable plan fingerprint, positive/negative controls, and a Harness-owned oracle verdict;
- an internal multi-service reproduction topology with dependency ordering, no host ports or outbound route, and temporary control containers on the same network.

These are internal executors, not unrestricted model tools. Docker and browser operations must be treated as controlled validation with an explicit predicate. An unavailable executor produces a gap or `needs_evidence` status.

When enabled with a real provider, `ReActVerificationReviewer` exposes `inspect_finding`, `read_source`, `run_static_verification`, `run_dynamic_verification`, `run_fuzzing_verification`, `run_browser_verification`, and `FinalizeVerification`. Evidence calls are permission-checked and audited; the terminal action is consumed by the harness. The completion contract requires a finding id, a verification predicate, and evidence. The Harness downgrades `verified` when required static/dynamic-or-browser predicates or controls are missing.

**Output**

`verified_findings`, `rejected_findings`, `needs_evidence_findings`, `verification_evidence`, and an `evidence_bundle` with evidence level and gaps. The final bundle merges verification observations with discovery evidence, preserving scanner artifact references and tool-execution ids through the verdict transition. Handoff target is Remediation.

**Current limitation**

Static predicates cover the built-in vulnerability families and framework semantics now cover Django/FastAPI/Flask, Express/Nest/Next, Spring, and common Go HTTP routers. Python bindings are AST-based; JavaScript/TypeScript, Java, and Go use Tree-sitter syntax validation with framework-specific provenance and bounded proximity paths, not universal data flow. Runtime and fuzz checks require explicit harnesses. Browser checks require explicit selectors and controls. Starting execution requires trusted Harness authorization; model-generated plans never grant authority. Missing Docker, Playwright, service, authorization, controls, or predicate evidence remains `needs_evidence`.

### 4.6 RemediationAgent

**Role**

Turns verified or evidence-bearing findings into safe, structured repair instructions for the coding Agent.

**Input**

```json
{
  "project_path": "path/to/project",
  "verified_findings": [],
  "prior_handoffs": "..."
}
```

**Context**

Finding location, evidence bundle, vulnerability type, severity, verification status, risk chain where available, and project handoff context.

**Tools**

No direct source-writing tool is currently exposed. Remediation is strategy-based generation. The package may include an `ai_patch_prompt`, but applying it belongs to the coding workflow.

**Output**

`remediation_bundles`, each containing:

- `finding_id` and location;
- `ai_patch_prompt`;
- patch strategy and constraints;
- machine-readable `change_scope` with required files, allowed files/test globs, and an approval gate for expansion;
- retest plan;
- acceptance criteria;
- positive and negative retest cases;
- expected runtime-surface change;
- safety notes and metadata. Unknown vulnerability types use the generic evidence-bound profile instead of being dropped.

Handoff target is the return/regression path.

### 4.7 RegressionAgent

**Role**

Consumes completed remediation packages and reports whether the vulnerability check, functional check, and side-effect check passed.

**Input**

```json
{
  "project_path": "path/to/project",
  "completed_packages": [],
  "prior_handoffs": "..."
}
```

**Context**

Package state, finding metadata, fix result, acceptance criteria, and retest plan.

**Tools**

The Regression Agent validates post-fix positive and negative controls, optionally runs a detected or explicitly approved argument-vector project test command, and checks changed files supplied by `fix_result.changed_files`, collected from a Git baseline, or calculated from the remediation bundle's immutable pre-change tree-snapshot artifact. Snapshot references are hash-checked before comparison. A control pass requires a predicate plus an artifact, tool-execution, trace, or screenshot reference; a bare `status=passed` claim fails. Changed files are checked against the remediation bundle's `change_scope`, and production-file scope expansion requires approval. Shell executables are denied. Missing fix, test, or changed-tree evidence is skipped/partial rather than passed. `run_retest()` and `python -m main retest` provide the post-fix entry points.

**Output**

`regression_reports` with individual test results, overall status, recommendations, and a handoff to the orchestrator.

## 5. Runtime Engine

The runtime under `core/agent_runtime/` is the AutoCVE-inspired control layer.

### 5.1 `AgentTask`

The durable unit of work. It records:

- task id and parent task id;
- Agent and phase;
- input payload;
- attempt and maximum attempts;
- current runtime state;
- completion contract;
- evidence references;
- turn count and token count;
- last error;
- handler state and loop context;
- state transition history.

### 5.2 `TaskStateMachine`

The strict state machine prevents invalid transitions. Important states include `CREATED`, `DISPATCHED`, `RUNNING`, `WAITING_TOOL`, `WAITING_HANDOFF`, `VERIFYING`, `COMPLETED`, `FAILED`, and `STOPPED`. Every transition includes a reason and is emitted to the session event stream.

### 5.3 `AgentTaskLoop`

The bounded execution loop performs:

1. dispatch and context restoration;
2. handler/model turn;
3. output guard evaluation;
4. loop-repeat detection;
5. tool wait and tool execution;
6. completion-contract validation;
7. retry/backoff for recoverable errors;
8. checkpoint emission after transitions, tool results, and turns.

It supports a terminal-action requirement. The Audit lane must return `FinalizeTask`; finding review must call `FinalizeFinding`; verification review must call `FinalizeVerification`. A natural-language `done` response is not enough when a contract is active.

### 5.4 `ReActHandler`

Maintains the model transcript and context window. It normalizes provider tool-call formats, appends tool results as `tool` messages, keeps assistant/tool protocol pairs atomic during compaction, persists handler state, forces terminal tools after an evidence budget, and recognizes terminal tools such as `FinalizeFinding` and `FinalizeVerification`.

### 5.5 `TaskGraphController`

Runs independent tasks concurrently once dependencies are satisfied. The audit phase uses it for lane fan-out. Verification uses it for finding fan-out. Each child can be inspected and resumed independently from session checkpoints.

### 5.6 Guards and Stop Hooks

- `PermissionedToolExecutor`: evaluates policy before invoking a tool and records allowed/denied calls.
- `PermissionPolicy`: controls denied tool names, denied prefixes, network access, file writes, domains, and critical actions.
- `ReasoningGuard`: detects unsupported confirmation, evidence mismatch, reward-hacking risk, premature finalization, insufficient context, and logical inconsistency.
- `StopHookPolicy`: nudges a task when it claims completion without the required terminal action.
- `CompletionValidator`: checks required fields, evidence count, unresolved gaps, and contract predicates.

The reviewer policy is explicitly read-only. Verification executors are separate controlled components and should not be accidentally exposed through the reviewer tool schema.

### 5.7 Retry, Checkpoint, and Resume

`RetryPolicy` handles bounded recoverable failures with exponential backoff. `RunSession` stores phase events and checkpoints. `SessionStore` appends JSONL snapshots under the configured session directory. `ResumeManager` loads the newest task checkpoint, restores `AgentTask` and handler state, and continues the same loop. A paused task records `paused_from`, so resume returns to `WAITING_TOOL`, `WAITING_HANDOFF`, `VERIFYING`, or `RUNNING` instead of skipping pending work.

Checkpoint records may include the task state, current loop context, pending tool call, tool results, completion feedback, and child task metadata. The persistence boundary converts domain objects and enums to JSON-safe values and redacts common credential literals with stable SHA-256 fingerprints. Callers must still avoid intentionally placing credentials in task context or logs.

### 5.8 Artifact Manifest and Retention

`ArtifactStore` writes immutable evidence files under a session directory and appends creation records to `manifest.jsonl`. JSON payloads and artifact metadata are sanitized at the storage boundary, in addition to adapter-level redaction. The manifest can be queried by artifact type or producer. Explicit age-based cleanup defaults to dry-run; an actual deletion appends a tombstone event, preserving the audit trail instead of rewriting history.

Source excerpts, search results, scanner output, verification output, service/browser evidence, project-test output, and checkpoint payloads are sanitized before persistence or model exposure. Automated cleanup schedules, storage quotas, and deployment-specific retention periods are policy configuration that remains outside the current local runtime.

## 6. Context and Handoff Rules

The data-flow rule is to pass small handoff summaries plus references, while the orchestrator owns the authoritative in-memory state:

```text
Recon
  -> ProjectProfile + TaskHandoff
Surface
  -> RuntimeSurface + RuntimeSurfaceGraph + RuntimeThreatModel
Audit
  -> lane Findings + EvidenceBundle + TaskHandoff
Merge
  -> deduplicated Findings + graph node attachments
Verification
  -> VerificationEvidence + verification status
Remediation
  -> RemediationBundle
Return
  -> coding-agent-ready return packages
Regression
  -> closure and retest status
```

`TaskHandoff.context_refs` is a reference map for prompt/context construction. It is not an authorization mechanism. Untrusted source content, tool descriptions, prompts, and external artifacts must remain data and must never override runtime policy.

## 7. Runtime Graph Visualization Contract

`runtime_surface_graph` is the canonical graph object. It contains stable source ids, typed nodes, typed edges, metadata, and a nested `visualization` projection.

The WebUI should consume `runtime_surface_graph.visualization` rather than reverse-engineering source objects. The current projection is:

```json
{
  "schema": "vibe-sec.runtime-surface-visualization",
  "version": "1",
  "layout": {
    "algorithm": "layered",
    "direction": "LR",
    "layer_gap": 180,
    "node_gap": 80
  },
  "nodes": [
    {
      "id": "prompt-...",
      "label": "prompt_0",
      "type": "prompt",
      "layer": 2,
      "style": {
        "group": "context",
        "color": "#7c3aed",
        "shape": "prompt",
        "risk": true,
        "risk_color": "#dc2626"
      },
      "security": {
        "trust_zone": "model_context",
        "privilege_level": "model_controlled",
        "asset_type": null,
        "threat_categories": ["prompt_injection"],
        "risk_level": null
      },
      "risk_hypothesis_ids": ["RH-..."],
      "attributes": {"file_path": "agent.py", "line_start": 1}
    }
  ],
  "edges": [
    {
      "id": "edge-...",
      "source": "external_actor-...",
      "target": "prompt-...",
      "relation": "supplies_input",
      "style": {"risk": true, "color": "#dc2626", "width": 3},
      "risk_hypothesis_ids": ["RH-..."],
      "attributes": {"trust_crossing": true}
    }
  ],
  "risk_paths": [
    {
      "id": "RH-...",
      "technique_id": "T-PROMPT-INJECTION",
      "severity": "high",
      "confidence": 0.62,
      "path_node_ids": ["external_actor-...", "prompt-...", "tool-..."],
      "evidence_predicates": [],
      "status": "open"
    }
  ],
  "legend": {}
}
```

Projection semantics:

- `layer` gives a default left-to-right layout from source to asset.
- `style.risk` and `risk_hypothesis_ids` identify nodes on a candidate risk path.
- risk edges are red and thicker, but color is presentation only; the hypothesis remains the security meaning.
- `risk_paths` provides an explanation layer for selecting a path in a future WebUI.
- `security` exposes trust zone, privilege, asset, threat categories, and risk level without requiring UI code to understand internal dataclasses.
- stable node ids allow findings and future browser evidence to attach to the same graph object.

The graph is intentionally suitable for a future React/Cytoscape/React Flow adapter, but no frontend dependency is required by the current CLI.

## 8. LLM Configuration and Real Test Run

The CLI selects a DeepSeek provider only when `use_llm=True` and a key is available in this order:

```text
--api-key
VIBE_SEC_DEEPSEEK_API_KEY
DEEPSEEK_API_KEY
```

Example using a process-local environment variable:

```powershell
$env:VIBE_SEC_DEEPSEEK_API_KEY = "<your-key>"
python -m main audit tests/fixtures --use-llm --session-dir .tmp-session --format json
```

The key must not be committed, placed in source, copied into a checkpoint, or printed in logs. `--use-llm` requires an explicit key from the sources above and fails fast when it is absent; it does not silently switch to `MockLLMService`. The deterministic mock path is available only when LLM mode is disabled or when tests inject a mock service. A real DeepSeek run also requires the optional `openai` package because `DeepSeekService` uses the OpenAI-compatible client.

The result protocol reports provider name, model, and whether the provider was real, without exposing credentials. Real provider regression must use a newly rotated key supplied through the process environment; a key previously exposed in chat must not be reused.

## 9. Current Gaps and Next Engineering Targets

The architecture is intentionally ahead of the first detector set. The main gaps are:

1. Deepen the implemented framework semantics from AST/provenance and bounded paths into interprocedural Java, Go, and framework-specific data flow.
2. Extend MCP authorization analysis to more SDKs and deployment gateway policies, and add structured workflow engines beyond GitHub Actions.
3. Add reproducible offline vulnerability database profiles or additional package/image adapters where database version and freshness can be proven.
4. Add a co-located browser image for the implemented internal multi-service environment. The existing host Playwright path remains loopback-only and separate.
5. Make tree-snapshot artifacts portable across machines or remote runners; unavailable or invalid snapshots currently produce skipped/failed evidence rather than an assumed pass. Project-test execution remains intentionally opt-in.
6. Configure deployment-level retention periods, automatic cleanup schedules, and storage quotas. The local append-only manifest, filtered lookup, explicit cleanup, and deletion tombstones are implemented.
7. Extend trigger integrations beyond the implemented `vibe-sec.skill-audit.v1` explicit/suggested CLI contract when host environments expose reliable change events.
8. Build the WebUI only after this graph and evidence protocol have remained stable across more fixtures.

The non-negotiable design constraints remain:

- a threat hypothesis is not a confirmed finding;
- an LLM conclusion is not evidence by itself;
- a privileged executor must be policy-checked and auditable;
- a remediation package does not mean the source was changed;
- a successful regression report requires real post-fix evidence as the implementation matures.
