# Agentic Audit Engine and Tool Fabric

## 1. Purpose

This document defines the security-agent core that Vibe Sec Platform must deliver. It resolves the relationship between the three reference systems:

```text
AutoCVE       -> agentic audit behavior and completion discipline
Cairn         -> containerized security-tool integration idea only
Vibe Sec      -> runtime-surface modeling and Vibe Coding security loop
```

The platform is not an orchestration shell with an optional scanner. The Agentic Audit Engine is a required core. The control plane and Harness make that engine usable in a high-permission development workflow by controlling triggers, tools, evidence, remediation, and regression.

## 2. Target Architecture

```text
Claude Code Skill / CLI / future Web UI
                |
        Security Control Plane
  trigger, scope, policy, session, gates
                |
       Agentic Audit Engine
  plan -> observe -> investigate -> hypothesize
       -> call tools -> reconcile evidence
       -> verify -> finalize -> remediate
                |
       Runtime Surface and Threat Model
  code + API + UI + prompt + model + tool/MCP
  permission + browser + workflow + data asset
                |
       Tool Fabric / Tool Container
  scanner adapters, read-only tools, browser,
  focused security tools, knowledge base, artifacts
```

The control plane is deterministic. The audit engine is LLM-assisted but contract-bound. The tool fabric is capability-based and policy-controlled. Runtime modeling is a shared security context, not a separate report disconnected from findings.

## 3. AutoCVE Capability Migration

The following capabilities are mandatory for the audit core:

| Capability | Required behavior | Current repository status |
| --- | --- | --- |
| Explicit phases | Plan, recon, surface, audit, merge, verify, remediate, return, retest | Implemented in the orchestrator |
| Task state machine | Legal transitions, state history, waiting for tools, pause/resume | Implemented in `core/agent_runtime` |
| ReAct loop | Bounded observe, tool call, tool result, next decision cycle | Implemented for multi-target discovery, finding review, and verification review |
| Completion contract | A model claim cannot close a task without a terminal contract | Implemented with `FinalizeFinding` and `FinalizeVerification` |
| Tool audit | Allowed, denied, failed, duplicate, and completed calls are recorded | Implemented for local permissioned executors |
| Checkpoint/resume | Session and task state can be persisted and restored | Implemented with sanitized JSONL checkpoints and exact recovery of pending tool/handoff/verification state |
| Retry/degradation | Transient failures retry; invalid provider failures do not loop forever; degraded status is explicit | Implemented in the task runtime |
| Loop protection | Repeated tool calls, nudges, and turn/time budgets stop runaway agents | Implemented in the task loop |
| Parallel tasks | Audit lanes and finding-level verification can run as child tasks | Implemented with bounded concurrency |
| Evidence-bound verdict | Confirmed/verified requires evidence predicates; missing evidence becomes a gap | Implemented and intentionally strict |
| Deep source audit | Cross-file reasoning, candidate generation, source exploration, and vulnerability explanation | Implemented with bounded multi-target discovery, changed-file prioritization, per-candidate review, clustering, measured coverage, and AST-backed Python and JavaScript/JSX source-to-sink paths; other languages remain best-effort |
| Scanner/tool integration | External deterministic signals enter the same evidence model | Implemented for bounded source/knowledge/dependency tools, fixed-endpoint OSV matching, Semgrep, and Gitleaks through `ToolGateway`; failed scanner runs retain sanitized raw artifacts |
| Isolated tool container | Security scanners and verification tools run with resource and target controls | Implemented with focused images, read-only mounts/root, no network by default, dropped capabilities, and resource limits; real execution requires a running Docker daemon and built image |

The last three rows are material product work. A state machine around shallow patterns is not sufficient to claim AutoCVE-level audit capability.

## 4. Agent Responsibilities

Agents are roles over a shared task and evidence model. They are not independent chat personalities.

### 4.1 Planner / Orchestrator

Determines the audit scope, selects lanes, creates child tasks, applies policy, and owns phase transitions. It does not decide that a vulnerability is true merely because a child agent says so.

### 4.2 Recon Agent

Builds a `ProjectProfile`: languages, frameworks, package manifests, entry points, test commands, service startup hints, deployment files, and likely sensitive assets. It emits observations with file and line provenance.

### 4.3 Surface Agent

Builds and updates the `RuntimeSurfaceGraph`. It identifies APIs, pages, prompts, models, tools, MCP resources, permission profiles, trust boundaries, browser sinks, storage, external content, and privileged operations. It emits risk hypotheses and evidence predicates.

### 4.4 Audit Agents

Audit agents perform deep investigation in bounded lanes:

- Web and API source audit;
- agent and prompt audit;
- MCP audit;
- secrets and dependency audit;
- workflow and browser automation audit.

An audit agent may start from a scanner signal, a runtime hypothesis, a changed-file trigger, or an exploratory target. It must navigate beyond one matched line: read callers and callees, inspect configuration, compare trust boundaries, and test whether a suspected source reaches a dangerous sink.

### 4.5 Verification Agent

Converts a finding into explicit verification predicates. It selects static, local execution, browser, fuzzing, or Docker checks according to risk and available evidence. It records `verified`, `rejected`, or `needs_evidence`; it never turns tool availability into proof.

### 4.6 Remediation Agent

Creates a `RemediationBundle` tied to the finding and its evidence. It supplies an AI patch prompt, constraints, acceptance criteria, positive and negative retest cases, and the expected runtime-surface change.

### 4.7 Regression Agent

Runs the finding's retest plan after a changed tree is available. It checks exploit closure, intended behavior, and relevant side effects. A missing changed tree or unavailable verifier is `skipped` or `partial`, never a simulated pass.

## 5. ReAct State Machine

The engine uses two nested state machines.

### 5.1 Workflow State Machine

```text
INIT -> PLAN -> RECON -> SURFACE -> AUDIT -> MERGE
     -> VERIFICATION -> REMEDIATION -> RETURN -> REGRESSION
     -> COMPLETED | FAILED
```

### 5.2 Agent Task State Machine

```text
PLANNED -> DISPATCHED -> RUNNING
                    -> WAITING_TOOL -> RUNNING
                    -> WAITING_HANDOFF -> COMPLETED
                    -> RETRYING -> RUNNING
                    -> PAUSED -> RESUMED -> RUNNING
                    -> FAILED
```

One bounded turn is:

```text
observe current task and context
  -> choose a read or execution tool, or propose a hypothesis
  -> policy checks the request
  -> execute, sanitize, and persist evidence output as an artifact
  -> append a normalized ToolSignal with provenance
  -> compare supporting and contradicting evidence
  -> continue, request another bounded tool call, or call a finalize contract
```

The model controls the next investigation proposal. The Harness controls whether that proposal is legal, whether the task can transition, and whether the final result meets its contract.

## 6. Shared Security Data Model

The current finding and evidence objects should converge on these primitives:

```text
ArtifactRef
  id, type, uri/path, sha256, producer, created_at, retention, sensitivity

ToolSignal
  id, tool_execution_id, kind, location, summary, confidence, artifact_refs

RiskHypothesis
  id, technique, source_nodes, target_nodes, assumptions,
  evidence_predicates, status

VerificationResult
  finding_id, predicates, observations, outcome, gaps, artifact_refs
```

The relationship is deliberately small:

```text
ToolRequest -> ToolExecution -> Artifact + ToolSignal
ToolSignal + Runtime Graph + Agent analysis -> Hypothesis
Hypothesis -> Finding -> Verification
Verification -> Remediation -> Regression
```

This is not a Cairn-style blackboard. `ToolSignal` is only a normalized adapter output, while `ArtifactRef` preserves the raw material needed to reproduce or inspect a conclusion. Task ownership and coordination remain in the existing Vibe Sec task runtime.

## 7. Tool Fabric

All tools, including built-in source readers, should eventually use one contract:

```text
ToolSpec
  name, version, capability, input_schema, output_schema,
  risk_class, required_permissions, supported_targets

ToolRequest
  request_id, session_id, task_id, tool_name, arguments, target_scope

ToolExecution
  request_id, status, allowed, policy_decision, started_at,
  ended_at, exit_code, artifact_refs, signals, error
```

The registry must describe capabilities rather than merely expose executable names. A model should request "bounded source read" or "local HTTP probe for the project service", and the policy layer should resolve the implementation and limits.

Every execution must enforce:

- project-root and target-scope restrictions;
- network policy and allowlists;
- read/write/execute/destructive capability classes;
- timeout, CPU, memory, process, and output limits;
- secret redaction before model exposure;
- artifact retention and hash recording;
- complete allow/deny/failure audit records.

Tools should be separated into tiers:

| Tier | Examples | Default model access |
| --- | --- | --- |
| Read-only analysis | source read, symbol search, dependency inspection, graph query | Allowed within project scope |
| Deterministic scanners | Semgrep, CodeQL, Gitleaks, Trivy, Bandit, package audit | Allowed through adapters |
| Local verification | test runner, bounded HTTP probe, Playwright, fuzz harness | Policy and resource gated |
| Active security tools | Nuclei, ffuf, naabu, nikto, dalfox | Explicit target and authorization required |
| Destructive or mutating | file write, shell mutation, dependency install, database reset | Human or project-policy gate |

The model must never receive an unbounded generic shell tool by default.

## 8. Containerized Tool Environment

The Cairn reference is limited to placing traditional security tools in a container for agent use. It does not imply adopting Cairn's Worker-agent architecture, dispatcher, blackboard, or Fact/Intent protocol.

The default execution topology is:

```text
Vibe Sec Orchestrator and Agent Runtime
  -> permissioned Tool Gateway
  -> start or reuse a bounded Tool Container
  -> run one approved scanner or verifier
  -> collect ToolExecution, ToolSignal, and ArtifactRef
  -> return evidence to the current Agent task
```

The Tool Container may contain:

- a curated security-tool image;
- a versioned knowledge base;
- browser automation dependencies;
- scanner templates and rule packs;
- a local service-under-test when verification requires it.

The Agent runtime remains outside the container by default. Container lifecycle is an implementation detail of the Tool Gateway and existing orchestrator, not a separate coordination architecture. The container cannot mutate task state or bypass tool policy.

### Container rollout status

1. Implemented: versioned tool protocol, immutable local artifact store, append-only per-session manifest with filtered lookup and deletion tombstones, policy gateway, and execution audit records.
2. Implemented: Semgrep and Gitleaks adapters with normalized signals and failure artifact retention.
3. Implemented and integration-tested: focused `vibe-sec-tools` image, pinned multi-stage Gitleaks source, Semgrep compatibility pin, and versioned local rule packs. Real fixtures cover Python, JavaScript, TypeScript, agent prompt/tool rules, secret detection, normalized rule ids, artifacts, and container cleanup. Hosts without Docker skip real-container tests while retaining adapter tests.
4. Implemented as an explicit path: Recon emits non-executing framework startup hints; an authorized service plan can start an allowlisted image with a read-only project mount, ephemeral bridge, loopback-only published port, health predicate, timeout, and forced cleanup before Playwright controls run. Service startup is never inferred as authorization, and the service bridge may have outbound access.
5. Implemented selectively: dedicated offline Trivy and curated Nuclei images are accepted locally. The CodeQL image definition and adapter exist, but the image is not installed and its capability is therefore not exposed.
6. Implemented: replayable real-container scanner fixtures run when Docker and `vibe-sec-tools:latest` are available; fixtures verify normalized signals, artifact refs, zero evidence gaps, and no new residual scanner containers.
7. Implemented and accepted: Bandit, offline Trivy filesystem scanning, and explicitly registered Nuclei profiles. `web_audit` automatically collects Semgrep, Bandit, and Trivy signals when container tools are enabled. Trivy records scanner version plus DB schema, update time, download time, and next update in its result and artifact metadata. Nuclei has a real isolated-network fixture and remains unavailable unless the trusted control plane registers it and authorizes its target/network policy. CodeQL supports only a pre-built database and approved language-specific suites; because the local CodeQL image is absent, image preflight omits it from Agent schemas rather than simulating availability.
8. Implemented: image capability preflight validates image labels, pinned versions, and required capabilities before scanner adapters are registered. Unavailable or mismatched images are reported and not exposed to the model.
9. Implemented: `vibe-sec.poc-plan.v2`, trusted safety envelopes, source target binding, Harness-owned oracle controls, stable fingerprints, and internal multi-service reproduction with temporary verifier containers.

Kali is not required. A full Kali image should only be an optional profile; focused tool images are smaller, easier to version, and easier to reproduce.

## 9. Scanner Integration

Scanners are signal producers, not competing product silos. Initial adapter contracts should cover:

```text
Semgrep / CodeQL  -> source and data-flow candidates
Gitleaks          -> secret candidates
Trivy / OSV       -> dependency and image candidates
Bandit            -> Python-specific source candidates
npm audit         -> package candidates
Nuclei            -> service and HTTP candidates
Playwright        -> browser and UI evidence
```

An adapter must normalize tool output into `ToolExecution`, `ArtifactRef`, and `ToolSignal`. The Audit Engine then:

1. deduplicates signals;
2. maps them to source locations and runtime nodes;
3. expands the signal into a risk hypothesis;
4. investigates context across files and components;
5. chooses verification predicates;
6. produces an evidence-bound finding or records an evidence gap.

This is how fast deterministic scanning and deep LLM review cooperate.

OSV dependency matching is implemented as a separate fixed-endpoint adapter rather than hidden inside manifest parsing or the network-disabled tool image. `inspect_dependencies` remains offline. `query_dependency_vulnerabilities` requires trusted network authorization, is restricted to `api.osv.dev`, queries only exact pinned or locked versions, records query time and database freshness limitations, and returns unresolved versions as coverage gaps. An OSV match verifies that an affected version is present; it does not by itself prove exploitability in the application.

Current executable scanner boundaries:

| Tool | Current state | Execution boundary |
| --- | --- | --- |
| Semgrep 1.99.0 | Available | Pinned local rules, no network, read-only source/root |
| Gitleaks 8.21.2 | Available | No network, redacted secret artifacts, read-only source/root |
| Bandit 1.8.0 | Available | Python-specific SAST, no network, read-only source/root |
| Trivy 0.58.2 | Available | Offline DB snapshot, no network, read-only project; ephemeral container overlay is writable because Trivy opens BoltDB read-write |
| Nuclei 3.11.0 | Available only through explicit active-scanner registration | Curated local templates, authorized host allowlist, rate limit, no interactsh/update, isolated managed network |
| CodeQL 2.26.1 | Adapter and image definition only; not locally available | Not registered or exposed until the image and approved suites pass preflight; accepts only a pre-built project-scoped database |

## 10. Runtime Modeling as the Product Extension

The Runtime Surface Graph is the shared context that traditional source audit normally lacks. It must represent:

```text
External actor -> UI/API -> prompt/model -> tool/MCP
               -> permission boundary -> code operation -> data asset
               -> browser or external service
```

The graph is useful only when edges have security meaning. Each edge should describe at least one of:

- untrusted input flow;
- instruction or control influence;
- authentication or authorization decision;
- privileged capability access;
- data read/write flow;
- browser or network boundary crossing.

The Agentic Audit Engine uses graph hypotheses to explore complex paths, while source and scanner evidence ground those paths. The final finding should explain both the local defect and the runtime consequence.

## 11. Remaining Hardening Priorities

1. Deepen the implemented Django/FastAPI/Flask, Express/Nest/Next, Spring, and Go framework semantics into broader interprocedural data flow. Current non-Python framework paths are provenance-preserving bounded associations, not universal flow proofs.
2. Extend MCP authorization analysis to more SDKs and deployment-provided gateway policies, including effective host/header/origin rules and runtime caller/resource identity.
3. Add structured workflow analyzers beyond GitHub Actions and additional package/image sources such as offline OSV snapshots or Trivy DBs where reproducible database freshness can be recorded.
4. Add a co-located browser profile to the internal multi-service environment. The internal PoC topology is isolated; the separate host Playwright single-service path still uses loopback publication.
5. Configure automatic retention schedules and storage quotas for deployments. The local manifest index and explicit age-based cleanup are implemented and cleanup defaults to dry-run.
6. Keep the implemented `vibe-sec.skill-audit.v1` Skill/CLI contract stable; defer Web UI to a projection over session, graph, evidence, and finding objects.

## 12. Non-Goals and Claims Discipline

The platform should not claim that:

- an LLM explanation is proof;
- a static scanner result is automatically exploitable;
- a Docker run is verification without a predicate;
- a graph with guessed edges is a complete threat model;
- a Skill alone can observe every coding-agent event in every host environment;
- a container image is a security boundary by itself.

The product claim should be precise:

> Vibe Sec Platform combines a mature Agentic Code Audit Engine with fast security-tool integration, runtime-surface security modeling, controlled verification, and development-context remediation for Vibe Coding workflows.
