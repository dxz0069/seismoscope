# Agent Core Completion Audit

## Scope

This audit evaluates the local Skill/CLI Agent core against `PRODUCT_ARCHITECTURE_V2.md` and `AGENTIC_AUDIT_ENGINE_AND_TOOL_FABRIC.md`. It covers orchestration, source discovery, runtime modeling, controlled tools, evidence, verification, remediation return, and retest. Web UI, universal framework coverage, and enterprise deployment services are outside this completion boundary.

## Requirement Matrix

| Requirement | Status | Authoritative implementation and proof |
| --- | --- | --- |
| Deterministic workflow phases and gates | Implemented | `core/orchestrator/orchestrator.py`; orchestration and resume tests |
| Strict Agent task state machine | Implemented | `core/agent_runtime/`; transition, pause/resume, retry, timeout, and stop-hook tests |
| Bounded multi-turn ReAct | Implemented | discovery, finding review, and verification loops with terminal tools, context compaction, duplicate-call control, and checkpoints |
| Completion contracts | Implemented | `FinalizeAuditDiscovery`, `FinalizeFinding`, and `FinalizeVerification`; unsupported confirmation is rejected |
| Parallel lane and finding tasks | Implemented | parent/child task graph, bounded audit-lane fan-out, and bounded finding verification |
| AutoCVE-class source exploration core | Implemented for declared languages | changed-file seeds, transitive context, target planning, candidate clustering, callers/callees, guards, source-to-sink paths, and evidence coverage |
| Semantic source analysis | Implemented for Python, JavaScript/JSX, TypeScript/TSX | Python AST, Esprima, and Tree-sitter analyzers with bounded cross-file paths; other languages remain best effort |
| Trusted audit methodology | Implemented | `load_audit_guidance`; fixed trusted roots and explicit exclusion from project evidence |
| Composite runtime surface | Implemented | first-class entries, prompts, models, tools, MCP capabilities, permissions, external content, browser sinks, storage, workflows, trust boundaries, and code blocks |
| Stable source-grounded graph | Implemented | V3 stable node ids, provenance, deduplicated typed edges, `security_meaning`, and no global permission/dependency-noise edges |
| Graph-backed threat method | Implemented | nine executable techniques with continuous paths, evidence predicates, assumptions, coverage, and frontend-ready visualization |
| MCP protocol analysis | Implemented for declared SDK/config shapes | Python tool/resource decorators; JavaScript/TypeScript registrations; descriptions; consequential handlers; local gates; wildcard config; dynamic identity; remote transport auth gaps |
| Workflow analysis | Implemented for GitHub Actions | safe YAML parsing and attacker-controlled event expression binding to concrete jobs/steps and capabilities |
| Dependency inventory | Implemented offline | structured Python, Node, Go, Maven, Gradle, and Cargo manifest/lock parsing with provenance and honest parser gaps |
| Dependency vulnerability matching | Implemented with explicit network authorization | fixed-endpoint OSV adapter, domain allowlist, exact-version queries, 1000-package batches, bounded retry, freshness metadata, artifacts, signals, verification, and remediation |
| Traditional scanner integration | Implemented accepted local set | Semgrep, Gitleaks, Bandit, offline Trivy, authorized Nuclei, and OSV normalize into the same finding/evidence model; unavailable CodeQL is omitted by preflight |
| Focused tool container | Implemented | read-only project/root, no network by default, dropped capabilities, unprivileged user, CPU/memory/PID/time/output limits, and forced `--rm` cleanup |
| Scanner failure evidence | Implemented | failed, timed-out, and malformed outputs retain sanitized immutable artifacts and explicit gaps |
| Controlled verification | Implemented | location-bound static checks, protocol validators, first-class PoC contracts, Docker/fuzz predicates, loopback browser controls, and internal multi-service reproduction |
| Framework semantics | Implemented with explicit depth boundary | Python AST plus Tree-sitter-validated Django/FastAPI/Flask, Express/Nest/Next, Spring, and Go route/input/guard/ORM/sink provenance |
| Extended scanner adapters | Implemented with explicit availability boundary | Bandit, Trivy, and Nuclei passed real-container checks; CodeQL contract exists but its absent image is not exposed to Agents |
| Evidence-bound verdicts | Implemented | verified/rejected/needs-evidence semantics; availability or model prose cannot satisfy a predicate |
| Remediation return | Implemented | versioned bundles with patch prompt, constraints, change scope, positive/negative retests, and expected graph change |
| Post-fix regression | Implemented | changed-tree provenance, snapshot hash validation, exploit and behavior controls, project tests, skipped/partial semantics, and closure gates |
| Skill/CLI contract | Implemented and stable | `vibe-sec.skill-audit.v1`, changed-file scope, trigger suggestion, remediation return, `retest`, `--container-tools`, and explicit `--osv` |
| Source-package deployment | Implemented local bootstrap | Windows/Linux bootstrap, editable CLI install, locked image manifest, setup/update/doctor contracts, resumable checksum-verified tool artifacts, image preflight, and persisted non-secret install state |
| Artifact audit and retention primitives | Implemented locally | immutable artifacts, append-only manifest, hashes, redaction, lookup, dry-run cleanup, and deletion tombstones |

## Agent Context Boundaries

| Role | Receives | May call | Cannot decide alone |
| --- | --- | --- | --- |
| Planner/Orchestrator | trusted audit request, trigger, scope, policy, phase state | registered phase Agents and task graph | vulnerability truth |
| Recon | project root and bounded project files | deterministic structure/dependency inspection | exploitability |
| Surface | project profile and source/config parsers | local structured extractors | confirmation of a risk hypothesis |
| Audit discovery/review | one lane/target or candidate, graph hypothesis, bounded transcript | source list/read/search/outline, semantic traces, dependencies, optional OSV, guidance, graph/hypothesis query, optional scanner adapters | verified verdict without contract evidence |
| Verification | one finding, evidence bundle, policy and explicit authorization | static predicate, protocol analyzer, bounded Docker/fuzz/browser/service tools | proof from tool availability or failed infrastructure |
| Remediation | verified or needs-evidence finding and baseline tree | deterministic profile and artifact store | claim that a patch was applied |
| Regression | applied-tree evidence and remediation bundle | approved tests, changed-tree checks, retest predicates | pass without post-fix evidence |

## Verification Baseline

The completion baseline on 2026-07-22 is:

```text
python -m pytest -q
139 passed, 1 skipped (CodeQL image unavailable)

python -m compileall -q core agents main.py tests
passed

quick_validate.py skill
Skill is valid

real focused Docker scanner tests
passed for Semgrep, Gitleaks, Bandit, offline Trivy DB provenance/findings,
authorized internal-network Nuclei, artifacts, and cleanup; CodeQL skipped because its image is absent

deterministic changed-file Skill run
vibe-sec.skill-audit.v1, orchestration completed, V3 graph, 13 findings, 13 returned packages
```

The workspace contains no previously exposed DeepSeek key and no residual Vibe Sec scanner container or managed service network. Ruff was not run because the optional `ruff` package is not installed in this environment; compilation and the complete test suite passed.

## Explicit Extension Boundaries

These are future breadth or deployment work, not hidden claims of the completed local core:

- deeper interprocedural framework data flow beyond the implemented AST/provenance extractors;
- MCP SDK and deployment gateway policies not represented in analyzed source/configuration;
- structured workflow engines beyond GitHub Actions;
- CodeQL image/query-suite acceptance and real pre-built database analysis; the adapter remains unavailable until preflight succeeds;
- independently signed or mirrored offline vulnerability DB distribution beyond the recorded Trivy snapshot metadata;
- co-located browser execution inside the implemented isolated multi-service network;
- deployment quotas, scheduled retention, team policy, Web UI, and multi-user services;
- a live DeepSeek smoke test, which requires a newly rotated environment key. The previously exposed key must not be reused.

The completion claim is therefore precise: the Agent core and Harness contracts are implemented for the declared local Skill/CLI scope, with representative deterministic tool integration and explicit extension points. It is not a claim of universal language, framework, scanner, or runtime coverage.
