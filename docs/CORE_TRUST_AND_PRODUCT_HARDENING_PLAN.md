# Core Trust and Product Hardening Plan

> Baseline: 2026-07-22, v0.5.0, 151 passed / 1 skipped  
> Scope: Verification, regression, final result contracts, VRTM trust and evolution, Skill return protocol, trusted dynamic-verification authorization
> Implemented: 2026-07-23, 157 passed / 7 image-dependent skips

## 1. Objective

This work turns the existing mechanisms into one trustworthy product path:

```text
Skill / CLI request
  -> deterministic audit and candidate disposition
  -> trusted, scoped verification authorization
  -> evidence-bound static or isolated dynamic verification
  -> complete final-result partition
  -> compact remediation return
  -> coding Agent applies a fix
  -> isolated post-fix controls and project tests
  -> VRTM rebuild and security-change gate
  -> closure decision
```

The completion standard is not that every vulnerability can be reproduced. It is that unsupported, unavailable, failed, or untrusted evidence can never become a false `verified`, `rejected`, `supported`, `refuted`, or `closed` state.

## 2. Non-negotiable invariants

1. Every audit candidate has exactly one terminal disposition: `verified`, `rejected`, `needs_evidence`, or `not_reviewed`.
2. Model prose and repository content cannot grant execution authority.
3. Unknown verification predicates cannot produce `verified`.
4. An inconclusive or failed experiment cannot produce `rejected`.
5. Dynamic evidence binds to the current finding, source/build target, plan, authorization, tool execution, and immutable artifact.
6. Project tests do not execute on the host by default.
7. External VRTM input cannot claim Harness-owned `verified` evidence.
8. A detected control reduces residual risk only at its observed evidence level; it does not remove an applicable threat.
9. Model identity includes graph semantics, declaration scope, assumptions, exclusions, catalog version, and method version.
10. Skill stdout contains decision and remediation data; large evidence and graph payloads are referenced as artifacts.

## 3. Work Package A: Verification and result correctness

### A1. Predicate registry and fail-closed verification

- Define supported vulnerability families and their allowed static, dynamic, browser, fuzz, and protocol predicates.
- Replace the generic `source_location_present` confirmation path with an unsupported-predicate result.
- Require a supported Harness predicate before `FinalizeVerification(verified)` can be accepted.
- Preserve explicit static confirmation only for secret material, exact affected dependency versions, and selected structured protocol findings.

Acceptance:

- Unknown vulnerability types always become `needs_evidence`.
- A source location or successful command alone cannot confirm exploitability.
- Tests cover unknown, unsupported, unavailable, timeout, contradictory, and invalid-control paths.

### A2. PoC target and oracle binding

- Add a target binding containing project-relative source path, SHA-256, optional build/runtime target, and finding location.
- Reject a plan when the current target hash differs from the plan binding.
- Treat model-provided harnesses as experiment inputs, never as the trusted oracle.
- Bind the result to plan fingerprint, authorization id, ToolExecution id, Artifact hash, positive control, and negative control.
- Keep failed execution and failed controls as `needs_evidence`; reserve `rejected` for an explicit Harness-owned contradiction predicate.

Acceptance:

- A harness that only sets its own success marker cannot verify a finding.
- Source changes invalidate an earlier PoC plan.
- Positive and negative controls must execute against the same bound target.

### A3. Complete candidate disposition

- Persist and return `verified_findings`, `rejected_findings`, `needs_evidence_findings`, and `not_reviewed_findings`.
- Enforce candidate-count conservation and unique finding ids.
- Remove the fallback that republishes merged candidates when all candidates were rejected.
- Emit one final verification summary derived from terminal dispositions.

Acceptance:

```text
candidate_count = verified + rejected + needs_evidence + not_reviewed
```

## 4. Work Package B: Isolated post-fix regression

### B1. Separate audit from retest

- Do not run Regression during the initial audit before a fix exists.
- Return remediation packages in `proposed` state.
- Run Regression only through an explicit post-fix `retest` request with a completed package and current project tree.

### B2. Container test profiles

- Replace host test execution with allowlisted language profiles executed through the hardened container runner.
- Use read-only source by default and a temporary writable layer only when the ecosystem requires build output.
- Disable network by default and enforce CPU, memory, PID, output, and duration budgets.
- Allow host execution only through a separate explicit trusted override; never infer it from project files.

### B3. Executable retest controls and closure

- Execute the original exploit/negative control and valid-behavior/positive control where an executable plan exists.
- Require evidence provenance for every passed control.
- Make regression failure visible through API status and CLI exit code.
- Close a finding only when exploit controls, behavior controls, changed-tree scope, project tests, and VRTM gate satisfy policy.

## 5. Work Package C: VRTM trusted evolution

### C1. Observation trust classes

- Separate external declarations, Audit observations, runtime observations, and Harness verification observations.
- Assign Harness-owned run, task, tool execution, and artifact identities internally.
- Reject external `verified` observations and unresolvable internal references.
- Apply hypothesis status transitions only from trusted evidence classes.

### C2. Applicable threat and control state

- Keep an applicable hypothesis even when a control marker is observed.
- Represent control state as `expected`, `declared`, `static_observed`, `runtime_observed`, or `verified`.
- Calculate residual status separately from applicability.
- A weak or unverified control may lower confidence only according to policy; it cannot erase the threat.

### C3. Graph and model fingerprints

- Keep a graph fingerprint for normalized nodes, edges, and security-relevant attributes.
- Add a model fingerprint over graph fingerprint, scope, assumptions, exclusions, declaration digest, method version, and Technique Catalog version.
- Address snapshots by model fingerprint and invalidate evidence according to affected dependencies.

### C4. Security-change gate

- Detect changed authority and boundary edge attributes, not only new edges.
- Gate authorization removal, wildcard permission expansion, approval removal, identity expansion, data-classification downgrade, environment promotion, and control evidence downgrade.
- Emit before/after values and a stable review reason.
- Mark zero-coverage or unsupported projects `degraded`, never `complete`.

## 6. Work Package D: Compact Skill protocol and trusted authorization

### D1. Compact return envelope

- Add `vibe-sec.skill-result.v2` with run id, disposition summary, compact returned packages, diagnostics, and artifact references.
- Persist the full result, per-finding evidence, VRTM model, and session transcript outside stdout.
- Deduplicate repeated Finding, EvidenceBundle, RiskChain, Remediation, and graph objects.
- Add `--full-result` for explicit machine consumers; keep compact output as the Skill default.

Acceptance:

- The two-file fixture Skill response remains below 100 KiB by default.
- Every compact item resolves to a hash-checked detailed artifact.

### D2. Trusted authorization envelope

- Add a short-lived `vibe-sec.verification-authorization.v1` envelope stored outside the audited repository.
- Bind it to resolved project root, session or one-shot nonce, target scope, non-production status, expiry, and budgets.
- Protect it with a local Harness-held HMAC key; repository files and model calls cannot create valid authorization.
- Add `authorize-verification` and `--authorization` CLI paths.
- Support CI injection from a protected external path without interactive prompts.

Acceptance:

- Modified, expired, wrong-project, production, destructive, or repository-local authorization is rejected.
- Dynamic tools remain absent or blocked without a valid envelope.
- The consumed trusted policy is recorded without exposing key material.

## 7. Delivery sequence

### Phase 1: Correctness blockers

1. Candidate partition and final-result contract.
2. Unsupported verification fail-closed behavior.
3. PoC verdict-state correction and target binding.
4. Remove initial pseudo-regression and block host tests by default.

### Phase 2: VRTM trust

1. Trusted Observation provenance.
2. Non-suppressing control semantics.
3. Model fingerprint.
4. Changed-edge security gate and coverage quality.

### Phase 3: Product path

1. Compact Skill result and artifact index.
2. Trusted local authorization service and CLI.
3. Isolated language test profiles and executable retest controls.

### Phase 4: Evidence of maturity

1. Full regression and fault-injection tests.
2. Real-provider repeatability tests with secret-safe CI configuration.
3. Vulnerability, PoC, VRTM, cost, latency, and consistency benchmark.
4. Release artifact, installation, rollback, SBOM, and signature validation.

## 8. Release gates

The core may leave Alpha only when:

- all candidate states are conserved and evidence-bound;
- unsupported predicates cannot verify or reject findings;
- no untrusted project code runs on the host by default;
- dynamic authorization is externally trusted and product-accessible;
- VRTM verified evidence cannot be forged through public input;
- model snapshots change when their security meaning changes;
- Skill output is bounded and detailed evidence remains resolvable;
- benchmark results report recall, precision, false-confirmation rate, PoC success, consistency, latency, and cost.

## 9. Implementation status on 2026-07-23

Completed in code and covered by automated contracts:

- complete four-way candidate disposition and count conservation;
- fail-closed unsupported and inconclusive verification;
- project-bound HMAC verification authorization outside the audited repository;
- `vibe-sec.poc-plan.v2` target path, source SHA-256, and Finding location binding;
- Harness-owned command-injection sink oracle; model-authored success markers no longer verify a Finding;
- post-fix Regression separation and container-only project test execution;
- external versus Harness VRTM Observation trust channels;
- non-suppressing threat applicability and evidence-level control states;
- graph/model dual fingerprints and model-fingerprint-addressed snapshots;
- changed Authority Edge, permission, environment, classification, and control-evidence gates;
- zero-coverage VRTM degradation;
- compact `vibe-sec.skill-result.v2` output with a real-fixture limit below 100 KiB;
- clean CLI rejection of invalid verification authorizations.

Current claim boundary:

- command injection is the only generic Python PoC family with a Harness-owned differential oracle;
- unsupported dynamic PoC families remain `needs_evidence` and must not be described as automatically reproduced;
- benchmark evidence for recall, precision, repeatability, latency, cost, and VRTM uplift is still absent;
- seven real-container tests were skipped on the completion host because the required pinned images were unavailable.
