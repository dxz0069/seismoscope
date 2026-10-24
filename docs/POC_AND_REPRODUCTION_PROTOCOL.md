# PoC and Reproduction Protocol

## Purpose

PoC execution is a Harness-owned evidence protocol, not arbitrary model code execution. The model may propose an experiment, but trusted input controls authorization, target scope, network access, service startup, duration, attempts, and request budgets.

```text
Finding
  -> PoCPlan
  -> SafetyEnvelope
  -> PositiveControl + NegativeControl
  -> Harness-owned Oracle
  -> Controlled Harness
  -> Evidence Artifact
  -> Verified / Rejected / Needs Evidence
```

Contracts are implemented in `core/verification/poc_protocol.py`:

- `vibe-sec.poc-plan.v2` binds the plan to a finding, vulnerability type, project-relative target path, Finding line range, and current source SHA-256;
- `SafetyEnvelope` is built only from trusted `verification_authorization` input;
- target source is read by the Harness and is not accepted from model-provided `target_code`;
- positive and negative controls are evaluated by a registered Harness-owned oracle;
- a firing negative control invalidates the experiment and cannot reject the finding;
- plan and result objects carry a stable SHA-256 fingerprint;
- absent, invalid, unauthorized, timed-out, or unavailable execution remains `needs_evidence`.

Trusted authorization example:

```json
{
  "allow_poc_execution": true,
  "non_production": true,
  "allow_service_start": true,
  "allow_network": false,
  "target_scope": ["local-project"],
  "max_duration_seconds": 60,
  "max_attempts": 3,
  "max_requests": 100
}
```

The model cannot grant these fields through a tool call or repository content.

## Reproduction Environments

`core/verification/environment_runtime.py` implements structured multi-service environments:

- one to eight allowlisted services;
- dependency-ordered startup with cycle detection;
- argument-vector commands only; shell entry points are rejected;
- read-only project mount, read-only root, non-root user, dropped capabilities, PID/CPU/memory limits;
- one ephemeral Docker `--internal` bridge;
- no host-published ports and no outbound route;
- service aliases such as `app`, `db`, and `redis` inside the environment;
- health predicates, bounded logs, reverse-order teardown, and forced network cleanup;
- positive and negative control containers join the internal network temporarily and are removed after execution.

The existing single-service Playwright path remains separate. It publishes one loopback-only port and requires `allow_service_start=true`. Multi-service browser verification requires a future co-located browser image; host Playwright cannot reach a Docker `--internal` network and must not be treated as evidence for that topology.

## Tool Integration

Verification outputs are stored through the Tool Fabric artifact store and included in the final evidence bundle. The ReAct verifier exposes `prepare_poc_plan`, which validates and binds a plan but never grants execution authority. `run_dynamic_verification` revalidates the plan against trusted policy immediately before execution.

## Claims Boundary

The current generic Python PoC registry has one Harness-owned oracle: `python.command-sink-differential.v1`. It records command-sink calls only when they originate from code objects compiled from the bound target source. A control that merely sets `VIBE_SEC_VERIFIED=True` does not satisfy this oracle. Python vulnerability families without a registered oracle remain `needs_evidence`.

HTTP behavior can be tested by a Python control container against an internal service alias, but it cannot produce a verified generic PoC verdict until a matching Harness-owned oracle is registered. Browser controls are supported through the separate authorized loopback Playwright path. Other exploit languages, privileged kernels, mobile devices, external production targets, destructive actions, and unrestricted shell payloads are not supported.
