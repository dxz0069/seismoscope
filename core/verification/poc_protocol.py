"""First-class, safety-bound proof-of-concept verification contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class PoCHarnessKind(str, Enum):
    PYTHON = "python"
    HTTP = "http"
    BROWSER = "browser"
    FUZZ = "fuzz"
    WORKFLOW = "workflow"


class PoCVerdict(str, Enum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    NEEDS_EVIDENCE = "needs_evidence"


# Oracle profiles map (harness_kind, vulnerability_type) → oracle_id.
# Each oracle_id must have a matching entry in HARNESS_ORACLE_PREDICATES.
# Callers that add new harness kinds should call register_oracle_profile()
# rather than modifying this dict directly.
HARNESS_ORACLE_PROFILES: dict[tuple, str] = {
    # ── Python harness ────────────────────────────────────────────────────
    (PoCHarnessKind.PYTHON.value, "command_injection"):      "python.command-sink-differential.v1",
    (PoCHarnessKind.PYTHON.value, "sql_injection"):          "python.sql-sink-differential.v1",
    (PoCHarnessKind.PYTHON.value, "path_traversal"):         "python.path-sink-differential.v1",
    (PoCHarnessKind.PYTHON.value, "hardcoded_password"):     "python.secret-static-presence.v1",
    (PoCHarnessKind.PYTHON.value, "api_key"):                "python.secret-static-presence.v1",
    (PoCHarnessKind.PYTHON.value, "secret_leak"):            "python.secret-static-presence.v1",
    (PoCHarnessKind.PYTHON.value, "prompt_injection"):       "python.prompt-sink-differential.v1",
    (PoCHarnessKind.PYTHON.value, "excessive_agency"):       "python.tool-invocation-differential.v1",
    (PoCHarnessKind.PYTHON.value, "unsafe_deserialization"): "python.deserialization-sink-differential.v1",
    # ── HTTP harness ──────────────────────────────────────────────────────
    (PoCHarnessKind.HTTP.value, "sql_injection"):             "http.injection-differential.v1",
    (PoCHarnessKind.HTTP.value, "command_injection"):         "http.injection-differential.v1",
    (PoCHarnessKind.HTTP.value, "path_traversal"):            "http.injection-differential.v1",
    (PoCHarnessKind.HTTP.value, "ssrf"):                      "http.ssrf-differential.v1",
    (PoCHarnessKind.HTTP.value, "authorization_bypass"):      "http.authz-differential.v1",
    (PoCHarnessKind.HTTP.value, "broken_access_control"):     "http.authz-differential.v1",
    (PoCHarnessKind.HTTP.value, "prompt_injection"):          "http.injection-differential.v1",
    (PoCHarnessKind.HTTP.value, "mcp_insecurity"):            "http.mcp-authorization-differential.v1",
    # ── Browser harness ───────────────────────────────────────────────────
    (PoCHarnessKind.BROWSER.value, "xss"):                    "browser.dom-sink-differential.v1",
    (PoCHarnessKind.BROWSER.value, "prompt_injection"):       "browser.dom-sink-differential.v1",
    # ── Fuzz harness ──────────────────────────────────────────────────────
    (PoCHarnessKind.FUZZ.value, "sql_injection"):             "fuzz.injection-crash-differential.v1",
    (PoCHarnessKind.FUZZ.value, "command_injection"):         "fuzz.injection-crash-differential.v1",
    (PoCHarnessKind.FUZZ.value, "unsafe_deserialization"):    "fuzz.injection-crash-differential.v1",
    # ── Workflow harness ──────────────────────────────────────────────────
    (PoCHarnessKind.WORKFLOW.value, "workflow_insecurity"):   "workflow.expression-injection-differential.v1",
    (PoCHarnessKind.WORKFLOW.value, "excessive_agency"):      "workflow.permission-scope-differential.v1",
}

HARNESS_ORACLE_PREDICATES: dict[str, str] = {
    # Python
    "python.command-sink-differential.v1": (
        "The positive control causes a command sink call from bound target code and the negative control does not"
    ),
    "python.sql-sink-differential.v1": (
        "The positive control causes a SQL query to reach the database sink without parameterization and the negative control does not"
    ),
    "python.path-sink-differential.v1": (
        "The positive control causes a path traversal sequence to reach the file sink and the negative control does not"
    ),
    "python.secret-static-presence.v1": (
        "The bound source location contains a literal credential or key value that is not loaded from an environment variable or secret store"
    ),
    "python.prompt-sink-differential.v1": (
        "The positive control injects an instruction-like string into the prompt and the model executes it; the negative control does not"
    ),
    "python.tool-invocation-differential.v1": (
        "The positive control triggers a privileged tool invocation without an explicit approval gate and the negative control requires approval"
    ),
    "python.deserialization-sink-differential.v1": (
        "The positive control causes untrusted bytes to reach the deserialization sink and the negative control does not"
    ),
    # HTTP
    "http.injection-differential.v1": (
        "The positive HTTP request containing an injection payload triggers a distinct server-side effect compared to the negative control"
    ),
    "http.ssrf-differential.v1": (
        "The positive control causes the server to issue an outbound network request to an attacker-controlled destination and the negative control does not"
    ),
    "http.authz-differential.v1": (
        "The positive control accesses a protected resource without valid authorization and the negative control is correctly denied"
    ),
    "http.mcp-authorization-differential.v1": (
        "The positive control invokes a privileged MCP capability without caller authorization and the negative control is denied"
    ),
    # Browser
    "browser.dom-sink-differential.v1": (
        "The positive control injects a script payload into the browser DOM and it executes; the negative control is sanitized and does not execute"
    ),
    # Fuzz
    "fuzz.injection-crash-differential.v1": (
        "The fuzzer produces an input that triggers an unhandled error or unexpected behavior from the injection sink that normal inputs do not trigger"
    ),
    # Workflow
    "workflow.expression-injection-differential.v1": (
        "The positive workflow run with an attacker-controlled event expression reaches a privileged execution step and the negative control does not"
    ),
    "workflow.permission-scope-differential.v1": (
        "The positive control demonstrates that the workflow identity can exercise permissions beyond the required operation scope"
    ),
}


def register_oracle_profile(
    harness_kind: str,
    vulnerability_type: str,
    oracle_id: str,
    predicate: str,
) -> None:
    """Register a custom oracle profile at runtime (e.g. from a plugin).

    Raises ValueError if the oracle_id already exists with a different predicate,
    preventing silent predicate overwrites.
    """
    key = (harness_kind.lower(), vulnerability_type.lower())
    existing_predicate = HARNESS_ORACLE_PREDICATES.get(oracle_id)
    if existing_predicate is not None and existing_predicate != predicate:
        raise ValueError(
            f"Oracle {oracle_id!r} is already registered with a different predicate. "
            "Use a new oracle_id for a different verification predicate."
        )
    HARNESS_ORACLE_PROFILES[key] = oracle_id
    HARNESS_ORACLE_PREDICATES[oracle_id] = predicate


@dataclass(frozen=True)
class SafetyEnvelope:
    """Trusted Harness policy. Model-provided fields never grant authority."""

    authorized: bool = False
    non_production: bool = True
    target_scope: list[str] = field(default_factory=list)
    allow_network: bool = False
    allow_service_start: bool = False
    allow_destructive_actions: bool = False
    max_duration_seconds: int = 60
    max_attempts: int = 3
    max_requests: int = 100

    def __post_init__(self) -> None:
        if not 1 <= int(self.max_duration_seconds) <= 600:
            raise ValueError("max_duration_seconds must be between 1 and 600")
        if not 1 <= int(self.max_attempts) <= 20:
            raise ValueError("max_attempts must be between 1 and 20")
        if not 1 <= int(self.max_requests) <= 10_000:
            raise ValueError("max_requests must be between 1 and 10000")
        if self.allow_destructive_actions:
            raise ValueError("Destructive PoC actions are not supported")
        if self.authorized and not self.non_production:
            raise ValueError("PoC execution is restricted to non-production targets")

    @classmethod
    def from_trusted_input(cls, value: dict[str, Any] | None) -> SafetyEnvelope:
        value = dict(value or {})
        trusted = value.get("_trusted_authorization_verified") is True
        return cls(
            authorized=trusted and bool(value.get("allow_poc_execution", False)),
            non_production=bool(value.get("non_production", True)),
            target_scope=[str(item) for item in value.get("target_scope", []) or []],
            allow_network=bool(value.get("allow_network", False)),
            allow_service_start=bool(value.get("allow_service_start", False)),
            allow_destructive_actions=bool(value.get("allow_destructive_actions", False)),
            max_duration_seconds=int(value.get("max_duration_seconds", 60) or 60),
            max_attempts=int(value.get("max_attempts", 3) or 3),
            max_requests=int(value.get("max_requests", 100) or 100),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PoCControl:
    name: str
    harness: str
    expected_marker: str
    should_match: bool

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("PoC control name is required")
        if not self.harness.strip():
            raise ValueError(f"PoC control {self.name!r} requires a harness")
        if not self.expected_marker.strip():
            raise ValueError(f"PoC control {self.name!r} requires an expected marker")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PoCTargetBinding:
    path: str
    sha256: str
    line_start: int = 0
    line_end: int = 0
    build_identity: str = ""
    runtime_identity: str = ""

    def __post_init__(self) -> None:
        if not self.path or Path(self.path).is_absolute():
            raise ValueError("PoC target path must be project-relative")
        if len(self.sha256) != 64 or any(char not in "0123456789abcdef" for char in self.sha256.lower()):
            raise ValueError("PoC target sha256 is invalid")
        if self.line_start < 0 or self.line_end < 0 or (
            self.line_start and self.line_end and self.line_end < self.line_start
        ):
            raise ValueError("PoC target line range is invalid")


@dataclass(frozen=True)
class PoCPlan:
    finding_id: str
    vulnerability_type: str
    goal: str
    harness_kind: PoCHarnessKind
    predicate: str
    target_binding: PoCTargetBinding
    oracle_id: str
    positive_control: PoCControl
    negative_control: PoCControl
    target_code: str = field(default="", repr=False, compare=False)
    image: str = "python:3.12-slim"
    environment: dict[str, Any] = field(default_factory=dict)
    assumptions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.finding_id.strip() or not self.vulnerability_type.strip():
            raise ValueError("PoC plan must bind to a finding and vulnerability type")
        if not self.goal.strip() or not self.predicate.strip():
            raise ValueError("PoC plan requires a goal and verification predicate")
        if self.positive_control.should_match is not True:
            raise ValueError("Positive control must be expected to match")
        if self.negative_control.should_match is not False:
            raise ValueError("Negative control must be expected not to match")
        if self.positive_control.expected_marker != self.negative_control.expected_marker:
            raise ValueError("Positive and negative controls must evaluate the same marker")
        if not self.image or any(char in self.image for char in "\r\n\0"):
            raise ValueError("PoC image is invalid")

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        finding: dict[str, Any],
        target_binding: PoCTargetBinding,
        target_code: str,
        oracle_id: str,
    ) -> PoCPlan:
        value = dict(value or {})
        marker = str(value.get("success_marker", "VIBE_SEC_VERIFIED") or "VIBE_SEC_VERIFIED")
        positive = dict(value.get("positive_control") or {})
        negative = dict(value.get("negative_control") or {})
        positive_harness = str(
            positive.get("harness", value.get("exploit_harness", "")) or ""
        )
        negative_harness = str(
            negative.get("harness", value.get("negative_control_harness", "")) or ""
        )
        kind = str(value.get("harness_kind", "python") or "python").lower()
        return cls(
            finding_id=str(value.get("finding_id", finding.get("id", "unknown"))),
            vulnerability_type=str(
                value.get("vulnerability_type", finding.get("vulnerability_type", "unknown"))
            ),
            goal=str(value.get("goal", f"Validate finding {finding.get('id', 'unknown')}")),
            harness_kind=PoCHarnessKind(kind),
            predicate=HARNESS_ORACLE_PREDICATES.get(
                oracle_id,
                str(value.get("predicate", f"Positive control emits {marker!r} and negative control does not")),
            ),
            target_binding=target_binding,
            oracle_id=oracle_id,
            positive_control=PoCControl(
                name=str(positive.get("name", "positive")),
                harness=positive_harness,
                expected_marker=str(positive.get("expected_marker", marker)),
                should_match=True,
            ),
            negative_control=PoCControl(
                name=str(negative.get("name", "negative")),
                harness=negative_harness,
                expected_marker=str(negative.get("expected_marker", marker)),
                should_match=False,
            ),
            target_code=target_code,
            image=str(value.get("image", "python:3.12-slim") or "python:3.12-slim"),
            environment=dict(value.get("environment") or {}),
            assumptions=[str(item) for item in value.get("assumptions", []) or []],
        )

    def fingerprint(self) -> str:
        value = asdict(self)
        value.pop("target_code", None)
        value["harness_kind"] = self.harness_kind.value
        serialized = json.dumps(value, sort_keys=True, ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("target_code", None)
        value["harness_kind"] = self.harness_kind.value
        value["fingerprint"] = self.fingerprint()
        return value


@dataclass(frozen=True)
class PoCValidation:
    executable: bool
    plan: PoCPlan | None
    envelope: SafetyEnvelope
    gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": "vibe-sec.poc-plan.v2",
            "executable": self.executable,
            "plan": self.plan.to_dict() if self.plan else None,
            "safety_envelope": self.envelope.to_dict(),
            "gaps": list(self.gaps),
        }


def validate_poc_plan(
    raw_plan: dict[str, Any] | None,
    *,
    finding: dict[str, Any],
    trusted_authorization: dict[str, Any] | None,
    project_root: str,
) -> PoCValidation:
    try:
        envelope = SafetyEnvelope.from_trusted_input(trusted_authorization)
    except (TypeError, ValueError) as exc:
        envelope = SafetyEnvelope()
        return PoCValidation(False, None, envelope, [f"Invalid trusted safety envelope: {exc}"])

    if not raw_plan:
        return PoCValidation(False, None, envelope, ["No explicit PoC plan was supplied"])
    target_binding, target_code, target_gaps = _bind_target(
        raw_plan, finding=finding, project_root=project_root,
    )
    if target_binding is None:
        return PoCValidation(False, None, envelope, target_gaps)
    try:
        kind = str(raw_plan.get("harness_kind", "python") or "python").lower()
        vulnerability_type = str(
            raw_plan.get("vulnerability_type", finding.get("vulnerability_type", "unknown"))
        ).lower()
        oracle_id = HARNESS_ORACLE_PROFILES.get((kind, vulnerability_type), "")
        plan = PoCPlan.from_dict(
            raw_plan,
            finding=finding,
            target_binding=target_binding,
            target_code=target_code,
            oracle_id=oracle_id,
        )
    except (TypeError, ValueError) as exc:
        return PoCValidation(False, None, envelope, [f"Invalid PoC plan: {exc}"])

    gaps: list[str] = list(target_gaps)
    if plan.finding_id != str(finding.get("id", "unknown")):
        gaps.append("PoC plan is not bound to the current finding id")
    if plan.vulnerability_type.lower() != str(finding.get("vulnerability_type", "unknown")).lower():
        gaps.append("PoC plan vulnerability type does not match the finding")
    if not plan.oracle_id:
        gaps.append("No Harness-owned PoC oracle is registered for this harness and vulnerability type")
    if not envelope.authorized:
        gaps.append("Trusted Harness authorization allow_poc_execution=true is required")
    if plan.harness_kind in {PoCHarnessKind.HTTP, PoCHarnessKind.BROWSER} and not envelope.allow_service_start:
        gaps.append("HTTP/browser PoC requires trusted service-start authorization")
    if plan.environment.get("services") and not envelope.allow_service_start:
        gaps.append("Multi-service PoC requires trusted service-start authorization")
    if plan.harness_kind == PoCHarnessKind.PYTHON and plan.positive_control.expected_marker != "VIBE_SEC_VERIFIED":
        gaps.append("The current Python PoC executor requires the VIBE_SEC_VERIFIED marker")
    if plan.environment.get("network_required") and not envelope.allow_network:
        gaps.append("PoC environment requests network access that was not authorized")
    return PoCValidation(not gaps, plan, envelope, gaps)


def _bind_target(
    raw_plan: dict[str, Any], *, finding: dict[str, Any], project_root: str,
) -> tuple[PoCTargetBinding | None, str, list[str]]:
    gaps: list[str] = []
    root = Path(project_root).resolve()
    if not root.is_dir():
        return None, "", ["PoC project root is unavailable"]
    supplied = dict(raw_plan.get("target_binding") or {})
    target_value = str(
        supplied.get("path") or raw_plan.get("target_path") or finding.get("file_path") or ""
    )
    if not target_value:
        return None, "", ["PoC target path is required"]
    candidate = Path(target_value)
    target = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    try:
        relative = target.relative_to(root).as_posix()
    except ValueError:
        return None, "", ["PoC target path escapes the project root"]

    finding_value = str(finding.get("file_path") or "")
    if finding_value:
        finding_path = Path(finding_value)
        finding_target = finding_path.resolve() if finding_path.is_absolute() else (root / finding_path).resolve()
        if finding_target != target:
            gaps.append("PoC target path does not match the current finding location")
    if not target.is_file():
        return None, "", [*gaps, "PoC target file does not exist"]
    try:
        content = target.read_bytes()
    except OSError as exc:
        return None, "", [*gaps, f"PoC target file could not be read: {exc}"]
    if len(content) > 2_000_000:
        return None, "", [*gaps, "PoC target file exceeds the 2 MB verification limit"]
    current_sha256 = hashlib.sha256(content).hexdigest()
    expected_sha256 = str(supplied.get("sha256") or raw_plan.get("target_sha256") or "").lower()
    if expected_sha256 and expected_sha256 != current_sha256:
        gaps.append("PoC target source hash is stale or does not match the current file")

    line_start = int(finding.get("line_start", 0) or 0)
    line_end = int(finding.get("line_end", line_start) or line_start)
    supplied_start = int(supplied.get("line_start", line_start) or 0)
    supplied_end = int(supplied.get("line_end", line_end) or 0)
    if (supplied_start, supplied_end) != (line_start, line_end):
        gaps.append("PoC target line range does not match the current finding")
    binding = PoCTargetBinding(
        path=relative,
        sha256=current_sha256,
        line_start=line_start,
        line_end=line_end,
        build_identity=str(supplied.get("build_identity", "")),
        runtime_identity=str(supplied.get("runtime_identity", "")),
    )
    return binding, content.decode("utf-8", errors="replace"), gaps


def bind_poc_verdict(
    validation: PoCValidation,
    *,
    positive_matched: bool,
    negative_matched: bool,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    if not validation.executable or validation.plan is None:
        verdict = PoCVerdict.NEEDS_EVIDENCE
    elif positive_matched and not negative_matched:
        verdict = PoCVerdict.VERIFIED
    elif negative_matched:
        # A firing negative control invalidates the experiment. It does not
        # prove that the product finding is fixed or false.
        verdict = PoCVerdict.NEEDS_EVIDENCE
    else:
        verdict = PoCVerdict.NEEDS_EVIDENCE
    return {
        "contract": "vibe-sec.poc-result.v1",
        "plan_fingerprint": validation.plan.fingerprint() if validation.plan else None,
        "verdict": verdict.value,
        "predicate": validation.plan.predicate if validation.plan else "",
        "oracle_id": validation.plan.oracle_id if validation.plan else "",
        "target_binding": asdict(validation.plan.target_binding) if validation.plan else None,
        "positive_control_matched": bool(positive_matched),
        "negative_control_matched": bool(negative_matched),
        "evidence_refs": list(evidence_refs or []),
        "gaps": list(validation.gaps),
    }
