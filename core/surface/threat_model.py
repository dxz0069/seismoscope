"""Executable runtime threat modeling contracts and deterministic hypotheses."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from hashlib import sha1
from typing import Any

from ..harness.models import RuntimeSurfaceGraph

VRTM_METHOD_VERSION = "0.4"
TECHNIQUE_CATALOG_VERSION = "2026.07.22"


class HypothesisStatus(str):
    """Valid hypothesis lifecycle statuses.

    Using named constants (rather than a plain Enum) keeps the dataclass
    serialization simple while still making typos a NameError at the call site.
    """
    OPEN = "open"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    MITIGATED = "mitigated"

    _VALID = frozenset({"open", "supported", "refuted", "mitigated"})

    @classmethod
    def validate(cls, value: str) -> str:
        """Return *value* if it is a known status, otherwise raise ValueError."""
        if value not in cls._VALID:
            raise ValueError(
                f"Invalid HypothesisStatus {value!r}. "
                f"Must be one of: {sorted(cls._VALID)}"
            )
        return value


@dataclass(frozen=True)
class ThreatTechnique:
    technique_id: str
    name: str
    category: str
    description: str
    default_severity: str
    required_node_types: list[str] = field(default_factory=list)
    verification_strategy: str = "static_and_runtime"
    flow_planes: list[str] = field(default_factory=list)
    path_pattern: list[str] = field(default_factory=list)
    external_mappings: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.technique_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "default_severity": self.default_severity,
            "required_node_types": self.required_node_types,
            "verification_strategy": self.verification_strategy,
            "flow_planes": self.flow_planes,
            "path_pattern": self.path_pattern,
            "external_mappings": self.external_mappings,
        }


@dataclass
class EvidencePredicateSpec:
    predicate_id: str
    description: str
    evidence_type: str
    required: bool = True
    verification_tool: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.predicate_id,
            "description": self.description,
            "evidence_type": self.evidence_type,
            "required": self.required,
            "verification_tool": self.verification_tool,
        }


@dataclass
class RiskHypothesis:
    hypothesis_id: str
    technique_id: str
    title: str
    source_node_ids: list[str]
    boundary_node_ids: list[str]
    target_node_ids: list[str]
    attack_path: list[str]
    impact: str
    severity: str
    confidence: float
    evidence_predicates: list[EvidencePredicateSpec] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    status: str = "open"
    flow_planes: list[str] = field(default_factory=list)
    control_gaps: list[dict[str, Any]] = field(default_factory=list)
    risk_factors: dict[str, Any] = field(default_factory=dict)
    external_mappings: dict[str, list[str]] = field(default_factory=dict)
    applicability: str = "applicable"
    residual_status: str = "unresolved"
    control_state: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Validate status at construction time so typos raise immediately.
        # RiskHypothesis is a mutable dataclass, so plain assignment works.
        self.status = HypothesisStatus.validate(self.status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "technique_id": self.technique_id,
            "title": self.title,
            "source_node_ids": self.source_node_ids,
            "boundary_node_ids": self.boundary_node_ids,
            "target_node_ids": self.target_node_ids,
            "attack_path": self.attack_path,
            "impact": self.impact,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_predicates": [item.to_dict() for item in self.evidence_predicates],
            "assumptions": self.assumptions,
            "status": self.status,
            "flow_planes": self.flow_planes,
            "control_gaps": self.control_gaps,
            "risk_factors": self.risk_factors,
            "external_mappings": self.external_mappings,
            "applicability": self.applicability,
            "residual_status": self.residual_status,
            "control_state": self.control_state,
        }


@dataclass
class RuntimeThreatModel:
    method: str = "vibe_runtime_threat_model"
    version: str = VRTM_METHOD_VERSION
    techniques: list[ThreatTechnique] = field(default_factory=list)
    hypotheses: list[RiskHypothesis] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "version": self.version,
            "technique_catalog_version": TECHNIQUE_CATALOG_VERSION,
            "techniques": [item.to_dict() for item in self.techniques],
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "coverage": self.coverage,
            "assumptions": self.assumptions,
        }


_TECHNIQUE_DETAILS: dict[str, dict[str, Any]] = {
    "T-PROMPT-INJECTION": {
        "flow_planes": ["instruction"],
        "path_pattern": ["external_actor", "prompt", "model"],
        "external_mappings": {
            "stride": ["Tampering", "Elevation of Privilege"],
            "mitre_atlas": ["AML.T0051 - LLM Prompt Injection"],
            "cwe": ["CWE-1427"],
            "owasp": ["LLM01:2025 - Prompt Injection"],
        },
    },
    "T-EXCESSIVE-AGENCY": {
        "flow_planes": ["instruction", "authority"],
        "path_pattern": ["prompt_or_model", "tool", "privileged_asset"],
        "external_mappings": {
            "stride": ["Elevation of Privilege"],
            "mitre_atlas": ["AML.T0051 - LLM Prompt Injection"],
            "cwe": ["CWE-250", "CWE-269"],
            "owasp": ["LLM06:2025 - Excessive Agency"],
        },
    },
    "T-MCP-DESCRIPTION-INJECTION": {
        "flow_planes": ["instruction", "authority"],
        "path_pattern": ["tool_metadata", "model_decision", "tool"],
        "external_mappings": {
            "stride": ["Tampering", "Spoofing"],
            "mitre_atlas": ["AML.T0051 - LLM Prompt Injection"],
            "cwe": ["CWE-1427"],
            "owasp": ["LLM01:2025 - Prompt Injection", "OWASP MCP - Tool Poisoning"],
        },
    },
    "T-UNPROTECTED-ENTRY": {
        "flow_planes": ["data", "authority"],
        "path_pattern": ["external_actor", "entry_point", "protected_operation"],
        "external_mappings": {
            "stride": ["Spoofing", "Elevation of Privilege"],
            "cwe": ["CWE-306", "CWE-862"],
            "capec": ["CAPEC-115 - Authentication Bypass"],
            "owasp": ["A01:2021 - Broken Access Control"],
        },
    },
    "T-INDIRECT-PROMPT-INJECTION": {
        "flow_planes": ["data", "instruction"],
        "path_pattern": ["external_content", "prompt", "model"],
        "external_mappings": {
            "stride": ["Tampering"],
            "mitre_atlas": ["AML.T0051 - LLM Prompt Injection"],
            "cwe": ["CWE-1427"],
            "owasp": ["LLM01:2025 - Prompt Injection"],
        },
    },
    "T-MCP-AUTHORIZATION": {
        "flow_planes": ["authority"],
        "path_pattern": ["model", "mcp_capability", "privileged_asset"],
        "external_mappings": {
            "stride": ["Elevation of Privilege"],
            "cwe": ["CWE-862", "CWE-863"],
            "owasp": ["LLM06:2025 - Excessive Agency", "OWASP MCP - Excessive Permissions"],
        },
    },
    "T-BROWSER-SINK-INJECTION": {
        "flow_planes": ["data"],
        "path_pattern": ["external_content", "browser_sink"],
        "external_mappings": {
            "stride": ["Tampering", "Information Disclosure"],
            "cwe": ["CWE-79", "CWE-601"],
            "capec": ["CAPEC-63 - Cross-Site Scripting"],
            "owasp": ["A03:2021 - Injection", "LLM05:2025 - Improper Output Handling"],
        },
    },
    "T-WORKFLOW-PRIVILEGE": {
        "flow_planes": ["instruction", "authority", "artifact"],
        "path_pattern": ["external_actor", "workflow", "privileged_asset"],
        "external_mappings": {
            "stride": ["Tampering", "Elevation of Privilege"],
            "mitre_attack": ["T1059 - Command and Scripting Interpreter"],
            "cwe": ["CWE-78", "CWE-829"],
            "owasp": ["A08:2021 - Software and Data Integrity Failures"],
        },
    },
    "T-SENSITIVE-STORAGE-ACCESS": {
        "flow_planes": ["data", "authority", "artifact"],
        "path_pattern": ["tool_or_mcp", "storage_asset"],
        "external_mappings": {
            "stride": ["Information Disclosure", "Tampering"],
            "cwe": ["CWE-862", "CWE-922"],
            "owasp": ["A01:2021 - Broken Access Control", "A02:2021 - Cryptographic Failures"],
        },
    },
    "T-MEMORY-POISONING": {
        "flow_planes": ["data", "instruction", "artifact"],
        "path_pattern": ["external_content", "memory", "model"],
        "external_mappings": {
            "stride": ["Tampering"],
            "mitre_atlas": ["AML.T0051 - LLM Prompt Injection"],
            "cwe": ["CWE-1427"],
            "owasp": ["LLM01:2025 - Prompt Injection", "OWASP Agentic - Memory Poisoning"],
        },
    },
    "T-RETRIEVAL-INJECTION": {
        "flow_planes": ["data", "instruction"],
        "path_pattern": ["external_content", "retriever", "model"],
        "external_mappings": {
            "stride": ["Tampering"],
            "mitre_atlas": ["AML.T0051 - LLM Prompt Injection"],
            "cwe": ["CWE-1427"],
            "owasp": ["LLM01:2025 - Prompt Injection", "LLM08:2025 - Vector and Embedding Weaknesses"],
        },
    },
    "T-SECRET-DELEGATION": {
        "flow_planes": ["data", "authority", "artifact"],
        "path_pattern": ["agent_or_capability", "secret_asset"],
        "external_mappings": {
            "stride": ["Information Disclosure", "Elevation of Privilege"],
            "cwe": ["CWE-522", "CWE-862"],
            "owasp": ["A01:2021 - Broken Access Control", "A02:2021 - Cryptographic Failures"],
        },
    },
    "T-DEPLOYMENT-TAMPERING": {
        "flow_planes": ["authority", "artifact"],
        "path_pattern": ["agent_or_workflow", "deployment_capability", "deployment_asset"],
        "external_mappings": {
            "stride": ["Tampering", "Elevation of Privilege"],
            "mitre_attack": ["T1195 - Supply Chain Compromise"],
            "cwe": ["CWE-269", "CWE-829"],
            "owasp": ["A08:2021 - Software and Data Integrity Failures"],
        },
    },
    "T-SERVICE-IDENTITY-OVERPRIVILEGE": {
        "flow_planes": ["authority"],
        "path_pattern": ["agent_or_workflow", "service_identity", "privileged_asset"],
        "external_mappings": {
            "stride": ["Spoofing", "Elevation of Privilege"],
            "mitre_attack": ["T1078 - Valid Accounts"],
            "cwe": ["CWE-250", "CWE-269"],
            "owasp": ["A01:2021 - Broken Access Control", "LLM06:2025 - Excessive Agency"],
        },
    },
}

_CONTROL_EXPECTATIONS = {
    "T-PROMPT-INJECTION": ("instruction_boundary", "Separate untrusted input from trusted instructions and constrain instruction precedence."),
    "T-EXCESSIVE-AGENCY": ("least_privilege_and_approval", "Constrain tool scope and require approval for consequential operations."),
    "T-MCP-DESCRIPTION-INJECTION": ("tool_metadata_integrity", "Trust, pin, and review tool metadata before exposing it to the model."),
    "T-UNPROTECTED-ENTRY": ("authentication_and_authorization", "Enforce authentication and operation-level authorization at the entry point."),
    "T-INDIRECT-PROMPT-INJECTION": ("external_content_isolation", "Label and isolate external content before it enters model instructions."),
    "T-MCP-AUTHORIZATION": ("mcp_authorization", "Enforce caller- and operation-specific authorization at the MCP capability."),
    "T-BROWSER-SINK-INJECTION": ("output_encoding", "Apply context-specific sanitization or safe browser APIs before rendering."),
    "T-WORKFLOW-PRIVILEGE": ("workflow_input_and_permission_guard", "Separate untrusted event data from commands and minimize workflow permissions."),
    "T-SENSITIVE-STORAGE-ACCESS": ("storage_access_control", "Enforce caller and object-level authorization for sensitive storage operations."),
    "T-MEMORY-POISONING": ("memory_provenance_and_isolation", "Track memory provenance and prevent untrusted content from becoming trusted instructions."),
    "T-RETRIEVAL-INJECTION": ("retrieval_content_boundary", "Filter, label, and isolate retrieved content before model instruction processing."),
    "T-SECRET-DELEGATION": ("secret_broker_and_scope", "Broker secret access with operation scope, caller binding, and non-disclosure controls."),
    "T-DEPLOYMENT-TAMPERING": ("deployment_approval_and_integrity", "Require approval, artifact integrity, and environment-scoped deployment authority."),
    "T-SERVICE-IDENTITY-OVERPRIVILEGE": ("identity_least_privilege", "Constrain service identity permissions and bind delegation to the initiating operation."),
}


def _technique(*args: Any) -> ThreatTechnique:
    details = _TECHNIQUE_DETAILS.get(str(args[0]), {})
    return ThreatTechnique(
        *args,
        flow_planes=list(details.get("flow_planes", [])),
        path_pattern=list(details.get("path_pattern", [])),
        external_mappings={
            key: list(values) for key, values in details.get("external_mappings", {}).items()
        },
    )


class RuntimeThreatModelAnalyzer:
    """Build bounded, evidence-oriented risk hypotheses from the surface graph.

    ``surface`` may be None when the analyzer is constructed from the
    orchestrator (which already has a pre-built graph and does not re-run
    surface extraction).  Callers that pass None accept the constraint that
    any analyzer logic gated on live surface metadata is skipped.

    Additional techniques can be registered at runtime via
    ``register_technique()`` without touching this module.
    """

    TECHNIQUES = (
        _technique(
            "T-PROMPT-INJECTION",
            "Prompt injection",
            "agent_security",
            "Untrusted content can influence instructions or model-controlled behavior.",
            "high",
            ["external_actor", "prompt"],
            "static_plus_controlled_prompt",
        ),
        _technique(
            "T-EXCESSIVE-AGENCY",
            "Excessive agency",
            "agent_security",
            "A model-facing tool can perform privileged operations without a strong approval boundary.",
            "high",
            ["prompt", "tool", "privileged_asset"],
            "static_plus_permission_probe",
        ),
        _technique(
            "T-MCP-DESCRIPTION-INJECTION",
            "Tool description injection",
            "mcp_security",
            "Tool metadata contains instruction-like content that may influence tool selection or policy.",
            "high",
            ["tool"],
            "static_plus_tool_selection_probe",
        ),
        _technique(
            "T-UNPROTECTED-ENTRY",
            "Unprotected entry point",
            "application_security",
            "An externally reachable entry point has no detected authentication or authorization gate.",
            "medium",
            ["external_actor", "entry_point"],
            "static_plus_authorization_probe",
        ),
        _technique(
            "T-INDIRECT-PROMPT-INJECTION",
            "Indirect prompt injection",
            "agent_security",
            "External content is carried into a prompt or model context and can influence behavior.",
            "high",
            ["external_content", "prompt", "model"],
            "static_data_flow_plus_controlled_prompt",
        ),
        _technique(
            "T-MCP-AUTHORIZATION",
            "MCP capability authorization gap",
            "mcp_security",
            "A model-callable MCP capability crosses an unresolved authorization boundary.",
            "high",
            ["mcp_capability", "trust_boundary", "privileged_asset"],
            "static_plus_permission_probe",
        ),
        _technique(
            "T-BROWSER-SINK-INJECTION",
            "Browser sink injection",
            "browser_security",
            "Externally controlled content reaches an executable or navigation-sensitive browser sink.",
            "high",
            ["external_content", "browser_sink"],
            "static_data_flow_plus_browser_control",
        ),
        _technique(
            "T-WORKFLOW-PRIVILEGE",
            "Untrusted workflow input reaches privileged automation",
            "workflow_security",
            "An attacker-influenced workflow event reaches a step with code, credential, network, or deployment capability.",
            "critical",
            ["external_actor", "workflow", "privileged_asset"],
            "structured_workflow_plus_controlled_replay",
        ),
        _technique(
            "T-SENSITIVE-STORAGE-ACCESS",
            "Sensitive storage capability exposure",
            "data_security",
            "A model-callable capability can access a sensitive persistent asset.",
            "high",
            ["tool", "mcp_capability", "storage_asset"],
            "static_data_flow_plus_access_control_probe",
        ),
        _technique(
            "T-MEMORY-POISONING", "Persistent memory poisoning", "agent_security",
            "Untrusted content can persist into memory and influence later model decisions.",
            "high", ["external_content", "memory", "model"], "provenance_plus_controlled_memory_replay",
        ),
        _technique(
            "T-RETRIEVAL-INJECTION", "Retrieval content injection", "agent_security",
            "Untrusted retrieved content can cross into model instruction processing.",
            "high", ["external_content", "retriever", "model"], "retrieval_trace_plus_controlled_prompt",
        ),
        _technique(
            "T-SECRET-DELEGATION", "Delegated secret exposure", "authority_security",
            "An agent or model-callable capability can read or disclose a secret asset.",
            "critical", ["runtime_agent", "tool", "secret_asset"], "secret_scope_plus_access_control_probe",
        ),
        _technique(
            "T-DEPLOYMENT-TAMPERING", "Unapproved deployment authority", "artifact_security",
            "An agent, workflow, or deployment capability can modify a deployment without a strong approval control.",
            "critical", ["runtime_agent", "deployment_capability", "deployment_asset"], "artifact_integrity_plus_approval_probe",
        ),
        _technique(
            "T-SERVICE-IDENTITY-OVERPRIVILEGE", "Overprivileged delegated service identity", "authority_security",
            "An agent or workflow can assume a service identity whose effective permissions exceed the operation need.",
            "high", ["runtime_agent", "service_identity", "privileged_asset"], "identity_policy_plus_permission_probe",
        ),
    )

    # Registry for extra techniques added at runtime (e.g. from plugins or tests).
    _extra_techniques: dict[str, ThreatTechnique] = {}

    @classmethod
    def register_technique(cls, technique: ThreatTechnique) -> None:
        """Register an additional ThreatTechnique without modifying TECHNIQUES.

        The registered technique will be picked up by all subsequent analyzer
        instances.  If a technique with the same id already exists in TECHNIQUES
        the registration is rejected with ValueError to prevent silent shadowing.
        """
        builtin_ids = {item.technique_id for item in cls.TECHNIQUES}
        if technique.technique_id in builtin_ids:
            raise ValueError(
                f"Technique {technique.technique_id!r} already exists in the built-in catalog. "
                "Use a new technique_id for custom techniques."
            )
        cls._extra_techniques[technique.technique_id] = technique

    @classmethod
    def unregister_technique(cls, technique_id: str) -> None:
        """Remove a previously registered extra technique (idempotent)."""
        cls._extra_techniques.pop(technique_id, None)

    def __init__(self, surface: Any, graph: RuntimeSurfaceGraph):
        # ``surface`` may legitimately be None when the analyzer is constructed
        # from an already-built graph (e.g. inside the orchestrator).  Guard
        # every surface attribute access with a None check rather than raising.
        self.surface = surface
        self.graph = graph
        self.nodes = {node.node_id: node for node in graph.nodes}
        self.edges = list(graph.edges)
        self.techniques = {
            item.technique_id: item
            for item in (*self.TECHNIQUES, *self._extra_techniques.values())
        }

    def analyze(self) -> RuntimeThreatModel:
        hypotheses: list[RiskHypothesis] = []
        hypotheses.extend(self._prompt_injection_hypotheses())
        hypotheses.extend(self._excessive_agency_hypotheses())
        hypotheses.extend(self._description_injection_hypotheses())
        hypotheses.extend(self._unprotected_entry_hypotheses())
        hypotheses.extend(self._indirect_prompt_injection_hypotheses())
        hypotheses.extend(self._mcp_authorization_hypotheses())
        hypotheses.extend(self._browser_sink_hypotheses())
        hypotheses.extend(self._workflow_privilege_hypotheses())
        hypotheses.extend(self._sensitive_storage_hypotheses())
        hypotheses.extend(self._memory_poisoning_hypotheses())
        hypotheses.extend(self._retrieval_injection_hypotheses())
        hypotheses.extend(self._secret_delegation_hypotheses())
        hypotheses.extend(self._deployment_tampering_hypotheses())
        hypotheses.extend(self._service_identity_hypotheses())
        hypotheses = self._rank_and_deduplicate_hypotheses(hypotheses)

        node_types: dict[str, int] = {}
        for node in self.graph.nodes:
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1
        modeled_types = {item for technique in self.TECHNIQUES for item in technique.required_node_types}
        modeled_nodes = sum(count for node_type, count in node_types.items() if node_type in modeled_types)
        high_risk_nodes = [
            node.node_id
            for node in self.graph.nodes
            if node.attributes.get("risk_level") in {"high", "critical"}
            or node.node_type == "privileged_asset"
        ]

        return RuntimeThreatModel(
            techniques=list(self.TECHNIQUES),
            hypotheses=hypotheses,
            coverage={
                "node_count": len(self.graph.nodes),
                "edge_count": len(self.graph.edges),
                "node_types": node_types,
                "modeled_node_types": sorted(modeled_types),
                "modeled_node_count": modeled_nodes,
                "high_risk_node_ids": high_risk_nodes,
                "hypothesis_count": len(hypotheses),
                "auth_unknown_entry_count": sum(
                    node.node_type == "entry_point"
                    and node.attributes.get("authentication_state", "unknown") == "unknown"
                    for node in self.graph.nodes
                ),
                "flow_plane_hypothesis_counts": {
                    plane: sum(plane in item.flow_planes for item in hypotheses)
                    for plane in ("data", "instruction", "authority", "artifact")
                },
                "graph_coverage": dict(self.graph.metadata.get("coverage", {})),
                "unknown_count": self.graph.metadata.get("coverage", {}).get("unknown_count", 0),
            },
            assumptions=[
                "Static surface extraction is incomplete when framework metadata is dynamic.",
                "A missing permission profile is treated as an unresolved authorization boundary, not proof of exploitability.",
                "A hypothesis requires agent or controlled verification before becoming a confirmed finding.",
            ],
        )

    def _prompt_injection_hypotheses(self) -> list[RiskHypothesis]:
        prompts = [node for node in self.graph.nodes if node.node_type == "prompt"]
        results = []
        for prompt in prompts:
            incoming = [
                edge for edge in self.edges
                if edge.target == prompt.node_id and edge.relation == "influences"
                and self.nodes.get(edge.source) is not None
                and self.nodes[edge.source].node_type == "external_content"
            ]
            for edge in incoming:
                downstream = self._first_path(prompt.node_id, {"model", "mcp_capability", "tool", "privileged_asset"})
                path = [edge.source, prompt.node_id] + downstream[1:]
                results.append(self._hypothesis(
                    technique_id="T-PROMPT-INJECTION",
                    title=f"External instructions can reach prompt: {prompt.label}",
                    source_ids=[edge.source], target_ids=path[-1:], path=path,
                    impact="Model behavior or downstream tool selection may be influenced by external content.",
                    severity="high" if len(path) > 2 else "medium", confidence=0.72,
                    predicates=[
                        EvidencePredicateSpec("prompt-input-flow", "Show how external content reaches this prompt.", "data_flow", True, "read_source"),
                        EvidencePredicateSpec("prompt-boundary", "Show whether prompt content is separated from trusted instructions.", "configuration", True, "inspect_surface"),
                    ],
                ))
        return results

    def _excessive_agency_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for tool in self.graph.nodes:
            if tool.node_type != "tool" or tool.attributes.get("risk_level") not in {"high", "critical"}:
                continue
            requires_confirmation = bool(tool.attributes.get("requires_confirmation"))
            permission_edges = [
                edge for edge in self.edges
                if edge.source == tool.node_id and edge.relation in {"governed_by", "crosses"}
            ]
            asset_ids = self._ids_for_tool_asset(tool.node_id)
            capability_ids = [
                edge.source for edge in self.edges
                if edge.target == tool.node_id and edge.relation == "implemented_as"
                and self.nodes.get(edge.source) is not None
                and self.nodes[edge.source].node_type == "mcp_capability"
            ]
            model_ids = [
                edge.source for edge in self.edges
                if edge.target in capability_ids and edge.relation == "can_invoke"
                and self.nodes.get(edge.source) is not None
                and self.nodes[edge.source].node_type == "model"
            ]
            path = model_ids[:1] + capability_ids[:1] + [tool.node_id] + asset_ids[:1]
            if not path:
                path = [tool.node_id]
            results.append(self._hypothesis(
                technique_id="T-EXCESSIVE-AGENCY",
                title=f"Privileged tool authority path: {tool.label}",
                source_ids=model_ids[:1] or capability_ids[:1] or [tool.node_id],
                target_ids=[tool.node_id] + asset_ids,
                path=path,
                impact="A model or attacker-influenced instruction may reach a privileged operation without sufficient human or policy control.",
                severity="critical" if tool.attributes.get("risk_level") == "critical" else "high",
                confidence=0.5 if requires_confirmation else 0.7 if not permission_edges else 0.58,
                predicates=[
                    EvidencePredicateSpec("tool-capability", "Read the implementation and enumerate privileged operations.", "code", True, "read_source"),
                    EvidencePredicateSpec("approval-boundary", "Confirm whether policy or human approval is enforced at execution time.", "runtime_behavior", True, "inspect_surface"),
                ],
                assumptions=["Tool can be selected by a model or exposed to an untrusted workflow."],
            ))
        return results

    def _description_injection_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        markers = ("ignore", "override", "disregard", "forget", "system prompt")
        for tool in self.graph.nodes:
            if tool.node_type != "tool":
                continue
            description = str(tool.attributes.get("description", "")).lower()
            if not any(marker in description for marker in markers):
                continue
            results.append(self._hypothesis(
                technique_id="T-MCP-DESCRIPTION-INJECTION",
                title=f"Instruction-like tool description: {tool.label}",
                source_ids=self._ids_by_type("external_actor")[:1],
                target_ids=[tool.node_id],
                path=[tool.node_id],
                impact="Tool metadata may influence model policy or cause unsafe tool selection.",
                severity="high",
                confidence=0.68,
                predicates=[
                    EvidencePredicateSpec("description-content", "Capture the complete tool description and its trust origin.", "code", True, "read_source"),
                    EvidencePredicateSpec("selection-impact", "Demonstrate whether the description changes tool selection or arguments.", "runtime_behavior", True, "inspect_surface"),
                ],
            ))
        return results

    def _unprotected_entry_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        actor_ids = self._ids_by_type("external_actor")
        for entry in self.graph.nodes:
            if entry.node_type != "entry_point":
                continue
            # Static extraction can miss a global guard.  Do not turn "no
            # detected auth marker" into an access-control finding.  A route is
            # eligible only after controlled runtime evidence establishes that
            # it is unauthenticated and it exposes a sensitive operation.
            if entry.attributes.get("authentication_required"):
                continue
            if entry.attributes.get("authentication_state") not in {"runtime_observed", "verified"}:
                continue
            if not self._is_sensitive_entry(entry):
                continue
            results.append(self._hypothesis(
                technique_id="T-UNPROTECTED-ENTRY",
                title=f"Externally reachable entry point: {entry.label}",
                source_ids=actor_ids[:1],
                target_ids=[entry.node_id],
                path=actor_ids[:1] + [entry.node_id],
                impact="Unauthenticated users may reach application logic or sensitive operations.",
                severity="medium",
                confidence=0.82 if entry.attributes.get("authentication_state") == "verified" else 0.68,
                predicates=[
                    EvidencePredicateSpec("entry-auth", "Inspect the route and its authorization middleware.", "code", True, "read_source"),
                    EvidencePredicateSpec("auth-probe", "Run a controlled unauthenticated request and record the response.", "runtime_behavior", True, "controlled_request"),
                ],
            ))
        return results

    @staticmethod
    def _is_sensitive_entry(entry: Any) -> bool:
        method = str(entry.attributes.get("method") or entry.label.split(" ", 1)[0]).upper()
        path = str(entry.attributes.get("path") or entry.label).lower()
        sensitive_terms = (
            "admin", "account", "user", "profile", "payment", "refund", "order",
            "checkout", "token", "secret", "credential", "upload", "delete", "internal",
        )
        return method in {"POST", "PUT", "PATCH", "DELETE"} or any(term in path for term in sensitive_terms)

    @staticmethod
    def _hypothesis_priority(item: RiskHypothesis) -> tuple[int, float, str]:
        severity = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return (severity.get(item.severity, 0), item.confidence, item.hypothesis_id)

    def _rank_and_deduplicate_hypotheses(
        self, hypotheses: list[RiskHypothesis],
    ) -> list[RiskHypothesis]:
        """Collapse identical technique/path hypotheses without hiding evidence."""
        clusters: dict[tuple[str, tuple[str, ...], tuple[str, ...]], RiskHypothesis] = {}
        for hypothesis in hypotheses:
            key = (
                hypothesis.technique_id,
                tuple(hypothesis.source_node_ids),
                tuple(hypothesis.target_node_ids),
            )
            existing = clusters.get(key)
            if existing is None:
                clusters[key] = hypothesis
                continue
            if self._hypothesis_priority(hypothesis) > self._hypothesis_priority(existing):
                existing, hypothesis = hypothesis, existing
                clusters[key] = existing
            related = existing.risk_factors.setdefault("related_hypothesis_ids", [])
            related.append(hypothesis.hypothesis_id)
            existing.risk_factors["cluster_size"] = len(related) + 1
        return sorted(clusters.values(), key=self._hypothesis_priority, reverse=True)

    def _indirect_prompt_injection_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        seen_paths = set()
        for prompt in self.graph.nodes:
            if prompt.node_type != "prompt":
                continue
            incoming = [
                edge for edge in self.edges
                if edge.target == prompt.node_id
                and self.nodes.get(edge.source) is not None
                and self.nodes[edge.source].node_type == "external_content"
                and edge.relation == "influences"
            ]
            for edge in incoming:
                source = self.nodes[edge.source]
                downstream = self._first_path(prompt.node_id, {"model", "mcp_capability", "tool", "privileged_asset"})
                path = [source.node_id, prompt.node_id] + downstream[1:]
                seen_paths.add(tuple(path))
                target_ids = downstream[-1:] if len(downstream) > 1 else [prompt.node_id]
                results.append(self._hypothesis(
                    technique_id="T-INDIRECT-PROMPT-INJECTION",
                    title=f"External content can influence model context: {prompt.label}",
                    source_ids=[source.node_id], target_ids=target_ids, path=path,
                    impact="Untrusted retrieved, uploaded, or network content may alter model decisions and downstream capability use.",
                    severity="high" if len(path) > 2 else "medium",
                    confidence=0.78 if edge.attributes.get("confidence") == "explicit_reference" else 0.62,
                    predicates=[
                        EvidencePredicateSpec("external-content-origin", "Confirm the extracted external content source and attacker control.", "code", True, "read_source"),
                        EvidencePredicateSpec("prompt-data-flow", "Confirm the external content value reaches the prompt without an instruction/data boundary.", "data_flow", True, "trace_source_flow"),
                        EvidencePredicateSpec("model-impact", "Use a controlled prompt payload to observe model or tool-selection impact.", "runtime_behavior", True, "controlled_prompt_probe"),
                    ],
                    assumptions=["The external content source is reachable in the deployed runtime."],
                ))
        for model in self.graph.nodes:
            if model.node_type != "model":
                continue
            incoming = [
                edge for edge in self.edges
                if edge.target == model.node_id and edge.relation == "supplies_content"
                and self.nodes.get(edge.source) is not None
                and self.nodes[edge.source].node_type == "external_content"
            ]
            for edge in incoming:
                downstream = self._first_path(model.node_id, {"mcp_capability", "tool", "privileged_asset"})
                path = [edge.source, model.node_id] + downstream[1:]
                if tuple(path) in seen_paths:
                    continue
                seen_paths.add(tuple(path))
                results.append(self._hypothesis(
                    technique_id="T-INDIRECT-PROMPT-INJECTION",
                    title=f"External content enters model context: {model.label}",
                    source_ids=[edge.source], target_ids=path[-1:], path=path,
                    impact="Untrusted retrieved, uploaded, or network content may alter model decisions and downstream capability use.",
                    severity="high" if len(path) > 2 else "medium", confidence=0.82,
                    predicates=[
                        EvidencePredicateSpec("external-content-origin", "Confirm the extracted external content source and attacker control.", "code", True, "read_source"),
                        EvidencePredicateSpec("model-content-flow", "Confirm the external value enters model content without an instruction/data boundary.", "data_flow", True, "trace_source_flow"),
                        EvidencePredicateSpec("model-impact", "Use a controlled indirect-injection payload to observe model or tool-selection impact.", "runtime_behavior", True, "controlled_prompt_probe"),
                    ],
                    assumptions=["The model invocation is reachable with attacker-controlled external content."],
                ))
        return results

    def _mcp_authorization_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for capability in self.graph.nodes:
            if capability.node_type != "mcp_capability":
                continue
            consequential = list(capability.attributes.get("consequential_operations", []))
            permissions = list(capability.attributes.get("permissions", []))
            dynamic = bool(capability.attributes.get("dynamic_registration"))
            wildcard = any(str(value).strip() == "*" or str(value).endswith(":*") for value in permissions)
            assets = self._outgoing_targets(capability.node_id, relations={"accesses"})
            if not (consequential or wildcard or dynamic or assets):
                continue
            path = [capability.node_id] + assets[:1]
            results.append(self._hypothesis(
                technique_id="T-MCP-AUTHORIZATION",
                title=f"MCP capability authority path: {capability.label}",
                source_ids=[capability.node_id], target_ids=assets[:1] or [capability.node_id], path=path,
                impact="A caller or model may invoke a dynamically registered, wildcard, or consequential MCP capability without object-level policy enforcement.",
                severity="critical" if consequential else "high",
                confidence=(
                    0.8 if wildcard else 0.7 if consequential else 0.58
                ) if capability.attributes.get("authorization", "unknown") != "enforced" else 0.45,
                predicates=[
                    EvidencePredicateSpec("mcp-identity", "Resolve server, transport, caller identity, and capability identity.", "configuration", True, "inspect_surface"),
                    EvidencePredicateSpec("mcp-authorization", "Confirm authorization is enforced for this specific tool or resource at invocation time.", "runtime_behavior", True, "permission_probe"),
                    EvidencePredicateSpec("mcp-operation", "Confirm the registered handler reaches the extracted consequential operation.", "code", bool(consequential), "read_source"),
                ],
                assumptions=["Global gateway policy may exist outside the analyzed project and must be checked before confirmation."],
            ))
        return results

    def _browser_sink_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for sink in self.graph.nodes:
            if sink.node_type != "browser_sink":
                continue
            incoming = [
                edge for edge in self.edges
                if edge.target == sink.node_id and edge.relation == "renders_at"
                and self.nodes.get(edge.source) is not None
                and self.nodes[edge.source].node_type == "external_content"
            ]
            for edge in incoming:
                results.append(self._hypothesis(
                    technique_id="T-BROWSER-SINK-INJECTION",
                    title=f"External content reaches browser sink: {sink.label}",
                    source_ids=[edge.source], target_ids=[sink.node_id],
                    path=[edge.source, sink.node_id],
                    impact="Attacker-controlled markup or URL content may execute in a user session or navigate a privileged browser context.",
                    severity="high", confidence=0.82,
                    predicates=[
                        EvidencePredicateSpec("browser-source", "Confirm attacker control of the value entering the sink.", "data_flow", True, "trace_source_flow"),
                        EvidencePredicateSpec("browser-sanitization", "Confirm context-appropriate encoding or sanitization is absent.", "code", True, "read_source"),
                        EvidencePredicateSpec("browser-control", "Run positive and negative browser controls in an authorized local service.", "runtime_behavior", True, "playwright_probe"),
                    ],
                ))
        return results

    def _workflow_privilege_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        actor_ids = self._ids_by_type("external_actor")
        for workflow in self.graph.nodes:
            if not self._is_eligible_workflow_node(workflow):
                continue
            # A job and its individual steps can all contain the same event
            # expression.  The job-level path is the review unit; emitting a
            # second hypothesis for each child step inflates the model without
            # adding a distinct attacker-controlled entry point.
            if self._has_eligible_workflow_ancestor(workflow.node_id):
                continue
            assets = self._outgoing_targets(workflow.node_id, relations={"accesses"})
            parents = [
                edge.source for edge in self.edges
                if edge.target == workflow.node_id and edge.relation == "executes"
            ]
            path = actor_ids[:1] + parents[:1] + [workflow.node_id] + assets[:1]
            hypothesis = self._hypothesis(
                technique_id="T-WORKFLOW-PRIVILEGE",
                title=f"Untrusted event input reaches privileged workflow node: {workflow.label}",
                source_ids=actor_ids[:1], target_ids=assets[:1], path=path,
                impact="Attacker-controlled event data may affect shell execution, credentials, network requests, artifacts, or deployment actions.",
                severity="critical" if "credentials" in workflow.attributes.get("capabilities", []) else "high",
                confidence=0.86,
                predicates=[
                    EvidencePredicateSpec("workflow-expression", "Confirm the structured workflow step consumes the extracted untrusted event expression.", "configuration", True, "inspect_workflow"),
                    EvidencePredicateSpec("workflow-capability", "Confirm the job or step capability and effective token permissions.", "configuration", True, "inspect_workflow"),
                    EvidencePredicateSpec("workflow-control", "Replay a non-destructive payload or evaluate shell construction with positive and negative controls.", "runtime_behavior", True, "workflow_probe"),
                ],
            )
            related_nodes = self._eligible_workflow_descendants(workflow.node_id)
            if related_nodes:
                hypothesis.risk_factors["aggregated_workflow_node_ids"] = related_nodes
                hypothesis.risk_factors["aggregated_workflow_node_count"] = len(related_nodes)
            results.append(hypothesis)
        return results

    def _is_eligible_workflow_node(self, node: Any) -> bool:
        return (
            node.node_type == "workflow"
            and bool(node.attributes.get("untrusted_inputs"))
            and bool(self._outgoing_targets(node.node_id, relations={"accesses"}))
        )

    def _has_eligible_workflow_ancestor(self, node_id: str) -> bool:
        pending = [
            edge.source for edge in self.edges
            if edge.target == node_id and edge.relation == "executes"
        ]
        seen: set[str] = set()
        while pending:
            parent_id = pending.pop()
            if parent_id in seen:
                continue
            seen.add(parent_id)
            parent = self.nodes.get(parent_id)
            if parent is not None and self._is_eligible_workflow_node(parent):
                return True
            pending.extend(
                edge.source for edge in self.edges
                if edge.target == parent_id and edge.relation == "executes"
            )
        return False

    def _eligible_workflow_descendants(self, node_id: str) -> list[str]:
        pending = [node_id]
        seen: set[str] = set()
        related: list[str] = []
        while pending:
            current_id = pending.pop()
            if current_id in seen:
                continue
            seen.add(current_id)
            current = self.nodes.get(current_id)
            if current is not None and self._is_eligible_workflow_node(current):
                related.append(current_id)
            pending.extend(
                edge.target for edge in self.edges
                if edge.source == current_id and edge.relation == "executes"
            )
        return sorted(related)

    def _sensitive_storage_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for storage in self.graph.nodes:
            if storage.node_type != "storage_asset" or not storage.attributes.get("sensitive"):
                continue
            incoming = [
                edge for edge in self.edges
                if edge.target == storage.node_id and edge.relation in {"reads", "writes"}
                and self.nodes.get(edge.source) is not None
                and self.nodes[edge.source].node_type in {"tool", "mcp_capability"}
            ]
            for edge in incoming:
                source = self.nodes[edge.source]
                results.append(self._hypothesis(
                    technique_id="T-SENSITIVE-STORAGE-ACCESS",
                    title=f"Model-callable capability accesses sensitive storage: {storage.label}",
                    source_ids=[source.node_id], target_ids=[storage.node_id],
                    path=[source.node_id, storage.node_id],
                    impact="Tool misuse or prompt-driven agency may disclose or modify credentials, sessions, or other sensitive persisted data.",
                    severity="high", confidence=0.72,
                    predicates=[
                        EvidencePredicateSpec("storage-classification", "Confirm the key, file, table, or cookie contains sensitive data.", "data_classification", True, "read_source"),
                        EvidencePredicateSpec("storage-authorization", "Confirm caller and object-level authorization for the read or write.", "runtime_behavior", True, "permission_probe"),
                    ],
                ))
        return results

    def _memory_poisoning_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for edge in self.edges:
            source = self.nodes.get(edge.source)
            memory = self.nodes.get(edge.target)
            if not source or not memory or memory.node_type != "memory":
                continue
            if source.node_type not in {"external_actor", "external_content", "external_service", "retriever"}:
                continue
            path = [source.node_id, memory.node_id]
            outgoing = next((
                item for item in self.edges
                if item.source == memory.node_id and self.nodes.get(item.target)
                and self.nodes[item.target].node_type in {"prompt", "model", "runtime_agent"}
            ), None)
            if outgoing:
                path.append(outgoing.target)
            results.append(self._hypothesis(
                technique_id="T-MEMORY-POISONING",
                title=f"Untrusted content can persist into memory: {memory.label}",
                source_ids=[source.node_id], target_ids=[path[-1]], path=path,
                impact="Poisoned persistent context may influence later decisions, users, or privileged tool calls.",
                severity="high", confidence=0.66,
                predicates=[
                    EvidencePredicateSpec("memory-write", "Confirm attacker-controlled content is persisted without provenance isolation.", "data_flow", True, "trace_data_flow"),
                    EvidencePredicateSpec("memory-reuse", "Confirm the stored content is loaded into a later model context.", "runtime_behavior", True, "memory_replay"),
                ],
            ))
        return results

    def _retrieval_injection_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for edge in self.edges:
            source = self.nodes.get(edge.source)
            retriever = self.nodes.get(edge.target)
            if not source or not retriever or retriever.node_type != "retriever":
                continue
            if source.node_type not in {"external_content", "external_service", "storage_asset"}:
                continue
            path = [source.node_id, retriever.node_id]
            outgoing = next((
                item for item in self.edges
                if item.source == retriever.node_id and self.nodes.get(item.target)
                and self.nodes[item.target].node_type in {"prompt", "model", "runtime_agent"}
            ), None)
            if outgoing:
                path.append(outgoing.target)
            results.append(self._hypothesis(
                technique_id="T-RETRIEVAL-INJECTION",
                title=f"Retrieved content can influence model context through {retriever.label}",
                source_ids=[source.node_id], target_ids=[path[-1]], path=path,
                impact="Malicious indexed content may steer model output or downstream tool selection.",
                severity="high", confidence=0.64,
                predicates=[
                    EvidencePredicateSpec("retrieval-provenance", "Confirm retrieved content can be controlled by an untrusted publisher.", "data_provenance", True, "inspect_retrieval_source"),
                    EvidencePredicateSpec("context-boundary", "Confirm retrieved content is separated from trusted instructions.", "runtime_behavior", True, "controlled_prompt"),
                ],
            ))
        return results

    def _secret_delegation_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for edge in self.edges:
            source = self.nodes.get(edge.source)
            secret = self.nodes.get(edge.target)
            if not source or not secret or secret.node_type != "secret_asset":
                continue
            if source.node_type not in {
                "runtime_agent", "coding_agent", "model", "tool", "mcp_capability",
                "workflow", "code_execution", "deployment_capability",
            }:
                continue
            results.append(self._hypothesis(
                technique_id="T-SECRET-DELEGATION",
                title=f"Delegated capability can access secret asset: {secret.label}",
                source_ids=[source.node_id], target_ids=[secret.node_id], path=[source.node_id, secret.node_id],
                impact="A prompt, workflow input, or compromised agent may disclose or misuse the delegated secret.",
                severity="critical", confidence=0.7,
                predicates=[
                    EvidencePredicateSpec("secret-scope", "Confirm the effective secret scope and operations available to the caller.", "authorization", True, "permission_probe"),
                    EvidencePredicateSpec("secret-disclosure", "Confirm secret material cannot be returned to model or user-visible output.", "runtime_behavior", True, "controlled_secret_probe"),
                ],
            ))
        return results

    def _deployment_tampering_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for edge in self.edges:
            source = self.nodes.get(edge.source)
            target = self.nodes.get(edge.target)
            if not source or not target or target.node_type != "deployment_asset":
                continue
            if (edge.semantic_relation or edge.relation) != "deploys":
                continue
            results.append(self._hypothesis(
                technique_id="T-DEPLOYMENT-TAMPERING",
                title=f"Deployment authority path: {target.label}",
                source_ids=[source.node_id], target_ids=[target.node_id], path=[source.node_id, target.node_id],
                impact="Compromised instructions or workflow input may alter a deployed environment or release artifact.",
                severity="critical", confidence=0.68,
                predicates=[
                    EvidencePredicateSpec("deployment-authority", "Confirm effective deployment identity and environment scope.", "authorization", True, "permission_probe"),
                    EvidencePredicateSpec("deployment-approval", "Confirm an enforced, non-bypassable approval and artifact integrity check.", "control", True, "deployment_probe"),
                ],
            ))
        return results

    def _service_identity_hypotheses(self) -> list[RiskHypothesis]:
        results = []
        for identity in self.graph.nodes:
            if identity.node_type != "service_identity":
                continue
            permissions = identity.attributes.get("permissions", []) or []
            broad = not permissions or "*" in permissions or any(
                "admin" in str(item).lower() for item in permissions
            )
            if not broad:
                continue
            incoming = [
                edge for edge in self.edges
                if edge.target == identity.node_id
                and (edge.semantic_relation or edge.relation) in {"authenticates_as", "delegates_authority"}
            ]
            for edge in incoming:
                source = self.nodes.get(edge.source)
                if not source:
                    continue
                results.append(self._hypothesis(
                    technique_id="T-SERVICE-IDENTITY-OVERPRIVILEGE",
                    title=f"Delegated service identity has unresolved or broad permissions: {identity.label}",
                    source_ids=[source.node_id], target_ids=[identity.node_id], path=[source.node_id, identity.node_id],
                    impact="The initiating agent or workflow may exercise identity permissions beyond the intended operation.",
                    severity="high", confidence=0.6 if not permissions else 0.75,
                    predicates=[
                        EvidencePredicateSpec("effective-identity-policy", "Resolve the effective identity policy including inherited permissions.", "authorization", True, "inspect_identity_policy"),
                        EvidencePredicateSpec("delegation-scope", "Confirm delegation is bound to the initiating operation and tenant.", "runtime_behavior", True, "permission_probe"),
                    ],
                ))
        return results

    def _has_effective_control(self, node_id: str, control_types: set[str]) -> bool:
        for edge in self.edges:
            if edge.source != node_id or edge.relation not in {"governed_by", "approves", "governs"}:
                continue
            control = self.nodes.get(edge.target)
            if not control or control.node_type not in control_types:
                continue
            effectiveness = (control.attributes.get("control") or {}).get("effectiveness")
            if effectiveness in {"implemented", "strong"}:
                return True
        return False

    def _hypothesis(
        self,
        *,
        technique_id: str,
        title: str,
        source_ids: list[str],
        target_ids: list[str],
        path: list[str],
        impact: str,
        severity: str,
        confidence: float,
        predicates: list[EvidencePredicateSpec],
        assumptions: list[str] | None = None,
    ) -> RiskHypothesis:
        fingerprint = "|".join([technique_id, title, *path])
        technique = self.techniques[technique_id]
        boundary_ids = self._boundary_ids_for_path(path)
        control_state = self._control_state(technique_id, path, boundary_ids)
        control_strength = str(control_state["strength"])

        path_set = set(path)
        path_edges = [
            edge for edge in self.edges
            if edge.source in path_set and edge.target in path_set
        ]
        flow_planes = sorted({
            plane for edge in path_edges for plane in edge.flow_planes
        } | set(technique.flow_planes))
        evidence_levels = sorted({
            str((edge.evidence or {}).get("level", "unknown")) for edge in path_edges
        } | {
            str((self.nodes[node_id].evidence or {}).get("level", "unknown"))
            for node_id in path if node_id in self.nodes
        })
        control_type, expectation = _CONTROL_EXPECTATIONS[technique_id]
        control_gaps = [] if control_state["state"] == "verified" else [{
            "control_type": control_type,
            "state": "missing" if control_state["state"] == "expected" else "present_unverified",
            "expected_control": expectation,
            "observed_control_node_ids": control_state["observed_control_node_ids"],
            "evidence_level": control_state["evidence_level"],
        }]
        return RiskHypothesis(
            hypothesis_id=f"RH-{sha1(fingerprint.encode('utf-8')).hexdigest()[:12]}",
            technique_id=technique_id,
            title=title,
            source_node_ids=source_ids,
            boundary_node_ids=boundary_ids,
            target_node_ids=target_ids,
            attack_path=path,
            impact=impact,
            severity=severity,
            confidence=confidence,
            evidence_predicates=predicates,
            assumptions=list(assumptions or []),
            flow_planes=flow_planes,
            control_gaps=control_gaps,
            risk_factors={
                "impact": severity,
                "exploitability": "high" if control_strength in {"missing", "unknown"} else "medium",
                "evidence_confidence": confidence,
                "evidence_levels": evidence_levels,
                "control_strength": control_strength,
            },
            external_mappings={key: list(values) for key, values in technique.external_mappings.items()},
            applicability="applicable",
            residual_status={
                "verified": "controlled",
                "runtime_observed": "reduced",
                "static_observed": "control_observed_unverified",
                "declared": "control_declared_unverified",
            }.get(str(control_state["state"]), "unresolved"),
            control_state=control_state,
        )

    def _control_state(
        self, technique_id: str, path: list[str], boundary_ids: list[str],
    ) -> dict[str, Any]:
        observed_ids: list[str] = []
        evidence_levels: list[str] = []
        for node_id in boundary_ids:
            node = self.nodes.get(node_id)
            if not node:
                continue
            effectiveness = str((node.attributes.get("control") or {}).get("effectiveness", "unknown"))
            if effectiveness not in {"implemented", "partial", "strong"}:
                continue
            observed_ids.append(node_id)
            evidence_levels.append(str((node.evidence or {}).get("level", "unknown")))

        for node_id in path:
            node = self.nodes.get(node_id)
            if not node or not self._node_has_control_marker(technique_id, node):
                continue
            if node_id not in observed_ids:
                observed_ids.append(node_id)
            evidence_levels.append(str((node.evidence or {}).get("level", "unknown")))

        rank = {
            "unknown": 0, "inferred": 0, "declared": 1,
            "static_observed": 2, "runtime_observed": 3, "verified": 4,
        }
        evidence_level = max(evidence_levels, key=lambda value: rank.get(value, 0), default="unknown")
        state = evidence_level if rank.get(evidence_level, 0) else "expected"
        strength = {
            "expected": "missing",
            "declared": "partial",
            "static_observed": "implemented",
            "runtime_observed": "implemented",
            "verified": "strong",
        }[state]
        control_type, _ = _CONTROL_EXPECTATIONS[technique_id]
        return {
            "control_type": control_type,
            "state": state,
            "strength": strength,
            "evidence_level": evidence_level,
            "observed_control_node_ids": observed_ids,
            "affects_applicability": False,
        }

    @staticmethod
    def _node_has_control_marker(technique_id: str, node: Any) -> bool:
        attributes = node.attributes
        if technique_id in {"T-PROMPT-INJECTION", "T-INDIRECT-PROMPT-INJECTION"}:
            return node.node_type == "prompt" and bool(attributes.get("has_injection_protection"))
        if technique_id == "T-EXCESSIVE-AGENCY":
            return node.node_type == "tool" and bool(attributes.get("requires_confirmation"))
        if technique_id == "T-UNPROTECTED-ENTRY":
            return node.node_type == "entry_point" and bool(attributes.get("authentication_required"))
        if technique_id == "T-MCP-AUTHORIZATION":
            permissions = list(attributes.get("permissions", []) or [])
            wildcard = any(str(value).strip() == "*" or str(value).endswith(":*") for value in permissions)
            return node.node_type == "mcp_capability" and attributes.get("authorization") == "enforced" and not wildcard
        if technique_id == "T-BROWSER-SINK-INJECTION":
            return node.node_type == "browser_sink" and bool(attributes.get("sanitization_detected"))
        if technique_id == "T-SENSITIVE-STORAGE-ACCESS":
            return node.node_type == "storage_asset" and attributes.get("access_control") in {
                True, "enforced", "implemented", "strong",
            }
        return False

    def _ids_by_type(self, node_type: str) -> list[str]:
        return [node.node_id for node in self.graph.nodes if node.node_type == node_type]

    def _ids_for_tool_asset(self, tool_id: str) -> list[str]:
        return [
            edge.target for edge in self.edges
            if edge.source == tool_id and edge.relation == "accesses"
        ]

    def _outgoing_targets(self, node_id: str, *, relations: set[str]) -> list[str]:
        return [edge.target for edge in self.edges if edge.source == node_id and edge.relation in relations]

    def _first_path(self, source_id: str, target_types: set[str], max_depth: int = 4) -> list[str]:
        queue: list[list[str]] = [[source_id]]
        visited = {source_id}
        while queue:
            path = queue.pop(0)
            if len(path) > max_depth + 1:
                continue
            if len(path) > 1 and self.nodes.get(path[-1]) and self.nodes[path[-1]].node_type in target_types:
                return path
            for edge in self.edges:
                if edge.source != path[-1] or edge.target in visited:
                    continue
                if edge.relation not in {"supplies_instructions", "supplies_content", "can_invoke", "implemented_as", "accesses", "reads", "writes"}:
                    continue
                visited.add(edge.target)
                queue.append(path + [edge.target])
        return [source_id]

    def _boundary_ids_for_path(self, path: Iterable[str]) -> list[str]:
        path_set = set(path)
        return [
            edge.target
            for edge in self.edges
            if edge.source in path_set and edge.relation in {"crosses", "governed_by"}
            and self.nodes.get(edge.target, None) is not None
            and self.nodes[edge.target].node_type in {
                "trust_boundary", "permission", "security_control", "approval_control", "policy_gateway",
            }
        ]
