"""Stable contracts shared by audit, verification, remediation, and reports."""

from dataclasses import dataclass, field
from datetime import datetime, timezone, UTC
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class EvidenceBundle:
    """Evidence collected for one finding, including explicit gaps."""

    items: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    level: int = 1
    artifact_refs: list[str] = field(default_factory=list)

    def add(self, evidence: dict[str, Any]) -> None:
        self.items.append(evidence)
        evidence_type = evidence.get("evidence_type", evidence.get("type", "static"))
        self.level = max(self.level, {"static": 1, "surface": 2, "dynamic": 3, "fuzzing": 3, "browser": 4}.get(evidence_type, 1))

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": self.items,
            "gaps": self.gaps,
            "level": self.level,
            "artifact_refs": self.artifact_refs,
        }


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    vulnerability_type: str
    confidence: float = 0.0
    status: str = "candidate"
    verification_status: str = "unverified"
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    description: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_bundle: EvidenceBundle = field(default_factory=EvidenceBundle)
    risk_chain: dict[str, Any] | None = None
    surface_node_ids: list[str] = field(default_factory=list)
    lane: str = "web_audit"
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    @classmethod
    def from_dict(cls, value: dict[str, Any], index: int = 1) -> "Finding":
        finding_id = value.get("id") or f"FINDING-{index:03d}"
        raw_bundle = value.get("evidence_bundle") or {}
        raw_bundle = raw_bundle if isinstance(raw_bundle, dict) else {}
        evidence = value.get("evidence") or raw_bundle.get("items", []) or []
        if isinstance(evidence, dict):
            evidence = [evidence]
        bundle = EvidenceBundle(
            items=list(raw_bundle.get("items", evidence) or evidence),
            gaps=list(raw_bundle.get("gaps", value.get("evidence_gaps", [])) or []),
            level=int(raw_bundle.get("level", value.get("evidence_level", 1)) or 1),
            artifact_refs=list(raw_bundle.get("artifact_refs", value.get("artifact_refs", [])) or []),
        )
        return cls(
            id=finding_id,
            title=value.get("title", value.get("finding_title", "Unknown finding")),
            severity=value.get("severity", "medium"),
            vulnerability_type=value.get("vulnerability_type", "unknown"),
            confidence=float(value.get("confidence", 0.0) or 0.0),
            status=value.get("status", "candidate"),
            verification_status=value.get("verification_status", "unverified"),
            file_path=value.get("file_path", ""),
            line_start=int(value.get("line_start", 0) or 0),
            line_end=int(value.get("line_end", 0) or 0),
            description=value.get("description", ""),
            evidence=evidence,
            evidence_bundle=bundle,
            risk_chain=value.get("risk_chain"),
            surface_node_ids=list(value.get("surface_node_ids", [])),
            lane=value.get("lane", ""),
            metadata=dict(value.get("metadata", {})),
            created_at=value.get("created_at", _now()),
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "vulnerability_type": self.vulnerability_type,
            "confidence": self.confidence,
            "status": self.status,
            "verification_status": self.verification_status,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "description": self.description,
            "evidence": self.evidence,
            "evidence_bundle": self.evidence_bundle.to_dict(),
            "evidence_gaps": self.evidence_bundle.gaps,
            "evidence_level": self.evidence_bundle.level,
            "artifact_refs": self.evidence_bundle.artifact_refs,
            "risk_chain": self.risk_chain,
            "surface_node_ids": self.surface_node_ids,
            "lane": self.lane,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }
        return value


@dataclass
class ValidationSession:
    finding_id: str
    method: str
    status: str = "needs_evidence"
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "method": self.method,
            "status": self.status,
            "evidence": self.evidence.to_dict(),
            "notes": self.notes,
        }


def normalize_finding(value: dict[str, Any], index: int = 1) -> dict[str, Any]:
    """Return a stable dict without discarding legacy agent-specific fields."""

    finding = Finding.from_dict(value, index=index)
    normalized = dict(value)
    normalized.update(finding.to_dict())
    return normalized
