"""Completion contracts that prevent an agent from declaring success early."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

Predicate = Callable[[dict[str, Any]], bool]


@dataclass
class CompletionValidationResult:
    valid: bool
    missing_fields: list[str] = field(default_factory=list)
    unresolved_gaps: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def feedback(self) -> str:
        parts = []
        if self.missing_fields:
            parts.append("Missing fields: " + ", ".join(self.missing_fields))
        if self.unresolved_gaps:
            parts.append("Unresolved gaps: " + ", ".join(self.unresolved_gaps))
        parts.extend(self.errors)
        return "; ".join(parts) or "Completion contract accepted"


@dataclass
class CompletionContract:
    name: str
    required_fields: Iterable[str] = field(default_factory=tuple)
    evidence_required: bool = False
    minimum_evidence: int = 1
    allow_unresolved_gaps: bool = False
    predicate: Predicate | None = None

    def validate(
        self,
        payload: dict[str, Any],
        *,
        evidence_refs: Iterable[str] | None = None,
    ) -> CompletionValidationResult:
        payload = dict(payload or {})
        missing = [
            field_name
            for field_name in self.required_fields
            if field_name not in payload or payload[field_name] in (None, "")
        ]

        evidence = payload.get("evidence_bundle") or payload.get("evidence") or {}
        if isinstance(evidence, list):
            evidence_items = evidence
            gaps = []
        else:
            evidence_items = evidence.get("items", []) if isinstance(evidence, dict) else []
            gaps = list(evidence.get("gaps", [])) if isinstance(evidence, dict) else []
        evidence_items = list(evidence_items or [])
        refs = list(evidence_refs or payload.get("evidence_refs", []) or [])
        evidence_count = len(evidence_items) + len(refs)
        errors = []
        if self.evidence_required and evidence_count < self.minimum_evidence:
            errors.append(
                f"Evidence required: expected at least {self.minimum_evidence}, got {evidence_count}"
            )

        unresolved = [str(item) for item in payload.get("unresolved_gaps", []) or []]
        unresolved.extend(str(item) for item in gaps)
        if unresolved and not self.allow_unresolved_gaps:
            errors.append("Completion cannot close while evidence gaps remain")

        if self.predicate:
            try:
                if not self.predicate(payload):
                    errors.append("Completion predicate returned false")
            except Exception as exc:
                errors.append(f"Completion predicate failed: {exc}")

        return CompletionValidationResult(
            valid=not missing and not errors,
            missing_fields=missing,
            unresolved_gaps=unresolved,
            errors=errors,
            details={
                "contract": self.name,
                "evidence_count": evidence_count,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "required_fields": list(self.required_fields),
            "evidence_required": self.evidence_required,
            "minimum_evidence": self.minimum_evidence,
            "allow_unresolved_gaps": self.allow_unresolved_gaps,
        }


class FinalizeTaskContract(CompletionContract):
    def __init__(self):
        super().__init__(
            name="FinalizeTask",
            required_fields=("summary", "next_action"),
            evidence_required=False,
        )


class FinalizeFindingContract(CompletionContract):
    def __init__(self):
        super().__init__(
            name="FinalizeFinding",
            required_fields=(
                "id",
                "title",
                "severity",
                "vulnerability_type",
                "description",
                "file_path",
                "line_start",
                "line_end",
                "verdict",
            ),
            # Review tools are audited by the Harness and are merged into the
            # final evidence bundle after the model returns. Requiring the
            # model to repeat that nested structure made otherwise valid
            # terminal actions fail schema validation.
            evidence_required=False,
            minimum_evidence=1,
            allow_unresolved_gaps=True,
            predicate=self._finding_verdict_is_supported,
        )

    @staticmethod
    def _finding_verdict_is_supported(payload: dict[str, Any]) -> bool:
        verdict = str(payload.get("verdict", "")).lower()
        if verdict not in {"confirmed", "verified", "potential", "unconfirmed"}:
            return False
        evidence = payload.get("evidence_bundle") or payload.get("evidence") or {}
        gaps = evidence.get("gaps", []) if isinstance(evidence, dict) else []
        # A confirmed finding cannot close while its own evidence says that a
        # required validation step is still missing.
        return not (verdict in {"confirmed", "verified"} and gaps)


class FinalizeVerificationContract(CompletionContract):
    def __init__(self):
        super().__init__(
            name="FinalizeVerification",
            required_fields=("finding_id", "verification_status", "verification_predicate"),
            # Verification tools are audited by the Harness and their results
            # are bound after the model finalizes. Requiring the model to
            # duplicate a nested evidence bundle caused otherwise valid
            # terminal actions to fail before that binding could happen.
            evidence_required=False,
            minimum_evidence=1,
            allow_unresolved_gaps=True,
            predicate=self._verification_is_supported,
        )

    @staticmethod
    def _verification_is_supported(payload: dict[str, Any]) -> bool:
        status = str(payload.get("verification_status", "")).lower()
        if status not in {"verified", "rejected", "needs_evidence"}:
            return False
        if not str(payload.get("verification_predicate", "")).strip():
            return False
        evidence = payload.get("evidence_bundle") or payload.get("evidence") or {}
        gaps = evidence.get("gaps", []) if isinstance(evidence, dict) else []
        return not (status == "verified" and gaps)


class FinalizeAuditDiscoveryContract(CompletionContract):
    def __init__(self):
        super().__init__(
            name="FinalizeAuditDiscovery",
            required_fields=("lane", "summary", "coverage", "candidates"),
            evidence_required=False,
            allow_unresolved_gaps=True,
            predicate=self._discovery_payload_is_valid,
        )

    @staticmethod
    def _discovery_payload_is_valid(payload: dict[str, Any]) -> bool:
        coverage = payload.get("coverage")
        candidates = payload.get("candidates")
        if not isinstance(coverage, dict) or not isinstance(candidates, list):
            return False
        if not isinstance(coverage.get("files_examined", []), list):
            return False
        required = {
            "title", "severity", "vulnerability_type", "description",
            "file_path", "line_start", "line_end", "evidence_bundle",
        }
        for candidate in candidates:
            if not isinstance(candidate, dict) or not required.issubset(candidate):
                return False
            bundle = candidate.get("evidence_bundle")
            if not isinstance(bundle, dict) or not list(bundle.get("items", []) or []):
                return False
        return True


class CompletionValidator:
    """Small adapter allowing contracts to be selected by serialized name."""

    CONTRACTS = {
        "FinalizeTask": FinalizeTaskContract,
        "FinalizeFinding": FinalizeFindingContract,
        "FinalizeVerification": FinalizeVerificationContract,
        "FinalizeAuditDiscovery": FinalizeAuditDiscoveryContract,
    }

    def validate(
        self,
        contract: CompletionContract | dict[str, Any] | None,
        payload: dict[str, Any],
        *,
        evidence_refs: Iterable[str] | None = None,
    ) -> CompletionValidationResult:
        if contract is None:
            return CompletionValidationResult(valid=True, details={"contract": "none"})
        if isinstance(contract, dict):
            name = str(contract.get("name", "FinalizeTask"))
            contract_type = self.CONTRACTS.get(name, CompletionContract)
            if contract_type is CompletionContract:
                contract = contract_type(
                    name=name,
                    required_fields=contract.get("required_fields", []),
                    evidence_required=bool(contract.get("evidence_required", False)),
                    minimum_evidence=int(contract.get("minimum_evidence", 1)),
                    allow_unresolved_gaps=bool(contract.get("allow_unresolved_gaps", False)),
                )
            else:
                contract = contract_type()
        return contract.validate(payload, evidence_refs=evidence_refs)
