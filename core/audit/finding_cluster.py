"""Conservative, traceable finding clustering for review queues.

The audit pipeline retains every raw candidate in the task result.  This
module only builds a smaller review projection, so UI-oriented de-duplication
never discards the evidence required to inspect an individual scanner result.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable
from copy import deepcopy
from typing import Any

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_EVIDENCE_LEVEL_RANK = {
    "unknown": 0,
    "inferred": 0,
    "declared": 1,
    "static_observed": 2,
    "runtime_observed": 3,
    "verified": 4,
}
_VERIFICATION_RANK = {
    "not_reviewed": 0,
    "needs_evidence": 1,
    "static_only": 1,
    "candidate": 1,
    "rejected": 2,
    "verified": 3,
    "confirmed": 3,
}
_TYPE_ALIASES = {
    "hardcoded_password": "secret_leak",
    "hardcoded_secrets": "secret_leak",
    "api_key": "secret_leak",
    "credential_exposure": "secret_leak",
    "unsafe_deserialization": "insecure_deserialization",
}


def cluster_findings(
    findings: Iterable[dict[str, Any]],
    *,
    line_tolerance: int = 2,
) -> list[dict[str, Any]]:
    """Return a severity and evidence ordered review projection.

    Two findings are merged only when their canonical type and normalized file
    match, and either their source ranges overlap or a nearby finding has the
    same source/sink evidence fingerprint.  This keeps separate calls in the
    same file visible while collapsing repeated scanner, lane, and task output.
    """
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    clusters: list[dict[str, Any]] = []

    for ordinal, raw in enumerate(findings, 1):
        candidate = _new_member(raw)
        candidate["_member_ordinal"] = ordinal
        candidate["duplicate_finding_ids"] = [_member_id(candidate)]
        bucket = buckets[
            (candidate["canonical_vulnerability_type"], _path(candidate.get("file_path")))
        ]
        match = next(
            (cluster for cluster in bucket if _same_cluster(cluster, candidate, line_tolerance)),
            None,
        )
        if match is None:
            candidate["id"] = _cluster_id(candidate)
            bucket.append(candidate)
            clusters.append(candidate)
        else:
            _merge_into(match, candidate)

    for cluster in clusters:
        _finalize(cluster)
    return sorted(
        clusters,
        key=lambda item: (
            -int(item["review_priority_score"]),
            -SEVERITY_RANK.get(_normalized(item.get("severity")), 0),
            -_confidence(item.get("confidence")),
            _path(item.get("file_path")),
            _range(item)[0],
            item["id"],
        ),
    )


def _new_member(raw: dict[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(dict(raw))
    candidate["canonical_vulnerability_type"] = _canonical_type(candidate.get("vulnerability_type"))
    candidate["severity"] = _normalized(candidate.get("severity")) or "medium"
    candidate["confidence"] = _confidence(candidate.get("confidence"))
    candidate["line_start"], candidate["line_end"] = _range(candidate)
    candidate["evidence"] = _evidence_items(candidate)
    candidate["evidence_bundle"] = _merged_bundle(candidate)
    candidate["_evidence_fingerprint"] = _evidence_fingerprint(candidate)
    member_id = _member_id(candidate)
    task_id = str(candidate.get("task_id") or candidate.get("source_task_id") or "")
    candidate["duplicate_finding_ids"] = [member_id]
    candidate["source_task_ids"] = [task_id] if task_id else []
    candidate["duplicate_count"] = 1
    return candidate


def _same_cluster(left: dict[str, Any], right: dict[str, Any], tolerance: int) -> bool:
    if left["canonical_vulnerability_type"] != right["canonical_vulnerability_type"]:
        return False
    if _path(left.get("file_path")) != _path(right.get("file_path")):
        return False
    left_start, left_end = _range(left)
    right_start, right_end = _range(right)
    if left_start <= right_end and right_start <= left_end:
        return True
    fingerprints_match = bool(left.get("_evidence_fingerprint")) and (
        left.get("_evidence_fingerprint") == right.get("_evidence_fingerprint")
    )
    return (
        fingerprints_match
        and left_start <= right_end + tolerance
        and right_start <= left_end + tolerance
    )


def _merge_into(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    target["line_start"] = min(_range(target)[0], _range(incoming)[0])
    target["line_end"] = max(_range(target)[1], _range(incoming)[1])
    target["severity"] = max(
        (_normalized(target.get("severity")), _normalized(incoming.get("severity"))),
        key=lambda value: SEVERITY_RANK.get(value, 0),
    )
    if _confidence(incoming.get("confidence")) > _confidence(target.get("confidence")):
        for key in ("title", "description", "recommendation", "risk_chain", "surface_node_ids"):
            if incoming.get(key):
                target[key] = deepcopy(incoming[key])
    target["confidence"] = max(
        _confidence(target.get("confidence")), _confidence(incoming.get("confidence"))
    )
    target["verification_status"] = _stronger_verification(
        target.get("verification_status"),
        incoming.get("verification_status"),
    )
    target["verification_level"] = max(
        _integer(target.get("verification_level"), 1),
        _integer(incoming.get("verification_level"), 1),
    )
    target["evidence"] = _unique_dicts([*target["evidence"], *incoming["evidence"]])
    target["evidence_bundle"] = _merge_bundles(
        target["evidence_bundle"], incoming["evidence_bundle"]
    )
    target["duplicate_finding_ids"] = list(
        dict.fromkeys(
            [
                *target["duplicate_finding_ids"],
                *incoming["duplicate_finding_ids"],
            ]
        )
    )
    target["source_task_ids"] = list(
        dict.fromkeys(
            [
                *target["source_task_ids"],
                *incoming["source_task_ids"],
            ]
        )
    )
    target["duplicate_count"] = len(target["duplicate_finding_ids"])


def _finalize(cluster: dict[str, Any]) -> None:
    cluster["duplicate_count"] = len(cluster["duplicate_finding_ids"])
    cluster["deduplication_key"] = "|".join(
        [
            cluster["canonical_vulnerability_type"],
            _path(cluster.get("file_path")),
            str(_range(cluster)[0]),
            str(_range(cluster)[1]),
            str(cluster.get("_evidence_fingerprint") or "source_range"),
        ]
    )
    level = max(
        _integer(cluster.get("verification_level"), 1),
        _integer(cluster.get("evidence_bundle", {}).get("level"), 1),
    )
    cluster["verification_level"] = level
    score = _priority_score(cluster, level)
    cluster["review_priority_score"] = score
    cluster["review_priority"] = (
        "P0" if score >= 82 else "P1" if score >= 62 else "P2" if score >= 40 else "P3"
    )
    cluster.pop("_evidence_fingerprint", None)
    cluster.pop("_member_ordinal", None)


def _priority_score(finding: dict[str, Any], level: int) -> int:
    severity_score = {"critical": 50, "high": 38, "medium": 25, "low": 12, "info": 3}.get(
        _normalized(finding.get("severity")),
        20,
    )
    verification = _normalized(finding.get("verification_status"))
    if verification == "rejected":
        return 0
    verification_score = (
        18
        if verification in {"verified", "confirmed"}
        else 8
        if verification == "needs_evidence"
        else 4
    )
    confidence_score = round(_confidence(finding.get("confidence")) * 16)
    evidence_score = min(max(level, 1), 5) * 2
    surface_score = 5 if finding.get("surface_node_ids") or finding.get("risk_chain") else 0
    duplicate_score = min(max(int(finding.get("duplicate_count", 1)) - 1, 0), 5) * 2
    return min(
        100,
        severity_score
        + verification_score
        + confidence_score
        + evidence_score
        + surface_score
        + duplicate_score,
    )


def _merged_bundle(finding: dict[str, Any]) -> dict[str, Any]:
    bundle = dict(finding.get("evidence_bundle") or {})
    bundle["items"] = _unique_dicts(
        [
            *list(bundle.get("items") or []),
            *_evidence_items(finding),
        ]
    )
    bundle["gaps"] = list(
        dict.fromkeys(str(item) for item in bundle.get("gaps", []) if str(item).strip())
    )
    bundle["artifact_refs"] = list(
        dict.fromkeys(str(item) for item in bundle.get("artifact_refs", []) if str(item).strip())
    )
    bundle["level"] = max(
        _integer(bundle.get("level"), 1), _integer(finding.get("verification_level"), 1)
    )
    return bundle


def _merge_bundles(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {
        "items": _unique_dicts([*list(left.get("items") or []), *list(right.get("items") or [])]),
        "gaps": list(
            dict.fromkeys(
                [
                    *[str(item) for item in left.get("gaps", []) if str(item).strip()],
                    *[str(item) for item in right.get("gaps", []) if str(item).strip()],
                ]
            )
        ),
        "artifact_refs": list(
            dict.fromkeys(
                [
                    *[str(item) for item in left.get("artifact_refs", []) if str(item).strip()],
                    *[str(item) for item in right.get("artifact_refs", []) if str(item).strip()],
                ]
            )
        ),
        "level": max(_integer(left.get("level"), 1), _integer(right.get("level"), 1)),
    }


def _evidence_items(finding: dict[str, Any]) -> list[dict[str, Any]]:
    value = finding.get("evidence") or finding.get("evidence_bundle", {}).get("items") or []
    if isinstance(value, dict):
        value = [value]
    return [dict(item) for item in value if isinstance(item, dict)]


def _evidence_fingerprint(finding: dict[str, Any]) -> str:
    values = []
    for item in _evidence_items(finding):
        value = next(
            (
                item.get(key)
                for key in (
                    "sink",
                    "sink_name",
                    "expression",
                    "rule_id",
                    "pattern",
                    "content",
                    "summary",
                )
                if item.get(key)
            ),
            None,
        )
        if value:
            normalized = _normal_text(value)
            # 密钥类证据内容统一脱敏为 "[REDACTED]"，若参与指纹会让同文件内
            # 任意两个相邻密钥互相"指纹匹配"而被错误合并——不同密钥是不同
            # 漏洞（各自的轮换与整改互不替代），脱敏占位不构成匹配证据。
            if normalized in _REDACTED_PLACEHOLDER_VALUES:
                continue
            values.append(normalized)
    return values[0][:180] if values else ""


_REDACTED_PLACEHOLDER_VALUES = {"[redacted]", "redacted"}


def _member_id(finding: dict[str, Any]) -> str:
    value = str(finding.get("id") or "finding")
    task_id = str(finding.get("task_id") or finding.get("source_task_id") or "")
    if task_id:
        return f"{task_id}:{value}"
    lane = str(finding.get("lane") or "")
    suffix = str(finding.get("_member_ordinal") or "")
    return ":".join(part for part in (lane, value, suffix) if part)


def _cluster_id(finding: dict[str, Any]) -> str:
    identity = "|".join(
        [
            finding["canonical_vulnerability_type"],
            _path(finding.get("file_path")),
            str(_range(finding)[0]),
            str(finding.get("_evidence_fingerprint") or "source_range"),
        ]
    )
    return "cluster-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _stronger_verification(left: Any, right: Any) -> str:
    left_value, right_value = _normalized(left), _normalized(right)
    return (
        max((left_value, right_value), key=lambda item: _VERIFICATION_RANK.get(item, 0))
        or "needs_evidence"
    )


def _range(finding: dict[str, Any]) -> tuple[int, int]:
    start = max(0, _integer(finding.get("line_start"), 0))
    end = max(start, _integer(finding.get("line_end"), start))
    return start, end


def _integer(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.5


def _canonical_type(value: Any) -> str:
    normalized = _normalized(value) or "unknown"
    return _TYPE_ALIASES.get(normalized, normalized)


def _path(value: Any) -> str:
    return str(value or "").replace("\\", "/").lower().lstrip("./")


def _normalized(value: Any) -> str:
    return str(value or "").strip().lower()


def _normal_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value).strip().lower())


def _unique_dicts(values: Iterable[Any]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for value in values:
        if not isinstance(value, dict):
            continue
        key = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result
