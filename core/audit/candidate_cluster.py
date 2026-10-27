"""Deterministic clustering for candidates emitted by parallel audit targets."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from copy import deepcopy
from typing import Any

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def cluster_candidates(
    candidates: Iterable[dict[str, Any]],
    *,
    line_tolerance: int = 5,
) -> list[dict[str, Any]]:
    """Merge same-file/type candidates whose source ranges overlap or are close.

    Complexity: O(n) average case using a (file_path, vulnerability_type) bucket
    index. Within each bucket we still do a linear scan, but buckets are small
    (typically 1-3 items for a given file+type combination), making the overall
    cost effectively linear for realistic scan outputs.
    """
    # bucket: (normalised_path, normalised_vuln_type) → list of cluster dicts
    buckets: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    result_order: list[dict[str, Any]] = []  # preserves insertion order

    for raw in candidates:
        candidate = deepcopy(raw)
        bucket_key = (_path(candidate.get("file_path")), _normalized(candidate.get("vulnerability_type")))
        bucket = buckets[bucket_key]

        match = next(
            (item for item in bucket if _same_cluster(item, candidate, line_tolerance)),
            None,
        )
        if match is None:
            # Generate a stable id anchored to the *original* line_start before
            # any merging can shift the range.  We store the anchor so future
            # merges into this cluster do not change its id.
            original_line_start = int(candidate.get("line_start", 1) or 1)
            candidate["id"] = _stable_id(candidate, original_line_start)
            candidate.setdefault("_id_anchor_line", original_line_start)
            metadata = dict(candidate.get("discovery_metadata") or {})
            target_id = metadata.get("target_id")
            metadata["target_ids"] = [target_id] if target_id else []
            candidate["discovery_metadata"] = metadata
            bucket.append(candidate)
            result_order.append(candidate)
            continue
        _merge_into(match, candidate)
    return result_order


def _same_cluster(left: dict[str, Any], right: dict[str, Any], tolerance: int) -> bool:
    if _normalized(left.get("vulnerability_type")) != _normalized(right.get("vulnerability_type")):
        return False
    if _path(left.get("file_path")) != _path(right.get("file_path")):
        return False
    left_start, left_end = _range(left)
    right_start, right_end = _range(right)
    return left_start <= right_end + tolerance and right_start <= left_end + tolerance


def _merge_into(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    target_start, target_end = _range(target)
    incoming_start, incoming_end = _range(incoming)
    target["line_start"] = min(target_start, incoming_start)
    target["line_end"] = max(target_end, incoming_end)

    target_confidence = _confidence(target.get("confidence"))
    incoming_confidence = _confidence(incoming.get("confidence"))
    if incoming_confidence > target_confidence:
        for field in ("title", "description"):
            if incoming.get(field):
                target[field] = incoming[field]
    target["confidence"] = max(target_confidence, incoming_confidence)
    target["severity"] = max(
        (_normalized(target.get("severity")), _normalized(incoming.get("severity"))),
        key=lambda value: SEVERITY_RANK.get(value, 0),
    )

    target_bundle = dict(target.get("evidence_bundle") or {})
    incoming_bundle = dict(incoming.get("evidence_bundle") or {})
    target_bundle["items"] = _unique_dicts([
        *list(target_bundle.get("items", []) or []),
        *list(incoming_bundle.get("items", []) or []),
    ])
    target_bundle["gaps"] = list(dict.fromkeys(
        str(item) for item in [
            *list(target_bundle.get("gaps", []) or []),
            *list(incoming_bundle.get("gaps", []) or []),
        ] if str(item).strip()
    ))
    target_bundle["artifact_refs"] = list(dict.fromkeys([
        *list(target_bundle.get("artifact_refs", []) or []),
        *list(incoming_bundle.get("artifact_refs", []) or []),
    ]))
    target["evidence_bundle"] = target_bundle
    target["evidence"] = list(target_bundle["items"])

    metadata = dict(target.get("discovery_metadata") or {})
    incoming_metadata = dict(incoming.get("discovery_metadata") or {})
    metadata["target_ids"] = list(dict.fromkeys(item for item in [
        *list(metadata.get("target_ids", []) or []),
        metadata.get("target_id"),
        incoming_metadata.get("target_id"),
        *list(incoming_metadata.get("target_ids", []) or []),
    ] if item))
    metadata["tool_execution_ids"] = list(dict.fromkeys([
        *list(metadata.get("tool_execution_ids", []) or []),
        *list(incoming_metadata.get("tool_execution_ids", []) or []),
    ]))
    metadata["cluster_size"] = int(metadata.get("cluster_size", 1)) + int(
        incoming_metadata.get("cluster_size", 1)
    )
    target["discovery_metadata"] = metadata


def _stable_id(candidate: dict[str, Any], anchor_line: int | None = None) -> str:
    """Generate a stable id anchored to the *original* line_start.

    The id is computed once at cluster creation time and never changes even
    when _merge_into() expands the line range.  Callers that know the original
    line_start should pass it explicitly via ``anchor_line`` to guarantee
    stability across merges.
    """
    line = anchor_line if anchor_line is not None else _range(candidate)[0]
    identity = "|".join([
        _normalized(candidate.get("vulnerability_type")),
        _path(candidate.get("file_path")),
        str(line),
    ])
    return "discovery-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _range(candidate: dict[str, Any]) -> tuple[int, int]:
    start = max(1, int(candidate.get("line_start", 1) or 1))
    end = max(start, int(candidate.get("line_end", start) or start))
    return start, end


def _path(value: Any) -> str:
    return str(value or "").replace("\\", "/").lower().lstrip("./")


def _normalized(value: Any) -> str:
    return str(value or "unknown").strip().lower()


def _confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.5


def _unique_dicts(values: Iterable[Any]) -> list[Any]:
    seen = set()
    result = []
    for value in values:
        key = repr(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result
