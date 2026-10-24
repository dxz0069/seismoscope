from core.audit.candidate_cluster import cluster_candidates


def _candidate(line, target, *, confidence=0.7):
    return {
        "title": "Unsafe query",
        "severity": "high",
        "vulnerability_type": "sql_injection",
        "description": f"candidate from {target}",
        "file_path": "service.py",
        "line_start": line,
        "line_end": line,
        "confidence": confidence,
        "evidence_bundle": {
            "items": [{"type": "source", "target": target}],
            "gaps": [],
            "artifact_refs": [f"artifact-{target}"],
        },
        "discovery_metadata": {
            "target_id": target,
            "tool_execution_ids": [f"execution-{target}"],
        },
    }


def test_cluster_candidates_merges_parallel_target_evidence_and_has_stable_id():
    clustered = cluster_candidates([
        _candidate(10, "a"),
        _candidate(12, "b", confidence=0.9),
        {**_candidate(40, "c"), "vulnerability_type": "command_injection"},
    ])

    assert len(clustered) == 2
    merged = next(item for item in clustered if item["vulnerability_type"] == "sql_injection")
    assert merged["id"].startswith("discovery-")
    assert merged["line_start"] == 10
    assert merged["line_end"] == 12
    assert merged["confidence"] == 0.9
    assert merged["discovery_metadata"]["target_ids"] == ["a", "b"]
    assert merged["discovery_metadata"]["cluster_size"] == 2
    assert len(merged["evidence_bundle"]["artifact_refs"]) == 2
