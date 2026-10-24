from core.audit.finding_cluster import cluster_findings


def _finding(identifier, line, *, task_id="task-a", content="query(user_input)", severity="high"):
    return {
        "id": identifier,
        "task_id": task_id,
        "vulnerability_type": "sql_injection",
        "severity": severity,
        "confidence": 0.8,
        "title": "Unparameterized query",
        "description": "Request input is included in a query.",
        "file_path": "src/users.py",
        "line_start": line,
        "line_end": line,
        "verification_status": "needs_evidence",
        "verification_level": 1,
        "evidence": [{"type": "code_snippet", "content": content}],
    }


def test_cluster_findings_preserves_member_references_and_priority_order():
    clusters = cluster_findings([
        _finding("one", 10, task_id="task-one"),
        _finding("two", 11, task_id="task-two"),
        _finding("three", 50, task_id="task-three", severity="medium"),
    ])

    assert len(clusters) == 2
    merged = clusters[0]
    assert merged["duplicate_count"] == 2
    assert merged["duplicate_finding_ids"] == ["task-one:one", "task-two:two"]
    assert merged["source_task_ids"] == ["task-one", "task-two"]
    assert merged["review_priority"] in {"P0", "P1"}
    assert merged["review_priority_score"] > clusters[1]["review_priority_score"]


def test_cluster_findings_does_not_merge_nearby_distinct_evidence():
    clusters = cluster_findings([
        _finding("first", 10, content="query(user_input)"),
        _finding("second", 11, content="query(other_parameter)"),
    ])

    assert len(clusters) == 2
