"""Tests for deterministic, bounded audit target planning."""

from core.audit.target_planner import AuditTargetPlanner


def test_planner_prioritizes_candidates_then_surface_and_uncovered_source(tmp_path):
    for name in ("route.py", "service.py", "agent.py", "other.py"):
        (tmp_path / name).write_text("value = 1\n", encoding="utf-8")
    planner = AuditTargetPlanner(str(tmp_path))

    targets = planner.plan(
        lane="web_audit",
        candidates=[{"file_path": "service.py", "vulnerability_type": "sql_injection"}],
        surface_graph={"nodes": [{
            "id": "entry-1",
            "type": "entry_point",
            "attributes": {"file_path": "route.py"},
        }]},
        threat_model={"hypotheses": [{
            "id": "hyp-1",
            "technique_id": "T-UNPROTECTED-ENTRY",
        }]},
        max_targets=3,
    )

    assert targets[0].priority == 100
    assert targets[0].seed_files == ["service.py"]
    assert targets[1].priority == 80
    assert targets[1].seed_files == ["route.py"]
    assert targets[1].hypothesis_ids == ["hyp-1"]
    assert set(targets[2].seed_files) == {"agent.py", "other.py"}
    assert len({item.target_id for item in targets}) == len(targets)


def test_planner_is_bounded_and_ignores_dependencies(tmp_path):
    for index in range(20):
        (tmp_path / f"module_{index}.py").write_text("value = 1\n", encoding="utf-8")
    dependency = tmp_path / "node_modules"
    dependency.mkdir()
    (dependency / "ignored.js").write_text("danger()\n", encoding="utf-8")

    targets = AuditTargetPlanner(str(tmp_path)).plan(
        lane="web_audit",
        max_targets=2,
        files_per_target=3,
    )

    assert len(targets) == 2
    assert all(len(item.seed_files) <= 3 for item in targets)
    assert all("node_modules/ignored.js" not in item.seed_files for item in targets)


def test_source_inventory_supports_large_repository_coverage_accounting(tmp_path):
    for name in ("a.py", "b.ts", "notes.txt"):
        (tmp_path / name).write_text("value = 1\n", encoding="utf-8")

    inventory = AuditTargetPlanner(str(tmp_path)).source_inventory()

    assert inventory == ["a.py", "b.ts"]


def test_planner_prioritizes_changed_files_but_preserves_transitive_context(tmp_path):
    for name in ("route.py", "service.py", "unrelated.py"):
        (tmp_path / name).write_text("value = 1\n", encoding="utf-8")

    targets = AuditTargetPlanner(str(tmp_path)).plan(
        lane="web_audit",
        changed_files=["route.py", "../outside.py", "deleted.py"],
        max_targets=2,
        files_per_target=2,
    )

    assert targets[0].priority == 110
    assert targets[0].seed_files == ["route.py"]
    assert targets[0].reasons == ["changed_file_scope", "transitive_security_context"]
    assert set(targets[1].seed_files) == {"service.py", "unrelated.py"}


def test_inventory_does_not_treat_project_parent_name_as_ignored(tmp_path):
    project = tmp_path / "build" / "actual-project"
    project.mkdir(parents=True)
    (project / "app.py").write_text("value = 1\n", encoding="utf-8")

    assert AuditTargetPlanner(str(project)).source_inventory() == ["app.py"]
