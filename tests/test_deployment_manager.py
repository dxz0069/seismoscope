import hashlib
import json
import sys
from pathlib import Path

from core.deployment import DeploymentManager


def _manifest(tmp_path: Path) -> Path:
    payload = {
        "schema_version": "vibe-sec.tool-images.v1",
        "release": "test",
        "images": [
            {
                "id": "base", "image": "vibe-sec-base:test", "image_version": "1",
                "default_install": False, "build_context": "base", "capabilities": ["base"],
                "tool_versions": {}, "artifacts": [],
            },
            {
                "id": "scanner", "image": "vibe-sec-scanner:test", "image_version": "1",
                "default_install": True, "depends_on": ["base"], "build_context": "scanner",
                "capabilities": ["scan"], "tool_versions": {}, "artifacts": [],
            },
            {
                "id": "codeql", "image": "vibe-sec-codeql:test", "image_version": "1",
                "default_install": False, "build_context": "codeql",
                "capabilities": ["codeql"], "tool_versions": {}, "artifacts": [],
            },
        ],
    }
    path = tmp_path / "tool-images.lock.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_setup_dry_run_resolves_dependencies_without_building(tmp_path, monkeypatch):
    manager = DeploymentManager(root=str(tmp_path), manifest_path=str(_manifest(tmp_path)))
    doctor = {
        "status": "not_ready",
        "docker": {"daemon_available": True, "error": ""},
        "images": [],
    }
    monkeypatch.setattr(manager, "doctor", lambda: doctor)
    monkeypatch.setattr(manager, "_inspect_image", lambda item: {
        "id": item["id"], "available": False, "reason": "missing",
    })

    report = manager.setup(include=["scanner"], dry_run=True)

    assert report["status"] == "planned"
    assert report["selected"] == ["base", "scanner"]
    assert [item["status"] for item in report["actions"]] == ["planned", "planned"]
    assert report["actions"][0]["command"][:2] == ["docker", "build"]
    assert not (tmp_path / ".vibe-sec" / "install-state.json").exists()


def test_doctor_separates_required_and_optional_gaps_without_exposing_key(tmp_path, monkeypatch):
    manager = DeploymentManager(root=str(tmp_path), manifest_path=str(_manifest(tmp_path)))
    monkeypatch.setattr(manager, "_docker_status", lambda: {
        "binary": "docker", "client_available": True, "daemon_available": True,
        "server_version": "test", "error": "",
    })
    monkeypatch.setattr(manager, "_inspect_image", lambda item: {
        "id": item["id"], "default_install": item["default_install"],
        "available": item["id"] == "base", "reason": "test",
    })
    monkeypatch.setattr("core.deployment.manager.tree_sitter_status", lambda: _ts_status())
    monkeypatch.setenv("VIBE_SEC_DEEPSEEK_API_KEY", "never-persist-this-key")

    report = manager.doctor()

    assert report["contract_version"] == "vibe-sec.doctor.v2"
    # 必备镜像缺失压低的是容器验证能力，静态核心仍可跑：degraded 而非 not_ready。
    assert report["status"] == "degraded_ready"
    assert report["degraded_capabilities"] == ["container_verification"]
    assert report["capabilities"]["container_verification"]["available"] is False
    assert report["capabilities"]["static_audit"]["available"] is True
    assert report["required_gaps"] == ["scanner"]
    assert report["optional_gaps"] == ["codeql"]
    assert report["llm"]["configured"] is True
    assert "never-persist-this-key" not in json.dumps(report)


def _ts_status(all_ready: bool = True):
    languages = {"python": all_ready, "typescript": all_ready, "javascript": all_ready}
    return {
        "contract_version": "vibe-sec.tree-sitter-status.v1",
        "pack_installed": True,
        "enabled": True,
        "cache_dir": None,
        "languages": languages,
        "all_ready": all_ready,
        "hint": "test",
    }


def _green_environment(tmp_path, monkeypatch, *, docker_up=True, ts_ready=True, images_ready=True):
    manager = DeploymentManager(root=str(tmp_path), manifest_path=str(_manifest(tmp_path)))
    monkeypatch.setattr(manager, "_docker_status", lambda: {
        "binary": "docker", "client_available": docker_up, "daemon_available": docker_up,
        "server_version": "test", "error": "" if docker_up else "daemon down",
    })
    monkeypatch.setattr(manager, "_inspect_image", lambda item: {
        "id": item["id"], "default_install": item["default_install"],
        "available": images_ready, "reason": "test",
    })
    monkeypatch.setattr("core.deployment.manager.tree_sitter_status", lambda: _ts_status(ts_ready))
    return manager


def test_doctor_ready_when_all_core_capabilities_available(tmp_path, monkeypatch):
    report = _green_environment(tmp_path, monkeypatch).doctor()

    assert report["status"] == "ready"
    assert report["degraded_capabilities"] == []
    for name, info in report["capabilities"].items():
        if not info["optional"]:
            assert info["available"], name


def test_doctor_degraded_when_docker_down_but_static_core_alive(tmp_path, monkeypatch):
    report = _green_environment(tmp_path, monkeypatch, docker_up=False).doctor()

    assert report["status"] == "degraded_ready"
    assert "container_verification" in report["degraded_capabilities"]
    assert "static_audit" not in report["degraded_capabilities"]
    assert report["capabilities"]["container_verification"]["fallback"]


def test_doctor_degraded_when_ast_parsers_missing(tmp_path, monkeypatch):
    report = _green_environment(tmp_path, monkeypatch, ts_ready=False).doctor()

    assert report["status"] == "degraded_ready"
    assert "mcp_ast_analysis" in report["degraded_capabilities"]
    blocking = report["capabilities"]["mcp_ast_analysis"]["blocking"]
    assert any("not cached" in item for item in blocking)
    assert report["capabilities"]["mcp_ast_analysis"]["fallback"]


def test_doctor_not_ready_only_when_static_core_unusable(tmp_path, monkeypatch):
    manager = _green_environment(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "version_info", (3, 10, 0, "final", 0))

    report = manager.doctor()

    assert report["status"] == "not_ready"
    assert report["platform"]["python_supported"] is False
    assert "static_audit" in report["degraded_capabilities"]
    assert report["capabilities"]["static_audit"]["blocking"] == ["python>=3.11 required"]


def test_doctor_optional_capabilities_never_degrade_status(tmp_path, monkeypatch):
    report = _green_environment(tmp_path, monkeypatch, docker_up=False).doctor()

    # codeql/LLM 未配置是默认形态：能力矩阵如实标注，但不进入 degraded 列表。
    assert report["capabilities"]["codeql_scan"]["optional"] is True
    assert report["capabilities"]["llm_deep_analysis"]["optional"] is True
    assert "codeql_scan" not in report["degraded_capabilities"]
    assert "llm_deep_analysis" not in report["degraded_capabilities"]


def test_artifact_download_uses_locked_sha256(tmp_path):
    manager = DeploymentManager(root=str(tmp_path), manifest_path=str(_manifest(tmp_path)))
    source = tmp_path / "source.bin"
    source.write_bytes(b"locked artifact")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    result = manager._prepare_artifact({
        "url": source.as_uri(),
        "path": "cache/artifact.bin",
        "sha256": digest,
    })

    assert result["status"] == "downloaded"
    assert Path(result["path"]).read_bytes() == b"locked artifact"
    cached = manager._prepare_artifact({
        "url": source.as_uri(), "path": "cache/artifact.bin", "sha256": digest,
    })
    assert cached["status"] == "cached"


def test_doctor_cli_emits_machine_readable_contract(monkeypatch, capsys):
    import main

    monkeypatch.setattr(DeploymentManager, "doctor", lambda self: {
        "contract_version": "vibe-sec.doctor.v1",
        "status": "ready",
        "docker": {"daemon_available": True, "server_version": "test"},
        "images": [],
        "llm": {"configured": False, "credential_values_exposed": False},
    })
    monkeypatch.setattr(sys, "argv", ["vibe-sec", "doctor", "--json"])

    main.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["contract_version"] == "vibe-sec.doctor.v1"
    assert payload["status"] == "ready"
    assert "credential_values_exposed" in payload["llm"]


def test_doctor_cli_human_output_renders_capability_matrix(monkeypatch, capsys):
    import main

    monkeypatch.setattr(DeploymentManager, "doctor", lambda self: {
        "contract_version": "vibe-sec.doctor.v2",
        "status": "degraded_ready",
        "docker": {"daemon_available": False},
        "images": [],
        "llm": {"configured": False},
        "capabilities": {
            "static_audit": {"available": True, "optional": False, "blocking": [], "fallback": None},
            "container_verification": {
                "available": False, "optional": False,
                "blocking": ["docker daemon unavailable"],
                "fallback": "static verification only", "next_step": "vibe-sec setup",
            },
            "llm_deep_analysis": {
                "available": False, "optional": True,
                "blocking": ["VIBE_SEC_DEEPSEEK_API_KEY / DEEPSEEK_API_KEY not set"],
                "fallback": "deterministic pipeline without LLM enrichment",
            },
        },
    })
    monkeypatch.setattr(sys, "argv", ["vibe-sec", "doctor"])

    main.main()

    out = capsys.readouterr().out
    assert "degraded_ready" in out
    assert "[READY] static_audit" in out
    assert "[DEGRADED] container_verification (docker daemon unavailable; fallback: static verification only; next: vibe-sec setup)" in out
    assert "[OPTIONAL] llm_deep_analysis" in out
