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
    monkeypatch.setenv("VIBE_SEC_DEEPSEEK_API_KEY", "never-persist-this-key")

    report = manager.doctor()

    assert report["status"] == "not_ready"
    assert report["required_gaps"] == ["scanner"]
    assert report["optional_gaps"] == ["codeql"]
    assert report["llm"]["configured"] is True
    assert "never-persist-this-key" not in json.dumps(report)


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
