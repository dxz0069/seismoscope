from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _compose(path: str):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_default_compose_is_source_only_and_publishes_web_only():
    compose = _compose("compose.yml")

    assert set(compose["services"]) == {"api", "web", "audit"}
    assert compose["services"]["web"]["ports"] == ["${VIBE_SEC_HTTP_PORT:-8000}:80"]
    assert compose["services"]["api"]["volumes"][1]["target"] == "/workspace"
    assert compose["services"]["api"]["volumes"][1]["read_only"] is True
    assert "/var/run/docker.sock" not in (ROOT / "compose.yml").read_text(encoding="utf-8")


def test_llm_overlay_uses_external_secret_file():
    compose = _compose("compose.llm.yml")

    secret_file = compose["secrets"]["deepseek_api_key"]["file"]
    assert secret_file.startswith("${VIBE_SEC_DEEPSEEK_API_KEY_FILE")
    assert compose["services"]["api"]["environment"]["VIBE_SEC_DEEPSEEK_API_KEY_FILE"] == (
        "/run/secrets/deepseek_api_key"
    )


def test_deployment_scripts_and_skill_entrypoint_are_packaged():
    required = [
        "deploy/Dockerfile",
        "deploy/entrypoint.sh",
        "deploy/nginx.conf",
        "scripts/deploy.ps1",
        "scripts/deploy.sh",
        "scripts/install-agent-skill.ps1",
        "scripts/install-agent-skill.sh",
        "skill/SKILL.md",
        "docs/DEPLOYMENT.md",
    ]

    assert all((ROOT / path).is_file() for path in required)
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "*.key" in dockerignore
    assert ".lab-cache" in dockerignore
