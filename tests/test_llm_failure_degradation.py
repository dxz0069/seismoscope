import asyncio
import json

from agents.audit_agent import AuditAgent


class AuthenticationFailingLLM:
    provider = "deepseek"
    model = "deepseek-chat"

    async def chat(self, *args, **kwargs):
        raise RuntimeError("Error code: 401 authentication_error for sk-sensitive-test-value")


def test_llm_react_failure_preserves_static_candidate_and_redacts_provider_error(tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        "def run(command):\n"
        "    return subprocess.call(command, shell=True)\n",
        encoding="utf-8",
    )

    result = asyncio.run(AuditAgent(llm_service=AuthenticationFailingLLM()).run({
        "project_path": str(tmp_path),
        "audit_scope": {
            "web_vulns": True,
            "agent_vulns": False,
            "mcp_vulns": False,
            "secret_leaks": False,
            "workflow_vulns": False,
        },
        "use_llm": True,
        "enable_react_review": True,
        "enable_react_discovery": False,
        "react_review_limit": 1,
        "react_max_turns": 2,
    }))

    assert result.success is True
    findings = result.data["findings"]
    assert len(findings) == 1
    assert findings[0]["status"] == "needs_evidence"
    review_stats = result.data["audit_summary"]["react_review_stats"]
    assert review_stats["failed"] + review_stats["degraded"] == 1

    serialized = json.dumps(result.data, ensure_ascii=False)
    assert "sk-sensitive-test-value" not in serialized
    assert "authentication_failed" in serialized
