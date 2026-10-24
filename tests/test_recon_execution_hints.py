import asyncio
import json

from agents.recon_agent import ReconAgent


def test_recon_emits_structured_non_executing_startup_and_test_hints(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "scripts": {"dev": "vite", "test": "vitest run"},
        "dependencies": {"express": "1.0.0"},
    }), encoding="utf-8")
    (tmp_path / "server.js").write_text("const express = require('express')\n", encoding="utf-8")

    result = asyncio.run(ReconAgent().run({"project_path": str(tmp_path)}))
    hints = result.data["project_profile"]["execution_hints"]
    dependencies = result.data["project_profile"]["dependencies"]

    assert hints["auto_execute"] is False
    assert any(item["command"] == ["npm", "run", "dev"] for item in hints["startup"])
    assert any(item["command"] == ["npm", "test"] for item in hints["tests"])
    assert all(item["requires_explicit_authorization"] for item in [*hints["startup"], *hints["tests"]])
    assert dependencies["direct"] == ["express"]
    assert dependencies["records"][0]["version_spec"] == "1.0.0"
    assert dependencies["records"][0]["provenance"]["file_path"] == "package.json"
    assert dependencies["lock_coverage"][0]["status"] == "missing"
