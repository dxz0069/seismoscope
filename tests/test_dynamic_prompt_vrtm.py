"""VRTM 动态提示词提取：f-string / 拼接构造的提示词进入四平面图。

此前仅识别纯字符串字面量的提示词赋值——vibe coding 最典型的动态构造
（f-string 插值、字符串拼接）全部漏掉，导致 T-PROMPT-INJECTION 等
假设生成器在 Python 项目上哑火。
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from core.surface.runtime_surface import RuntimeSurfaceBuilder, _python_dynamic_prompt
from main import run_audit

FSTRING_AGENT = (
    "def run(query):\n"
    "    system_prompt = f'Answer the question: {query}'\n"
    "    return system_prompt\n"
)

CONCAT_AGENT = (
    "import os\n"
    "\n"
    "\n"
    "def chat(user_input):\n"
    "    prompt = 'System: help\\nUser: ' + user_input\n"
    "    return os.system('echo ' + user_input)\n"
)

LITERAL_ONLY = (
        "system_prompt = 'You are a helpful assistant.'\n"
)


def _prompts(code: str, filename: str = "agent.py"):
    async def build():
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / filename).write_text(code, encoding="utf-8")
            return await RuntimeSurfaceBuilder(str(td)).build()

    return asyncio.run(build())


def test_fstring_prompt_creates_node_and_external_edge():
    surface = _prompts(FSTRING_AGENT)
    prompt = [c for c in surface.prompt_configs if c.name == "system_prompt"]
    assert prompt, "f-string 提示词应生成 prompt 节点"
    assert "{query}" in prompt[0].content
    edges = [e for e in surface.external_content_inputs if e.target_refs == ["system_prompt"]]
    assert any(e.name == "query" for e in edges), "插值变量应成为指向提示词的 external_content"


def test_concat_prompt_creates_node_and_external_edge():
    surface = _prompts(CONCAT_AGENT)
    prompt = [c for c in surface.prompt_configs if c.name == "prompt"]
    assert prompt, "拼接构造的提示词应生成 prompt 节点"
    assert "user_input" in prompt[0].content
    edges = [e for e in surface.external_content_inputs if e.target_refs == ["prompt"]]
    assert any(e.name == "user_input" for e in edges)
    assert not any(e.name in {"chr", "str", "os"} for e in edges), "内建/模块名不得混入外部输入"


def test_literal_prompt_still_single_node():
    surface = _prompts(LITERAL_ONLY, "config.py")
    assert any(c.name == "system_prompt" for c in surface.prompt_configs)
    assert not [e for e in surface.external_content_inputs if e.target_refs == ["system_prompt"]]


def test_dynamic_prompt_text_normalization():
    import ast

    value = ast.parse("x = f'a {q} b {r.name}'").body[0].value  # type: ignore[attr-defined]
    text, identifiers = _python_dynamic_prompt(value, "")
    assert text == "a {q} b {r.name}" or text == "a {q} b {?}"
    assert identifiers[0] == "q"


def test_end_to_end_prompt_injection_hypothesis(tmp_path):
    (tmp_path / "fstr.py").write_text(FSTRING_AGENT, encoding="utf-8")
    result = asyncio.run(run_audit(str(tmp_path), use_llm=False, output_format="json"))
    data = result if isinstance(result, dict) else __import__("json").loads(result)
    techniques = {
        h.get("technique_id")
        for h in (data.get("threat_model") or {}).get("hypotheses") or []
    }
    assert "T-PROMPT-INJECTION" in techniques, "动态提示词应触发提示词注入假设"
    coverage = (data.get("threat_model") or {}).get("coverage") or {}
    assert (coverage.get("node_types") or {}).get("prompt", 0) >= 1


def test_mermaid_export_renders_graph_and_paths():
    from core.vrtm.exporters import export_vrtm

    result = {
        "graph": {
            "nodes": [
                {"id": "ext-1", "label": "user query", "type": "external_content", "flow_plane": "data"},
                {"id": "p-1", "label": "system_prompt", "type": "prompt", "flow_plane": "instruction"},
            ],
            "edges": [
                {"source": "ext-1", "target": "p-1", "relation": "influences", "flow_planes": ["data"]},
            ],
        },
        "threat_model": {"hypotheses": [{"attack_path": ["ext-1", "p-1"]}]},
    }
    out = export_vrtm(result, "mermaid")
    assert out.startswith("flowchart LR")
    assert "system_prompt" in out and "influences" in out
    assert out.count("#dc2626") == 2, "攻击路径上的两个节点都应标红"
    assert '"n0"' not in out  # 节点引用不带引号
