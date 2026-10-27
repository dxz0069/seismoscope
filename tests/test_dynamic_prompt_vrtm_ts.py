"""VRTM 动态提示词提取（JS/TS）：模板字面量与拼接构造进入四平面图。"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from core.surface.runtime_surface import RuntimeSurfaceBuilder
from main import run_audit

TS_TEMPLATE = (
    "function chat(userInput: string) {\n"
    "  const systemPrompt = `Answer: ${userInput} done`;\n"
    "  return systemPrompt;\n"
    "}\n"
)
TS_CONCAT = (
    "function greet(name: string) {\n"
    "  const promptText = 'Hello ' + name + ', help?';\n"
    "  return promptText;\n"
    "}\n"
)
TS_LITERAL = "const systemMessage = 'You are helpful.';\n"


def _build(files: dict[str, str]):
    async def run():
        with tempfile.TemporaryDirectory() as td:
            for name, code in files.items():
                (Path(td) / name).write_text(code, encoding="utf-8")
            return await RuntimeSurfaceBuilder(td).build()

    return asyncio.run(run())


def test_ts_template_prompt_creates_node_and_edge():
    surface = _build({"a.ts": TS_TEMPLATE})
    prompts = [c for c in surface.prompt_configs if c.name == "systemPrompt"]
    assert prompts and "${userInput}" in prompts[0].content
    edges = [e for e in surface.external_content_inputs if e.target_refs == ["systemPrompt"]]
    assert any(e.name == "userInput" for e in edges)


def test_ts_concat_prompt_not_misread_as_literal():
    # 拼接（'Hello ' + name）不得被当作纯字面量 'Hello' 处理——
    # 必须走动态路径并生成外部输入边。
    surface = _build({"b.ts": TS_CONCAT})
    prompts = [c for c in surface.prompt_configs if c.name == "promptText"]
    assert prompts and "name" in prompts[0].content, "拼接应保留完整动态文本"
    edges = [e for e in surface.external_content_inputs if e.target_refs == ["promptText"]]
    assert any(e.name == "name" for e in edges)


def test_ts_literal_prompt_keeps_plain_node():
    surface = _build({"c.ts": TS_LITERAL})
    assert any(c.name == "systemMessage" for c in surface.prompt_configs)
    assert not [e for e in surface.external_content_inputs if e.target_refs == ["systemMessage"]]


def test_ts_template_end_to_end_prompt_injection_hypothesis(tmp_path):
    import json

    (tmp_path / "chat.ts").write_text(TS_TEMPLATE, encoding="utf-8")
    result = asyncio.run(run_audit(str(tmp_path), use_llm=False, output_format="json"))
    data = result if isinstance(result, dict) else json.loads(result)
    techniques = {
        h.get("technique_id")
        for h in (data.get("threat_model") or {}).get("hypotheses") or []
    }
    assert "T-PROMPT-INJECTION" in techniques, "TS 模板提示词应触发提示词注入假设"
