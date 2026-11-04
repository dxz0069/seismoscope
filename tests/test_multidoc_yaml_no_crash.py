"""多文档 YAML 不得使审计中止。

实测触发（2026-10-27 独立复评）：被审计项目含 `---` 分隔的多文档
YAML（PyYAML sdist 的 examples/pygments-lexer/example.yaml；k8s
manifest 合并文件、文档站配置等同形态极常见）时，surface 阶段
`yaml.safe_load` 抛 ComposerError，`run_audit` 整体抛 RuntimeError
——审计中止而非降级。

修复：`_extract_config` 解析失败/多文档时跳过该配置文件。配置面
提取是增强信息，一个非标准 YAML 不能拖垮整个审计。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from main import run_audit

MULTI_DOC_YAML = """\
- Mark McGwire
- Sammy Sosa
- Ken Griffey
---
- Chicago Cubs
- St Louis Cardinals
"""

BROKEN_JSON = '{"openapi": "3.0.0", "paths": {'  # 截断的 JSON

APP_PY = (
    'from flask import request\n'
    '\n'
    '\n'
    'def lookup():\n'
    '    query = "SELECT * FROM t WHERE id = " + request.args.get("id")\n'
    '    return query\n'
)


def _project(tmp_path: Path) -> Path:
    (tmp_path / "example.yaml").write_text(MULTI_DOC_YAML, encoding="utf-8")
    (tmp_path / "broken-spec.json").write_text(BROKEN_JSON, encoding="utf-8")
    (tmp_path / "app.py").write_text(APP_PY, encoding="utf-8")
    return tmp_path


def test_multidoc_yaml_and_broken_json_do_not_abort_audit(tmp_path):
    result = asyncio.run(run_audit(project_path=str(_project(tmp_path)), use_llm=False))
    assert result["orchestration_completed"] is True
    types = {str(item.get("vulnerability_type")) for item in result.get("findings", [])}
    assert "sql_injection" in types, "配置文件解析失败只应跳过自身，不得影响源码审计"


def test_extract_config_skips_unparseable_without_raising():
    from core.surface.runtime_surface import RuntimeSurfaceBuilder

    builder = RuntimeSurfaceBuilder.__new__(RuntimeSurfaceBuilder)
    # 多文档与非法内容：跳过、不抛（surface 增强信息缺失≠审计失败）
    builder._extract_config("example.yaml", MULTI_DOC_YAML, ".yaml")
    builder._extract_config("bad.json", BROKEN_JSON, ".json")
