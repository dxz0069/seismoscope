"""Regression tests for the real-world tree-sitter native crash.

mem0 的 openclaw/index.ts 曾让审计进程在 Windows 上直接 SIGSEGV
(0xC0000005)：原生绑定的 start_point/end_point 访问在部分语法树上崩溃，
而字节偏移访问稳定。行号因此统一经
core.languages.tree_sitter_gateway.node_line_span 从字节偏移换算，
禁止再直接读取 start_point/end_point。此测试若回归（进程直接崩溃），
CI 会以非零退出码暴露。
"""

import pathlib

from core.audit.protocol_analysis import _analyze_mcp_typescript
from core.languages.tree_sitter_gateway import node_line_span, parser_for

# tests/fixtures/ 同时是其他测试的被审计项目，崩溃样本放独立目录避免污染。
FIXTURE = pathlib.Path(__file__).parent / "regression_fixtures" / "openclaw_registertool_crash.ts"


def _fixture_lines(source: bytes) -> int:
    return source.count(b"\n") + 2


def test_mcp_typescript_analysis_survives_large_registration_subtree():
    content = FIXTURE.read_text(encoding="utf-8", errors="replace")
    signals = _analyze_mcp_typescript(str(FIXTURE), content)
    assert signals, "expected MCP signals from the registerTool fixture"
    assert all(s.line_start >= 1 for s in signals)
    assert any(s.vulnerability_type == "mcp_insecurity" for s in signals)


def test_node_line_span_covers_whole_tree_with_sane_lines():
    source = FIXTURE.read_bytes()
    limit = _fixture_lines(source)
    parser = parser_for("typescript")
    assert parser is not None, "tree-sitter gateway unavailable"
    tree = parser.parse(source)
    stack, seen = [tree.root_node], 0
    min_line, max_line = limit, 1
    while stack:
        node = stack.pop()
        start, end = node_line_span(source, node)
        assert 1 <= start <= limit
        assert start <= end <= limit
        min_line, max_line = min(min_line, start), max(max_line, end)
        seen += 1
        stack.extend(node.children)
    assert seen > 100, "fixture tree unexpectedly small"
    assert min_line == 1 and max_line >= limit - 3
