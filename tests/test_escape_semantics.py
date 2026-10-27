"""转义正则语义分析：环视缺端锚的 script 闭合标签中和绕过。"""

from __future__ import annotations

from core.audit.escape_semantics import find_lookahead_bypasses

VULNERABLE = (
    'var SCRIPT_CLOSE_REGEXP = /<\\/script[^<>]*>|<\\/script(?=[\\t\\n\\f\\r \\/>])/gi;'
)
FIXED = (
    'var SCRIPT_CLOSE_REGEXP = /<\\/script[^<>]*>|<\\/script(?=$|[\\t\\n\\f\\r \\/>])/gi;'
)
FIRST_ROUND = (
    'var SCRIPT_CLOSE_REGEXP = /<\\/script[^>]*>/gi;'
)


def test_vulnerable_lookahead_without_anchor_is_flagged():
    candidates = find_lookahead_bypasses(VULNERABLE + "\n")
    assert len(candidates) == 1
    assert "端锚" in candidates[0]["reason"]
    assert candidates[0]["line_start"] == 1
    assert "<\/script" in candidates[0]["evidence"] and "(?=" in candidates[0]["evidence"]


def test_fixed_form_with_dollar_anchor_is_clean():
    assert find_lookahead_bypasses(FIXED + "\n") == []


def test_first_round_form_without_lookahead_is_not_this_analyzer():
    # 无环视的旧形态不属于本分析器职责（缺端锚语义不成立）
    assert find_lookahead_bypasses(FIRST_ROUND + "\n") == []


def test_unrelated_lookaheads_do_not_trigger():
    benign = "const m = /foo(?=bar)/g; str.replace(m, '');\n"
    assert find_lookahead_bypasses(benign) == []


def test_line_numbers_count_from_one():
    content = "line0\nline1\n" + VULNERABLE + "\n"
    candidates = find_lookahead_bypasses(content)
    assert candidates[0]["line_start"] == 3
