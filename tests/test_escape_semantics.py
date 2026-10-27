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


def test_first_round_complete_tag_only_form_is_flagged():
    # 形态二（PSECBUGS-117112）：只有完整标签分支，分块转义串尾绕过
    candidates = find_lookahead_bypasses(FIRST_ROUND + "\n")
    assert len(candidates) == 1
    assert "完整标签分支" in candidates[0]["reason"]
    assert "分裂载荷" in candidates[0]["reason"]


def test_bare_matcher_form_is_clean():
    # 裸匹配任意出现（含串尾）无此缺陷
    bare = "var R = /<\\/script/gi; str.replace(R, '');"
    assert find_lookahead_bypasses(bare + "\n") == []


def test_unrelated_lookaheads_do_not_trigger():
    benign = "const m = /foo(?=bar)/g; str.replace(m, '');\n"
    assert find_lookahead_bypasses(benign) == []


def test_line_numbers_count_from_one():
    content = "line0\nline1\n" + VULNERABLE + "\n"
    candidates = find_lookahead_bypasses(content)
    assert candidates[0]["line_start"] == 3
