"""转义例程的正则语义分析：环视缺端锚的 script 闭合标签中和缺陷。

真实 CVE 形态（serialize-javascript，PSECBUGS-118415）：

.. code-block:: js

   // 漏洞版：环视要求后面必须跟界定字符，缺 $ 端锚——
   // 序列化函数体以 </script 结尾（串尾）时环视失败，标签未被中和，
   // 后续序列化值补上 > 即可逃出脚本上下文（XSS）。
   var SCRIPT_CLOSE_REGEXP = /<\\/script[^<>]*>|<\\/script(?=[\\t\\n\\f\\r \\/>])/gi;
   // 修复版：(?=$|[\\t\\n\\f\\r \\/>])

判定标准（全部满足才告警）：

1. 正则字面量内含 ``</script``（源码转义写法 ``<\\/script``）的中和模式；
2. 该字面量含正向环视 ``(?=...)`` 分支；
3. 环视体既无 ``$`` 锚也无 ``\\z``——中和只在"后面还有字符"时生效，
   串尾绕过成立。

误报控制：条件 1 限定 script 闭合标签中和语境；普通环视用法不触发。
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

#: 锚点：源码中出现在正则字面量内的 </script（转义写法 <\/script）
_SCRIPT_CLOSE_ANCHOR = re.compile(r"<\\/script", re.IGNORECASE)

#: 提取正则字面量内的正向环视体
_LOOKAHEAD = re.compile(r"\(\?=([^()]*)\)")


def _literal_span(content: str, anchor_start: int) -> tuple[int, int] | None:
    """从 </script 锚点回溯正则字面量的起止（感知字符类与转义）。

    返回 (开斜杠索引, 结束索引含 flags)；跨行或无法闭合时返回 None。
    """
    open_idx = content.rfind("/", 0, anchor_start)
    # 跳过被转义的斜杠（<\/script 的 \/ 不是字面量边界）
    while open_idx > 0 and content[open_idx - 1] == "\\":
        open_idx = content.rfind("/", 0, open_idx)
    if open_idx < 0:
        return None
    i = open_idx + 1
    in_class = False
    while i < len(content):
        ch = content[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
        elif ch == "/":
            break
        elif ch == "\n":
            return None
        i += 1
    else:
        return None
    end = i + 1
    while end < len(content) and content[end].isalpha():
        end += 1
    return open_idx, end


def find_lookahead_bypasses(content: str) -> list[dict[str, Any]]:
    """返回转义正则缺端锚的候选列表（1 起始行号、证据与原因）。"""
    candidates: list[dict[str, Any]] = []
    seen_literals = set()
    for anchor in _SCRIPT_CLOSE_ANCHOR.finditer(content):
        span = _literal_span(content, anchor.start())
        if span is None:
            continue
        open_idx, end = span
        if open_idx in seen_literals:
            continue
        seen_literals.add(open_idx)
        literal = content[open_idx:end]
        reason = _bypass_reason(literal)
        if reason is None:
            continue
        line = content.count("\n", 0, open_idx) + 1
        candidates.append({
            "line_start": line,
            "line_end": line + literal.count("\n"),
            "evidence": literal,
            "reason": reason,
        })
    return candidates


def _bypass_reason(literal: str) -> str | None:
    """判定一个 script 闭合标签中和正则的绕过形态，返回原因或 None。

    形态一（环视缺端锚，PSECBUGS-118415）：有环视分支但环视体无 ``$``/``\\z``
    ——中和仅在后面还有界定字符时生效，串尾裸标签未中和。

    形态二（只有完整标签分支，PSECBUGS-117112）：无任何环视与端锚，
    分支要求闭合 ``>``——分块转义场景下（各函数体独立转义）裸 ``</script``
    串尾绕过，闭合 ``>`` 可由后续序列化值补上。
    """
    lookaheads = _LOOKAHEAD.findall(literal)
    has_anchor = "$" in literal or "\\z" in literal
    if lookaheads:
        if has_anchor:
            return None
        unanchored = [body for body in lookaheads if "$" not in body and "\\z" not in body]
        if not unanchored:
            return None
        return (
            "script 闭合标签中和正则的正向环视缺少端锚（$ / \\z）："
            "中和仅在标签后还有界定字符时生效，序列化内容以 </script "
            "结尾（串尾）时环视失败、标签未被中和——串尾绕过"
        )
    # 形态二：无环视无端锚，且分支要求闭合 >（完整标签才中和）
    if has_anchor:
        return None
    after_anchor = literal[literal.lower().find("<\\/script") + len("<\\/script"):]
    if ">" not in after_anchor:
        return None  # 裸匹配任意出现（含串尾），无此缺陷
    return (
        "script 闭合标签中和正则只有要求闭合 > 的完整标签分支，"
        "无裸前缀环视、无端锚：分块转义场景下（各片段独立转义）串尾"
        "裸 </script 未被中和，闭合 > 可由后续片段补上——分裂载荷绕过"
    )
