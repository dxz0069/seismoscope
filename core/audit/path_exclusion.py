"""项目路径排除：默认排除 + 项目内 .vibe-secignore + 显式附加模式。

语义（gitignore 近似）：模式用 fnmatch 匹配项目相对路径（POSIX 风格）；
以 ``/`` 结尾匹配目录前缀；不含 ``/`` 的模式同时按文件名匹配。
安全边界：.vibe-secignore 位于被审计项目内，恶意仓库可携带全排除文件，
因此审计摘要必须回显生效的排除模式与命中规模（见 orchestrator 标注），
"全排除"攻击对使用者可见。
"""

from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, List, Optional

DEFAULT_EXCLUDES = [
    "**/*.min.js",
    "**/*.map",
    "dist/",
    "**/dist/**",
]


def load_ignore_file(project_path: str) -> List[str]:
    path = Path(project_path) / ".vibe-secignore"
    if not path.is_file():
        return []
    lines = (ln.strip() for ln in path.read_text(encoding="utf-8-sig").splitlines())
    return [ln for ln in lines if ln and not ln.startswith("#")]


def resolve_excludes(project_path: str, extra: Optional[Iterable[str]] = None) -> List[str]:
    """合并默认排除、.vibe-secignore 与显式附加模式，保持顺序去重。"""
    merged: List[str] = []
    for pattern in [*DEFAULT_EXCLUDES, *load_ignore_file(project_path), *(extra or [])]:
        text = str(pattern).strip().replace("\\", "/")
        if text and text not in merged:
            merged.append(text)
    return merged


def is_excluded(rel_path: str, patterns: Iterable[str]) -> bool:
    rel = str(rel_path).replace("\\", "/").lstrip("./")
    if not rel:
        return False
    for raw in patterns:
        pattern = str(raw).strip()
        if not pattern:
            continue
        if pattern.endswith("/"):
            directory = pattern.rstrip("/")
            if rel == directory or rel.startswith(directory + "/") or fnmatch(rel, directory + "/*"):
                return True
            continue
        if fnmatch(rel, pattern.lstrip("/")):
            return True
        if "/" not in pattern and fnmatch(rel.rsplit("/", 1)[-1], pattern):
            return True
    return False
