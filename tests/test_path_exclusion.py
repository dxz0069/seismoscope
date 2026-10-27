"""路径排除（默认排除 / .vibe-secignore / --exclude）的契约测试。

真实仓库的检测噪声主要来自构建产物与 vendor 内容（mem0 实测 224 条
prompt_injection 模板噪声）；排除只在工具侧生效并在结果中保持可审计。
"""

import asyncio

from core.audit.path_exclusion import is_excluded, resolve_excludes
from main import run_audit

SQLI_SNIPPET = """
import sqlite3
def get_user(username):
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM users WHERE name = '{username}'").fetchall()
"""


def _make_project(tmp_path, with_min_js=True, with_dist=True, extra_files=None):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(SQLI_SNIPPET, encoding="utf-8")
    if with_min_js:
        (project / "bundle.min.js").write_text("var q=`SELECT * FROM t WHERE i='${x}'`;", encoding="utf-8")
    if with_dist:
        dist = project / "dist"
        dist.mkdir()
        (dist / "app.py").write_text(SQLI_SNIPPET, encoding="utf-8")
    for rel, text in (extra_files or {}).items():
        target = project / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return project


def test_default_excludes_drop_min_js_and_dist():
    patterns = resolve_excludes("/nonexistent")
    assert is_excluded("static/bundle.min.js", patterns)
    assert is_excluded("dist/app.py", patterns)
    assert is_excluded("web/dist/deep/x.py", patterns)
    assert not is_excluded("app.py", patterns)


def test_vibe_secignore_and_extra_patterns(tmp_path):
    project = _make_project(tmp_path)
    (project / ".vibe-secignore").write_text("# comment\nvendor/\ntools/legacy.py\n", encoding="utf-8")
    patterns = resolve_excludes(str(project), extra=["generated/**"])
    assert "vendor/" in patterns and "generated/**" in patterns
    assert is_excluded("vendor/lib.py", patterns)
    assert is_excluded("tools/legacy.py", patterns)
    assert is_excluded("generated/x.py", patterns)
    assert not is_excluded("app.py", patterns)


def test_audit_respects_exclusions_end_to_end(tmp_path):
    project = _make_project(tmp_path)
    result = asyncio.run(
        run_audit(str(project), output_format="json", session_dir=str(tmp_path / "s1"))
    )
    files = {str(f.get("file_path", "")).replace("\\", "/") for f in result["merged_findings"]}
    assert any(f.endswith("app.py") and not f.startswith("dist") for f in files), "根目录 app.py 应有检出"
    assert not any(".min.js" in f for f in files), "*.min.js 默认排除"
    assert not any(f.startswith("dist/") for f in files), "dist/ 默认排除"


def test_audit_respects_vibe_secignore(tmp_path):
    extra = {"legacy/app.py": SQLI_SNIPPET}
    project = _make_project(tmp_path, extra_files=extra)
    (project / ".vibe-secignore").write_text("legacy/\n", encoding="utf-8")
    result = asyncio.run(
        run_audit(str(project), output_format="json", session_dir=str(tmp_path / "s2"))
    )
    files = {str(f.get("file_path", "")).replace("\\", "/") for f in result["merged_findings"]}
    assert not any("legacy/" in f for f in files), ".vibe-secignore 应排除 legacy/"
    assert any(f.endswith("app.py") and "legacy" not in f for f in files)


def test_audit_result_echoes_effective_exclusions(tmp_path):
    """恶意仓库可携带全排除 .vibe-secignore——生效模式必须随结果回显。"""
    import asyncio

    from main import run_audit

    (tmp_path / ".vibe-secignore").write_text("vendor/**\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        'q = "SELECT * FROM t WHERE x = " + user_input\ndb.execute(q)\n', encoding="utf-8"
    )
    result = asyncio.run(run_audit(project_path=str(tmp_path), use_llm=False))
    exclusion = result.get("exclusion")
    assert exclusion is not None, "结果必须携带 exclusion 回显"
    assert exclusion["ignore_file_present"] is True
    assert any("vendor" in pattern for pattern in exclusion["patterns"])
    assert ".vibe-secignore" in exclusion["warning"]
