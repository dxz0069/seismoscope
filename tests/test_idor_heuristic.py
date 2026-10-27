"""IDOR 启发式门控：按路由标识符的对象查询与所有权谓词缺席。"""

from __future__ import annotations

import asyncio
import re

from agents.audit_agent import AuditAgent
from main import run_audit

VAMPI_IDOR = '''from flask import jsonify, Response, request
from api_views.users import token_validator
from models.books_model import Book


def get_by_title(book_title):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response("unauthorized", 401)
    book = Book.query.filter_by(book_title=str(book_title)).first()
    if book:
        return Response(jsonify({'secret': book.secret_content}), 200)
    return Response("not found", 404)
'''

FIXED_IDOR = VAMPI_IDOR.replace(
    "book = Book.query.filter_by(book_title=str(book_title)).first()",
    "book = Book.query.filter_by(user=user, book_title=str(book_title)).first()",
)

PUBLIC_LOOKUP = '''from models.books_model import Book


def public_catalog(book_title):
    return Book.query.filter_by(book_title=str(book_title)).first()
'''

POST_QUERY_CHECK = '''from flask import abort, request
from flask_login import current_user
from api_views.users import token_validator
from models.books_model import Book


def get_by_title(book_title):
    token_validator(request.headers.get('Authorization'))
    book = Book.query.filter_by(book_title=str(book_title)).first()
    if book.user_id != current_user.id:
        abort(403)
    return book
'''


def _matches_vulnerable(content: str) -> bool:
    agent = AuditAgent()
    for pattern in agent.web_vulnerability_patterns["idor"]["patterns"]:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            if AuditAgent._is_idor_signal(content, match.start()):
                return True
    return False


def test_vampi_idor_form_flagged():
    assert _matches_vulnerable(VAMPI_IDOR)


def test_fixed_form_with_ownership_kwarg_clean():
    assert not _matches_vulnerable(FIXED_IDOR)


def test_public_anonymous_lookup_clean():
    assert not _matches_vulnerable(PUBLIC_LOOKUP)


def test_post_query_ownership_check_clean():
    assert not _matches_vulnerable(POST_QUERY_CHECK)


def test_end_to_end_idor_candidate(tmp_path):
    (tmp_path / "books.py").write_text(VAMPI_IDOR, encoding="utf-8")
    (tmp_path / "safe.py").write_text(POST_QUERY_CHECK, encoding="utf-8")
    result = asyncio.run(run_audit(str(tmp_path), use_llm=False, output_format="json"))
    data = result if isinstance(result, dict) else __import__("json").loads(result)
    idor = [
        f for f in data.get("findings", [])
        if f.get("vulnerability_type") == "idor" and f.get("file_path") == "books.py"
    ]
    assert idor, "VAmPI 形态应产生 idor 候选"
    assert not [
        f for f in data.get("findings", [])
        if f.get("vulnerability_type") == "idor" and f.get("file_path") == "safe.py"
    ], "事后所有权检查过的代码不得告警"
