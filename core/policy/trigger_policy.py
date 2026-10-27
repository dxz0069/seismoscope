"""Evidence-aware trigger suggestions for host integrations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from collections.abc import Iterable, Mapping

try:
    import yaml
except ImportError:  # pragma: no cover - declared dependency
    yaml = None


@dataclass
class TriggerDecision:
    should_audit: bool
    mode: str
    reasons: list[str] = field(default_factory=list)
    matched_paths: list[str] = field(default_factory=list)
    risk_score: int = 0
    matched_rules: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self):
        return {
            "should_audit": self.should_audit,
            "mode": self.mode,
            "reasons": self.reasons,
            "matched_paths": self.matched_paths,
            "risk_score": self.risk_score,
            "matched_rules": self.matched_rules,
        }


class TriggerPolicy:
    """Score security-sensitive paths and added code without auto-running audits."""

    CODE_SUFFIXES = {
        ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
        ".java", ".go", ".rs", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h",
        ".yaml", ".yml", ".json", ".toml", ".xml", ".tf", ".sh", ".ps1",
    }
    PATH_WEIGHTS = {
        "auth": 3,
        "login": 3,
        "permission": 3,
        "upload": 2,
        "download": 2,
        "prompt": 3,
        "mcp": 3,
        "tool": 3,
        "secret": 4,
        "token": 4,
        "password": 2,
        "subprocess": 4,
        "shell": 4,
        "workflow": 3,
        "innerhtml": 4,
        "security": 2,
    }
    CONTENT_RULES = {
        "dynamic_code_execution": (r"\b(?:eval|exec)\s*\(", 5),
        "process_execution": (
            r"\b(?:os\.system|subprocess\.(?:run|popen|call)|execsync|child_process\.exec)\s*\(",
            5,
        ),
        "shell_enabled": (r"\bshell\s*=\s*(?:true|True)\b", 5),
        "unsafe_html": (r"\b(?:dangerouslySetInnerHTML|innerHTML|outerHTML|srcdoc)\b", 4),
        "raw_query_or_markup": (r"\b(?:raw|Markup)\s*\(", 4),
        "hardcoded_credential": (
            r"(?i)\b(?:password|passwd|api[_-]?key|secret|token)\b\s*[:=]\s*['\"][^'\"]{4,}",
            5,
        ),
        "authorization_bypass": (
            r"(?i)\b(?:bypass|disable[_-]?(?:auth|permission)|skip[_-]?(?:auth|permission)|allow[_-]?all|unsafe)\b",
            4,
        ),
        "wildcard_permission": (r"(?i)\bpermissions?\b\s*[:=]\s*['\"]?\*", 5),
        "command_or_sql_input": (
            r"(?i)\b(?:execute|query|system|popen)\s*\([^\n]*(?:request|user|input|param|payload)",
            5,
        ),
    }
    SENSITIVE_MARKERS = tuple(PATH_WEIGHTS)

    def __init__(
        self,
        project_path: str | None = None,
        *,
        config_path: str | None = None,
    ) -> None:
        self.threshold = 3
        self.path_weights = dict(self.PATH_WEIGHTS)
        self.content_rules = dict(self.CONTENT_RULES)
        self.code_suffixes = set(self.CODE_SUFFIXES)
        policy_path = Path(config_path) if config_path else None
        if policy_path is None and project_path:
            policy_path = Path(project_path) / ".vibe-sec" / "trigger-policy.yaml"
        if policy_path and policy_path.is_file():
            self._load_config(policy_path)

    def evaluate(
        self,
        changed_paths: Iterable[str],
        *,
        explicit: bool = False,
        diffs: Mapping[str, str] | None = None,
        changed_content: Mapping[str, str] | None = None,
    ) -> TriggerDecision:
        paths = list(dict.fromkeys(str(path) for path in changed_paths))
        content_by_path = {
            self._normalize_path(path): str(content)
            for source in (diffs or {}, changed_content or {})
            for path, content in source.items()
        }
        scores: dict[str, int] = {}
        matched_rules: dict[str, list[str]] = {}

        for path in paths:
            normalized = self._normalize_path(path)
            if Path(normalized).suffix.lower() not in self.code_suffixes:
                continue
            added_code = None
            if normalized in content_by_path:
                added_code = self._added_code(content_by_path[normalized])
                if not added_code:
                    continue

            path_rules = [marker for marker in self.path_weights if marker in normalized.lower()]
            content_rules = []
            content_score = 0
            if added_code is not None:
                for name, (pattern, weight) in self.content_rules.items():
                    if re.search(pattern, added_code):
                        content_rules.append(name)
                        content_score += int(weight)
            path_score = max((self.path_weights[name] for name in path_rules), default=0)
            score = path_score + content_score
            if score:
                scores[path] = score
                matched_rules[path] = [
                    *(f"path:{name}" for name in path_rules),
                    *(f"content:{name}" for name in content_rules),
                ]

        matched = [path for path in paths if scores.get(path, 0) >= self.threshold]
        risk_score = max(scores.values(), default=0)
        if explicit:
            return TriggerDecision(
                True,
                "explicit",
                ["user_requested_audit"],
                matched,
                risk_score,
                matched_rules,
            )
        if matched:
            reasons = []
            if any(rule.startswith("path:") for path in matched for rule in matched_rules[path]):
                reasons.append("security_sensitive_path")
            if any(rule.startswith("content:") for path in matched for rule in matched_rules[path]):
                reasons.append("security_sensitive_diff")
            return TriggerDecision(False, "suggest", reasons, matched, risk_score, matched_rules)
        return TriggerDecision(False, "none", [], [], risk_score, matched_rules)

    def _load_config(self, path: Path) -> None:
        if yaml is None:
            return
        try:
            config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError, yaml.YAMLError):
            return
        if not isinstance(config, dict):
            return
        try:
            self.threshold = max(1, int(config.get("threshold", self.threshold)))
        except (TypeError, ValueError):
            pass
        path_weights = config.get("path_weights")
        if isinstance(path_weights, dict):
            for marker, weight in path_weights.items():
                try:
                    self.path_weights[str(marker).lower()] = max(0, int(weight))
                except (TypeError, ValueError):
                    continue
        content_rules = config.get("content_rules")
        if isinstance(content_rules, dict):
            for name, rule in content_rules.items():
                if not isinstance(rule, dict) or not str(rule.get("pattern", "")):
                    continue
                try:
                    re.compile(str(rule["pattern"]))
                    weight = max(0, int(rule.get("weight", 1)))
                except (re.error, TypeError, ValueError):
                    continue
                self.content_rules[str(name)] = (str(rule["pattern"]), weight)

    @staticmethod
    def _normalize_path(path: str) -> str:
        return str(path).replace("\\", "/")

    @staticmethod
    def _added_code(value: str) -> str:
        lines = value.splitlines()
        looks_like_diff = any(line.startswith(("+++", "---", "@@", "+")) for line in lines)
        if looks_like_diff:
            lines = [line[1:] for line in lines if line.startswith("+") and not line.startswith("+++")]
        code = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*", "<!--")):
                continue
            code.append(line)
        return "\n".join(code)
