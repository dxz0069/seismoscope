"""
Vibe Sec Platform — Recon Agent

信息收集 Agent，负责：
1. 识别技术栈、框架、语言
2. 扫描文件结构
3. 识别入口点和依赖关系
4. 构建项目画像
"""

import os
import re
import json
import logging
from typing import Any, Dict, List, Optional
from pathlib import Path

from core.agents.base import (
    AgentConfig,
    AgentPattern,
    AgentResult,
    AgentType,
    BaseAgent,
)
from core.tool_fabric.dependency_inspection import inspect_dependencies


logger = logging.getLogger(__name__)


class ReconAgent(BaseAgent):
    """
    信息收集 Agent

    负责分析项目的技术栈、文件结构、依赖关系等信息。

    Example:
        agent = ReconAgent(
            config=AgentConfig(
                name="Recon",
                agent_type=AgentType.RECON,
            ),
            llm_service=llm_service,
        )

        result = await agent.run({
            "project_path": "/path/to/project"
        })
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        llm_service=None,
        tools=None,
        event_emitter=None,
    ):
        if config is None:
            config = AgentConfig(
                name="Recon",
                agent_type=AgentType.RECON,
                pattern=AgentPattern.REACT,
                max_iterations=15,
            )

        super().__init__(
            config=config,
            llm_service=llm_service,
            tools=tools,
            event_emitter=event_emitter,
        )

        # 语言/框架检测模式
        self.language_patterns = {
            "python": [
                r"requirements\.txt",
                r"setup\.py",
                r"pyproject\.toml",
                r"Pipfile",
                r"\.py$",
            ],
            "javascript": [
                r"package\.json",
                r"\.js$",
                r"\.jsx$",
            ],
            "typescript": [
                r"tsconfig\.json",
                r"\.ts$",
                r"\.tsx$",
            ],
            "java": [
                r"pom\.xml",
                r"build\.gradle",
                r"\.java$",
            ],
            "go": [
                r"go\.mod",
                r"go\.sum",
                r"\.go$",
            ],
            "ruby": [
                r"Gemfile",
                r"\.rb$",
            ],
            "php": [
                r"composer\.json",
                r"\.php$",
            ],
        }

        # Web 框架检测模式
        self.framework_patterns = {
            "flask": [
                r"from flask import",
                r"import flask",
                r"Flask\(__name__\)",
            ],
            "django": [
                r"from django",
                r"import django",
                r"django\.conf",
            ],
            "fastapi": [
                r"from fastapi import",
                r"import fastapi",
                r"FastAPI\(\)",
            ],
            "express": [
                r"require\(['\"]express['\"]\)",
                r"const express = require",
                r"app\.use\(",
            ],
            "nest": [
                r"from ['\"]@nestjs/",
                r"@Controller\(",
                r"NestFactory\.create\(",
            ],
            "next": [
                r"from ['\"]next/",
                r"NextRequest",
                r"next\.config\.(js|ts|mjs)",
            ],
            "spring": [
                r"org\.springframework",
                r"@RestController",
                r"SpringApplication\.run\(",
            ],
            "gin": [
                r"github\.com/gin-gonic/gin",
                r"gin\.Default\(",
            ],
            "echo": [
                r"github\.com/labstack/echo",
                r"echo\.New\(",
            ],
            "chi": [
                r"github\.com/go-chi/chi",
                r"chi\.NewRouter\(",
            ],
            "react": [
                r"import.*React",
                r"from ['\"]react['\"]",
                r"ReactDOM\.render",
            ],
            "vue": [
                r"import.*Vue",
                r"from ['\"]vue['\"]",
                r"new Vue\(",
            ],
        }

    async def run(self, payload: Dict[str, Any]) -> AgentResult:
        """
        执行信息收集

        Args:
            payload: 包含以下字段：
                - project_path: 项目路径

        Returns:
            AgentResult 包含项目画像信息
        """
        project_path = payload.get("project_path")
        if not project_path:
            return AgentResult.failure_result("project_path is required")

        logger.info(f"Starting reconnaissance for project: {project_path}")

        try:
            # 1. 扫描项目结构
            project_structure = await self._scan_project_structure(project_path)

            # 2. 检测技术栈
            tech_stack = await self._detect_tech_stack(project_path, project_structure)

            # 3. 识别入口点
            entry_points = await self._identify_entry_points(project_path, project_structure, tech_stack)

            # 4. 分析依赖关系
            dependencies = await self._analyze_dependencies(project_path, tech_stack)

            # 5. Derive argument-vector startup and test hints. These are data,
            # not automatically authorized commands.
            execution_hints = self._detect_execution_hints(project_path, tech_stack, entry_points)

            # 6. 构建项目画像
            project_profile = {
                "project_path": project_path,
                "project_structure": project_structure,
                "tech_stack": tech_stack,
                "entry_points": entry_points,
                "dependencies": dependencies,
                "execution_hints": execution_hints,
            }

            # 7. 使用 LLM 生成洞察（如果有 LLM 服务）
            insights = []
            if self.llm_service:
                insights = await self._generate_insights(project_profile)

            # 8. 创建 TaskHandoff
            handoff = self.create_handoff(
                to_agent="surface",
                summary=f"项目侦察完成。技术栈: {', '.join(tech_stack.get('languages', []))}",
                work_completed=[
                    "扫描项目结构",
                    "检测技术栈",
                    "识别入口点",
                    "分析依赖关系",
                ],
                key_findings=[
                    {
                        "type": "tech_stack",
                        "languages": tech_stack.get("languages", []),
                        "frameworks": tech_stack.get("frameworks", []),
                    },
                    {
                        "type": "entry_points",
                        "count": len(entry_points),
                        "examples": entry_points[:5],
                    },
                ],
                insights=insights,
                context_refs={
                    "project_profile": json.dumps(project_profile),
                },
            )

            return AgentResult.success_result(
                data={
                    "project_profile": project_profile,
                    "insights": insights,
                },
                handoff=handoff,
                tokens_used=0,
            )

        except Exception as e:
            logger.error(f"Recon failed: {e}", exc_info=True)
            return AgentResult.failure_result(f"Reconnaissance failed: {str(e)}")

    async def _scan_project_structure(self, project_path: str) -> Dict[str, Any]:
        """扫描项目结构"""
        logger.info(f"Scanning project structure: {project_path}")

        structure = {
            "total_files": 0,
            "total_directories": 0,
            "file_types": {},
            "directory_tree": [],
        }

        for root, dirs, files in os.walk(project_path):
            # 跳过隐藏目录和常见忽略目录
            dirs[:] = [
                d for d in dirs
                if not d.startswith('.') and d not in ['node_modules', '__pycache__', '.git', 'venv', 'env']
            ]

            structure["total_directories"] += len(dirs)
            structure["total_files"] += len(files)

            # 统计文件类型
            for file in files:
                ext = Path(file).suffix.lower()
                if ext:
                    structure["file_types"][ext] = structure["file_types"].get(ext, 0) + 1

            # 构建目录树（只保留前3层）
            rel_path = os.path.relpath(root, project_path)
            if rel_path.count(os.sep) < 3:
                structure["directory_tree"].append({
                    "path": rel_path,
                    "file_count": len(files),
                    "dir_count": len(dirs),
                })

        return structure

    async def _detect_tech_stack(self, project_path: str, structure: Dict) -> Dict[str, Any]:
        """检测技术栈"""
        logger.info("Detecting tech stack")

        tech_stack = {
            "languages": [],
            "frameworks": [],
            "build_tools": [],
            "package_managers": [],
        }

        # 检测语言
        for language, patterns in self.language_patterns.items():
            for root, dirs, files in os.walk(project_path):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]

                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(1024)  # 只读取前 1KB

                        for pattern in patterns:
                            if re.search(pattern, file) or re.search(pattern, content):
                                if language not in tech_stack["languages"]:
                                    tech_stack["languages"].append(language)
                                break
                    except Exception:
                        continue

        # 检测框架
        for framework, patterns in self.framework_patterns.items():
            for root, dirs, files in os.walk(project_path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]

                for file in files:
                    if not file.endswith(('.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb', '.php')):
                        continue

                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(2048)  # 读取前 2KB

                        for pattern in patterns:
                            if re.search(pattern, content):
                                if framework not in tech_stack["frameworks"]:
                                    tech_stack["frameworks"].append(framework)
                                break
                    except Exception:
                        continue

        # 检测构建工具和包管理器
        build_tools = {
            "webpack": r"webpack\.config\.(js|ts)",
            "vite": r"vite\.config\.(js|ts)",
            "maven": r"pom\.xml",
            "gradle": r"build\.gradle",
            "make": r"Makefile",
        }

        for tool, pattern in build_tools.items():
            for _, _, files in os.walk(project_path):
                for file in files:
                    if re.search(pattern, file):
                        if tool not in tech_stack["build_tools"]:
                            tech_stack["build_tools"].append(tool)

        package_managers = {
            "npm": r"package\.json",
            "yarn": r"yarn\.lock",
            "pip": r"requirements\.txt",
            "poetry": r"pyproject\.toml",
            "maven": r"pom\.xml",
            "gradle": r"build\.gradle",
        }

        for manager, pattern in package_managers.items():
            for _, _, files in os.walk(project_path):
                for file in files:
                    if re.search(pattern, file):
                        if manager not in tech_stack["package_managers"]:
                            tech_stack["package_managers"].append(manager)

        return tech_stack

    async def _identify_entry_points(
        self,
        project_path: str,
        structure: Dict,
        tech_stack: Dict,
    ) -> List[str]:
        """识别入口点"""
        logger.info("Identifying entry points")

        entry_points = []

        # 常见的入口点文件
        common_entry_files = [
            "main.py",
            "app.py",
            "index.js",
            "index.ts",
            "index.jsx",
            "index.tsx",
            "server.js",
            "server.ts",
            "wsgi.py",
            "asgi.py",
        ]

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                if file in common_entry_files:
                    entry_points.append(os.path.relpath(os.path.join(root, file), project_path))

        # 检测框架特定的入口点
        frameworks = tech_stack.get("frameworks", [])

        if "flask" in frameworks or "fastapi" in frameworks:
            for root, _, files in os.walk(project_path):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                            if re.search(r'@(app|router)\.(get|post|put|delete|patch)', content):
                                rel_path = os.path.relpath(file_path, project_path)
                                if rel_path not in entry_points:
                                    entry_points.append(rel_path)
                        except Exception:
                            continue

        return entry_points[:10]  # 最多返回10个入口点

    async def _analyze_dependencies_legacy(self, project_path: str, tech_stack: Dict) -> Dict[str, Any]:
        """分析依赖关系"""
        logger.info("Analyzing dependencies")

        dependencies = {
            "direct": [],
            "dev": [],
        }

        # 分析 Python 依赖
        if "python" in tech_stack.get("languages", []):
            # requirements.txt
            req_file = os.path.join(project_path, "requirements.txt")
            if os.path.exists(req_file):
                try:
                    with open(req_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                pkg = line.split('==')[0].split('>=')[0].split('<=')[0]
                                dependencies["direct"].append(pkg)
                except Exception:
                    pass

        # 分析 Node.js 依赖
        if "javascript" in tech_stack.get("languages", []) or "typescript" in tech_stack.get("languages", []):
            package_file = os.path.join(project_path, "package.json")
            if os.path.exists(package_file):
                try:
                    with open(package_file, 'r') as f:
                        package_data = json.load(f)
                    dependencies["direct"].extend(package_data.get("dependencies", {}).keys())
                    dependencies["dev"].extend(package_data.get("devDependencies", {}).keys())
                except Exception:
                    pass

        return dependencies

    async def _analyze_dependencies(self, project_path: str, tech_stack: Dict) -> Dict[str, Any]:
        """Build one structured dependency profile shared with audit tooling."""
        del tech_stack
        logger.info("Analyzing structured dependency manifests")
        inventory = inspect_dependencies(Path(project_path), max_packages=2_000, max_manifests=200)
        direct: List[str] = []
        dev: List[str] = []
        for item in inventory["dependencies"]:
            name = str(item.get("name", ""))
            scope = str(item.get("scope", "")).lower()
            target = dev if any(marker in scope for marker in ("dev", "test")) else direct
            if name and name not in target:
                target.append(name)
        return {
            "direct": direct,
            "dev": dev,
            "records": inventory["dependencies"],
            "locked_records": inventory["locked_dependencies"],
            "manifests": inventory["manifests"],
            "lock_coverage": inventory["lock_coverage"],
            "ecosystems": inventory["ecosystems"],
            "unpinned_direct_count": inventory["unpinned_direct_count"],
            "coverage": inventory["coverage"],
        }

    def _detect_execution_hints(
        self,
        project_path: str,
        tech_stack: Dict[str, Any],
        entry_points: List[str],
    ) -> Dict[str, Any]:
        root = Path(project_path)
        startup: List[Dict[str, Any]] = []
        tests: List[Dict[str, Any]] = []
        frameworks = set(tech_stack.get("frameworks", []))

        python_entry = next((item for item in entry_points if item.endswith(".py")), None)
        if "django" in frameworks and (root / "manage.py").is_file():
            startup.append(self._execution_hint(
                ["python", "manage.py", "runserver", "127.0.0.1:8000"],
                "manage.py", "django", "http://127.0.0.1:8000", 0.9,
            ))
        if "flask" in frameworks and python_entry:
            startup.append(self._execution_hint(
                ["python", "-m", "flask", "--app", python_entry, "run", "--host", "127.0.0.1", "--port", "8000"],
                python_entry, "flask", "http://127.0.0.1:8000", 0.75,
            ))
        if "fastapi" in frameworks and python_entry:
            module = python_entry[:-3].replace("/", ".").replace("\\", ".")
            startup.append(self._execution_hint(
                ["python", "-m", "uvicorn", f"{module}:app", "--host", "127.0.0.1", "--port", "8000"],
                python_entry, "fastapi", "http://127.0.0.1:8000", 0.7,
            ))

        package_file = root / "package.json"
        if package_file.is_file():
            try:
                package = json.loads(package_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                package = {}
            scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
            manager = "pnpm" if (root / "pnpm-lock.yaml").exists() else ("yarn" if (root / "yarn.lock").exists() else "npm")
            for script in ("start", "dev"):
                if script in scripts:
                    command = [manager, script] if manager == "yarn" else [manager, "run", script]
                    startup.append(self._execution_hint(
                        command, "package.json", str(script), "http://127.0.0.1:3000", 0.65,
                    ))
            if "test" in scripts:
                tests.append(self._execution_hint(
                    [manager, "test"], "package.json", "node_test", None, 0.9,
                ))

        if any((root / item).exists() for item in ("pyproject.toml", "pytest.ini", "setup.cfg")) or (root / "tests").is_dir():
            tests.append(self._execution_hint(
                ["python", "-m", "pytest", "-q"],
                "pyproject.toml" if (root / "pyproject.toml").exists() else "tests/",
                "pytest", None, 0.9,
            ))
        if (root / "go.mod").is_file():
            tests.append(self._execution_hint(["go", "test", "./..."], "go.mod", "go", None, 0.95))
        if (root / "Cargo.toml").is_file():
            tests.append(self._execution_hint(["cargo", "test", "--quiet"], "Cargo.toml", "cargo", None, 0.95))

        return {
            "startup": startup,
            "tests": tests,
            "auto_execute": False,
            "policy": "Hints require explicit verification or retest authorization before execution.",
        }

    @staticmethod
    def _execution_hint(
        command: List[str],
        source: str,
        kind: str,
        default_url: Optional[str],
        confidence: float,
    ) -> Dict[str, Any]:
        return {
            "command": command,
            "source": source,
            "kind": kind,
            "default_url": default_url,
            "confidence": confidence,
            "requires_explicit_authorization": True,
        }

    async def _generate_insights(self, project_profile: Dict) -> List[str]:
        """使用 LLM 生成项目洞察"""
        if not self.llm_service:
            return []

        try:
            from core.llm_service import LLMMessage

            prompt = f"""分析以下项目画像，提供安全审查的关键洞察：

项目技术栈:
- 语言: {', '.join(project_profile['tech_stack']['languages'])}
- 框架: {', '.join(project_profile['tech_stack']['frameworks'])}
- 构建工具: {', '.join(project_profile['tech_stack']['build_tools'])}
- 包管理器: {', '.join(project_profile['tech_stack']['package_managers'])}

入口点: {len(project_profile['entry_points'])} 个
直接依赖: {len(project_profile['dependencies']['direct'])} 个

请提供 3-5 条关键洞察，重点关注：
1. 潜在的安全风险区域
2. 需要重点审查的模块
3. 建议的审查策略

用中文回答，每条洞察用一行。"""

            response = await self.llm_service.chat([
                LLMMessage(role="user", content=prompt),
            ])

            insights = [line.strip() for line in response.content.split('\n') if line.strip()]
            return insights

        except Exception:
            logger.warning("LLM reconnaissance insights unavailable; continuing without them")
            return []
