"""
Vibe Sec Platform — Surface Agent

攻击面建模 Agent，负责：
1. 构建 RuntimeSurface（攻击面画像）
2. 构建 RuntimeSurfaceGraph（关系图）
3. 构建 RiskChain（风险链）
4. 识别高风险区域
"""

import logging
from typing import Any, Dict, List, Optional

from core.agents.base import (
    AgentConfig,
    AgentPattern,
    AgentResult,
    AgentType,
    BaseAgent,
)
from core.surface.runtime_surface import RuntimeSurface, RuntimeSurfaceBuilder
from core.surface.risk_chain import RiskChain, RiskChainBuilder
from core.surface.threat_model import RuntimeThreatModelAnalyzer
from core.harness.models import RuntimeSurfaceGraph
from core.vrtm.declaration import VRTMDeclaration


logger = logging.getLogger(__name__)


class SurfaceAgent(BaseAgent):
    """
    攻击面建模 Agent

    基于 ReconAgent 的输出，构建完整的攻击面画像和风险链分析。

    Example:
        agent = SurfaceAgent(
            config=AgentConfig(
                name="Surface",
                agent_type=AgentType.SURFACE,
            ),
            llm_service=llm_service,
        )

        result = await agent.run({
            "project_path": "/path/to/project",
            "recon_handoff": "...",
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
                name="Surface",
                agent_type=AgentType.SURFACE,
                pattern=AgentPattern.REACT,
                max_iterations=15,
            )

        super().__init__(
            config=config,
            llm_service=llm_service,
            tools=tools,
            event_emitter=event_emitter,
        )

    async def run(self, payload: Dict[str, Any]) -> AgentResult:
        """
        执行攻击面建模

        Args:
            payload: 包含以下字段：
                - project_path: 项目路径
                - recon_handoff: ReconAgent 的交接信息（可选）

        Returns:
            AgentResult 包含攻击面画像和风险链
        """
        project_path = payload.get("project_path")
        if not project_path:
            return AgentResult.failure_result("project_path is required")

        logger.info(f"Starting surface modeling for project: {project_path}")

        try:
            # 1. 提取 Recon 数据
            recon_data = self._extract_recon_data(payload)

            # 2. 构建 RuntimeSurface
            builder = RuntimeSurfaceBuilder(project_path)
            runtime_surface = await builder.build(recon_data=recon_data)
            surface_graph = RuntimeSurfaceGraph.from_surface(runtime_surface)
            declaration = VRTMDeclaration.discover(
                project_path, payload.get("vrtm_declaration"),
            )
            declaration_application = declaration.merge_into(surface_graph) if declaration else None
            surface_graph.metadata["base_fingerprint"] = surface_graph.content_fingerprint()
            observation_application = None
            graph_observations = payload.get("graph_observations")
            if isinstance(graph_observations, list) and graph_observations:
                observation_application = surface_graph.apply_observations(graph_observations)
            threat_model = RuntimeThreatModelAnalyzer(runtime_surface, surface_graph).analyze()
            surface_graph.metadata["threat_model_version"] = threat_model.version
            surface_graph.metadata["hypothesis_count"] = len(threat_model.hypotheses)
            graph_diff = None
            previous_graph_data = payload.get("previous_runtime_surface_graph")
            if isinstance(previous_graph_data, dict):
                try:
                    previous_graph = RuntimeSurfaceGraph.from_dict(previous_graph_data)
                    graph_diff = surface_graph.diff(previous_graph)
                except (TypeError, ValueError, KeyError) as exc:
                    logger.warning("Ignoring invalid previous runtime surface graph: %s", exc)
            graph_data = surface_graph.to_dict()
            graph_data["visualization"] = surface_graph.to_visualization(threat_model.to_dict())

            # 3. 识别高风险区域
            high_risk_areas = self._identify_high_risk_areas(runtime_surface)

            # 4. 使用 LLM 生成洞察（如果有 LLM 服务）
            insights = []
            if self.llm_service:
                insights = await self._generate_insights(runtime_surface, high_risk_areas)

            # 5. 创建 TaskHandoff
            handoff = self.create_handoff(
                to_agent="audit",
                summary=f"攻击面建模完成。发现 {len(runtime_surface.page_entries)} 个入口, {len(high_risk_areas)} 个高风险区域",
                work_completed=[
                    "构建 RuntimeSurface",
                    "识别页面入口",
                    "分析工具画像",
                    "推断信任边界",
                    "识别高风险区域",
                ],
                key_findings=[
                    {
                        "type": "surface_summary",
                        "total_entries": len(runtime_surface.page_entries),
                        "total_tools": len(runtime_surface.tool_profiles),
                        "total_mcp_capabilities": len(runtime_surface.mcp_capabilities),
                        "total_external_inputs": len(runtime_surface.external_content_inputs),
                        "total_browser_sinks": len(runtime_surface.browser_sinks),
                        "total_storage_assets": len(runtime_surface.storage_assets),
                        "total_workflow_nodes": len(runtime_surface.workflow_nodes),
                        "total_trust_boundaries": len(runtime_surface.trust_boundaries),
                        "high_risk_areas": len(high_risk_areas),
                        "risk_hypotheses": len(threat_model.hypotheses),
                        "graph_fingerprint": surface_graph.metadata.get("fingerprint"),
                        "graph_unknowns": surface_graph.metadata.get("coverage", {}).get("unknown_count", 0),
                    },
                    {
                        "type": "high_risk_tools",
                        "count": len([t for t in runtime_surface.tool_profiles if t.risk_level in ["high", "critical"]]),
                        "examples": [t.name for t in runtime_surface.tool_profiles if t.risk_level in ["high", "critical"]][:3],
                    },
                ],
                insights=insights,
                context_refs={
                    "runtime_surface": runtime_surface.to_json(),
                    "high_risk_areas": str(high_risk_areas),
                },
            )

            return AgentResult.success_result(
                data={
                    "runtime_surface": runtime_surface.to_dict(),
                    "runtime_surface_graph": graph_data,
                    "runtime_surface_object": runtime_surface,
                    "threat_model": threat_model.to_dict(),
                    "runtime_surface_graph_diff": graph_diff,
                    "graph_observation_application": observation_application,
                    "declaration_application": declaration_application,
                    "high_risk_areas": high_risk_areas,
                    "insights": insights,
                    "summary": runtime_surface.get_summary(),
                },
                handoff=handoff,
                tokens_used=0,
            )

        except Exception as e:
            logger.error(f"Surface modeling failed: {e}", exc_info=True)
            return AgentResult.failure_result(f"Surface modeling failed: {str(e)}")

    def _extract_recon_data(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """提取 Recon 数据"""
        # 从 recon_handoff 中提取数据
        recon_handoff = payload.get("recon_handoff")
        if recon_handoff:
            try:
                # 尝试解析 JSON
                import json
                if isinstance(recon_handoff, str):
                    # 查找 JSON 部分
                    if "{" in recon_handoff:
                        start = recon_handoff.find("{")
                        end = recon_handoff.rfind("}") + 1
                        if start >= 0 and end > start:
                            return json.loads(recon_handoff[start:end])
                elif isinstance(recon_handoff, dict):
                    return recon_handoff
            except Exception as e:
                logger.warning(f"Failed to parse recon_handoff: {e}")

        # 从 prior_handoffs 中提取
        prior_handoffs = payload.get("prior_handoffs", "")
        if prior_handoffs:
            # 简化处理，返回 None
            pass

        return None

    def _identify_high_risk_areas(self, surface: RuntimeSurface) -> List[Dict[str, Any]]:
        """识别高风险区域"""
        high_risk_areas = []

        # 1. 高风险工具
        high_risk_tools = [t for t in surface.tool_profiles if t.risk_level in ["high", "critical"]]
        for tool in high_risk_tools:
            high_risk_areas.append({
                "type": "high_risk_tool",
                "name": tool.name,
                "file_path": tool.file_path,
                "line_start": tool.line_start,
                "risk_level": tool.risk_level,
                "dangerous_operations": tool.dangerous_operations,
                "description": f"High-risk tool: {tool.name}",
            })

        # 2. Runtime evidence can establish an unauthenticated entry.  Lack of
        # a local static marker is an unknown boundary, not a high-risk fact.
        unprotected_entries = [
            entry for entry in surface.page_entries
            if not entry.authentication_required
            and entry.authentication_state in {"runtime_observed", "verified"}
        ]
        for entry in unprotected_entries[:5]:  # 最多5个
            high_risk_areas.append({
                "type": "unprotected_entry",
                "path": entry.path,
                "method": entry.method,
                "file_path": entry.file_path,
                "line_start": entry.line_start,
                "description": f"Unprotected endpoint: {entry.method} {entry.path}",
            })

        # 3. 缺少注入保护的 Prompt
        vulnerable_prompts = [p for p in surface.prompt_configs if not p.has_injection_protection]
        for prompt in vulnerable_prompts[:3]:  # 最多3个
            high_risk_areas.append({
                "type": "vulnerable_prompt",
                "name": prompt.name,
                "file_path": prompt.file_path,
                "line_start": prompt.line_start,
                "description": f"Prompt without injection protection: {prompt.name}",
            })

        # 4. 可绕过的信任边界
        bypassable_boundaries = [b for b in surface.trust_boundaries if not b.validation_mechanism]
        for boundary in bypassable_boundaries[:3]:  # 最多3个
            high_risk_areas.append({
                "type": "bypassable_boundary",
                "boundary_type": boundary.boundary_type,
                "source": boundary.source,
                "target": boundary.target,
                "file_path": boundary.file_path,
                "description": f"Bypassable trust boundary: {boundary.boundary_type}",
            })

        for capability in [
            item for item in surface.mcp_capabilities
            if item.authorization != "enforced" and (
                item.consequential_operations or item.dynamic_registration or "*" in item.permissions
            )
        ][:5]:
            high_risk_areas.append({
                "type": "mcp_authorization_gap",
                "name": capability.name,
                "capability_type": capability.capability_type,
                "file_path": capability.file_path,
                "line_start": capability.line_start,
                "operations": capability.consequential_operations,
                "description": f"MCP capability has unresolved authorization: {capability.name}",
            })

        for sink in [
            item for item in surface.browser_sinks
            if item.dangerous and not item.sanitization_detected
        ][:5]:
            high_risk_areas.append({
                "type": "unsafe_browser_sink",
                "sink_type": sink.sink_type,
                "file_path": sink.file_path,
                "line_start": sink.line_start,
                "input_refs": sink.input_refs,
                "description": f"Unsanitized browser sink: {sink.sink_type}",
            })

        for workflow in [
            item for item in surface.workflow_nodes
            if item.untrusted_inputs and item.capabilities
        ][:5]:
            high_risk_areas.append({
                "type": "workflow_privilege_path",
                "name": workflow.node_name,
                "file_path": workflow.file_path,
                "line_start": workflow.line_start,
                "capabilities": workflow.capabilities,
                "untrusted_inputs": workflow.untrusted_inputs,
                "description": f"Untrusted workflow input reaches capabilities: {workflow.node_name}",
            })

        for storage in [item for item in surface.storage_assets if item.sensitive][:5]:
            high_risk_areas.append({
                "type": "sensitive_storage_asset",
                "name": storage.name,
                "storage_type": storage.storage_type,
                "operation": storage.operation,
                "file_path": storage.file_path,
                "line_start": storage.line_start,
                "description": f"Sensitive storage access: {storage.storage_type}:{storage.name}",
            })

        logger.info(f"Identified {len(high_risk_areas)} high-risk areas")

        return high_risk_areas

    async def _generate_insights(
        self,
        surface: RuntimeSurface,
        high_risk_areas: List[Dict[str, Any]],
    ) -> List[str]:
        """使用 LLM 生成洞察"""
        if not self.llm_service:
            return []

        try:
            from core.llm_service import LLMMessage

            summary = surface.get_summary()

            prompt = f"""分析以下攻击面画像，提供安全审查的关键洞察：

攻击面摘要：
- 页面入口: {summary['total_entries']} 个
- 工具: {summary['total_tools']} 个
- 信任边界: {summary['total_trust_boundaries']} 个
- 高风险工具: {summary['high_risk_tools']} 个
- 未保护入口: {summary['unprotected_entries']} 个

高风险区域:
{chr(10).join(f'- {area["description"]}' for area in high_risk_areas[:5])}

请提供 3-5 条关键洞察，重点关注：
1. 最严重的攻击面
2. 需要优先审查的区域
3. 潜在的攻击路径
4. 建议的审查策略

用中文回答，每条洞察用一行。"""

            response = await self.llm_service.chat([
                LLMMessage(role="user", content=prompt),
            ])

            insights = [line.strip() for line in response.content.split('\n') if line.strip()]
            return insights

        except Exception:
            logger.warning("LLM surface insights unavailable; continuing without them")
            return []


async def build_risk_chains_for_findings(
    runtime_surface: RuntimeSurface,
    findings: List[Dict[str, Any]],
) -> List[RiskChain]:
    """
    为 findings 构建风险链

    Args:
        runtime_surface: RuntimeSurface 实例
        findings: 漏洞发现列表

    Returns:
        RiskChain 列表
    """
    builder = RiskChainBuilder(runtime_surface)
    return builder.build_risk_chains(findings)
