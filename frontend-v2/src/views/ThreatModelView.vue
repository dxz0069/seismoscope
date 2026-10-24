<template>
  <section class="view-page threat-page">
    <div class="page-wrap threat-wrap">
      <header class="page-head threat-head">
        <div>
          <span class="page-kicker">运行面证据建模</span>
          <h1>运行面威胁模型</h1>
          <p>以风险路径为中心聚合外部输入、智能上下文、自动化能力、信任边界与敏感资产；源码节点仅用于追溯证据。</p>
        </div>
        <div class="head-actions">
          <label class="project-picker">
            <span>项目</span>
            <select :value="platform.selectedProjectId" :disabled="platform.projectLoading" @change="selectProject">
              <option value="" disabled>选择已创建项目</option>
              <option v-for="project in platform.projects" :key="project.id" :value="project.id">{{ project.name }}</option>
            </select>
          </label>
          <button class="icon-button" type="button" title="刷新当前模型" :disabled="!platform.selectedProjectId || platform.vrtmLoading" @click="refresh">
            <RefreshCw :size="16" :class="{ spin: platform.vrtmLoading }" />
          </button>
          <button class="button" type="button" @click="ui.createReviewOpen = true"><Plus :size="16" />新建项目</button>
          <button class="button primary" type="button" :disabled="!platform.selectedProjectId || platform.vrtmLoading" @click="build">
            <LoaderCircle v-if="platform.vrtmLoading" :size="16" class="spin" />
            <Play v-else :size="16" />
            {{ model ? '重新建模' : '构建运行面' }}
          </button>
        </div>
      </header>

      <section v-if="!platform.projects.length" class="empty-state">
        <FolderPlus :size="28" />
        <div><strong>尚未添加本地项目</strong><p>创建项目后即可运行审计并构建 RuntimeSurfaceGraph。</p></div>
        <button class="button primary" type="button" @click="ui.createReviewOpen = true"><Plus :size="16" />新建项目</button>
      </section>

      <section v-else-if="!model && !platform.vrtmLoading" class="empty-state">
        <Network :size="28" />
        <div><strong>当前项目没有已保存的运行面模型</strong><p>构建会分析本地源码，生成版本化图、威胁假设和质量报告。</p></div>
        <button class="button primary" type="button" @click="build"><Play :size="16" />构建运行面</button>
      </section>

      <template v-else-if="model">
        <section class="model-summary" aria-label="建模摘要">
          <div><Fingerprint :size="20" /><span><small>模型版本</small><strong>{{ model.model_id }}</strong><em>{{ statusLabel(model.status) }}</em></span></div>
          <div><Layers3 :size="20" /><span><small>运行面概览</small><strong>{{ overviewNodeCount }} 个运行面角色</strong><em>{{ sourceNodeCount }} 个源码实体保留追溯</em></span></div>
          <div><Waypoints :size="20" /><span><small>风险研判</small><strong>{{ actionableRiskPaths.length }} 条待验证路径</strong><em>{{ riskGroups.length }} 类风险 · {{ resolvedRiskPathCount }} 条已排除</em></span></div>
          <div><ScanLine :size="20" /><span><small>建模质量</small><strong>{{ statusLabel(model.quality?.status || model.status) }}</strong><em>{{ generatedAt }}</em></span></div>
        </section>

        <section class="model-workbench">
          <aside class="risk-index">
            <header><span><ShieldAlert :size="16" /><strong>{{ actionableRiskPaths.length ? '待验证风险' : '建模判断' }}</strong></span><b>{{ actionableRiskPaths.length }}</b></header>
            <button
              v-for="group in riskGroups"
              :key="group.id"
              type="button"
              :class="{ active: group.paths.some(path => path.id === selectedPathId) }"
              @click="selectedPathId = group.primary.id"
            >
              <i :class="severityTone(group.severity)"></i>
              <span><code>{{ techniqueLabel(group.techniqueId) }}</code><strong>{{ riskGroupTitle(group) }}</strong><small>{{ group.paths.length > 1 ? `${group.paths.length} 个入口已归并` : `${group.primary.path_node_ids?.length || 0} 个角色` }} · {{ statusLabel(group.status) }} · 置信度 {{ confidence(group.confidence) }}</small></span>
              <b>{{ group.paths.length > 1 ? `${group.paths.length}处` : confidence(group.confidence) }}</b>
            </button>
            <button v-if="resolvedRiskGroups.length" class="resolved-toggle" type="button" @click="showResolvedPaths = !showResolvedPaths">
              <CircleCheck :size="15" />{{ showResolvedPaths ? '收起已排除路径' : `查看 ${resolvedRiskPathCount} 条已排除路径` }}
            </button>
            <button
              v-for="group in showResolvedPaths ? resolvedRiskGroups : []"
              :key="group.id"
              type="button"
              class="resolved-path"
              :class="{ active: group.paths.some(path => path.id === selectedPathId) }"
              @click="selectedPathId = group.primary.id"
            >
              <i class="low"></i>
              <span><code>{{ techniqueLabel(group.techniqueId) }}</code><strong>{{ riskGroupTitle(group) }}</strong><small>{{ group.paths.length > 1 ? `${group.paths.length} 条同类路径` : '单条路径' }} · {{ statusLabel(group.status) }}</small></span>
              <b>已排除</b>
            </button>
            <div v-if="!actionableRiskPaths.length" class="risk-brief">
              <section class="risk-brief__state">
                <CircleAlert :size="22" />
                <div><small>当前结论</small><strong>尚未形成可证伪风险路径</strong><p>模型观察到了运行面关系，但当前证据不足以把它们确认成漏洞。</p></div>
              </section>
              <div class="risk-brief__stats">
                <div><b>{{ overviewMemberCount('external_input') }}</b><span>外部输入实体</span></div>
                <div><b>{{ overviewMemberCount('sensitive_asset') }}</b><span>敏感资产与输出</span></div>
                <div><b>{{ overview.collapsed_implementation_node_count || 0 }}</b><span>已聚合实现节点</span></div>
              </div>
              <section class="risk-brief__relations">
                <header><Route :size="15" /><strong>观察到的运行面关系</strong></header>
                <article v-for="edge in overview.edges" :key="edge.id">
                  <div class="relation-flow"><strong>{{ roleLabel(edge.source) }}</strong><ChevronRight :size="14" /><strong>{{ roleLabel(edge.target) }}</strong></div>
                  <p>{{ relationExplanation(edge) }}</p>
                  <small>证据：{{ evidenceLabel(edge.evidence?.level) }} · 关联 {{ edge.attributes?.represented_edge_count || 0 }} 条代码关系</small>
                </article>
                <p v-if="!overview.edges?.length" class="risk-index__empty">当前没有形成可解释的实体关系。</p>
              </section>
              <section class="risk-brief__boundary"><ShieldCheck :size="15" /><p>静态建模只能说明“代码中存在这条可能路径”。是否可利用、是否有鉴权拦截，需要进入验证阶段确认。</p></section>
            </div>
          </aside>

          <main class="graph-panel">
            <header>
              <span><Network :size="16" /><strong>运行面风险图</strong><small>{{ visualization.fingerprint }}</small></span>
              <span class="graph-status"><CircleCheck v-if="model.status === 'complete'" :size="14" /><CircleAlert v-else :size="14" />{{ statusLabel(model.status) }}</span>
            </header>
            <RuntimeSurfaceGraph :visualization="visualization" :selected-path-id="selectedPathId" @select-node="selectedNode = $event" />
          </main>

          <aside class="node-inspector">
            <header><span><Crosshair :size="16" /><strong>实体详情</strong></span><span v-if="selectedNode" class="evidence-chip" :class="selectedNode.evidence?.level">{{ evidenceLabel(selectedNode.evidence?.level) }}</span></header>
            <div v-if="selectedNode" class="node-detail">
              <h2>{{ selectedNode.label }}</h2>
              <p class="node-meaning">{{ nodeMeaning(selectedNode) }}</p>
              <dl>
                <div><dt>系统角色</dt><dd>{{ roleLabel(selectedNode.type) }}</dd></div>
                <div><dt>证据状态</dt><dd>{{ evidenceLabel(selectedNode.evidence?.level) }}</dd></div>
                <div><dt>聚合范围</dt><dd>{{ selectedNode.attributes?.represented_node_count || 1 }} 个源码实体</dd></div>
                <div><dt>信任域</dt><dd>{{ trustLabel(selectedNode.security?.trust_zone) }}</dd></div>
                <div><dt>权限级别</dt><dd>{{ privilegeLabel(selectedNode.security?.privilege_level) }}</dd></div>
                <div><dt>风险等级</dt><dd>{{ riskLevelLabel(selectedNode.security?.risk_level) }}</dd></div>
                <div><dt>源码追溯</dt><dd>{{ nodeLocation(selectedNode) }}</dd></div>
              </dl>
              <section v-if="selectedNode.security?.threat_categories?.length">
                <small>关联风险类型</small>
                <span class="token-row"><em v-for="item in selectedNode.security.threat_categories" :key="item">{{ threatLabel(item) }}</em></span>
              </section>
              <section v-if="selectedNode.risk_hypothesis_ids?.length">
                <small>关联风险假设</small>
                <span class="token-row"><em v-for="item in nodeRiskLabels(selectedNode)" :key="item">{{ item }}</em></span>
              </section>
            </div>
            <div v-else class="node-placeholder">
              <MousePointerClick :size="22" />
              <strong>从威胁来源开始读图</strong>
              <p>先看红色边框的角色，再沿箭头看它可能影响的入口、工具或敏感资产。每张卡片是同类实体的聚合，不是单个函数。</p>
              <div class="node-placeholder__facts"><span>红色边框：仍待验证的风险路径</span><span>箭头：源码中观察到的关系</span><span>证据：{{ overviewEvidenceLabel }} · 待验证 {{ unresolvedCount }} 项</span></div>
            </div>
          </aside>
        </section>

        <section v-if="activePath" class="path-dossier">
          <header>
            <span><Route :size="16" /><strong>{{ activeRiskGroup ? riskGroupTitle(activeRiskGroup) : pathDisplayTitle(activePath) }}</strong><code>{{ techniqueLabel(activePath.technique_id) }}</code></span>
            <span class="severity-chip" :class="severityTone(activePath.severity)">{{ statusLabel(activePath.status) }} · {{ severityLabel(activePath.severity) }}</span>
          </header>
          <div class="path-story">
            <div><small>威胁来源</small><strong>{{ pathSourceText(activePath) }}</strong></div>
            <ChevronRight :size="16" />
            <div><small>可能触达</small><strong>{{ pathTargetText(activePath) }}</strong></div>
            <p>{{ pathNarrative(activePath) }}</p>
          </div>
          <div class="path-nodes">
            <template v-for="(nodeId, index) in activePath.path_node_ids" :key="nodeId">
              <button type="button" @click="selectPathNode(nodeId)"><small>{{ String(index + 1).padStart(2, '0') }}</small><strong>{{ nodeLabel(nodeId) }}</strong></button>
              <ChevronRight v-if="index < activePath.path_node_ids.length - 1" :size="15" />
            </template>
          </div>
            <div class="path-evidence">
              <span><ListChecks :size="15" /><strong>待验证证据</strong></span>
              <p v-for="predicate in activePath.evidence_predicates || []" :key="predicate.id || predicate">{{ evidencePredicateText(predicate) }}</p>
              <p v-if="!(activePath.evidence_predicates || []).length">该风险路径尚未声明可执行证据谓词。</p>
            </div>
            <div v-if="activeRiskGroup?.paths.length > 1" class="path-variants">
              <small>同类入口（{{ activeRiskGroup.paths.length }}）</small>
              <button v-for="path in activeRiskGroup.paths" :key="path.id" type="button" :class="{ active: path.id === activePath.id }" @click="selectedPathId = path.id">{{ pathTargetText(path) }}</button>
            </div>
        </section>

        <section v-if="diagnostics.length" class="diagnostics" aria-label="建模诊断">
          <header><CircleAlert :size="16" /><strong>建模诊断</strong></header>
          <span v-for="item in diagnostics" :key="`${item.code}-${item.count || ''}`" :class="item.level">{{ item.code }}<b v-if="item.count">{{ item.count }}</b></span>
        </section>
      </template>
    </div>
    <NewReviewModal />
  </section>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { ChevronRight, CircleAlert, CircleCheck, Crosshair, Fingerprint, FolderPlus, Layers3, ListChecks, LoaderCircle, MousePointerClick, Network, Play, Plus, RefreshCw, Route, ScanLine, ShieldAlert, Waypoints } from 'lucide-vue-next'
import NewReviewModal from '../components/NewReviewModal.vue'
import RuntimeSurfaceGraph from '../components/RuntimeSurfaceGraph.vue'
import { usePlatformStore } from '../stores/platform'
import { useUiStore } from '../stores/ui'

const platform = usePlatformStore()
const ui = useUiStore()
const selectedPathId = ref('')
const selectedNode = ref(null)
const showResolvedPaths = ref(false)
const model = computed(() => platform.runtimeModel)
const visualization = computed(() => model.value?.graph?.visualization || { nodes: [], edges: [], risk_paths: [], views: {}, fingerprint: '' })
const severityRank = { critical: 4, high: 3, medium: 2, low: 1 }
const riskPaths = computed(() => [...(visualization.value.risk_paths || [])].sort((left, right) => {
  const severity = (severityRank[String(right.severity || '').toLowerCase()] || 0) - (severityRank[String(left.severity || '').toLowerCase()] || 0)
  if (severity) return severity
  const confidence = Number(right.confidence || 0) - Number(left.confidence || 0)
  if (confidence) return confidence
  return String(left.title || left.id).localeCompare(String(right.title || right.id))
}))
const isActionablePath = path => !['refuted', 'mitigated', 'resolved'].includes(String(path?.status || '').toLowerCase())
const actionableRiskPaths = computed(() => riskPaths.value.filter(isActionablePath))
const resolvedRiskPaths = computed(() => riskPaths.value.filter(path => !isActionablePath(path)))
const buildRiskGroups = (paths, state) => {
  const groups = new Map()
  for (const path of paths) {
    const techniqueId = String(path.technique_id || path.id || 'unknown')
    const key = `${state}:${techniqueId}:${state === 'resolved' ? path.status : 'active'}`
    const group = groups.get(key) || {
      id: key,
      techniqueId,
      paths: [],
      severity: path.severity,
      confidence: Number(path.confidence || 0),
      status: path.status,
      primary: path
    }
    group.paths.push(path)
    if ((severityRank[String(path.severity || '').toLowerCase()] || 0) > (severityRank[String(group.severity || '').toLowerCase()] || 0)
      || (String(path.severity || '').toLowerCase() === String(group.severity || '').toLowerCase() && Number(path.confidence || 0) > group.confidence)) {
      group.severity = path.severity
      group.confidence = Number(path.confidence || 0)
      group.primary = path
    }
    groups.set(key, group)
  }
  return [...groups.values()].sort((left, right) => {
    const severity = (severityRank[String(right.severity || '').toLowerCase()] || 0) - (severityRank[String(left.severity || '').toLowerCase()] || 0)
    return severity || right.confidence - left.confidence || left.techniqueId.localeCompare(right.techniqueId)
  })
}
const riskGroups = computed(() => buildRiskGroups(actionableRiskPaths.value, 'active'))
const resolvedRiskGroups = computed(() => buildRiskGroups(resolvedRiskPaths.value, 'resolved'))
const resolvedRiskPathCount = computed(() => resolvedRiskPaths.value.length)
const activePath = computed(() => riskPaths.value.find(item => item.id === selectedPathId.value) || null)
const activeRiskGroup = computed(() => [...riskGroups.value, ...resolvedRiskGroups.value]
  .find(group => group.paths.some(path => path.id === selectedPathId.value)) || null)
const nodeIndex = computed(() => new Map(visualization.value.nodes.map(node => [node.id, node])))
const overview = computed(() => visualization.value.projections?.risk_overview || { nodes: [], edges: [], collapsed_implementation_node_count: 0 })
const overviewNodeCount = computed(() => visualization.value.projections?.risk_overview?.nodes?.length || visualization.value.nodes.length)
const sourceNodeCount = computed(() => visualization.value.nodes.length)
const diagnostics = computed(() => model.value?.quality?.diagnostics || [])
const verifiedEvidenceCount = computed(() => visualization.value.nodes.filter(node => node.evidence?.level === 'verified').length)
const unresolvedCount = computed(() => Number(model.value?.quality?.coverage?.unknown_count || model.value?.quality?.coverage?.unknown || 0))
const overviewEvidenceLabel = computed(() => {
  const levels = overview.value.nodes.flatMap(node => node.evidence?.member_evidence_levels || [])
  return levels.includes('runtime_observed') || levels.includes('verified') ? '包含运行时证据' : '以静态代码观察为主'
})
const generatedAt = computed(() => model.value?.generated_at ? new Date(model.value.generated_at).toLocaleString('zh-CN') : '暂无时间')

watch(riskPaths, paths => {
  if (!paths.some(item => item.id === selectedPathId.value)) selectedPathId.value = paths.find(isActionablePath)?.id || paths[0]?.id || ''
}, { immediate: true })

watch(visualization, graph => {
  if (!selectedNode.value || !graph.nodes.some(node => node.id === selectedNode.value.id)) selectedNode.value = null
})

const selectProject = async event => {
  selectedNode.value = null
  selectedPathId.value = ''
  await platform.selectProject(event.target.value)
}

const refresh = async () => {
  try {
    await platform.loadRuntimeModel()
    platform.notify(platform.runtimeModel ? '已加载最新运行面模型。' : '当前项目没有已保存模型。', 'info', 'VRTM')
  } catch (error) {
    platform.notify(error.userMessage || '刷新模型失败。', 'error', 'VRTM')
  }
}

const build = async () => {
  try {
    selectedNode.value = null
    await platform.buildRuntimeModel()
  } catch (error) {
    platform.notify(error.userMessage || error.message || '构建运行面失败。', 'error', 'VRTM')
  }
}

const confidence = value => `${Math.round(Number(value || 0) * (Number(value || 0) <= 1 ? 100 : 1))}%`
const severityTone = value => ['critical', 'high', 'medium', 'low'].includes(String(value || '').toLowerCase()) ? String(value).toLowerCase() : 'unknown'
const severityLabel = value => ({ critical: '严重', high: '高', medium: '中', low: '低' }[String(value || '').toLowerCase()] || '未分级')
const statusLabel = value => ({ complete: '完整', degraded: '需补充证据', invalid: '模型无效', open: '待验证', supported: '有证据支持', refuted: '已有反证', mitigated: '已缓解', resolved: '已缓解', pending: '等待中', running: '运行中', failed: '失败' }[String(value || '').toLowerCase()] || '未知')
const evidenceLabel = value => ({ verified: '已验证', runtime_observed: '受控运行观察', static_observed: '静态代码观察', declared: '项目声明', inferred: '语义推断', unknown: '待补充证据' }[String(value || '').toLowerCase()] || '待补充证据')
const trustLabel = value => ({ untrusted: '不可信输入域', persistent_data: '持久化数据域', application: '应用域', internal: '内部可信域', mixed: '多信任域混合' }[String(value || '').toLowerCase()] || '未知信任域')
const privilegeLabel = value => ({ none: '无特权', application: '应用权限', user: '用户权限', elevated: '提升权限', high: '高权限', mixed: '多权限级别混合' }[String(value || '').toLowerCase()] || '未知权限')
const riskLevelLabel = value => severityLabel(value)
const roleLabels = {
  external_input: '外部与不可信输入', application_entry: '应用入口', ai_context: '智能上下文',
  agent_workflow: '自动化代理与工作流', capability: '工具、MCP 与执行能力',
  control_boundary: '信任边界、授权与审批', sensitive_asset: '敏感资产与输出',
  entry_point: '应用入口', workflow: '工作流', prompt: '提示词', model: '模型', memory: '记忆',
  retriever: '检索器', tool: '工具', mcp_capability: 'MCP 能力', code_execution: '代码执行',
  trust_boundary: '信任边界', permission: '权限控制', security_control: '安全控制',
  approval_control: '审批控制', policy_gateway: '策略网关', browser_sink: '浏览器输出',
  storage_asset: '存储资产', privileged_asset: '特权资产', secret_asset: '密钥资产',
  source_artifact: '源码工件', deployment_asset: '部署资产',
  external_actor: '外部访问者', external_content: '外部内容'
}
const roleLabel = value => {
  const key = String(value || '').split(':').pop()
  return roleLabels[key] || key || '未知实体'
}
const techniqueLabel = value => ({
  'T-INDIRECT-PROMPT-INJECTION': '间接提示词注入',
  'T-TOOL-DESCRIPTION-INJECTION': '工具描述注入',
  'T-EXCESSIVE-AGENCY': '自动化代理权限过度委托',
  'T-UNPROTECTED-ENTRY': '外部入口保护不足',
  'T-WORKFLOW-PRIVILEGE': '工作流权限扩张',
  'T-DEPLOYMENT-TAMPERING': '部署工件被篡改'
}[String(value || '')] || String(value || '风险假设'))
const pathDisplayTitle = path => {
  const title = String(path?.title || '')
  if (title && !/[A-Za-z]{3,}/.test(title)) return title
  const technique = techniqueLabel(path?.technique_id)
  const target = path?.target_node_ids?.[0] ? nodeLabel(path.target_node_ids[0]) : ''
  return target ? `${technique}：${target}` : technique
}
const riskGroupTitle = group => {
  const technique = techniqueLabel(group?.techniqueId)
  if (!group || group.paths.length <= 1) return pathDisplayTitle(group?.primary)
  return `${technique}：${group.paths.length} 个同类入口待统一验证`
}
const pathTargetText = path => {
  const targetId = path?.target_node_ids?.[0] || path?.path_node_ids?.at(-1)
  return targetId ? nodeLabel(targetId) : pathDisplayTitle(path)
}
const pathSourceText = path => {
  const labels = [...new Set((path?.source_node_ids || path?.path_node_ids?.slice(0, 1) || [])
    .map(id => roleLabel(nodeIndex.value.get(id)?.type || nodeLabel(id)))
    .filter(Boolean))]
  return labels.join('、') || '待确认的外部来源'
}
const pathNarrative = path => {
  const technique = String(path?.technique_id || '')
  if (technique === 'T-UNPROTECTED-ENTRY') return '外部访问者可以到达该入口；当前仅从代码关系推断，需要在受控环境确认认证和操作授权是否真正拦截。'
  if (technique === 'T-EXCESSIVE-AGENCY') return '自动化能力可能触达高权限操作；需要确认工具白名单、参数限制和执行前审批是否在服务端强制执行。'
  if (technique.includes('PROMPT') || technique.includes('INJECTION')) return '不可信内容可能影响智能上下文；需要确认内容隔离、提示词边界和工具调用约束。'
  return '该路径由源码关系推导而来，尚需补充运行时证据，不能直接视为已确认漏洞。'
}
const evidencePredicateText = predicate => {
  if (typeof predicate === 'string') return predicate
  const item = predicate || {}
  const text = {
    'tool-capability': '核对工具实现，列出实际可执行的高权限操作和参数边界。',
    'approval-boundary': '确认高影响操作在执行时是否强制经过策略或人工审批。',
    'entry-auth': '检查该入口的认证与操作级授权中间件是否在实际路由上生效。',
    'auth-probe': '在受控靶场使用未认证请求验证响应和实际访问边界。'
  }[String(item.id || '')]
  if (text) return text
  const tool = {
    read_source: '源码审阅', inspect_surface: '运行面检查', controlled_request: '受控请求验证'
  }[String(item.verification_tool || '')] || '人工复核'
  const evidence = {
    code: '静态代码', runtime_behavior: '受控运行行为', configuration: '配置'
  }[String(item.evidence_type || '')] || '补充'
  return `通过${tool}补充${evidence}证据。`
}
const threatLabel = value => ({ injection: '注入', prompt_injection: '提示词注入', ssrf: '服务端请求伪造', unauthorized_access: '未授权访问', data_tampering: '数据篡改', sensitive_data_exposure: '敏感数据暴露', excessive_agency: '权限过度委托' }[String(value || '').toLowerCase()] || value)
const nodeRiskLabels = node => {
  const counts = new Map()
  for (const id of node?.risk_hypothesis_ids || []) {
    const path = riskPaths.value.find(item => item.id === id)
    const label = path ? techniqueLabel(path.technique_id) : '待确认风险假设'
    counts.set(label, (counts.get(label) || 0) + 1)
  }
  return [...counts.entries()].map(([label, count]) => count > 1 ? `${label}（${count} 条）` : label)
}
const overviewMemberCount = role => overview.value.nodes.find(node => node.type === role)?.attributes?.represented_node_count || 0
const nodeMeaning = node => ({
  external_input: '攻击者、用户输入或外部内容可能从这里进入应用运行面。',
  application_entry: '应用对外暴露的路由、任务或工作流入口。',
  ai_context: '影响模型指令、上下文、记忆或检索结果的内容。',
  agent_workflow: '自动化决策、任务编排和权限委托所在的执行链。',
  capability: '模型或工作流可以调用的工具、MCP、代码执行或部署能力。',
  control_boundary: '应该限制输入、权限、工具调用或跨域访问的控制点。',
  sensitive_asset: '数据库、文件、密钥、特权操作或浏览器输出等保护对象。'
}[node?.type] || '该实体是运行面中的一个可追溯角色。')
const relationText = value => String(value || '').split(',').map(item => ({ reads: '读取', writes: '写入', accesses: '访问', invokes: '调用', can_invoke: '可调用', supplies_data: '提供数据', influences_instruction: '影响指令', influences: '影响', delegates_authority: '委托权限', crosses_boundary: '跨越边界', persists_to: '持久化', loads_from: '加载', authenticates_as: '身份认证', renders: '渲染输出', semantic_flow: '运行面关联', flows: '数据流' }[item.trim()] || item.trim())).filter(Boolean).join(' / ') || '运行面关联'
const relationExplanation = edge => {
  const source = String(edge?.source || '').split(':').pop()
  const target = String(edge?.target || '').split(':').pop()
  if (source === 'external_input' && target === 'ai_context') return '外部内容可能进入提示词、模型上下文或检索结果，需要验证隔离和注入防护。'
  if (source === 'ai_context' && target === 'capability') return '模型上下文可能影响工具选择或执行参数，需要验证最小权限和审批。'
  if (source === 'capability' && target === 'sensitive_asset') return '可调用能力可能触达敏感资产，需要验证服务端授权和调用边界。'
  if (target === 'control_boundary') return '该路径经过控制点，需要确认控制是在实际执行点强制生效，而不是仅存在配置。'
  return `模型观察到“${roleLabel(source)}”经实现路径关联到“${roleLabel(target)}”，关系为${relationText(edge.relation)}。`
}
const nodeLabel = id => nodeIndex.value.get(id)?.label || id
const nodeLocation = node => {
  const provenance = node.attributes?.provenance || {}
  if (provenance.file_path) return `${provenance.file_path}:${provenance.line_start || '?'}`
  if (node.attributes?.represented_node_count) return '已聚合源码实体；请切换源码追溯查看成员'
  return '暂无源码位置'
}
const selectPathNode = nodeId => { selectedNode.value = nodeIndex.value.get(nodeId) || null }
</script>

<style scoped>
.threat-wrap { width: min(1640px, 100%); max-width: none; }
.threat-head { margin-bottom: 18px; }
.head-actions { justify-content: flex-end; }
.project-picker { display: grid; gap: 3px; min-width: 220px; color: var(--ink-muted); font-family: var(--font-mono); font-size: 10px; }
.project-picker select { min-height: 42px; max-width: 280px; padding: 0 10px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--surface); color: var(--ink); font-family: var(--font-ui); font-size: 13px; }
.empty-state { display: flex; min-height: 220px; align-items: center; justify-content: center; gap: 16px; padding: 24px; border: 1px dashed var(--line-strong); background: var(--canvas-soft); color: var(--focus); text-align: left; }
.empty-state > div { max-width: 440px; display: grid; gap: 5px; }
.empty-state strong { color: var(--ink); font-size: 16px; }
.empty-state p { margin: 0; color: var(--ink-muted); font-size: 13px; line-height: 1.6; }
.model-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 16px; border: 1px solid var(--line); background: var(--canvas-soft); }
.model-summary > div { display: flex; min-height: 96px; align-items: center; gap: 10px; padding: 14px; border-right: 1px solid var(--line); }
.model-summary > div:last-child { border-right: 0; }
.model-summary svg { color: var(--focus); }
.model-summary span { display: grid; gap: 3px; min-width: 0; }
.model-summary small, .model-summary em { overflow: hidden; color: var(--ink-muted); font-family: var(--font-mono); font-size: 10px; font-style: normal; text-overflow: ellipsis; white-space: nowrap; }
.model-summary strong { overflow: hidden; color: var(--ink); font-size: 15px; text-overflow: ellipsis; white-space: nowrap; }
.model-workbench { display: grid; height: clamp(660px, calc(100vh - 230px), 790px); min-height: 0; grid-template-columns: 330px minmax(0, 1fr) 320px; border: 1px solid var(--line); background: var(--canvas-soft); }
.risk-index, .node-inspector { min-width: 0; background: var(--canvas-soft); }
.risk-index { overflow-y: auto; border-right: 1px solid var(--line); }
.node-inspector { overflow-y: auto; border-left: 1px solid var(--line); }
.risk-index > header, .node-inspector > header, .graph-panel > header, .path-dossier > header, .diagnostics > header { display: flex; min-height: 50px; align-items: center; justify-content: space-between; gap: 8px; padding: 0 13px; border-bottom: 1px solid var(--line); }
.risk-index > header span, .node-inspector > header span, .graph-panel > header span, .path-dossier > header span, .diagnostics > header { display: flex; align-items: center; gap: 7px; }
.risk-index header svg, .node-inspector header svg, .graph-panel header svg, .path-dossier header svg, .diagnostics header svg { color: var(--focus); }
.risk-index header strong, .node-inspector header strong, .graph-panel header strong, .path-dossier header strong, .diagnostics header strong { font-size: 13px; }
.risk-index header b { color: var(--focus); font-family: var(--font-mono); font-size: 12px; }
.risk-index > button { display: grid; width: 100%; min-height: 90px; grid-template-columns: 5px minmax(0, 1fr) 38px; align-items: center; gap: 9px; padding: 10px 12px; border: 0; border-bottom: 1px solid var(--line); background: transparent; color: var(--ink-secondary); cursor: pointer; text-align: left; }
.risk-index > button:hover, .risk-index > button.active { background: var(--surface); }
.risk-index > button.active { box-shadow: inset 2px 0 var(--focus); }
.risk-index > button > i { width: 5px; height: 34px; background: var(--line-strong); }
.risk-index > button > i.critical, .severity-chip.critical { background: var(--critical); }
.risk-index > button > i.high, .severity-chip.high { background: #f79009; }
.risk-index > button > i.medium, .severity-chip.medium { background: var(--warning); }
.risk-index > button > i.low, .severity-chip.low { background: var(--verified); }
.risk-index > button > span { display: grid; gap: 4px; min-width: 0; }
.risk-index code { overflow: hidden; color: var(--focus); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.risk-index strong { display: -webkit-box; overflow: hidden; color: var(--ink); font-size: 12px; line-height: 1.4; -webkit-line-clamp: 2; -webkit-box-orient: vertical; }
.risk-index small { color: var(--ink-muted); font-size: 10px; }
.risk-index > button > b { color: var(--ink); font-family: var(--font-mono); font-size: 11px; text-align: right; }
.resolved-toggle { display: inline-flex !important; width: 100%; min-height: 42px !important; align-items: center; justify-content: center; gap: 7px; padding: 8px 12px !important; border: 0 !important; border-bottom: 1px solid var(--line) !important; background: var(--canvas-soft) !important; color: var(--verified) !important; font-size: 12px; }
.resolved-toggle:hover { background: var(--verified-soft) !important; }
.resolved-path { min-height: 72px !important; opacity: .8; }
.resolved-path > i.low { background: var(--verified); }
.resolved-path > b { color: var(--verified); }
.risk-index__empty { padding: 16px; color: var(--ink-muted); font-size: 13px; line-height: 1.5; }
.risk-brief { display: grid; gap: 14px; padding: 14px; }
.risk-brief__state { display: grid; grid-template-columns: 24px minmax(0, 1fr); gap: 10px; padding: 12px; border: 1px solid color-mix(in srgb, var(--warning) 45%, var(--line)); background: color-mix(in srgb, var(--warning-soft) 70%, transparent); }
.risk-brief__state > svg { color: var(--warning); margin-top: 2px; }
.risk-brief__state div { display: grid; gap: 5px; }
.risk-brief__state small, .risk-brief__relations small { color: var(--ink-muted); font-family: var(--font-mono); font-size: 10px; }
.risk-brief__state strong { color: var(--ink); font-size: 13px; line-height: 1.4; }
.risk-brief__state p, .risk-brief__boundary p { margin: 0; color: var(--ink-secondary); font-size: 12px; line-height: 1.55; }
.risk-brief__stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; }
.risk-brief__stats div { display: grid; gap: 3px; min-height: 62px; align-content: center; padding: 8px; border: 1px solid var(--line); background: var(--surface); }
.risk-brief__stats b { color: var(--focus); font-family: var(--font-mono); font-size: 18px; }
.risk-brief__stats span { color: var(--ink-muted); font-size: 10px; line-height: 1.35; }
.risk-brief__relations { display: grid; gap: 9px; }
.risk-brief__relations > header { display: flex; align-items: center; gap: 6px; color: var(--ink); font-size: 12px; }
.risk-brief__relations > header svg { color: var(--focus); }
.risk-brief__relations article { display: grid; gap: 7px; padding: 10px; border-left: 2px solid var(--focus); background: var(--surface); }
.relation-flow { display: flex; align-items: center; gap: 4px; color: var(--ink); font-size: 11px; line-height: 1.35; }
.relation-flow svg { flex: 0 0 auto; color: var(--focus); }
.risk-brief__relations article p { margin: 0; color: var(--ink-secondary); font-size: 11px; line-height: 1.55; }
.risk-brief__boundary { display: flex; align-items: flex-start; gap: 7px; padding-top: 11px; border-top: 1px solid var(--line); }
.risk-brief__boundary > svg { flex: 0 0 auto; color: var(--focus); }
.graph-panel { position: relative; min-width: 0; min-height: 0; display: grid; grid-template-rows: 50px minmax(0, 1fr); background: var(--graph-bg); }
.graph-panel > header { color: var(--ink-secondary); background: var(--canvas-soft); }
.graph-panel > header small { max-width: 260px; overflow: hidden; color: var(--ink-muted); font-family: var(--font-mono); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.graph-status { color: var(--verified); font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; }
.node-inspector > header { align-items: center; }
.evidence-chip, .severity-chip { padding: 3px 7px; border-radius: 999px; background: var(--line); color: var(--ink-secondary); font-family: var(--font-mono); font-size: 10px; }
.evidence-chip.verified { background: var(--verified-soft); color: var(--verified); }
.evidence-chip.runtime_observed { background: var(--focus-soft); color: var(--focus); }
.node-detail { display: grid; gap: 13px; padding: 14px; }
.node-detail h2 { margin: 0; color: var(--ink); font-size: 17px; line-height: 1.35; word-break: break-word; }
.node-meaning { margin: -6px 0 0; color: var(--ink-secondary); font-size: 12px; line-height: 1.55; }
.node-detail dl { display: grid; margin: 0; border: 1px solid var(--line); }
.node-detail dl div { display: grid; gap: 3px; min-height: 52px; align-content: center; padding: 7px 9px; border-bottom: 1px solid var(--line); }
.node-detail dl div:last-child { border-bottom: 0; }
.node-detail dt, .node-detail section > small { color: var(--ink-muted); font-family: var(--font-mono); font-size: 10px; }
.node-detail dd { margin: 0; color: var(--ink-secondary); font-size: 12px; line-height: 1.45; word-break: break-word; }
.node-detail section { display: grid; gap: 7px; }
.token-row { display: flex; gap: 5px; flex-wrap: wrap; }
.token-row em { padding: 3px 6px; border: 1px solid var(--line); border-radius: 999px; color: var(--ink-secondary); font-size: 10px; font-style: normal; }
.node-placeholder { display: grid; place-items: center; gap: 10px; min-height: 280px; padding: 28px 22px; color: var(--ink-muted); text-align: center; font-size: 13px; line-height: 1.6; }
.node-placeholder svg { color: var(--focus); }
.node-placeholder strong { color: var(--ink); font-size: 14px; }
.node-placeholder p { max-width: 235px; margin: 0; color: var(--ink-secondary); font-size: 12px; line-height: 1.6; }
.node-placeholder__facts { display: grid; gap: 5px; width: 100%; padding-top: 9px; border-top: 1px solid var(--line); color: var(--ink-muted); font-size: 10px; }
.path-dossier { margin-top: 16px; border: 1px solid var(--line); background: var(--canvas-soft); }
.path-dossier > header code { color: var(--focus); font-size: 11px; }
.severity-chip { text-transform: uppercase; }
.severity-chip.critical { color: #fff; }
.severity-chip.high { background: #f79009; color: #211605; }
.severity-chip.medium { color: #211605; }
.severity-chip.low { color: #062815; }
.path-nodes { display: flex; min-height: 110px; align-items: center; gap: 8px; padding: 16px; overflow-x: auto; }
.path-nodes button { display: grid; flex: 0 0 155px; min-height: 72px; gap: 4px; padding: 10px; border: 1px solid var(--line-strong); background: var(--surface); color: var(--ink); cursor: pointer; text-align: left; }
.path-nodes button:hover { border-color: var(--focus); background: var(--focus-soft); }
.path-nodes button small { color: var(--focus); font-family: var(--font-mono); font-size: 10px; }
.path-nodes button strong { overflow: hidden; font-size: 12px; line-height: 1.35; text-overflow: ellipsis; white-space: nowrap; }
.path-nodes > svg { flex: 0 0 auto; color: var(--ink-muted); }
.path-story { display: grid; grid-template-columns: minmax(0, 1fr) 18px minmax(0, 1fr); align-items: center; gap: 9px; padding: 14px 16px 12px; border-bottom: 1px solid var(--line); background: var(--canvas-soft); }
.path-story > div { display: grid; gap: 4px; min-width: 0; }
.path-story small { color: var(--ink-muted); font-family: var(--font-mono); font-size: 10px; }
.path-story strong { overflow: hidden; color: var(--ink); font-size: 13px; text-overflow: ellipsis; white-space: nowrap; }
.path-story > svg { color: var(--focus); }
.path-story p { grid-column: 1 / -1; margin: 3px 0 0; color: var(--ink-secondary); font-size: 12px; line-height: 1.55; }
.path-evidence { display: grid; gap: 8px; padding: 13px 16px; border-top: 1px solid var(--line); }
.path-evidence > span { display: flex; align-items: center; gap: 7px; color: var(--ink-secondary); font-size: 12px; }
.path-evidence > span svg { color: var(--focus); }
.path-evidence p { margin: 0; color: var(--ink-muted); font-size: 12px; line-height: 1.55; }
.path-variants { display: flex; align-items: center; flex-wrap: wrap; gap: 7px; padding: 12px 16px; border-top: 1px solid var(--line); }
.path-variants > small { margin-right: 3px; color: var(--ink-muted); font-family: var(--font-mono); font-size: 10px; }
.path-variants button { min-height: 28px; padding: 4px 8px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--surface); color: var(--ink-secondary); cursor: pointer; font-size: 11px; }
.path-variants button:hover, .path-variants button.active { border-color: var(--focus); background: var(--focus-soft); color: var(--ink); }
.diagnostics { display: flex; align-items: center; gap: 8px; min-height: 58px; margin-top: 16px; padding: 0 13px; border: 1px solid var(--line); background: var(--canvas-soft); }
.diagnostics > header { min-height: auto; flex: 0 0 auto; padding: 0; border: 0; }
.diagnostics > span { display: inline-flex; gap: 5px; padding: 4px 7px; border: 1px solid var(--line); color: var(--warning); font-family: var(--font-mono); font-size: 10px; }
.diagnostics > span.error { color: var(--critical); }
.diagnostics > span b { color: var(--ink); }
@media (max-width: 1200px) { .model-summary { grid-template-columns: repeat(2, 1fr); } .model-summary > div:nth-child(2) { border-right: 0; } .model-summary > div:nth-child(n + 3) { border-top: 1px solid var(--line); } .model-workbench { grid-template-columns: 290px minmax(0, 1fr); } .node-inspector { grid-column: 1 / -1; border-top: 1px solid var(--line); border-left: 0; } .node-detail { grid-template-columns: minmax(220px, .8fr) minmax(240px, 1fr) minmax(180px, .8fr); align-items: start; } .node-detail h2, .node-detail > code, .node-meaning { grid-column: 1 / -1; } }
@media (max-width: 760px) { .page-wrap { padding: 20px 14px; } .page-head { flex-direction: column; } .head-actions { justify-content: flex-start; } .project-picker { width: min(100%, 320px); } .project-picker select { max-width: none; width: 100%; } .empty-state { align-items: flex-start; flex-direction: column; } .model-summary { grid-template-columns: 1fr; } .model-summary > div { min-height: 72px; border-right: 0; border-bottom: 1px solid var(--line); } .model-summary > div:last-child { border-bottom: 0; } .model-summary > div:nth-child(n + 3) { border-top: 0; } .model-workbench { display: block; height: auto; } .risk-index { border-right: 0; border-bottom: 1px solid var(--line); max-height: 280px; overflow: auto; } .graph-panel { min-height: 580px; } .node-inspector { border-top: 1px solid var(--line); } .node-detail { grid-template-columns: 1fr; } .node-detail h2, .node-detail > code { grid-column: auto; } .diagnostics { align-items: flex-start; flex-wrap: wrap; padding: 12px; } }
</style>
