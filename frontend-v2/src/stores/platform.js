import { defineStore } from 'pinia'
import { api, saveBlob } from '../services/api'
import {
  cloneDemo,
  demoActivity,
  demoAgentRuns,
  demoBundles,
  demoConfigs,
  demoEvidence,
  demoFindings,
  demoGraph,
  demoKnowledge,
  demoRiskChains,
  demoRun,
  demoScenarios,
  demoStages,
  demoStats,
  demoTargets,
  demoTasks
} from '../data/demo'
import { demoAuditEngine, demoThreatModel, demoToolFabric } from '../data/architecture'
import { useUiStore } from './ui'

const riskLabel = value => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[value] || value || '未知')

const normalizeVerificationStatus = (value, fallback = 'needs_evidence') => {
  const status = String(value || '').trim().toLowerCase()
  return ['confirmed', 'verified', 'needs_evidence', 'rejected', 'static_only', 'not_reviewed'].includes(status)
    ? status
    : fallback
}

const findingStatusFromVerification = verification => ({
  confirmed: 'confirmed', verified: 'confirmed', static_only: 'static_only', rejected: 'rejected', not_reviewed: 'deferred'
}[verification] || 'candidate')

const evidenceDisplayType = value => ({
  code_snippet: 'code',
  static: 'code',
  service: 'network',
  sandbox: 'fuzz',
  browser: 'browser'
}[value] || value || 'trace')

const evidenceDisplayStatus = value => ({
  supported: 'verified',
  contradicted: 'rejected'
}[value] || 'pending')

const evidenceContent = item => {
  if (item.content) return item.content
  const controls = [item.candidate_case, item.positive_control, item.negative_control]
    .filter(Boolean)
    .map(control => `${control.label}: ${control.observed_status}`)
  return [item.summary, item.verification_predicate, ...controls].filter(Boolean).join('\n')
}

const mapAuditEvidence = finding => {
  const bundleItems = finding.evidence_bundle?.items
  const items = Array.isArray(bundleItems) && bundleItems.length ? bundleItems : (finding.evidence || [])
  return items.map((item, index) => ({
    id: item.id || `${finding.id}-evidence-${index + 1}`,
    findingId: finding.id,
    title: item.summary || item.title || `验证证据 ${index + 1}`,
    subtitle: item.verification_predicate || item.outcome || item.type || '审计证据',
    type: evidenceDisplayType(item.method || item.evidence_type || item.type),
    status: evidenceDisplayStatus(item.outcome),
    capturedAt: item.captured_at || '',
    hash: item.artifact_ref || 'backend evidence',
    content: evidenceContent(item)
  }))
}

const mapAuditFinding = (finding, index) => {
  const severity = finding.severity || 'medium'
  const verification = normalizeVerificationStatus(finding.verification_status)
  return {
    id: finding.id || `F-${index}`,
    title: finding.title || '未命名风险',
    category: finding.vulnerability_type || 'unknown',
    family: 'live',
    severity,
    cvss: { critical: 9.2, high: 7.8, medium: 5.4, low: 2.8 }[severity] || 5,
    confidence: finding.confidence || 0.7,
    status: findingStatusFromVerification(verification),
    verification,
    verificationLevel: finding.verification_level || finding.evidence_bundle?.level || 1,
    file: finding.file_path || '',
    line: finding.line_start || null,
    summary: finding.description || '',
    recommendation: finding.recommendation || finding.mitigation || '',
    source: 'live',
    evidenceIds: mapAuditEvidence(finding).map(item => item.id),
    duplicateCount: Math.max(1, Number(finding.duplicate_count || 1)),
    duplicateFindingIds: finding.duplicate_finding_ids || [],
    sourceTaskIds: finding.source_task_ids || [],
    priorityScore: Number(finding.review_priority_score || 0),
    priority: finding.review_priority || 'P3',
    severityLabel: riskLabel(severity),
    raw: finding
  }
}

const displayList = values => (Array.isArray(values) ? values : []).map(item => {
  if (typeof item === 'string') return item
  return item?.description || item?.summary || item?.label || JSON.stringify(item)
})

const mapAuditBundle = (bundle, index, findings = []) => {
  const finding = findings.find(item => item.id === bundle.finding_id)
  const verification = normalizeVerificationStatus(bundle.verification_status || finding?.verification)
  return {
    id: bundle.package_id || `RB-${bundle.finding_id || index + 1}`,
    findingId: bundle.finding_id || '',
    title: bundle.title || bundle.finding_title || finding?.title || '整改建议',
    severity: bundle.severity || bundle.finding_severity || finding?.severity || 'medium',
    state: bundle.state || 'draft',
    target: 'Local project',
    updatedAt: bundle.updated_at || '',
    aiPatchPrompt: bundle.ai_patch_prompt || '',
    constraints: displayList(bundle.patch_constraints),
    acceptance: displayList(bundle.acceptance_criteria),
    verification,
    proposalOnly: bundle.proposal_only ?? (verification !== 'verified'),
    relay: [
      { state: 'draft', label: '已生成', time: bundle.updated_at || '-', done: true },
      { state: 'dispatched', label: 'Return 已发送', time: '-', done: false },
      { state: 'acknowledged', label: 'AI 已确认', time: '-', done: false },
      { state: 'consumed', label: '修复中', time: '-', done: false },
      { state: 'returned', label: '补丁已返回', time: '-', done: false }
    ]
  }
}

const liveStageDefinitions = [
  ['plan', 'Plan', '意图与审计范围'],
  ['recon', 'Recon', '技术栈与入口'],
  ['surface', 'Surface', '运行面 + 威胁模型'],
  ['audit', 'Audit Lanes', '静态审查 + 工具信号'],
  ['merge', 'Merge', '去重与风险链'],
  ['verify', 'Verify', '受控验证'],
  ['remediate', 'Remediate', '整改包'],
  ['return', 'Return', '返回开发现场'],
  ['retest', 'Retest', '定向复测']
]

const liveStagesForTask = task => {
  const status = task?.status
  return liveStageDefinitions.map(([id, label, description]) => {
    let stageStatus = 'pending'
    if (status === 'completed' && id !== 'retest') stageStatus = 'completed'
    else if (status === 'running' && id === 'audit') stageStatus = 'running'
    else if (status === 'failed' && id === 'audit') stageStatus = 'failed'
    return { id, label, description, status: stageStatus, duration: '-', artifacts: 0 }
  })
}

const liveRunForTask = (project, task) => {
  const status = task?.status || 'pending'
  const stage = status === 'running' ? 'audit' : status === 'completed' ? 'return' : status === 'failed' ? 'audit' : 'plan'
  return {
    id: project.id,
    name: project.name,
    project: project.path,
    branch: 'local project',
    commit: task ? String(task.id).slice(0, 8) : '-',
    checkpoint: status === 'pending' ? (task ? 'AUDIT QUEUED' : 'NO AUDIT TASK') : status === 'running' ? 'AUDIT RUNNING' : status === 'failed' ? 'AUDIT FAILED' : 'AUDIT COMPLETE',
    verificationTarget: 0,
    status,
    progress: status === 'pending' ? 0 : status === 'running' ? 48 : status === 'failed' ? 0 : 100,
    activeStage: stage,
    startedAt: task?.started_at || task?.created_at || '',
    duration: task?.completed_at || task?.created_at || '-',
    raw: task || null,
    source: 'live'
  }
}

const mapCheckToRun = check => ({
  id: check.check_id,
  name: check.name,
  project: check.name,
  branch: 'linked task',
  commit: check.source_task_id ? String(check.source_task_id).slice(0, 8) : '-',
  profile: check.source_mode || 'mixed',
  trigger: 'api_adapter',
  scope: check.source_task_id ? 'linked_task' : 'project',
  checkpoint: check.status === 'completed' ? 'CP-RETEST-FINAL' : 'CP-ADAPTER',
  verificationTarget: 2,
  status: check.status,
  activeStage: check.status === 'completed' ? 'retest' : check.status === 'processing' ? 'verify' : 'recon',
  progress: check.status === 'completed' ? 100 : check.status === 'processing' ? 58 : 0,
  startedAt: check.created_at,
  duration: check.updated_at || '-',
  totalScore: check.total_score,
  riskLevel: check.risk_level,
  raw: check,
  source: 'live'
})

const mapRiskToFinding = (risk, index, side = 'web') => {
  const severity = risk.severity || risk.risk_severity || 'medium'
  const verification = normalizeVerificationStatus(risk.verification_status)
  return {
    id: risk.finding_id || risk.id || `LIVE-${side.toUpperCase()}-${String(index + 1).padStart(3, '0')}`,
    title: risk.title || risk.name || '未命名风险',
    category: risk.category || risk.risk_category || side,
    family: side,
    severity,
    cvss: risk.cvss || ({ critical: 9.2, high: 7.8, medium: 5.4, low: 2.8 }[severity] || 5),
    confidence: risk.confidence || 0.78,
    status: findingStatusFromVerification(verification),
    verification,
    verificationLevel: risk.verification_level || 1,
    file: risk.file_path || risk.location || 'report snapshot',
    line: risk.line || null,
    sourceNode: `live-source-${index}`,
    sinkNode: `live-sink-${index}`,
    graphNodes: [`live-source-${index}`, `live-risk-${index}`, `live-sink-${index}`],
    summary: risk.description || risk.summary || risk.trigger_condition || '后端报告未提供详细摘要。',
    recommendation: risk.recommendation || risk.mitigation || '请根据报告建议进行整改。',
    evidenceIds: [],
    raw: risk,
    source: 'live',
    severityLabel: riskLabel(severity)
  }
}

const findingsFromCheck = check => {
  const report = check?.report_snapshot || {}
  const groups = [
    ['web', report.frontend_risks || []],
    ['agent', report.agent_risks || []],
    ['composite', report.composite_risks || []]
  ]
  let offset = 0
  return groups.flatMap(([side, items]) => {
    const mapped = items.map((risk, index) => mapRiskToFinding(risk, offset + index, side))
    offset += items.length
    return mapped
  })
}

const graphSeverityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

const graphCategoryLabel = category => ({
  command_injection: '命令注入',
  hardcoded_password: '硬编码凭据',
  mcp_insecurity: 'MCP 授权风险',
  path_traversal: '路径访问风险',
  prompt_injection: '提示词注入',
  sql_injection: 'SQL 注入',
  ssrf: '服务端请求伪造',
  unsafe_deserialization: '不安全反序列化',
  xss: '跨站脚本',
  sensitive_file: '敏感文件暴露'
}[category] || String(category || '未知风险').replaceAll('_', ' '))

const graphImpactFor = category => {
  if (['hardcoded_password', 'sensitive_file'].includes(category)) return '凭据与敏感资产'
  if (category === 'mcp_insecurity') return 'MCP 能力边界'
  if (['prompt_injection', 'excessive_agency'].includes(category)) return '模型指令边界'
  if (category === 'workflow_insecurity') return '自动化执行边界'
  if (['command_injection', 'unsafe_deserialization'].includes(category)) return '应用执行边界'
  return '应用数据边界'
}

const graphRiskGroups = findings => {
  const groups = new Map()
  findings.forEach(finding => {
    const key = `${finding.category}|${finding.severity}`
    const group = groups.get(key) || {
      category: finding.category,
      severity: finding.severity,
      findings: [],
      highestPriority: finding.priorityScore || 0,
      sourceRecords: 0
    }
    group.findings.push(finding)
    group.highestPriority = Math.max(group.highestPriority, finding.priorityScore || 0)
    group.sourceRecords += Math.max(1, finding.duplicateCount || 1)
    groups.set(key, group)
  })
  return [...groups.values()].sort((left, right) => (
    right.highestPriority - left.highestPriority ||
    graphSeverityRank[right.severity] - graphSeverityRank[left.severity] ||
    right.findings.length - left.findings.length ||
    left.category.localeCompare(right.category)
  ))
}

const graphFromFindings = findings => {
  if (!findings.length || findings.every(item => item.source === 'demo')) return cloneDemo(demoGraph)
  const groups = graphRiskGroups(findings).slice(0, 4)
  const nodes = [{
    id: 'live-entry',
    name: '审查队列',
    category: 'entry',
    symbolSize: 62,
    x: 240,
    y: 244,
    meta: `${findings.length} 个去重后审查项，按优先级聚合显示`
  }]
  const links = []
  const impacts = new Map()
  groups.forEach((group, index) => {
    const y = 74 + index * 78
    const riskId = `live-risk-group-${index}`
    const impactName = graphImpactFor(group.category)
    let sinkId = impacts.get(impactName)
    if (!sinkId) {
      sinkId = `live-impact-${impacts.size}`
      impacts.set(impactName, sinkId)
      nodes.push({
        id: sinkId,
        name: impactName,
        category: 'impact',
        symbolSize: 54,
        x: 810,
        y: 126 + (impacts.size - 1) * 110,
        meta: '聚合风险影响边界',
        risk: group.severity,
        draggable: true
      })
    }
    nodes.push({
      id: riskId,
      name: `${graphCategoryLabel(group.category)} ${group.findings.length} 项`,
      category: 'finding',
      symbolSize: 48 + Math.min(16, Math.round(Math.log2(group.findings.length + 1) * 3)),
      x: 414,
      y,
      meta: `${group.findings[0].priority} · ${riskLabel(group.severity)} · ${group.findings.length} 个审查项 / ${group.sourceRecords} 条来源记录`,
      risk: group.severity,
      draggable: true
    })
    links.push({ source: 'live-entry', target: riskId, kind: 'finding', risk: group.severity })
    links.push({ source: riskId, target: sinkId, kind: 'impact', risk: group.severity })
    group.findings.forEach(finding => {
      finding.graphNodes = ['live-entry', riskId, sinkId]
      finding.sourceNode = 'live-entry'
      finding.sinkNode = sinkId
    })
  })
  return { nodes, links }
}

const mapStats = data => ({
  totalChecks: data.total_checks ?? data.total ?? 0,
  completedChecks: data.completed_checks ?? data.by_status?.completed ?? 0,
  processingChecks: data.processing_checks ?? data.by_status?.processing ?? 0,
  criticalChecks: data.critical_checks ?? 0,
  highChecks: data.high_checks ?? 0,
  averageScore: data.average_score ?? 0,
  totalFindings: data.total_findings ?? 0,
  confirmedFindings: data.confirmed_findings ?? 0,
  evidenceCount: data.evidence_count ?? 0
})

export const usePlatformStore = defineStore('platform', {
  state: () => ({
    initialized: false,
    loading: false,
    projectLoading: false,
    auditTasksLoading: false,
    vrtmLoading: false,
    connection: 'checking',
    connectionMessage: '正在连接 FastAPI',
    sources: {},
    projects: [],
    selectedProjectId: '',
    auditTasks: [],
    runtimeModel: null,
    findingsSummary: { rawFindingsCount: 0, reviewFindingsCount: 0, duplicateFindingsCount: 0 },
    runs: [cloneDemo(demoRun)],
    selectedRun: cloneDemo(demoRun),
    stages: cloneDemo(demoStages),
    findings: cloneDemo(demoFindings),
    graph: cloneDemo(demoGraph),
    evidence: cloneDemo(demoEvidence),
    bundles: cloneDemo(demoBundles),
    riskChains: cloneDemo(demoRiskChains),
    activity: cloneDemo(demoActivity),
    stats: cloneDemo(demoStats),
    checks: [],
    tasks: cloneDemo(demoTasks),
    knowledge: cloneDemo(demoKnowledge),
    configs: cloneDemo(demoConfigs),
    targets: cloneDemo(demoTargets),
    scenarios: cloneDemo(demoScenarios),
    agentRuns: cloneDemo(demoAgentRuns),
    auditEngine: cloneDemo(demoAuditEngine),
    threatModel: cloneDemo(demoThreatModel),
    toolFabric: cloneDemo(demoToolFabric),
    agentStats: {},
    agentReport: {},
    lastError: null
  }),

  getters: {
    selectedFinding: state => id => state.findings.find(item => item.id === id) || null,
    findingEvidence: state => id => state.evidence.filter(item => item.findingId === id),
    findingBundle: state => id => state.bundles.find(item => item.findingId === id) || null,
    selectedProject: state => state.projects.find(item => item.id === state.selectedProjectId) || null,
    isLive: state => state.connection === 'live'
  },

  actions: {
    notify(message, tone = 'info', title = '') {
      useUiStore().toast(message, tone, title)
    },

    async loadWithFallback(name, loader, fallback) {
      try {
        const data = await loader()
        this[name] = Array.isArray(data) ? data : data || fallback
        this.sources[name] = 'live'
        return this[name]
      } catch (error) {
        this[name] = cloneDemo(fallback)
        this.sources[name] = 'demo'
        return this[name]
      }
    },

    async initialize(force = false) {
      if (this.initialized && !force) return
      this.loading = true
      this.lastError = null
      try {
        await api.health()
        this.connection = 'live'
        this.connectionMessage = 'FastAPI 已连接'
      } catch (error) {
        this.connection = 'demo'
        this.connectionMessage = 'FastAPI 未连接，使用演示数据'
        this.lastError = error.userMessage
      }

      if (this.connection === 'live') {
        try {
          this.projects = await api.getProjects()
          this.sources.projects = 'live'
          this.configs = await api.getModelConfigs()
          this.sources.configs = 'live'
          this.runs = this.projects.length
            ? this.projects.map(project => ({
                id: project.id,
                name: project.name,
                project: project.path,
                branch: 'local project',
                commit: '-',
                checkpoint: 'VRTM READY',
                status: 'completed',
                progress: 100,
                activeStage: 'surface',
                source: 'live'
              }))
            : [cloneDemo(demoRun)]
          const nextProjectId = this.projects.some(item => item.id === this.selectedProjectId)
            ? this.selectedProjectId
            : this.projects[0]?.id
          if (nextProjectId) await this.selectProject(nextProjectId)
          else this.useDemoRun()
        } catch (error) {
          this.connection = 'demo'
          this.connectionMessage = '项目列表不可用，使用演示数据'
          this.lastError = error.userMessage
          this.useDemoRun()
        }
      } else {
        this.useDemoRun()
      }

      this.loading = false
      this.initialized = true
    },

    useDemoRun() {
      this.selectedRun = cloneDemo(demoRun)
      this.stages = cloneDemo(demoStages)
      this.findings = cloneDemo(demoFindings)
      this.graph = cloneDemo(demoGraph)
      this.evidence = cloneDemo(demoEvidence)
      this.bundles = cloneDemo(demoBundles)
      this.riskChains = cloneDemo(demoRiskChains)
      this.activity = cloneDemo(demoActivity)
      this.findingsSummary = { rawFindingsCount: demoFindings.length, reviewFindingsCount: demoFindings.length, duplicateFindingsCount: 0 }
    },

    async selectProject(projectId) {
      this.selectedProjectId = projectId
      const project = this.projects.find(item => item.id === projectId)
      if (!project) return
      this.projectLoading = true
      this.selectedRun = liveRunForTask(project, null)
      this.stages = liveStagesForTask(null)
      try {
        await this.refreshAuditTasks(projectId)
        await this.loadProjectFindingQueue(projectId)
        await this.loadProjectRemediations()
        await this.loadRuntimeModel(projectId)
      } catch (error) {
        this.lastError = error.userMessage || '无法加载项目数据'
        this.notify(this.lastError, 'error', '项目加载失败')
      } finally {
        this.projectLoading = false
      }
    },

    async loadRuntimeModel(projectId = this.selectedProjectId) {
      if (!projectId) return null
      this.vrtmLoading = true
      try {
        this.runtimeModel = await api.getLatestRuntimeModel(projectId)
        this.sources.runtimeModel = 'live'
        return this.runtimeModel
      } catch (error) {
        if (error.response?.status === 404) {
          this.runtimeModel = null
          this.sources.runtimeModel = 'empty'
          return null
        }
        throw error
      } finally {
        this.vrtmLoading = false
      }
    },

    async refreshAuditTasks(projectId = this.selectedProjectId) {
      if (!projectId) {
        this.auditTasks = []
        return this.auditTasks
      }
      this.auditTasksLoading = true
      try {
        const tasks = await api.getAuditTasks(projectId)
        this.auditTasks = [...tasks].sort((left, right) => (
          String(right.created_at || '').localeCompare(String(left.created_at || ''))
        ))
        this.applyLiveTaskState(projectId)
        return this.auditTasks
      } finally {
        this.auditTasksLoading = false
      }
    },

    async loadProjectFindingQueue(projectId = this.selectedProjectId) {
      if (!projectId) return []
      const queue = await api.getProjectFindings(projectId)
      const queueFindings = Array.isArray(queue.findings) ? queue.findings : []
      this.findings = queueFindings.map(mapAuditFinding)
      this.evidence = queueFindings.flatMap(mapAuditEvidence)
      this.bundles = []
      this.riskChains = {}
      this.graph = graphFromFindings(this.findings)
      this.findingsSummary = {
        rawFindingsCount: Number(queue.raw_findings_count || 0),
        reviewFindingsCount: Number(queue.review_findings_count || 0),
        duplicateFindingsCount: Number(queue.duplicate_findings_count || 0)
      }
      this.sources.findings = 'live'
      return this.findings
    },

    async loadProjectRemediations(taskId = null) {
      const task = taskId
        ? this.auditTasks.find(item => item.id === taskId)
        : this.auditTasks.find(item => item.status === 'completed')
      if (!task) {
        this.bundles = []
        return this.bundles
      }
      const bundles = await api.getAuditRemediations(task.id)
      this.bundles = (Array.isArray(bundles) ? bundles : []).map((bundle, index) => (
        mapAuditBundle(bundle, index, this.findings)
      ))
      return this.bundles
    },

    async createAuditTask(projectId = this.selectedProjectId, useLlm = false, announce = true) {
      if (!projectId) {
        throw new Error('请先选择一个项目。')
      }
      const task = await api.createAuditTask({
        project_id: projectId,
        use_llm: Boolean(useLlm),
        output_format: 'markdown'
      })
      this.auditTasks = [task, ...this.auditTasks.filter(item => item.id !== task.id)]
      this.applyLiveTaskState(projectId)
      if (announce) this.notify('审计任务已进入后台队列。', 'success', 'Harness')
      return task
    },

    applyLiveTaskState(projectId = this.selectedProjectId) {
      const project = this.projects.find(item => item.id === projectId)
      if (!project) return
      const activeTask = this.auditTasks.find(item => ['pending', 'running'].includes(item.status)) || this.auditTasks[0] || null
      this.selectedRun = liveRunForTask(project, activeTask)
      this.stages = liveStagesForTask(activeTask)
    },

    async buildRuntimeModel() {
      if (!this.selectedProjectId) {
        throw new Error('请选择一个项目')
      }
      this.vrtmLoading = true
      try {
        this.runtimeModel = await api.buildRuntimeModel({
          project_id: this.selectedProjectId,
          observations: [],
          persist: true
        })
        this.sources.runtimeModel = 'live'
        this.notify('运行面模型已生成并保存。', 'success', 'VRTM')
        return this.runtimeModel
      } finally {
        this.vrtmLoading = false
      }
    },

    async createProjectAndAudit(payload) {
      const project = await api.createProject({
        name: payload.name,
        path: payload.path,
        description: payload.description || null,
        audit_scope: payload.audit_scope
      })
      this.projects = [project, ...this.projects]
      this.runs = [{
        id: project.id,
        name: project.name,
        project: project.path,
        branch: 'local project',
        commit: '-',
        checkpoint: 'AUDIT QUEUED',
        status: 'pending',
        progress: 0,
        activeStage: 'recon',
        source: 'live'
      }, ...this.runs.filter(item => item.id !== project.id)]
      await this.selectProject(project.id)
      const task = await this.createAuditTask(project.id, payload.use_llm, false)
      this.notify('项目已创建，审计任务已进入后台队列。', 'success', 'Harness')
      return { project, task }
    },

    async selectRun(id) {
      if (this.projects.some(item => item.id === id)) {
        await this.selectProject(id)
        return
      }
      const run = this.runs.find(item => item.id === id)
      if (!run || run.source === 'demo') {
        this.useDemoRun()
        return
      }
      this.loading = true
      try {
        const detail = await api.getHealthCheck(id)
        this.selectedRun = { ...mapCheckToRun(detail), raw: detail }
        const mapped = findingsFromCheck(detail)
        this.findings = mapped.length ? mapped : cloneDemo(demoFindings)
        this.sources.findings = mapped.length ? 'live' : 'demo'
        this.graph = graphFromFindings(this.findings)
        this.stages = demoStages.map(stage => ({
          ...stage,
          status: this.selectedRun.status === 'completed'
            ? 'completed'
            : stage.id === this.selectedRun.activeStage
              ? 'running'
              : demoStages.findIndex(item => item.id === stage.id) < demoStages.findIndex(item => item.id === this.selectedRun.activeStage)
                ? 'completed'
                : 'pending'
        }))
      } catch (error) {
        this.notify(error.userMessage || '无法加载体检详情', 'error')
      } finally {
        this.loading = false
      }
    },

    async createCheck(payload) {
      if (this.connection !== 'live') {
        this.notify('当前为演示模式，已预览创建流程但未写入后端。', 'warning')
        return null
      }
      const result = await api.createHealthCheck(payload)
      this.notify(payload.auto_run ? '审查任务已启动。' : '审查草稿已保存。', 'success')
      await this.initialize(true)
      return result
    },

    async rerunCheck(id) {
      if (this.connection !== 'live') return this.notify('演示任务不能重新执行。', 'warning')
      await api.runHealthCheck(id)
      this.notify('任务已进入后台执行。', 'success')
      await this.initialize(true)
    },

    async deleteCheck(id) {
      if (this.connection !== 'live') return this.notify('演示任务不能删除。', 'warning')
      await api.deleteHealthCheck(id)
      this.notify('体检记录已删除。', 'success')
      await this.initialize(true)
    },

    async createTask(payload) {
      if (this.connection !== 'live') return this.notify('当前为演示模式，源码任务未写入后端。', 'warning')
      await api.createSourceTask(payload)
      this.notify('源码审计任务已创建。', 'success')
      this.tasks = await api.getTasks({ limit: 100 })
    },

    async resumeTask(id) {
      if (this.connection !== 'live') return this.notify('演示任务不能恢复。', 'warning')
      await api.resumeTask(id)
      this.notify('任务已恢复执行。', 'success')
      this.tasks = await api.getTasks({ limit: 100 })
    },

    async deleteTask(id) {
      if (this.connection !== 'live') {
        this.tasks = this.tasks.filter(item => item.task_id !== id)
        return this.notify('已从演示列表移除。', 'success')
      }
      await api.deleteTask(id)
      this.tasks = await api.getTasks({ limit: 100 })
      this.notify('源码任务已删除。', 'success')
    },

    async saveKnowledge(item) {
      const payload = { ...item, tags: Array.isArray(item.tags) ? item.tags : String(item.tags || '').split(',').map(tag => tag.trim()).filter(Boolean) }
      if (this.connection !== 'live') {
        if (item.id) this.knowledge = this.knowledge.map(row => row.id === item.id ? { ...row, ...payload } : row)
        else this.knowledge.unshift({ ...payload, id: Date.now(), reference_count: 0 })
      } else if (item.id) await api.updateKnowledge(item.id, payload)
      else await api.createKnowledge(payload)
      if (this.connection === 'live') this.knowledge = await api.getKnowledge({ limit: 500 })
      this.notify('知识条目已保存。', 'success')
    },

    async deleteKnowledge(id) {
      if (this.connection === 'live') await api.deleteKnowledge(id)
      this.knowledge = this.knowledge.filter(item => item.id !== id)
      this.notify('知识条目已删除。', 'success')
    },

    async toggleKnowledge(item) {
      if (this.connection === 'live') await api.toggleKnowledge(item.id, !item.is_active)
      item.is_active = item.is_active ? 0 : 1
      this.notify(item.is_active ? '知识条目已启用。' : '知识条目已停用。', 'success')
    },

    async exportKnowledge() {
      if (this.connection !== 'live') return this.notify('CSV 导出需要连接 FastAPI。', 'warning')
      saveBlob(await api.exportKnowledge(), 'vulnerability-knowledge.csv')
    },

    async importKnowledge(file) {
      if (this.connection !== 'live') return this.notify('CSV 导入需要连接 FastAPI。', 'warning')
      await api.importKnowledge(file)
      this.knowledge = await api.getKnowledge({ limit: 500 })
      this.notify('知识库导入完成。', 'success')
    },

    async saveConfig(item) {
      if (this.connection !== 'live') {
        if (item.id) this.configs = this.configs.map(row => row.id === item.id ? { ...row, ...item } : row)
        else this.configs.unshift({ ...item, id: Date.now(), updated_at: new Date().toLocaleString() })
      } else if (item.id) await api.updateModelConfig(item.id, item)
      else await api.createModelConfig(item)
      if (this.connection === 'live') this.configs = await api.getModelConfigs()
      this.notify('模型配置已保存。', 'success')
    },

    async refreshModelConfigs() {
      if (this.connection !== 'live') {
        this.configs = cloneDemo(demoConfigs)
        this.sources.configs = 'demo'
        return this.configs
      }
      this.configs = await api.getModelConfigs()
      this.sources.configs = 'live'
      return this.configs
    },

    async deleteConfig(id) {
      if (this.connection === 'live') await api.deleteModelConfig(id)
      this.configs = this.configs.filter(item => item.id !== id)
      this.notify('模型配置已删除。', 'success')
    },

    async toggleConfig(item) {
      if (this.connection === 'live') await api.toggleModelConfig(item.id, !item.is_active)
      item.is_active = item.is_active ? 0 : 1
      this.notify(item.is_active ? '模型已激活。' : '模型已停用。', 'success')
    },

    async saveTarget(item) {
      if (this.connection !== 'live') {
        if (item.id) this.targets = this.targets.map(row => row.id === item.id ? { ...row, ...item } : row)
        else this.targets.unshift({ ...item, id: Date.now() })
      } else if (item.id) await api.updateAgentTarget(item.id, item)
      else await api.createAgentTarget(item)
      if (this.connection === 'live') this.targets = await api.getAgentTargets()
      this.notify('智能体目标已保存。', 'success')
    },

    async deleteTarget(id) {
      if (this.connection === 'live') await api.deleteAgentTarget(id)
      this.targets = this.targets.filter(item => item.id !== id)
      this.notify('智能体目标已删除。', 'success')
    },

    async toggleTarget(item) {
      if (this.connection === 'live') await api.toggleAgentTarget(item.id, !item.is_active)
      item.is_active = item.is_active ? 0 : 1
    },

    async saveScenario(item) {
      if (this.connection !== 'live') {
        if (item.id) this.scenarios = this.scenarios.map(row => row.id === item.id ? { ...row, ...item } : row)
        else this.scenarios.unshift({ ...item, id: Date.now() })
      } else if (item.id) await api.updateAgentScenario(item.id, item)
      else await api.createAgentScenario(item)
      if (this.connection === 'live') this.scenarios = await api.getAgentScenarios()
      this.notify('攻击场景已保存。', 'success')
    },

    async deleteScenario(id) {
      if (this.connection === 'live') await api.deleteAgentScenario(id)
      this.scenarios = this.scenarios.filter(item => item.id !== id)
      this.notify('攻击场景已删除。', 'success')
    },

    async toggleScenario(item) {
      if (this.connection === 'live') await api.toggleAgentScenario(item.id, !item.is_active)
      item.is_active = item.is_active ? 0 : 1
      this.notify(item.is_active ? '攻击场景已启用。' : '攻击场景已停用。', 'success')
    },

    async seedScenarios() {
      if (this.connection !== 'live') return this.notify('演示场景已包含默认模板。', 'info')
      const result = await api.seedAgentScenarios()
      this.scenarios = await api.getAgentScenarios()
      this.notify(`模板注入完成：新增 ${result.created || 0} 个。`, 'success')
    },

    async createAgentRun(payload, batch = false) {
      if (this.connection !== 'live') return this.notify('当前为演示模式，运行未写入后端。', 'warning')
      if (batch) await api.createAgentBatch(payload)
      else await api.createAgentRun(payload)
      this.agentRuns = await api.getAgentRuns({ limit: 100 })
      this.notify(batch ? '批量运行已创建。' : '安全运行已创建。', 'success')
    },

    async deleteAgentRun(id) {
      if (this.connection === 'live') await api.deleteAgentRun(id)
      this.agentRuns = this.agentRuns.filter(item => item.run_id !== id)
      this.notify('运行记录已删除。', 'success')
    },

    async exportAgentRuns() {
      if (this.connection !== 'live') return this.notify('CSV 导出需要连接 FastAPI。', 'warning')
      saveBlob(await api.exportAgentRuns(), 'agent-security-runs.csv')
    },

    async dispatchBundle(id) {
      const bundle = this.bundles.find(item => item.id === id)
      if (!bundle) return
      bundle.state = 'dispatched'
      const step = bundle.relay.find(item => item.state === 'dispatched')
      if (step) Object.assign(step, { done: true, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) })
      this.notify('RemediationBundle 已标记为 Return。后端 Skill/CLI adapter 接入后将返回开发现场。', 'success')
    }
  }
})
