<template>
  <section class="view-page findings-page">
    <div class="page-wrap compact-wrap">
      <header class="page-head findings-head">
        <div><span class="page-kicker">EVIDENCE-BACKED FINDINGS</span><h1>风险发现</h1><p>每个 Finding 显示 RiskChain、验证等级和未闭合的证据缺口。</p></div>
        <div class="head-actions">
          <span class="source-chip" :class="sourceMode">{{ sourceMode === 'live' ? '后端报告' : '关联演示数据' }}</span>
          <button class="button" type="button" @click="platform.initialize(true)"><RefreshCw :size="14" />刷新</button>
        </div>
      </header>

      <div class="finding-summary-line">
        <span><b>{{ filtered.length }}</b> 审查队列</span>
        <span v-if="platform.findingsSummary.duplicateFindingsCount"><i class="focus"></i>{{ platform.findingsSummary.rawFindingsCount }} 原始 / 合并 {{ platform.findingsSummary.duplicateFindingsCount }} 项重复</span>
        <span><i class="critical"></i>{{ criticalCount }} 高风险</span>
        <span><i class="verified"></i>{{ confirmedCount }} 已确认</span>
        <span><i class="warning"></i>{{ gapCount }} 有证据缺口</span>
        <div class="summary-filter"><Search :size="14" /><input v-model="query" placeholder="搜索风险、文件或类别" /></div>
      </div>

      <div class="findings-workbench">
        <aside class="finding-browser">
          <div class="browser-filters">
            <div class="segmented">
              <button v-for="item in statusFilters" :key="item.value" type="button" :class="{ active: status === item.value }" @click="status = item.value">{{ item.label }}</button>
            </div>
            <select v-model="severity" class="select mini-select"><option value="">全部等级</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option></select>
          </div>
          <div class="finding-list">
            <button v-for="finding in filtered" :key="finding.id" type="button" :class="{ active: selectedId === finding.id }" @click="selectedId = finding.id">
              <span class="severity-bar" :class="finding.severity"></span>
              <span class="finding-copy"><span><code>{{ finding.id }}</code><em>{{ finding.priority || familyLabel(finding.family) }}</em><span class="verification-level">L{{ finding.verificationLevel || 1 }}</span></span><strong>{{ finding.title }}</strong><small>{{ finding.file }}<template v-if="finding.line">:{{ finding.line }}</template><template v-if="finding.duplicateCount > 1"> · {{ finding.duplicateCount }} 条来源</template></small></span>
              <span class="score-box"><b>{{ finding.priorityScore || finding.cvss }}</b><small>{{ finding.priorityScore ? '优先级' : 'CVSS' }}</small></span>
            </button>
            <div v-if="!filtered.length" class="inline-empty">没有匹配的风险发现。</div>
          </div>
        </aside>

        <article v-if="selected" class="finding-dossier">
          <header class="dossier-head">
            <div class="dossier-title">
              <span><span class="severity-chip" :class="selected.severity">{{ severityLabel(selected.severity) }}</span><span class="verification-level">L{{ selected.verificationLevel || 1 }}</span><code>{{ selected.id }}</code><span class="status-chip" :class="selected.status">{{ statusLabel(selected.status) }}</span></span>
              <h2>{{ selected.title }}</h2>
              <p>{{ selected.summary }}</p>
            </div>
            <div class="dossier-score"><strong>{{ Math.round((selected.confidence || 0) * 100) }}%</strong><span>结论置信度</span></div>
          </header>

          <nav class="dossier-tabs">
            <button v-for="tab in tabs" :key="tab.id" type="button" :class="{ active: activeTab === tab.id }" @click="activeTab = tab.id"><component :is="tab.icon" :size="14" />{{ tab.label }}</button>
          </nav>

          <div v-if="activeTab === 'chain'" class="dossier-body chain-dossier">
            <div class="chain-spine">
              <div v-for="(step, index) in chain" :key="step.label" class="chain-spine-step" :class="step.status">
                <span>{{ index + 1 }}</span><div><small>{{ step.label }}</small><strong>{{ step.value }}</strong></div><CheckCircle2 v-if="step.status === 'supported'" :size="16" /><LoaderCircle v-else :size="16" />
              </div>
              <div v-if="!chain.length" class="inline-empty">当前后端报告未提供结构化 RiskChain，此处只展示原始 Finding。</div>
            </div>
            <aside class="finding-context">
              <div><span>代码位置</span><code>{{ selected.file }}<template v-if="selected.line">:{{ selected.line }}</template></code></div>
              <div><span>类别</span><strong>{{ selected.category }}</strong></div>
              <div><span>验证状态</span><strong>{{ statusLabel(selected.verification) }}</strong></div>
              <div v-if="selected.duplicateCount > 1"><span>合并来源</span><strong>{{ selected.duplicateCount }} 条 / {{ selected.sourceTaskIds.length }} 个任务</strong></div>
              <div><span>ValidationSession</span><strong>L{{ selected.verificationLevel || 1 }} · {{ verificationLabel(selected.verificationLevel) }}</strong></div>
              <button class="button" type="button" @click="$router.push('/workspace')"><Network :size="14" />在图谱中定位</button>
            </aside>
          </div>

          <div v-else-if="activeTab === 'evidence'" class="dossier-body evidence-dossier">
            <button v-for="item in evidence" :key="item.id" type="button" @click="openEvidence(item)">
              <component :is="evidenceIcon(item.type)" :size="17" /><span><strong>{{ item.title }}</strong><small>{{ item.subtitle }}</small></span><span class="evidence-state" :class="item.status"></span><ChevronRight :size="15" />
            </button>
            <div v-if="!evidence.length" class="inline-empty">该项尚未关联独立证据对象。</div>
          </div>

          <div v-else class="dossier-body remediation-dossier">
            <section><span>建议整改</span><p>{{ selected.recommendation }}</p></section>
            <template v-if="bundle">
              <section><span>AI Patch Prompt</span><pre>{{ bundle.aiPatchPrompt }}</pre></section>
              <section><span>不可修改范围</span><ul><li v-for="item in bundle.constraints" :key="item">{{ item }}</li></ul></section>
              <div class="button-row"><button class="button relay" type="button" @click="platform.dispatchBundle(bundle.id)"><Reply :size="14" />Return to Claude Code</button><router-link class="button" to="/remediation"><ArrowUpRight :size="14" />打开 Return 视图</router-link></div>
            </template>
            <div v-else class="inline-empty">只有已确认且证据闭合的 Finding 才会生成整改包。</div>
          </div>
        </article>
      </div>
    </div>

    <div v-if="evidencePreview" class="modal-backdrop" @click.self="evidencePreview = null">
      <section class="modal-panel evidence-modal"><header class="modal-head"><div><code>{{ evidencePreview.id }}</code><h2>{{ evidencePreview.title }}</h2></div><button class="icon-button" @click="evidencePreview = null"><X :size="16" /></button></header><div class="modal-body"><div class="artifact-meta"><span>{{ evidencePreview.type }}</span><span>{{ evidencePreview.capturedAt }}</span><code>{{ evidencePreview.hash }}</code></div><pre class="artifact-code">{{ evidencePreview.content }}</pre></div></section>
    </div>
  </section>
</template>

<script setup>
import { computed, markRaw, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ArrowUpRight, Braces, CheckCircle2, ChevronRight, Code2, FileJson, FlaskConical, GitBranch, LoaderCircle, Monitor, Network, RefreshCw, Reply, ScrollText, Search, ShieldCheck, X } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const route = useRoute()
const query = ref('')
const status = ref('all')
const severity = ref('')
const selectedId = ref(String(route.query.finding || platform.findings[0]?.id || ''))
const activeTab = ref('chain')
const evidencePreview = ref(null)
const statusFilters = [{ value: 'all', label: '全部' }, { value: 'open', label: '待处理' }, { value: 'confirmed', label: '已确认' }]
const tabs = [{ id: 'chain', label: '风险链', icon: markRaw(GitBranch) }, { id: 'evidence', label: '证据', icon: markRaw(FlaskConical) }, { id: 'remediation', label: '整改', icon: markRaw(ShieldCheck) }]

const filtered = computed(() => platform.findings.filter(item => {
  const text = `${item.id} ${item.title} ${item.category} ${item.file}`.toLowerCase()
  const statusMatch = status.value === 'all' || (status.value === 'confirmed' ? item.status === 'confirmed' : item.status !== 'confirmed')
  return text.includes(query.value.toLowerCase()) && statusMatch && (!severity.value || item.severity === severity.value)
}))
const selected = computed(() => platform.selectedFinding(selectedId.value) || filtered.value[0] || null)
const chain = computed(() => platform.riskChains[selected.value?.id] || [])
const evidence = computed(() => platform.findingEvidence(selected.value?.id))
const bundle = computed(() => platform.findingBundle(selected.value?.id))
const sourceMode = computed(() => platform.sources.findings || platform.selectedRun.source || 'demo')
const criticalCount = computed(() => filtered.value.filter(item => ['critical', 'high'].includes(item.severity)).length)
const confirmedCount = computed(() => filtered.value.filter(item => item.status === 'confirmed').length)
const gapCount = computed(() => filtered.value.filter(item => (
  ['needs_evidence', 'static_only'].includes(item.verification) ||
  ['blocked', 'inconclusive', 'verifying'].includes(item.status)
)).length)

watch(filtered, items => { if (items.length && !items.some(item => item.id === selectedId.value)) selectedId.value = items[0].id })
watch(() => route.query.finding, value => { if (value && platform.selectedFinding(String(value))) selectedId.value = String(value) })
const severityLabel = value => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[value] || value)
const familyLabel = value => ({ web: 'WEB', agent: 'AGENT', mcp: 'MCP', secret: 'SECRET', workflow: 'WORKFLOW', composite: 'CHAIN' }[value] || String(value || 'RISK').toUpperCase())
const statusLabel = value => ({ confirmed: '已确认', verified: '已验证', verifying: '验证中', blocked: '待授权', candidate: '候选', deferred: '待后续审查', not_reviewed: '待后续审查', inconclusive: '证据不足', partial: '部分验证', needs_approval: '需要批准', needs_evidence: '待补充证据', static_only: '仅静态', rejected: '已排除' }[value] || value)
const verificationLabel = value => ({ 1: '静态证据', 2: 'Surface 一致性', 3: '沙箱证明', 4: '浏览器 / 服务证据', 5: '修复后复测' }[value] || '未分级')
const icons = { code: markRaw(Code2), network: markRaw(Network), fuzz: markRaw(FlaskConical), browser: markRaw(Monitor), dom: markRaw(Braces), trace: markRaw(GitBranch), config: markRaw(FileJson) }
const evidenceIcon = type => icons[type] || markRaw(ScrollText)
const openEvidence = item => { evidencePreview.value = item }
</script>
