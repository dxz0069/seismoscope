<template>
  <section class="workspace-view">
    <header class="run-strip">
      <div class="run-selector-wrap">
        <span class="run-pulse" :class="platform.selectedRun.status"></span>
        <select :value="platform.selectedRun.id" class="run-selector" aria-label="选择审查任务" @change="selectRun">
          <option v-for="run in platform.runs" :key="run.id" :value="run.id">{{ run.name }} · {{ run.id }}</option>
        </select>
        <span class="run-context">{{ platform.selectedRun.project }} / {{ platform.selectedRun.branch }} / {{ platform.selectedRun.commit }}</span>
      </div>
      <div class="run-strip-actions">
        <span class="run-gate"><ShieldCheck :size="13" />{{ platform.selectedRun.checkpoint || 'NO CHECKPOINT' }}</span>
        <span class="source-chip" :class="platform.selectedRun.source">{{ platform.selectedRun.source === 'live' ? '后端报告' : '演示快照' }}</span>
        <span class="run-progress"><i :style="{ width: `${platform.selectedRun.progress || 0}%` }"></i><b>{{ platform.selectedRun.progress || 0 }}%</b></span>
        <button v-if="platform.selectedProjectId" class="icon-button" type="button" title="创建审计任务" :disabled="platform.projectLoading" @click="queueAuditTask"><Play :size="15" /></button>
        <button v-if="platform.selectedProjectId" class="icon-button" type="button" title="使用激活模型进行 LLM 审查" :disabled="platform.projectLoading" @click="queueAuditTask(true)"><Sparkles :size="15" /></button>
        <button v-else-if="platform.selectedRun.source === 'live'" class="icon-button" type="button" title="重新执行" @click="platform.rerunCheck(platform.selectedRun.id)"><RefreshCw :size="15" /></button>
        <button class="icon-button" type="button" title="刷新数据" @click="platform.initialize(true)"><RotateCw :size="15" /></button>
      </div>
    </header>

    <section class="audit-history" aria-label="审计历史">
      <header>
        <span><History :size="15" />AUDIT HISTORY</span>
        <strong>{{ platform.auditTasks.length }}</strong>
        <button class="icon-button" type="button" title="刷新审计历史" :disabled="!platform.selectedProjectId || platform.auditTasksLoading" @click="refreshAuditHistory">
          <RotateCw :size="14" :class="{ spin: platform.auditTasksLoading }" />
        </button>
      </header>
      <div v-if="platform.auditTasks.length" class="audit-history-scroll">
        <table>
          <thead><tr><th>任务</th><th>状态</th><th>创建时间</th><th>开始时间</th><th>完成时间</th><th>结果</th></tr></thead>
          <tbody>
            <tr v-for="task in platform.auditTasks" :key="task.id">
              <td><code>{{ shortTaskId(task.id) }}</code></td>
              <td><span class="status-chip" :class="task.status">{{ auditStatusText(task.status) }}</span></td>
              <td>{{ formatTaskTime(task.created_at) }}</td>
              <td>{{ formatTaskTime(task.started_at) }}</td>
              <td>{{ formatTaskTime(task.completed_at) }}</td>
              <td>{{ taskResultSummary(task) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="audit-history-empty">当前项目尚无审计任务。</p>
    </section>

    <StageTimeline :stages="platform.stages" :active="activeStage" @select="activeStage = $event" />

    <div class="workspace-canvas" :class="{ 'signals-collapsed': signalsCollapsed }">
      <SurfaceGraph :graph="platform.graph" :highlighted-nodes="highlightedNodes" @select-node="onNodeSelect" />

      <section class="signal-panel" :class="{ collapsed: signalsCollapsed }">
        <header>
          <div><span>AUDIT LANES</span><strong>{{ stageLabel }}</strong></div>
          <button type="button" :title="signalsCollapsed ? '展开信号面板' : '收起信号面板'" @click="signalsCollapsed = !signalsCollapsed">
            <PanelLeftOpen v-if="signalsCollapsed" :size="15" /><PanelLeftClose v-else :size="15" />
          </button>
        </header>
        <template v-if="!signalsCollapsed">
          <div class="signal-coverage">
            <span v-for="item in coverage" :key="item.label" :class="item.state" :title="item.state === 'extension' ? '架构扩展点，当前不执行独立审计 Lane' : '当前可执行 Lane'"><component :is="item.icon" :size="13" /><b>{{ item.label }}</b><small>{{ item.state === 'extension' ? 'EXT' : item.count }}</small></span>
          </div>
          <nav class="finding-stack" aria-label="当前风险发现">
            <button v-for="finding in platform.findings.slice(0, 3)" :key="finding.id" type="button" :class="{ active: finding.id === selectedFindingId }" @click="openFinding(finding.id)">
              <span class="severity-bar" :class="finding.severity"></span>
              <span><strong>{{ finding.title }}</strong><small>{{ finding.id }} · {{ finding.category }}</small></span>
              <span class="finding-state">{{ statusText(finding.status) }}</span>
            </button>
          </nav>
          <footer>
            <router-link to="/findings">查看全部 {{ platform.findings.length }} 项 <ArrowUpRight :size="13" /></router-link>
            <span>3 可执行 · 2 扩展点</span>
          </footer>
        </template>
      </section>

      <aside class="activity-rail" aria-label="审查活动">
        <div class="activity-head"><RadioTower :size="14" /><span>RUN EVENTS</span></div>
        <button v-for="item in platform.activity.slice(0, 3)" :key="item.id" type="button" @click="showActivity(item)">
          <span class="activity-dot" :class="item.type"></span>
          <span><time>{{ item.time }}</time><strong>{{ item.title }}</strong></span>
        </button>
      </aside>

      <div class="graph-legend">
        <span><i class="critical"></i>高风险路径</span><span><i class="verified"></i>已验证边界</span><span><i class="focus"></i>当前上下文</span>
      </div>

      <FindingPeek
        v-if="selectedFinding"
        :finding="selectedFinding"
        :chain="selectedChain"
        :evidence="selectedEvidence"
        :bundle="selectedBundle"
        @close="selectedFindingId = ''"
        @open-evidence="openEvidence"
        @dispatch="platform.dispatchBundle($event)"
      />

      <EvidenceTray :evidence="trayEvidence" :active-id="activeEvidenceId" :open="trayOpen" @toggle="trayOpen = !trayOpen" @select="activeEvidenceId = $event" />
    </div>
    <NewReviewModal />
  </section>
</template>

<script setup>
import { computed, markRaw, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ArrowUpRight, Bot, GitFork, Globe2, History, KeyRound, Network, PanelLeftClose, PanelLeftOpen, Play, RadioTower, RefreshCw, RotateCw, ShieldCheck, Sparkles, Wrench } from 'lucide-vue-next'
import EvidenceTray from '../components/EvidenceTray.vue'
import FindingPeek from '../components/FindingPeek.vue'
import NewReviewModal from '../components/NewReviewModal.vue'
import StageTimeline from '../components/StageTimeline.vue'
import SurfaceGraph from '../components/SurfaceGraph.vue'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const activeStage = ref(platform.selectedRun.activeStage || 'verify')
const selectedFindingId = ref('')
const activeEvidenceId = ref('')
const trayOpen = ref(false)
const signalsCollapsed = ref(false)
let auditTaskPoller = null

const stageLabel = computed(() => platform.stages.find(item => item.id === activeStage.value)?.description || '运行面重建')
const selectedFinding = computed(() => platform.selectedFinding(selectedFindingId.value))
const selectedChain = computed(() => platform.riskChains[selectedFindingId.value] || [])
const selectedEvidence = computed(() => platform.findingEvidence(selectedFindingId.value))
const selectedBundle = computed(() => platform.findingBundle(selectedFindingId.value))
const highlightedNodes = computed(() => selectedFinding.value?.graphNodes || [])
const trayEvidence = computed(() => selectedFindingId.value ? selectedEvidence.value : platform.evidence)

const coverage = computed(() => [
  { label: 'Web', icon: markRaw(Globe2), count: platform.findings.filter(item => item.family === 'web').length, state: 'executable' },
  { label: 'Agent', icon: markRaw(Bot), count: platform.findings.filter(item => item.family === 'agent').length, state: 'executable' },
  { label: 'Secret', icon: markRaw(KeyRound), count: platform.findings.filter(item => item.family === 'secret').length, state: 'executable' },
  { label: 'MCP', icon: markRaw(Wrench), count: platform.findings.filter(item => item.family === 'mcp').length, state: 'extension' },
  { label: 'Flow', icon: markRaw(GitFork), count: platform.findings.filter(item => item.family === 'workflow').length, state: 'extension' }
])

const statusText = value => ({ verifying: '验证中', confirmed: '已确认', static_only: '仅静态', needs_evidence: '待补充证据', blocked: '待授权', candidate: '候选', inconclusive: '证据冲突' }[value] || value)

const selectRun = async event => {
  await platform.selectRun(event.target.value)
  activeStage.value = platform.selectedRun.activeStage || 'recon'
  selectedFindingId.value = ''
}

const auditStatusText = value => ({
  pending: '排队中', running: '运行中', completed: '已完成', failed: '失败'
}[value] || value || '未知')

const formatTaskTime = value => value ? new Date(value).toLocaleString() : '-'
const shortTaskId = value => String(value || '-').slice(0, 12)
const taskResultSummary = task => task.status === 'completed'
  ? `${task.findings_count || 0} 发现 / ${task.remediation_count || 0} 整改包`
  : task.error || '-'

const refreshAuditHistory = async () => {
  try {
    await platform.refreshAuditTasks()
    await platform.loadProjectFindingQueue()
  } catch (error) {
    platform.notify(error.userMessage || error.message || '刷新审计历史失败。', 'error', 'Harness')
  }
}

watch(() => platform.selectedRun.activeStage, stage => {
  if (stage) activeStage.value = stage
})

const queueAuditTask = async (useLlm = false) => {
  try {
    await platform.createAuditTask(undefined, useLlm)
  } catch (error) {
    platform.notify(error.userMessage || error.message || '创建审计任务失败。', 'error', 'Harness')
  }
}

const openFinding = id => {
  selectedFindingId.value = id
  activeEvidenceId.value = platform.findingEvidence(id)[0]?.id || ''
}

const onNodeSelect = node => {
  const finding = platform.findings.find(item => item.graphNodes?.includes(node.id))
  if (finding) openFinding(finding.id)
  else platform.notify(`${node.name} · ${node.meta || node.category}`, 'info', 'Surface node')
}

const openEvidence = id => {
  activeEvidenceId.value = id
  trayOpen.value = true
}

const showActivity = item => platform.notify(item.detail, item.type === 'guard' ? 'warning' : 'info', item.agent)

onMounted(() => {
  signalsCollapsed.value = window.matchMedia('(max-width: 760px)').matches
  auditTaskPoller = window.setInterval(() => {
    if (platform.selectedProjectId && platform.auditTasks.some(task => (
      task.status === 'pending' || task.status === 'running'
    ))) refreshAuditHistory()
  }, 5000)
})

onBeforeUnmount(() => {
  if (auditTaskPoller) window.clearInterval(auditTaskPoller)
})
</script>
