<template>
  <section class="view-page audit-engine-page">
    <div class="page-wrap engine-wrap">
      <header class="page-head engine-head">
        <div>
          <span class="page-kicker">AUTOCVE-CLASS CORE CAPABILITY</span>
          <h1>Agentic Code Audit Engine</h1>
          <p>受 Harness 约束的源码探索、候选审查、证据协调与完成契约。</p>
        </div>
        <div class="head-actions">
          <span class="source-chip demo">架构演示快照</span>
          <span class="status-chip running"><Activity :size="13" />Bounded loop</span>
        </div>
      </header>

      <section class="engine-command-band">
        <div class="engine-mark"><BrainCircuit :size="24" /></div>
        <div class="engine-parent">
          <code>{{ engine.parentTask.id }}</code>
          <strong>{{ engine.parentTask.title }}</strong>
          <small>{{ engine.parentTask.checkpoint }} · {{ engine.parentTask.completion }}</small>
        </div>
        <div class="engine-metrics">
          <span><small>EXECUTABLE LANES</small><strong>03</strong></span>
          <span><small>RUNNING VERIFY</small><strong>{{ runningVerifications }}</strong></span>
        </div>
      </section>

      <div class="engine-layout">
        <aside class="task-graph-panel">
          <header>
            <div><GitBranch :size="16" /><span><strong>Parent / Child tasks</strong><small>隔离状态与独立检查点</small></span></div>
            <b>{{ executableTasks.length }}</b>
          </header>
          <div class="task-tree">
            <button
              v-for="task in visibleTasks"
              :key="task.id"
              type="button"
              :class="[task.kind, task.state, { active: activeTaskId === task.id }]"
              @click="selectTask(task)"
            >
              <span class="task-node"><Bot v-if="task.kind === 'child'" :size="14" /><BrainCircuit v-else-if="task.kind === 'parent'" :size="14" /><CircleDashed v-else :size="14" /></span>
              <span class="task-copy">
                <small>{{ task.id }}</small>
                <strong>{{ task.label }}</strong>
                <em>{{ task.checkpoint }} · {{ task.turn }}</em>
              </span>
              <span class="task-state">{{ taskStateLabel(task.state) }}</span>
            </button>
          </div>
          <footer><ShieldCheck :size="16" /><span><strong>MCP / Workflow</strong><small>保留为扩展点，当前不启动独立 Lane。</small></span></footer>
        </aside>

        <main class="candidate-review-panel">
          <header class="candidate-tabs">
            <button v-for="candidate in engine.candidates" :key="candidate.id" type="button" :class="{ active: candidate.id === activeCandidateId }" @click="activeCandidateId = candidate.id">
              <span :class="candidate.severity"></span><b>{{ candidate.id }}</b><small>{{ candidate.lane }}</small>
            </button>
          </header>

          <section class="candidate-title">
            <div>
              <span class="candidate-kicker">{{ activeCandidate.lane.toUpperCase() }} LANE · TURN {{ activeCandidate.turn }}/{{ activeCandidate.maxTurns }}</span>
              <h2>{{ activeCandidate.title }}</h2>
            </div>
            <div class="candidate-actions">
              <span class="status-chip" :class="activeCandidate.state">{{ candidateStateLabel(activeCandidate.state) }}</span>
              <div class="segmented candidate-mode" aria-label="候选审查视图">
                <button type="button" :class="{ active: viewMode === 'review' }" @click="viewMode = 'review'">审查轨迹</button>
                <button type="button" :class="{ active: viewMode === 'inputs' }" @click="viewMode = 'inputs'">证据输入</button>
                <button type="button" :class="{ active: viewMode === 'contract' }" @click="viewMode = 'contract'">完成契约</button>
              </div>
            </div>
          </section>

          <template v-if="viewMode === 'review'">
            <div class="review-cycle" aria-label="候选审查状态机">
              <div class="done"><span>01</span><strong>Observe</strong><small>candidate + hypothesis</small></div>
              <ChevronRight :size="15" />
              <div class="done"><span>02</span><strong>Tool calls</strong><small>read-only evidence</small></div>
              <ChevronRight :size="15" />
              <div :class="activeCandidate.state === 'evidence_review' ? 'running' : 'done'"><span>03</span><strong>Reconcile</strong><small>support + contradiction</small></div>
              <ChevronRight :size="15" />
              <div :class="activeCandidate.state === 'evidence_review' ? 'waiting' : 'done'"><span>04</span><strong>FinalizeFinding</strong><small>completion contract</small></div>
            </div>

            <section class="agent-transcript">
              <header><span>AGENT TRANSCRIPT / TOOL CALLS</span><b>{{ activeCandidate.transcript.length }} entries</b></header>
              <div v-for="entry in activeCandidate.transcript" :key="`${entry.time}-${entry.title}`" :class="entry.type">
                <span class="transcript-symbol">
                  <Wrench v-if="entry.type === 'tool'" :size="15" />
                  <ShieldCheck v-else-if="entry.type === 'guard'" :size="15" />
                  <Braces v-else-if="entry.type === 'finalize'" :size="15" />
                  <Bot v-else :size="15" />
                </span>
                <span class="transcript-copy"><small>{{ entry.actor }} · {{ entry.time }}</small><strong>{{ entry.title }}</strong><p>{{ entry.detail }}</p></span>
              </div>
            </section>
          </template>

          <section v-else-if="viewMode === 'inputs'" class="signal-input-panel">
            <header><ScanSearch :size="18" /><span><strong>Candidate evidence inputs</strong><small>三类信号进入同一个审查契约</small></span></header>
            <div class="signal-source-row">
              <div v-for="signal in activeCandidate.signals" :key="signal.type" :class="signal.tone">
                <ScanSearch v-if="signal.tone === 'tool'" :size="19" />
                <Radar v-else-if="signal.tone === 'hypothesis'" :size="19" />
                <FileSearch v-else :size="19" />
                <span><small>{{ signal.type }}</small><strong>{{ signal.label }}</strong></span>
              </div>
            </div>
          </section>

          <section v-else class="completion-panel completion-inline">
            <header><ListChecks :size="17" /><span><strong>Completion contract</strong><small>FinalizeFinding</small></span></header>
            <div class="contract-overview">
              <div class="contract-score"><strong>{{ completedContracts }}/{{ activeCandidate.contract.length }}</strong><span><i :style="{ width: `${contractProgress}%` }"></i></span><small>必填字段已满足</small></div>
              <div class="contract-list">
                <div v-for="item in activeCandidate.contract" :key="item.label" :class="item.state"><CircleCheck v-if="item.state === 'done'" :size="16" /><Clock3 v-else :size="16" /><span>{{ item.label }}</span></div>
              </div>
            </div>
            <div class="contract-notes">
              <div class="guard-box"><TriangleAlert :size="16" /><span><strong>ReasoningGuard</strong><small>证据缺口存在时阻止提前完成。</small></span></div>
              <div class="provider-gate"><KeyRound :size="16" /><span><strong>LLM credential gate</strong><small><code>--use-llm</code> 缺少显式 key 时立即失败。</small></span></div>
            </div>
            <button class="button contract-json-button" type="button" @click="showContract = !showContract"><Braces :size="15" />{{ showContract ? '收起契约' : '查看契约 JSON' }}</button>
            <pre v-if="showContract">{{ contractJson }}</pre>
          </section>
        </main>
      </div>

      <section class="verification-ledger">
        <header><div><ShieldCheck :size="17" /><span><strong>Finding-level verification children</strong><small>独立有界循环 · FinalizeVerification</small></span></div><span class="status-chip processing">{{ runningVerifications }} running</span></header>
        <div class="verification-row" v-for="task in engine.verificationTasks" :key="task.id">
          <span class="verification-mark" :class="task.state"><RotateCcw v-if="task.state === 'running'" :size="15" /><CircleCheck v-else :size="15" /></span>
          <span class="verification-copy"><code>{{ task.id }}</code><strong>{{ task.title }}</strong><small>parent {{ task.parentId }}</small></span>
          <span><small>TOOL</small><strong>{{ task.tool }}</strong></span>
          <span><small>LEVEL</small><strong>{{ task.level }}</strong></span>
          <span><small>TURNS</small><strong>{{ task.turn }}</strong></span>
          <span class="status-chip" :class="task.state">{{ taskStateLabel(task.state) }}</span>
        </div>
      </section>
    </div>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import { Activity, Bot, Braces, BrainCircuit, ChevronRight, CircleCheck, CircleDashed, Clock3, FileSearch, GitBranch, KeyRound, ListChecks, Radar, RotateCcw, ScanSearch, ShieldCheck, TriangleAlert, Wrench } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const engine = platform.auditEngine
const activeCandidateId = ref(engine.candidates[0].id)
const activeTaskId = ref(engine.tasks[1].id)
const showContract = ref(false)
const viewMode = ref('review')

const activeCandidate = computed(() => engine.candidates.find(item => item.id === activeCandidateId.value) || engine.candidates[0])
const executableTasks = computed(() => engine.tasks.filter(item => item.kind !== 'extension'))
const visibleTasks = computed(() => engine.tasks.filter(item => item.kind !== 'extension'))
const completedContracts = computed(() => activeCandidate.value.contract.filter(item => item.state === 'done').length)
const contractProgress = computed(() => Math.round(completedContracts.value / activeCandidate.value.contract.length * 100))
const runningVerifications = computed(() => engine.verificationTasks.filter(item => item.state === 'running').length)
const contractJson = computed(() => JSON.stringify({
  candidate_id: activeCandidate.value.id,
  action: 'FinalizeFinding',
  required: ['verdict', 'evidence_refs', 'contradictions', 'evidence_gaps', 'next_actions'],
  state: activeCandidate.value.state
}, null, 2))

const taskStateLabel = state => ({ running: '运行中', completed: '已完成', degraded: '降级', extension: '扩展点' }[state] || state)
const candidateStateLabel = state => ({ evidence_review: '证据审查中', finalized: '已完成契约', rejected: '已排除' }[state] || state)
const selectTask = task => {
  activeTaskId.value = task.id
  const candidate = engine.candidates.find(item => item.lane === task.lane)
  if (candidate) activeCandidateId.value = candidate.id
  if (task.kind === 'extension') platform.notify(`${task.label} 当前是架构扩展点，未作为本地可执行 Lane。`, 'warning', 'Lane status')
}
</script>

<style scoped>
.engine-wrap { max-width: 1540px; }
.engine-head { margin-bottom: 16px; }
.engine-command-band { display: grid; min-height: 92px; grid-template-columns: 54px minmax(260px, 1fr) auto; align-items: center; gap: 14px; padding: 14px 18px; border: 1px solid var(--line); background: var(--canvas-soft); }
.engine-mark { display: grid; width: 46px; height: 46px; place-items: center; border: 1px solid color-mix(in srgb, var(--focus) 40%, var(--line)); border-radius: 8px 3px 8px 3px; background: var(--focus-soft); color: var(--focus); }
.engine-parent { display: grid; min-width: 0; }
.engine-parent code { color: var(--focus); font-size: 13px; }
.engine-parent strong { margin-top: 3px; font-size: 19px; }
.engine-parent small { color: var(--ink-muted); font-family: var(--font-mono); font-size: 13px; }
.engine-metrics { display: grid; grid-template-columns: repeat(2, minmax(130px, 1fr)); }
.engine-metrics span { display: grid; gap: 3px; padding: 5px 16px; border-left: 1px solid var(--line); }
.engine-metrics small { color: var(--ink-muted); font-family: var(--font-mono); font-size: 12px; }
.engine-metrics strong { font-family: var(--font-display); font-size: 23px; }
.engine-layout { display: grid; min-height: 620px; margin-top: 16px; grid-template-columns: 320px minmax(0, 1fr); border: 1px solid var(--line); background: var(--canvas-soft); }
.task-graph-panel, .completion-panel { min-width: 0; }
.task-graph-panel { border-right: 1px solid var(--line); }
.task-graph-panel > header, .completion-panel > header, .verification-ledger > header { display: flex; min-height: 58px; align-items: center; justify-content: space-between; gap: 9px; padding: 0 13px; border-bottom: 1px solid var(--line); }
.task-graph-panel > header > div, .completion-panel > header, .verification-ledger > header > div { display: flex; align-items: center; gap: 9px; }
.task-graph-panel header span, .completion-panel header span, .verification-ledger header span { display: grid; }
.task-graph-panel header strong, .completion-panel header strong, .verification-ledger header strong { font-size: 13px; }
.task-graph-panel header small, .completion-panel header small, .verification-ledger header small { color: var(--ink-muted); font-size: 13px; }
.task-graph-panel header b { color: var(--focus); font-family: var(--font-mono); font-size: 12px; }
.task-tree { position: relative; display: grid; gap: 4px; padding: 10px; }
.task-tree::before { position: absolute; top: 75px; bottom: 84px; left: 31px; width: 1px; background: var(--line-strong); content: ''; }
.task-tree button { position: relative; z-index: 1; display: grid; width: 100%; min-height: 80px; grid-template-columns: 38px minmax(0, 1fr) auto; align-items: center; gap: 9px; padding: 10px; border: 1px solid transparent; border-radius: var(--radius-sm); background: transparent; color: var(--ink-muted); cursor: pointer; text-align: left; }
.task-tree button.child { margin-left: 14px; width: calc(100% - 14px); }
.task-tree button:hover { background: var(--surface); }
.task-tree button.active { border-color: color-mix(in srgb, var(--focus) 34%, var(--line)); background: var(--focus-soft); }
.task-tree button.extension { opacity: .72; }
.task-node { display: grid; width: 36px; height: 36px; place-items: center; border: 1px solid var(--line-strong); border-radius: 8px 3px 8px 3px; background: var(--surface-raised); color: var(--ink-muted); }
.task-tree .running .task-node { border-color: var(--focus); color: var(--focus); }
.task-tree .completed .task-node { color: var(--verified); }
.task-tree .degraded .task-node { color: var(--warning); }
.task-copy { display: grid; min-width: 0; }
.task-copy small, .task-copy em { overflow: hidden; font-family: var(--font-mono); font-size: 12px; font-style: normal; text-overflow: ellipsis; white-space: nowrap; }
.task-copy strong { overflow: hidden; color: var(--ink-secondary); font-size: 15px; text-overflow: ellipsis; white-space: nowrap; }
.task-copy em { color: var(--ink-muted); }
.task-state { font-size: 13px; white-space: nowrap; }
.task-graph-panel > footer { display: flex; align-items: flex-start; gap: 10px; margin: 10px 14px 14px; padding: 14px; border: 1px solid var(--line); color: var(--ink-muted); }
.task-graph-panel > footer span { display: grid; }
.task-graph-panel > footer strong { color: var(--ink-secondary); font-size: 13px; }
.task-graph-panel > footer small { margin-top: 3px; font-size: 13px; line-height: 1.55; }
.candidate-review-panel { min-width: 0; }
.candidate-tabs { display: flex; min-height: 58px; border-bottom: 1px solid var(--line); overflow-x: auto; }
.candidate-tabs button { position: relative; display: grid; min-width: 126px; grid-template-columns: 7px auto; align-content: center; gap: 1px 7px; padding: 0 13px; border-right: 1px solid var(--line); background: transparent; color: var(--ink-muted); cursor: pointer; text-align: left; }
.candidate-tabs button.active { background: var(--surface); color: var(--ink); }
.candidate-tabs button.active::after { position: absolute; right: 12px; bottom: 0; left: 12px; height: 2px; background: var(--focus); content: ''; }
.candidate-tabs button > span { width: 7px; height: 7px; grid-row: span 2; border-radius: 2px; background: var(--ink-muted); }
.candidate-tabs button > span.critical, .candidate-tabs button > span.high { background: var(--critical); }
.candidate-tabs button > span.medium { background: var(--warning); }
.candidate-tabs button > span.low { background: var(--verified); }
.candidate-tabs b { font-family: var(--font-mono); font-size: 12px; }
.candidate-tabs small { font-size: 13px; }
.candidate-title { display: flex; align-items: flex-start; justify-content: space-between; gap: 22px; padding: 22px 22px 18px; }
.candidate-kicker { color: var(--focus); font-family: var(--font-mono); font-size: 13px; }
.candidate-title h2 { max-width: 720px; margin: 8px 0 0; font-family: var(--font-display); font-size: 29px; line-height: 1.3; }
.candidate-actions { display: grid; flex: 0 0 auto; justify-items: end; gap: 10px; }
.candidate-mode button { min-width: 86px; }
.status-chip.evidence_review { background: var(--focus-soft); color: var(--focus); }
.status-chip.finalized { background: var(--verified-soft); color: var(--verified); }
.status-chip.rejected { background: var(--surface-hover); color: var(--ink-muted); }
.review-cycle { display: grid; margin: 0 22px 16px; grid-template-columns: repeat(4, minmax(110px, 1fr)); align-items: center; gap: 8px; }
.review-cycle > div { display: grid; min-height: 74px; grid-template-columns: 32px minmax(0, 1fr); align-content: center; gap: 2px 9px; padding: 10px; border: 1px solid var(--line); }
.review-cycle > div > span { display: grid; width: 28px; height: 28px; grid-row: span 2; place-items: center; border: 1px solid var(--line-strong); border-radius: 50%; font-family: var(--font-mono); font-size: 12px; }
.review-cycle .done > span { border-color: var(--verified); background: var(--verified-soft); color: var(--verified); }
.review-cycle .running > span { border-color: var(--focus); background: var(--focus-soft); color: var(--focus); animation: pulse 1.4s ease-in-out infinite; }
.review-cycle strong { font-size: 14px; }
.review-cycle small { color: var(--ink-muted); font-size: 12px; }
.review-cycle > svg { display: none; color: var(--line-strong); }
.signal-source-row { display: grid; margin: 0 22px 16px; grid-template-columns: repeat(3, 1fr); border: 1px solid var(--line); }
.signal-source-row > div { display: flex; min-height: 68px; align-items: center; gap: 10px; padding: 10px 12px; border-right: 1px solid var(--line); }
.signal-source-row > div:last-child { border-right: 0; }
.signal-source-row svg { color: var(--focus); }
.signal-source-row .hypothesis svg { color: var(--relay); }
.signal-source-row .source svg { color: var(--verified); }
.signal-source-row span { display: grid; min-width: 0; }
.signal-source-row small { color: var(--ink-muted); font-size: 13px; }
.signal-source-row strong { overflow: hidden; font-size: 15px; text-overflow: ellipsis; white-space: nowrap; }
.agent-transcript { margin: 0 22px 22px; border: 1px solid var(--line); }
.agent-transcript > header { display: flex; min-height: 48px; align-items: center; justify-content: space-between; padding: 0 14px; border-bottom: 1px solid var(--line); color: var(--ink-muted); font-family: var(--font-mono); font-size: 12px; }
.agent-transcript > header b { color: var(--focus); }
.agent-transcript > div { display: grid; min-height: 78px; grid-template-columns: 38px minmax(0, 1fr); align-items: center; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--line); }
.agent-transcript > div:last-child { border-bottom: 0; }
.transcript-symbol { display: grid; width: 30px; height: 30px; place-items: center; border: 1px solid var(--line-strong); border-radius: 50%; color: var(--ink-muted); }
.agent-transcript .tool .transcript-symbol { color: var(--focus); }
.agent-transcript .guard .transcript-symbol { border-radius: 7px 2px 7px 2px; color: var(--warning); }
.agent-transcript .finalize .transcript-symbol { color: var(--verified); }
.transcript-copy { display: grid; min-width: 0; }
.transcript-copy small { color: var(--ink-muted); font-family: var(--font-mono); font-size: 12px; }
.transcript-copy strong { font-size: 15px; }
.transcript-copy p { margin: 4px 0 0; color: var(--ink-muted); font-size: 14px; line-height: 1.6; }
.signal-input-panel { margin: 0 22px 22px; border: 1px solid var(--line); }
.signal-input-panel > header { display: flex; min-height: 64px; align-items: center; gap: 10px; padding: 0 16px; border-bottom: 1px solid var(--line); }
.signal-input-panel > header span { display: grid; }
.signal-input-panel > header strong { font-size: 15px; }
.signal-input-panel > header small { color: var(--ink-muted); font-size: 13px; }
.signal-input-panel .signal-source-row { margin: 0; border: 0; }
.completion-panel { margin: 0 22px 22px; padding-bottom: 16px; border: 1px solid var(--line); }
.completion-panel > header { justify-content: flex-start; }
.contract-overview { display: grid; grid-template-columns: 220px minmax(0, 1fr); border-bottom: 1px solid var(--line); }
.contract-score { display: grid; justify-items: center; align-content: center; gap: 9px; padding: 24px 20px; border-right: 1px solid var(--line); }
.contract-score > strong { font-family: var(--font-display); font-size: 26px; }
.contract-score > span { width: 100%; height: 4px; border-radius: 2px; background: var(--line); overflow: hidden; }
.contract-score i { display: block; height: 100%; background: var(--verified); transition: width var(--motion-normal); }
.contract-score small { color: var(--ink-muted); font-size: 12px; }
.contract-list { padding: 10px 18px; }
.contract-list > div { display: grid; min-height: 44px; grid-template-columns: 26px minmax(0, 1fr); align-items: center; gap: 7px; border-bottom: 1px solid var(--line); color: var(--ink-muted); font-size: 13px; }
.contract-list .done svg { color: var(--verified); }
.contract-list .waiting svg { color: var(--warning); }
.contract-notes { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; padding: 16px; }
.guard-box, .provider-gate { display: flex; align-items: flex-start; gap: 10px; margin: 0; padding: 14px; border: 1px solid color-mix(in srgb, var(--warning) 35%, var(--line)); background: var(--warning-soft); color: var(--warning); }
.guard-box span, .provider-gate span { display: grid; }
.guard-box strong, .provider-gate strong { font-size: 13px; }
.guard-box small, .provider-gate small { font-size: 12px; line-height: 1.55; }
.completion-panel > .contract-json-button { margin: 0 16px; }
.completion-panel pre { max-height: 240px; margin: 12px 16px 0; padding: 14px; background: var(--code-bg); color: var(--code-ink); font-size: 12px; overflow: auto; white-space: pre-wrap; }
.provider-gate { border-color: color-mix(in srgb, var(--focus) 30%, var(--line)); background: var(--focus-soft); color: var(--focus); }
.provider-gate code { color: inherit; }
.verification-ledger { margin-top: 12px; border: 1px solid var(--line); background: var(--canvas-soft); }
.verification-row { display: grid; min-height: 72px; grid-template-columns: 40px minmax(260px, 1fr) 150px 70px 80px auto; align-items: center; gap: 10px; padding: 8px 13px; border-bottom: 1px solid var(--line); }
.verification-row:last-child { border-bottom: 0; }
.verification-mark { display: grid; width: 34px; height: 34px; place-items: center; border: 1px solid var(--line-strong); border-radius: 50%; color: var(--verified); }
.verification-mark.running { color: var(--focus); }
.verification-mark.running svg { animation: spin 1.2s linear infinite; }
.verification-copy { display: grid; }
.verification-copy code { color: var(--focus); font-size: 12px; }
.verification-copy strong { font-size: 13px; }
.verification-copy small { color: var(--ink-muted); font-size: 12px; }
.verification-row > span:not(.verification-mark):not(.verification-copy):not(.status-chip) { display: grid; }
.verification-row > span > small { color: var(--ink-muted); font-size: 12px; }
.verification-row > span > strong { font-family: var(--font-mono); font-size: 12px; }
@media (max-width: 1250px) {
  .engine-command-band { grid-template-columns: 54px minmax(220px, 1fr); }
  .engine-metrics { grid-column: 1 / -1; border-top: 1px solid var(--line); }
  .engine-metrics span:first-child { border-left: 0; }
  .engine-layout { grid-template-columns: 280px minmax(0, 1fr); }
}
@media (max-width: 900px) {
  .engine-layout { grid-template-columns: 1fr; }
  .task-graph-panel, .candidate-review-panel { border-right: 0; border-bottom: 1px solid var(--line); }
  .task-tree { grid-template-columns: repeat(2, 1fr); }
  .task-tree::before { display: none; }
  .task-tree button.child { width: 100%; margin-left: 0; }
  .verification-row { grid-template-columns: 40px minmax(220px, 1fr) auto; }
  .verification-row > span:nth-child(3), .verification-row > span:nth-child(4), .verification-row > span:nth-child(5) { display: none !important; }
}
@media (max-width: 760px) {
  .engine-command-band { grid-template-columns: 46px minmax(0, 1fr); padding: 12px; }
  .engine-mark { width: 40px; height: 40px; }
  .engine-metrics { grid-template-columns: repeat(2, 1fr); }
  .engine-metrics span { padding: 8px; }
  .engine-metrics span:nth-child(odd) { border-left: 0; }
  .task-tree { grid-template-columns: 1fr; }
  .candidate-title { flex-direction: column; }
  .candidate-actions { width: 100%; grid-template-columns: auto 1fr; align-items: center; justify-items: start; }
  .review-cycle { grid-template-columns: repeat(2, 1fr); }
  .signal-source-row { grid-template-columns: 1fr; }
  .signal-source-row > div { border-right: 0; border-bottom: 1px solid var(--line); }
  .signal-source-row > div:last-child { border-bottom: 0; }
  .contract-overview, .contract-notes { grid-template-columns: 1fr; }
  .contract-score { border-right: 0; border-bottom: 1px solid var(--line); }
  .verification-row { grid-template-columns: 36px minmax(0, 1fr); }
  .verification-row > .status-chip { grid-column: 2; }
}
</style>
