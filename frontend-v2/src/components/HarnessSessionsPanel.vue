<template>
  <section class="foundation-panel harness-panel">
    <header class="foundation-toolbar harness-toolbar">
      <div><span class="toolbar-kicker">LOCAL SESSION LEDGER</span><strong>RunSession / Checkpoint</strong></div>
      <div class="inline-actions">
        <button class="button" type="button" @click="showObjects"><Braces :size="14" />对象清单</button>
        <button class="button primary" type="button" @click="resume"><Play :size="14" />从检查点继续</button>
      </div>
    </header>

    <div class="harness-layout">
      <main class="session-ledger">
        <section class="session-identity">
          <div>
            <span class="session-kicker">{{ platform.selectedRun.id }} · {{ triggerLabel(platform.selectedRun.trigger) }}</span>
            <h2>{{ platform.selectedRun.name }}</h2>
            <p>{{ platform.selectedRun.project }} / {{ platform.selectedRun.branch }} / {{ platform.selectedRun.commit }}</p>
          </div>
          <span class="status-chip" :class="platform.selectedRun.status">{{ statusLabel(platform.selectedRun.status) }}</span>
        </section>

        <div class="session-contracts">
          <span><small>Scope</small><strong>{{ scopeLabel(platform.selectedRun.scope) }}</strong></span>
          <span><small>Checkpoint</small><strong>{{ platform.selectedRun.checkpoint }}</strong></span>
          <span><small>Verification target</small><strong>L{{ platform.selectedRun.verificationTarget }}</strong></span>
          <span><small>Persistence</small><strong>JSONL / SQLite</strong></span>
        </div>

        <section class="phase-contract">
          <header><span>DETERMINISTIC ORCHESTRATION</span><b>{{ completedStages }}/{{ platform.stages.length }}</b></header>
          <div class="phase-contract-grid">
            <div v-for="(stage, index) in platform.stages" :key="stage.id" :class="stage.status">
              <span><Check v-if="stage.status === 'completed'" :size="13" /><LoaderCircle v-else-if="stage.status === 'running'" :size="13" class="spin" /><b v-else>{{ index + 1 }}</b></span>
              <strong>{{ stage.label }}</strong><small>{{ stage.description }}</small>
            </div>
          </div>
        </section>

        <section class="event-ledger">
          <header><span>RUN EVENTS</span><b>{{ platform.activity.length }}</b></header>
          <button v-for="event in platform.activity" :key="event.id" type="button" @click="inspectEvent(event)">
            <time>{{ event.time }}</time><span class="event-shape" :class="event.type"></span><span><strong>{{ event.title }}</strong><small>{{ event.agent }} · {{ event.detail }}</small></span><ChevronRight :size="14" />
          </button>
        </section>
      </main>

      <aside class="harness-side">
        <section class="checkpoint-list">
          <header><History :size="15" /><span><strong>检查点</strong><small>可恢复状态快照</small></span></header>
          <div v-for="item in checkpoints" :key="item.id">
            <span :class="item.status"><Check v-if="item.status === 'completed'" :size="12" /><CircleDashed v-else :size="12" /></span>
            <span><strong>{{ item.id }}</strong><small>{{ item.phase }} · {{ item.time }}</small></span>
          </div>
        </section>

        <section class="gate-list">
          <header><ShieldCheck :size="15" /><span><strong>Workflow Gates</strong><small>Harness 控制状态迁移</small></span></header>
          <div v-for="gate in gates" :key="gate.label"><component :is="gate.icon" :size="15" /><span><strong>{{ gate.label }}</strong><small>{{ gate.detail }}</small></span><span class="status-chip" :class="gate.tone">{{ gate.state }}</span></div>
        </section>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { computed, markRaw } from 'vue'
import { Braces, Check, ChevronRight, CircleDashed, FileLock2, GitMerge, History, LoaderCircle, Play, ScanSearch, ShieldCheck, UserRoundCheck } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const completedStages = computed(() => platform.stages.filter(item => item.status === 'completed').length)
const checkpoints = computed(() => {
  const material = platform.stages.filter(item => ['completed', 'running'].includes(item.status)).slice(-4)
  return material.reverse().map((stage, index) => ({ id: index === 0 ? platform.selectedRun.checkpoint : `CP-${stage.id.toUpperCase()}-${String(material.length - index).padStart(2, '0')}`, phase: stage.label, time: stage.duration, status: stage.status }))
})
const gates = [
  { label: 'Scope gate', detail: 'changed_files 已锁定', state: '通过', tone: 'completed', icon: markRaw(FileLock2) },
  { label: 'Lane handoff', detail: '3 条可执行 Lane 已合并', state: '通过', tone: 'completed', icon: markRaw(GitMerge) },
  { label: 'Evidence gate', detail: '仍有 2 个 evidence gaps', state: '阻断', tone: 'blocked', icon: markRaw(ScanSearch) },
  { label: 'Human confirmation', detail: '破坏性修复必须确认', state: '强制', tone: 'verifying', icon: markRaw(UserRoundCheck) }
]
const triggerLabel = value => ({ claude_code_skill: 'Claude Code Skill', cli: 'CLI', suggested_policy: '策略建议', api_adapter: 'FastAPI adapter' }[value] || value || 'Explicit')
const scopeLabel = value => ({ changed_files: 'Changed files', linked_task: 'Linked task', project: 'Whole project' }[value] || value || 'Project')
const statusLabel = value => ({ processing: '运行中', completed: '已完成', failed: '失败', pending: '等待中' }[value] || value)
const inspectEvent = event => platform.notify(event.detail, event.type === 'guard' ? 'warning' : 'info', `${event.agent} · ${event.time}`)
const resume = () => platform.notify(`将从 ${platform.selectedRun.checkpoint} 恢复；当前 V2 Session API 尚未接入 FastAPI。`, 'warning', 'Checkpoint adapter')
const showObjects = () => platform.notify('RunSession · RunEvent · Checkpoint · ProjectProfile · RuntimeSurfaceGraph · RuntimeThreatModel · RiskHypothesis · Finding · RiskChain · EvidenceBundle · ValidationSession · RemediationBundle · RegressionReport · ToolSpec · ToolSignal · ArtifactRef', 'info', 'V2 stable objects')
</script>

<style scoped>
.harness-panel { min-height: 640px; }
.harness-layout { display: grid; min-height: 574px; grid-template-columns: minmax(0, 1fr) 320px; }
.session-ledger { min-width: 0; padding: 20px; border-right: 1px solid var(--line); }
.session-identity { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
.session-kicker { color: var(--focus); font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; }
.session-identity h2 { margin: 7px 0 4px; font-size: 23px; }
.session-identity p { margin: 0; color: var(--ink-muted); font-family: var(--font-mono); font-size: 11px; }
.session-contracts { display: grid; margin: 18px 0; grid-template-columns: repeat(4, 1fr); border: 1px solid var(--line); border-radius: var(--radius-md); overflow: hidden; }
.session-contracts > span { display: grid; min-width: 0; gap: 3px; padding: 11px 12px; border-right: 1px solid var(--line); }
.session-contracts > span:last-child { border-right: 0; }
.session-contracts small { color: var(--ink-muted); font-size: 10px; }
.session-contracts strong { overflow: hidden; font-family: var(--font-mono); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.phase-contract,
.event-ledger { border: 1px solid var(--line); border-radius: var(--radius-md); overflow: hidden; }
.phase-contract > header,
.event-ledger > header { display: flex; min-height: 40px; align-items: center; justify-content: space-between; padding: 0 12px; border-bottom: 1px solid var(--line); color: var(--ink-muted); font-family: var(--font-mono); font-size: 10px; }
.phase-contract > header b,
.event-ledger > header b { color: var(--focus); }
.phase-contract-grid { display: grid; grid-template-columns: repeat(9, minmax(74px, 1fr)); overflow-x: auto; }
.phase-contract-grid > div { display: grid; min-width: 74px; min-height: 94px; justify-items: center; align-content: center; gap: 4px; padding: 8px 4px; border-right: 1px solid var(--line); color: var(--ink-muted); text-align: center; }
.phase-contract-grid > div:last-child { border-right: 0; }
.phase-contract-grid > div > span { display: grid; width: 24px; height: 24px; place-items: center; border: 1px solid var(--line-strong); border-radius: 50%; font-family: var(--font-mono); font-size: 10px; }
.phase-contract-grid .completed > span { border-color: var(--verified); background: var(--verified-soft); color: var(--verified); }
.phase-contract-grid .running > span { border-color: var(--focus); background: var(--focus-soft); color: var(--focus); }
.phase-contract-grid strong { color: var(--ink-secondary); font-size: 11px; }
.phase-contract-grid small { font-size: 10px; }
.event-ledger { margin-top: 14px; }
.event-ledger button { display: grid; width: 100%; min-height: 54px; grid-template-columns: 58px 12px minmax(0, 1fr) 18px; align-items: center; gap: 8px; padding: 5px 11px; border-bottom: 1px solid var(--line); background: transparent; color: var(--ink-muted); cursor: pointer; text-align: left; }
.event-ledger button:last-child { border-bottom: 0; }
.event-ledger button:hover { background: var(--surface); }
.event-ledger time { font-family: var(--font-mono); font-size: 10px; }
.event-ledger button > span:nth-child(3) { display: grid; min-width: 0; }
.event-ledger strong { color: var(--ink-secondary); font-size: 12px; }
.event-ledger small { overflow: hidden; margin-top: 2px; font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.event-shape { width: 7px; height: 7px; border-radius: 2px; background: var(--focus); }
.event-shape.pass { border-radius: 50%; background: var(--verified); }
.event-shape.guard { background: var(--warning); transform: rotate(45deg); }
.event-shape.handoff { background: var(--relay); }
.harness-side { display: grid; align-content: start; gap: 14px; padding: 14px; background: var(--canvas-soft); }
.checkpoint-list,
.gate-list { border: 1px solid var(--line); border-radius: var(--radius-md); background: var(--surface); overflow: hidden; }
.checkpoint-list > header,
.gate-list > header { display: flex; min-height: 50px; align-items: center; gap: 8px; padding: 0 11px; border-bottom: 1px solid var(--line); }
.checkpoint-list header span,
.gate-list header span,
.checkpoint-list > div > span:last-child,
.gate-list > div > span:nth-child(2) { display: grid; min-width: 0; }
.checkpoint-list header strong,
.gate-list header strong { font-size: 12px; }
.checkpoint-list header small,
.gate-list header small { color: var(--ink-muted); font-size: 10px; }
.checkpoint-list > div { display: grid; min-height: 52px; grid-template-columns: 28px minmax(0, 1fr); align-items: center; gap: 7px; padding: 5px 10px; border-bottom: 1px solid var(--line); }
.checkpoint-list > div:last-child { border-bottom: 0; }
.checkpoint-list > div > span:first-child { display: grid; width: 24px; height: 24px; place-items: center; border: 1px solid var(--line); border-radius: 50%; color: var(--ink-muted); }
.checkpoint-list > div > span:first-child.completed { color: var(--verified); }
.checkpoint-list > div strong { font-family: var(--font-mono); font-size: 10px; }
.checkpoint-list > div small { color: var(--ink-muted); font-size: 10px; }
.gate-list > div { display: grid; min-height: 66px; grid-template-columns: 24px minmax(0, 1fr) auto; align-items: center; gap: 7px; padding: 7px 10px; border-bottom: 1px solid var(--line); }
.gate-list > div:last-child { border-bottom: 0; }
.gate-list > div > svg { color: var(--ink-muted); }
.gate-list > div strong { font-size: 11px; }
.gate-list > div small { color: var(--ink-muted); font-size: 10px; }
.spin { animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (max-width: 1050px) {
  .harness-layout { grid-template-columns: 1fr; }
  .session-ledger { border-right: 0; border-bottom: 1px solid var(--line); }
  .harness-side { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 760px) {
  .harness-toolbar { align-items: flex-start; flex-direction: column; padding: 12px; }
  .session-ledger { padding: 12px; }
  .session-contracts { grid-template-columns: repeat(2, 1fr); }
  .session-contracts > span:nth-child(2) { border-right: 0; }
  .session-contracts > span:nth-child(-n + 2) { border-bottom: 1px solid var(--line); }
  .harness-side { grid-template-columns: 1fr; }
}
</style>
