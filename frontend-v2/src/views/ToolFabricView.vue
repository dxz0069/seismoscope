<template>
  <section class="view-page tool-fabric-page">
    <div class="page-wrap fabric-wrap">
      <header class="page-head fabric-head">
        <div>
          <span class="page-kicker">CONTROLLED SECURITY TOOL EXECUTION</span>
          <h1>Fast Scanner &amp; Tool Fabric</h1>
          <p>统一 ToolSpec、权限检查、隔离执行、ArtifactRef 与 ToolSignal，Agent runtime 保持在容器之外。</p>
        </div>
        <div class="head-actions"><span class="source-chip demo">后端适配待接入</span><span class="status-chip active"><PackageSearch :size="13" />{{ enabledCount }} in profile</span></div>
      </header>

      <section class="signal-rule-banner">
        <ScanSearch :size="17" />
        <span><strong>Tool result = Signal</strong><small>扫描器输出不会自动成为 Finding；仍需 Agent 审查、证据绑定、去重与验证契约。</small></span>
        <router-link to="/audit-engine">进入审计引擎 <ArrowUpRight :size="13" /></router-link>
      </section>

      <nav class="fabric-tabs" aria-label="工具织网视图">
        <button type="button" :class="{ active: fabricView === 'registry' }" @click="fabricView = 'registry'"><PackageSearch :size="17" />工具清单</button>
        <button type="button" :class="{ active: fabricView === 'boundary' }" @click="fabricView = 'boundary'"><Container :size="17" />执行边界</button>
        <button type="button" :class="{ active: fabricView === 'history' }" @click="fabricView = 'history'"><History :size="17" />执行记录</button>
      </nav>

      <section v-if="fabricView === 'boundary'" class="execution-boundary">
        <header><span>EXECUTION BOUNDARY</span><code>{{ fabric.profile }}</code></header>
        <div class="boundary-flow">
          <div class="runtime-node"><span><BrainCircuit :size="19" /></span><strong>Agent runtime</strong><small>host process · outside container</small></div>
          <div class="boundary-link"><ArrowRight :size="17" /><small>ToolRequest</small></div>
          <div class="gateway-node"><span><ShieldCheck :size="19" /></span><strong>Permission gateway</strong><small>allow-list · grants · audit log</small></div>
          <div class="boundary-link"><ArrowRight :size="17" /><small>approved</small></div>
          <div class="container-zone">
            <span class="zone-label"><Container :size="14" />FOCUSED CONTAINER</span>
            <div><Boxes :size="20" /><span><strong>{{ fabric.image }}</strong><small>only selected tools</small></span></div>
          </div>
          <div class="boundary-link"><ArrowRight :size="17" /><small>ArtifactRef</small></div>
          <div class="signal-node"><span><FileOutput :size="19" /></span><strong>ToolSignal</strong><small>normalized observation</small></div>
        </div>
        <footer><span><MapPin :size="14" />{{ fabric.runtimeLocation }}</span><span><LockKeyhole :size="14" />{{ fabric.permissionMode }}</span></footer>
      </section>

      <div v-if="fabricView === 'registry'" class="fabric-workbench">
        <main class="tool-registry">
          <header><div><PackageSearch :size="16" /><span><strong>Tool profile registry</strong><small>Profile 选择不代表适配器已在当前 FastAPI 后端落地</small></span></div><span class="registry-count">{{ fabric.tools.length }} specs</span></header>
          <div class="tool-table-head"><span>TOOL</span><span>CATEGORY</span><span>ADAPTER</span><span>PROFILE</span></div>
          <div v-for="tool in fabric.tools" :key="tool.id" class="tool-row" :class="{ active: activeToolId === tool.id }" :data-tool-id="tool.id">
            <button class="tool-identity" type="button" :aria-label="`查看 ${tool.name} 详情`" @click="activeToolId = tool.id"><span :class="tool.state"><TerminalSquare :size="16" /></span><span><strong>{{ tool.name }}</strong><small>{{ tool.id }}</small></span></button>
            <span class="tool-cell"><small>{{ tool.category }}</small></span>
            <span><em class="adapter-state" :class="tool.state">{{ toolStateLabel(tool.state) }}</em></span>
            <span class="tool-toggle">
              <label class="switch" :title="tool.enabled ? '从当前 Profile 移除' : '加入当前 Profile'">
                <input v-model="tool.enabled" type="checkbox" :aria-label="`${tool.name} Profile`" :disabled="tool.state === 'planned'" @change="profileChanged(tool)" />
                <span></span>
              </label>
            </span>
          </div>
        </main>

        <aside class="tool-inspector">
          <header><div><Wrench :size="16" /><span><strong>{{ activeTool.name }}</strong><small>ToolSpec / {{ activeTool.id }}</small></span></div><span class="status-chip" :class="activeTool.state === 'planned' ? 'pending' : 'active'">{{ toolStateLabel(activeTool.state) }}</span></header>
          <div class="tool-glyph"><TerminalSquare :size="27" /><span><code>{{ activeTool.category }}</code><strong>{{ activeTool.description }}</strong></span></div>
          <dl>
            <div><dt>Execution mode</dt><dd>{{ activeTool.mode }}</dd></div>
            <div><dt>Normalized output</dt><dd>{{ activeTool.output }}</dd></div>
            <div><dt>Raw artifact</dt><dd>{{ activeTool.artifact }}</dd></div>
            <div><dt>Profile state</dt><dd>{{ activeTool.enabled ? 'selected' : 'not selected' }}</dd></div>
          </dl>
          <section class="tool-contract">
            <header>VERSIONED CONTRACT</header>
            <code>ToolSpec → ToolRequest<br />→ ToolExecution → ToolSignal<br />→ ArtifactRef</code>
          </section>
          <section class="permission-summary">
            <ShieldCheck :size="16" /><span><strong>Permission checked</strong><small>源代码读取、网络访问与验证调用分别授权并记录。</small></span>
          </section>
        </aside>
      </div>

      <section v-if="fabricView === 'history'" class="execution-ledger">
        <header><div><History :size="16" /><span><strong>Recent tool executions</strong><small>前端契约演示 · ArtifactRef 可追溯</small></span></div><span class="status-chip candidate">Signal ledger</span></header>
        <div class="execution-row" v-for="run in fabric.executions" :key="run.id">
          <span class="execution-mark" :class="run.state"><CircleCheck v-if="run.state === 'completed'" :size="15" /><TriangleAlert v-else :size="15" /></span>
          <span class="execution-name"><code>{{ run.id }}</code><strong>{{ run.tool }}</strong><small>{{ run.request }}</small></span>
          <span><small>DURATION</small><strong>{{ run.duration }}</strong></span>
          <span><small>SIGNALS</small><strong>{{ run.signals }}</strong></span>
          <span class="finding-binding"><small>FINDING BINDING</small><strong>{{ run.finding }}</strong></span>
          <span class="status-chip" :class="run.state === 'degraded' ? 'blocked' : 'completed'">{{ run.state === 'degraded' ? '降级' : '完成' }}</span>
        </div>
      </section>
    </div>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import { ArrowRight, ArrowUpRight, Boxes, BrainCircuit, CircleCheck, Container, FileOutput, History, LockKeyhole, MapPin, PackageSearch, ScanSearch, ShieldCheck, TerminalSquare, TriangleAlert, Wrench } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const fabric = platform.toolFabric
const activeToolId = ref(fabric.tools[0].id)
const fabricView = ref('registry')
const activeTool = computed(() => fabric.tools.find(item => item.id === activeToolId.value) || fabric.tools[0])
const enabledCount = computed(() => fabric.tools.filter(item => item.enabled).length)
const toolStateLabel = value => ({ profile_ready: 'Profile ready', planned: '规划中' }[value] || value)
const profileChanged = tool => platform.notify(`${tool.name} ${tool.enabled ? '已加入' : '已移出'}前端 Profile 草稿；后端接入后才会生效。`, 'info', 'Tool profile')
</script>

<style scoped>
.fabric-wrap { max-width: 1540px; }
.fabric-head { margin-bottom: 16px; }
.signal-rule-banner { display: grid; min-height: 72px; grid-template-columns: 32px minmax(0, 1fr) auto; align-items: center; gap: 10px; padding: 12px 18px; border: 1px solid color-mix(in srgb, var(--focus) 28%, var(--line)); background: var(--focus-soft); color: var(--focus); }
.signal-rule-banner > span { display: grid; }
.signal-rule-banner strong { font-size: 15px; }
.signal-rule-banner small { color: var(--ink-secondary); font-size: 13px; line-height: 1.55; }
.signal-rule-banner a { display: flex; align-items: center; gap: 5px; font-size: 13px; font-weight: 700; }
.fabric-tabs { display: flex; min-height: 60px; margin-top: 18px; border: 1px solid var(--line); border-bottom: 0; background: var(--canvas-soft); overflow-x: auto; }
.fabric-tabs button { position: relative; display: flex; min-width: 150px; align-items: center; justify-content: center; gap: 8px; padding: 0 18px; border-right: 1px solid var(--line); background: transparent; color: var(--ink-muted); cursor: pointer; font-size: 14px; font-weight: 700; }
.fabric-tabs button:hover, .fabric-tabs button.active { background: var(--surface); color: var(--ink); }
.fabric-tabs button.active::after { position: absolute; right: 16px; bottom: 0; left: 16px; height: 2px; background: var(--focus); content: ''; }
.execution-boundary { margin-top: 0; border: 1px solid var(--line); background: var(--canvas-soft); }
.execution-boundary > header { display: flex; min-height: 46px; align-items: center; justify-content: space-between; padding: 0 14px; border-bottom: 1px solid var(--line); color: var(--ink-muted); font-family: var(--font-mono); font-size: 12px; }
.execution-boundary > header code { color: var(--focus); }
.boundary-flow { display: grid; min-height: 166px; grid-template-columns: minmax(150px, 1fr) 54px minmax(170px, 1fr) 54px minmax(220px, 1.3fr) 54px minmax(150px, 1fr); align-items: center; gap: 7px; padding: 20px; }
.runtime-node, .gateway-node, .signal-node { display: grid; min-height: 92px; grid-template-columns: 42px minmax(0, 1fr); align-content: center; gap: 3px 10px; padding: 12px; border: 1px solid var(--line-strong); border-radius: 8px 3px 8px 3px; background: var(--surface); }
.runtime-node > span, .gateway-node > span, .signal-node > span { display: grid; width: 36px; height: 36px; grid-row: span 2; place-items: center; border: 1px solid var(--line); border-radius: 8px 3px 8px 3px; color: var(--focus); }
.gateway-node > span { color: var(--verified); }
.signal-node > span { color: var(--relay); }
.runtime-node strong, .gateway-node strong, .signal-node strong { font-size: 13px; }
.runtime-node small, .gateway-node small, .signal-node small { color: var(--ink-muted); font-size: 12px; }
.boundary-link { display: grid; justify-items: center; gap: 3px; color: var(--line-strong); }
.boundary-link small { color: var(--ink-muted); font-family: var(--font-mono); font-size: 12px; }
.container-zone { position: relative; min-height: 112px; padding: 28px 12px 12px; border: 1px dashed color-mix(in srgb, var(--warning) 55%, var(--line)); background: var(--warning-soft); }
.zone-label { position: absolute; top: 8px; left: 10px; display: flex; align-items: center; gap: 5px; color: var(--warning); font-family: var(--font-mono); font-size: 12px; }
.container-zone > div { display: flex; min-height: 67px; align-items: center; justify-content: center; gap: 9px; border: 1px solid color-mix(in srgb, var(--warning) 35%, var(--line)); background: var(--surface); }
.container-zone > div > svg { color: var(--warning); }
.container-zone > div > span { display: grid; }
.container-zone strong { font-family: var(--font-mono); font-size: 12px; }
.container-zone small { color: var(--ink-muted); font-size: 12px; }
.execution-boundary > footer { display: flex; min-height: 50px; align-items: center; gap: 24px; padding: 0 15px; border-top: 1px solid var(--line); color: var(--ink-muted); font-size: 12px; }
.execution-boundary > footer span { display: flex; align-items: center; gap: 6px; }
.fabric-workbench { display: grid; min-height: 560px; margin-top: 0; grid-template-columns: minmax(0, 1fr) 360px; border: 1px solid var(--line); background: var(--canvas-soft); }
.tool-registry { min-width: 0; border-right: 1px solid var(--line); }
.tool-registry > header, .tool-inspector > header, .execution-ledger > header { display: flex; min-height: 58px; align-items: center; justify-content: space-between; gap: 10px; padding: 0 13px; border-bottom: 1px solid var(--line); }
.tool-registry > header > div, .tool-inspector > header > div, .execution-ledger > header > div { display: flex; align-items: center; gap: 8px; }
.tool-registry header span, .tool-inspector header span, .execution-ledger header span { display: grid; }
.tool-registry header strong, .tool-inspector header strong, .execution-ledger header strong { font-size: 15px; }
.tool-registry header small, .tool-inspector header small, .execution-ledger header small { color: var(--ink-muted); font-size: 13px; }
.registry-count { color: var(--focus); font-family: var(--font-mono); font-size: 12px; }
.tool-table-head, .tool-row { display: grid; grid-template-columns: minmax(210px, 1.25fr) minmax(120px, .8fr) 120px 70px; align-items: center; gap: 10px; padding: 0 14px; }
.tool-table-head { min-height: 44px; border-bottom: 1px solid var(--line); background: var(--table-head-bg); color: var(--ink-muted); font-family: var(--font-mono); font-size: 12px; }
.tool-row { min-height: 82px; border-bottom: 1px solid var(--line); color: var(--ink-muted); transition: background var(--motion-fast), box-shadow var(--motion-fast); }
.tool-row:hover, .tool-row.active { background: var(--surface); }
.tool-row.active { box-shadow: inset 2px 0 var(--focus); }
.tool-identity { display: flex; min-width: 0; align-items: center; gap: 10px; padding: 0; background: transparent; color: inherit; cursor: pointer; text-align: left; }
.tool-identity > span:first-child { display: grid; width: 32px; height: 32px; flex: 0 0 32px; place-items: center; border: 1px solid var(--line-strong); border-radius: 8px 3px 8px 3px; color: var(--verified); }
.tool-identity > span:first-child.planned { color: var(--ink-muted); }
.tool-identity > span:last-child { display: grid; min-width: 0; }
.tool-identity strong { color: var(--ink-secondary); font-size: 15px; }
.tool-identity small { font-family: var(--font-mono); font-size: 12px; }
.tool-cell { display: flex; min-width: 0; align-items: center; gap: 5px; }
.tool-cell small, .tool-cell code { overflow: hidden; font-size: 13px; text-overflow: ellipsis; white-space: nowrap; }
.tool-cell code { color: var(--focus); }
.adapter-state { display: inline-flex; padding: 4px 8px; border-radius: 11px; background: var(--verified-soft); color: var(--verified); font-size: 12px; font-style: normal; white-space: nowrap; }
.adapter-state.planned { background: var(--surface-hover); color: var(--ink-muted); }
.tool-toggle { display: flex; justify-content: center; }
.switch input:disabled + span { opacity: .45; }
.tool-glyph { display: flex; align-items: flex-start; gap: 11px; padding: 18px 14px; border-bottom: 1px solid var(--line); }
.tool-glyph > svg { color: var(--focus); }
.tool-glyph > span { display: grid; }
.tool-glyph code { color: var(--focus); font-size: 12px; }
.tool-glyph strong { margin-top: 6px; font-size: 15px; line-height: 1.6; }
.tool-inspector dl { margin: 0; padding: 7px 14px; }
.tool-inspector dl > div { display: grid; min-height: 45px; grid-template-columns: 105px minmax(0, 1fr); align-items: center; border-bottom: 1px solid var(--line); }
.tool-inspector dt { color: var(--ink-muted); font-size: 13px; }
.tool-inspector dd { margin: 0; color: var(--ink-secondary); font-family: var(--font-mono); font-size: 13px; text-align: right; }
.tool-contract { margin: 10px 14px; border: 1px solid var(--line); }
.tool-contract > header { min-height: 40px; padding: 0 11px; border-bottom: 1px solid var(--line); color: var(--ink-muted); font-family: var(--font-mono); font-size: 12px; line-height: 40px; }
.tool-contract > code { display: block; padding: 14px; background: var(--code-bg); color: var(--code-ink); font-size: 12px; line-height: 1.8; }
.permission-summary { display: flex; align-items: flex-start; gap: 8px; margin: 10px 14px; padding: 10px; border: 1px solid color-mix(in srgb, var(--verified) 30%, var(--line)); background: var(--verified-soft); color: var(--verified); }
.permission-summary span { display: grid; }
.permission-summary strong { font-size: 13px; }
.permission-summary small { color: var(--ink-secondary); font-size: 13px; line-height: 1.55; }
.execution-ledger { margin-top: 0; border: 1px solid var(--line); background: var(--canvas-soft); }
.execution-row { display: grid; min-height: 76px; grid-template-columns: 42px minmax(220px, 1fr) 100px 80px minmax(150px, .8fr) auto; align-items: center; gap: 10px; padding: 9px 14px; border-bottom: 1px solid var(--line); }
.execution-row:last-child { border-bottom: 0; }
.execution-mark { display: grid; width: 32px; height: 32px; place-items: center; border: 1px solid var(--line-strong); border-radius: 50%; color: var(--verified); }
.execution-mark.degraded { border-radius: 8px 3px 8px 3px; color: var(--warning); }
.execution-name { display: grid; }
.execution-name code { color: var(--focus); font-size: 12px; }
.execution-name strong { font-size: 13px; }
.execution-name small { color: var(--ink-muted); font-size: 12px; }
.execution-row > span:not(.execution-mark):not(.execution-name):not(.status-chip) { display: grid; }
.execution-row > span > small { color: var(--ink-muted); font-size: 12px; }
.execution-row > span > strong { font-family: var(--font-mono); font-size: 12px; }
.finding-binding strong { color: var(--warning); }
@media (max-width: 1150px) {
  .boundary-flow { grid-template-columns: 1fr 40px 1fr 40px 1.2fr; }
  .boundary-flow > .boundary-link:nth-last-child(2), .signal-node { display: none; }
  .tool-table-head, .tool-row { grid-template-columns: minmax(190px, 1.2fr) minmax(110px, .7fr) 110px 60px; }
  .execution-row { grid-template-columns: 38px minmax(200px, 1fr) 90px 72px minmax(120px, .7fr) auto; }
}
@media (max-width: 900px) {
  .boundary-flow { grid-template-columns: 1fr; justify-items: stretch; }
  .boundary-link { transform: rotate(90deg); }
  .boundary-flow > .boundary-link:nth-last-child(2), .signal-node { display: grid; }
  .execution-boundary > footer { align-items: flex-start; flex-direction: column; gap: 7px; padding: 10px 13px; }
  .fabric-workbench { grid-template-columns: 1fr; }
  .tool-registry { border-right: 0; border-bottom: 1px solid var(--line); }
  .execution-row { grid-template-columns: 36px minmax(190px, 1fr) minmax(120px, .7fr) auto; }
  .execution-row > span:nth-child(3), .execution-row > span:nth-child(4) { display: none !important; }
}
@media (max-width: 760px) {
  .signal-rule-banner { grid-template-columns: 24px minmax(0, 1fr); }
  .signal-rule-banner a { grid-column: 2; }
  .tool-table-head { display: none; }
  .tool-row { grid-template-columns: minmax(0, 1fr) auto 58px; padding: 9px 12px; }
  .tool-row > span:nth-child(2) { display: none; }
  .execution-row { grid-template-columns: 34px minmax(0, 1fr); }
  .execution-row > .finding-binding, .execution-row > .status-chip { grid-column: 2; }
}
</style>
