<template>
  <section class="view-page integrations-page">
    <div class="page-wrap integrations-wrap">
      <header class="page-head">
        <div><span class="page-kicker">SKILL-FIRST ENTRY</span><h1>Skill / CLI</h1><p>从开发现场触发本地安全 Harness，并把同一个 RemediationBundle 返回给 Coding Agent。</p></div>
        <span class="source-chip demo">Visualization layer · V2 contract</span>
      </header>

      <section class="integration-hero">
        <div class="relay-identity"><span><TerminalSquare :size="22" /></span><div><code>VIBE SEC HARNESS + AUDIT ENGINE</code><h2>Claude Code Skill + CLI parity</h2><p>Skill 与 CLI 是第一入口；Web 工作台只负责 RunSession、Agent tasks、证据和检查点的管理与可视化。</p></div></div>
        <div class="relay-path harness-path"><div class="done"><span>1</span><strong>Explicit trigger</strong><small>Skill / CLI</small></div><ArrowRight :size="16" /><div class="done"><span>2</span><strong>Plan + Surface</strong><small>scope + threat model</small></div><ArrowRight :size="16" /><div class="done"><span>3</span><strong>Audit Engine</strong><small>3 executable lanes</small></div><ArrowRight :size="16" /><div><span>4</span><strong>Verify</strong><small>FinalizeVerification</small></div><ArrowRight :size="16" /><div><span>5</span><strong>Return</strong><small>stable payload</small></div><ArrowRight :size="16" /><div><span>6</span><strong>Retest</strong><small>closure gate</small></div></div>
      </section>

      <div class="integration-grid">
        <article class="integration-panel skill-contract">
          <header><div><Braces :size="17" /><span><strong>Claude Code Skill 契约</strong><small>第一入口 · 显式触发</small></span></div><button class="icon-button" title="复制 Skill 契约" @click="copy(skillContract)"><Copy :size="14" /></button></header>
          <pre>{{ skillContract }}</pre>
        </article>

        <article class="integration-panel skill-contract">
          <header><div><SquareTerminal :size="17" /><span><strong>CLI parity</strong><small>本地自动化与复测</small></span></div><button class="icon-button" title="复制 CLI 命令" @click="copy(cliContract)"><Copy :size="14" /></button></header>
          <pre>{{ cliContract }}</pre>
        </article>

        <article class="integration-panel trigger-panel">
          <header><div><Zap :size="17" /><span><strong>Trigger Policy</strong><small>先显式触发，再保守建议</small></span></div><span class="status-chip active">policy-controlled</span></header>
          <div class="trigger-grid">
            <section><span>EXPLICIT</span><p>审计项目、提交前检查、指定文件验证、补丁后复测。</p></section>
            <section><span>SUGGESTED</span><p>鉴权、文件、网络、Shell、Prompt、MCP、Secret、Browser sink 或 Workflow 节点发生变化。</p></section>
          </div>
        </article>

        <article class="integration-panel return-panel">
          <header><div><Reply :size="17" /><span><strong>Return Protocol</strong><small>同一对象模型的三种视图</small></span></div><div class="segmented return-tabs"><button v-for="item in formats" :key="item.id" :class="{ active: format === item.id }" @click="format = item.id">{{ item.label }}</button></div></header>
          <pre>{{ returnViews[format] }}</pre>
        </article>

        <article class="integration-panel adapter-panel">
          <header><div><ShieldCheck :size="17" /><span><strong>执行适配状态</strong><small>架构契约与现有 FastAPI 边界</small></span></div><span class="status-chip" :class="platform.connection === 'live' ? 'active' : 'blocked'">{{ platform.connection === 'live' ? 'FastAPI connected' : 'Demo fallback' }}</span></header>
          <div class="endpoint-list"><span><b>LIVE</b><code>/api/process-task</code><small>源码采集与现有审计适配</small></span><span><b>LIVE</b><code>/api/agent-test-runs</code><small>Agent 目标、场景与回归运行</small></span><span><b>V2</b><code>core/agent_runtime + core/audit</code><small>Parent/child tasks、完成契约与 Agentic review · 当前后端待接入</small></span><span><b>V2</b><code>core/tool_fabric + core/surface</code><small>ToolSignal、RuntimeThreatModel 与 RiskHypothesis · 当前后端待接入</small></span></div>
        </article>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import { ArrowRight, Braces, Copy, Reply, ShieldCheck, SquareTerminal, TerminalSquare, Zap } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const format = ref('claude')
const formats = [{ id: 'claude', label: 'Claude Code' }, { id: 'markdown', label: 'Markdown' }, { id: 'json', label: 'JSON' }]
const skillContract = `name: vibe-sec-audit
entry: claude_code_skill
trigger: explicit
scope: changed_files
verification_target: L4
lanes: [web, agent, secrets]
extension_lanes: [mcp, workflow]
agent_runtime: bounded_multi_turn
return: claude_code_native
destructive_fixes: require_confirmation`
const cliContract = `vibesec audit ./project \\
  --scope changed-files \\
  --lanes web,agent,secrets \\
  --verification-target L4 \\
  --use-llm

# --use-llm requires an explicit provider key;
# missing key exits immediately without mock fallback.

vibesec retest RUN-0248 \\
  --from-checkpoint CP-VERIFY-05 \\
  --positive-and-negative-controls`
const returnViews = {
  claude: `SECURITY RETURN · RUN-0248
Finding: F-012 · Unsafe tool permission boundary
Evidence: artifact://RUN-0248/EV-NET-01
Patch: require confirmation + server-side ownership check
Constraints: preserve legitimate refund flow
Next: apply patch, then run targeted retest`,
  markdown: `## F-012 Unsafe tool permission boundary
- Verification: L3 / target L4
- Evidence: \`artifact://RUN-0248/EV-NET-01\`
- Constraint: preserve legitimate refund flow
- Retest: negative authorization + positive business control`,
  json: `{
  "run_session": "RUN-0248",
  "finding_id": "F-012",
  "evidence_refs": ["artifact://RUN-0248/EV-NET-01"],
  "verification_level": 3,
  "return_target": "claude_code",
  "retest_required": true
}`
}
const copy = async value => { await navigator.clipboard.writeText(value); platform.notify('内容已复制。', 'success') }
</script>

<style scoped>
.harness-path { gap: 7px; }
.harness-path > div { min-width: 104px; }
.trigger-grid { display: grid; grid-template-columns: repeat(2, 1fr); }
.trigger-grid section { padding: 18px; }
.trigger-grid section + section { border-left: 1px solid var(--line); }
.trigger-grid span { color: var(--focus); font-family: var(--font-mono); font-size: 11px; }
.trigger-grid p { margin: 8px 0 0; color: var(--ink-secondary); font-size: 13px; line-height: 1.7; }
.return-panel pre { min-height: 176px; margin: 0; padding: 15px; background: var(--code-bg); color: var(--code-ink); font-size: 13px; line-height: 1.7; white-space: pre-wrap; }
.return-tabs { flex-wrap: nowrap; }
.return-tabs button { white-space: nowrap; }
.adapter-panel { grid-column: 1 / -1; }
.adapter-panel .endpoint-list { grid-template-columns: repeat(2, 1fr); }
.adapter-panel .endpoint-list > span:nth-child(odd) { border-right: 1px solid var(--line); }
@media (max-width: 900px) {
  .harness-path { align-items: flex-start; flex-direction: column; }
  .harness-path > svg { margin-left: 5px; transform: rotate(90deg); }
}
@media (max-width: 760px) {
  .trigger-grid,
  .adapter-panel .endpoint-list { grid-template-columns: 1fr; }
  .trigger-grid section + section { border-top: 1px solid var(--line); border-left: 0; }
  .adapter-panel .endpoint-list > span:nth-child(odd) { border-right: 0; }
  .return-panel header { align-items: flex-start; flex-direction: column; padding: 10px 12px; }
}
</style>
