<template>
  <aside v-if="finding" class="finding-peek">
    <header class="peek-head">
      <div class="peek-id"><span class="severity-dot" :class="finding.severity"></span><code>{{ finding.id }}</code><span>{{ finding.category }}</span></div>
      <button type="button" aria-label="关闭 Finding 详情" @click="$emit('close')"><X :size="17" /></button>
    </header>

    <div class="peek-scroll">
      <section class="peek-title">
        <div class="peek-badges"><span class="severity-chip" :class="finding.severity">{{ severityLabel(finding.severity) }} · CVSS {{ finding.cvss }}</span><span class="verification-level">L{{ finding.verificationLevel || 1 }}</span></div>
        <h2>{{ finding.title }}</h2>
        <p>{{ finding.summary }}</p>
        <div class="peek-meta">
          <span><FileCode2 :size="13" />{{ finding.file }}<template v-if="finding.line">:{{ finding.line }}</template></span>
          <span><BadgeCheck :size="13" />置信度 {{ Math.round(finding.confidence * 100) }}%</span>
        </div>
      </section>

      <nav class="peek-tabs" aria-label="Finding 详情视图">
        <button v-for="item in tabs" :key="item.id" type="button" :class="{ active: tab === item.id }" @click="tab = item.id">{{ item.label }}</button>
      </nav>

      <section v-if="tab === 'chain'" class="peek-section chain-view">
        <div v-if="chain.length" class="chain-list">
          <div v-for="(step, index) in chain" :key="step.label" class="chain-step">
            <span class="chain-node" :class="step.status">{{ index + 1 }}</span>
            <div><strong>{{ step.label }}</strong><p>{{ step.value }}</p></div>
            <span class="claim-mark" :class="step.status">{{ claimLabel(step.status) }}</span>
          </div>
        </div>
        <div v-else class="peek-empty">当前 Finding 尚未形成完整 RiskChain。</div>
      </section>

      <section v-else-if="tab === 'evidence'" class="peek-section">
        <div class="section-line"><strong>验证证据</strong><span>{{ evidence.length }} 项</span></div>
        <button v-for="item in evidence" :key="item.id" class="peek-evidence" type="button" @click="$emit('open-evidence', item.id)">
          <component :is="evidenceIcon(item.type)" :size="15" />
          <span><strong>{{ item.title }}</strong><small>{{ item.subtitle }}</small></span>
          <span class="evidence-state" :class="item.status"></span>
        </button>
        <div v-if="!evidence.length" class="peek-empty">后端报告未提供可引用的原始证据。</div>
      </section>

      <section v-else class="peek-section remediation-view">
        <template v-if="bundle">
          <div class="relay-summary"><Bot :size="16" /><span>{{ relayLabel(bundle.state) }}</span><code>{{ bundle.id }}</code></div>
          <h3>AI 修复指令</h3>
          <p>{{ bundle.aiPatchPrompt }}</p>
          <h3>不可修改约束</h3>
          <ul><li v-for="item in bundle.constraints" :key="item">{{ item }}</li></ul>
          <h3>验收标准</h3>
          <ul><li v-for="item in bundle.acceptance" :key="item">{{ item }}</li></ul>
          <button v-if="bundle.state === 'draft'" class="peek-primary relay" type="button" @click="$emit('dispatch', bundle.id)"><Reply :size="15" />Return to Claude Code</button>
          <router-link v-else to="/remediation" class="peek-primary"><ArrowUpRight :size="15" />查看整改流转</router-link>
        </template>
        <template v-else>
          <div class="peek-empty">该 Finding 尚未生成整改包。</div>
          <button class="peek-primary" type="button"><WandSparkles :size="15" />生成整改包</button>
        </template>
      </section>
    </div>

    <footer class="peek-actions">
      <span class="status-chip" :class="finding.status">{{ statusLabel(finding.status) }}</span>
      <button type="button" @click="$emit('focus-path', finding)"><Route :size="15" />定位风险链</button>
    </footer>
  </aside>
</template>

<script setup>
import { computed, markRaw, ref, watch } from 'vue'
import {
  ArrowUpRight,
  BadgeCheck,
  Bot,
  Braces,
  Code2,
  FileCode2,
  FileJson,
  FlaskConical,
  Monitor,
  Network,
  RadioTower,
  Route,
  Reply,
  WandSparkles,
  X
} from 'lucide-vue-next'

const props = defineProps({
  finding: { type: Object, default: null },
  chain: { type: Array, default: () => [] },
  evidence: { type: Array, default: () => [] },
  bundle: { type: Object, default: null }
})
defineEmits(['close', 'open-evidence', 'focus-path', 'dispatch'])

const tab = ref('chain')
const tabs = [
  { id: 'chain', label: '风险链' },
  { id: 'evidence', label: '证据' },
  { id: 'remediation', label: '整改' }
]

const icons = { code: markRaw(Code2), network: markRaw(Network), fuzz: markRaw(FlaskConical), browser: markRaw(Monitor), dom: markRaw(Braces), trace: markRaw(RadioTower), config: markRaw(FileJson) }
const evidenceIcon = type => icons[type] || markRaw(FileCode2)
const severityLabel = value => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[value] || value)
const statusLabel = value => ({ verifying: '验证中', confirmed: '已确认', static_only: '仅静态', needs_evidence: '待补充证据', blocked: '待批准', candidate: '候选项', inconclusive: '证据不足', fixed: '已修复' }[value] || value)
const claimLabel = value => ({ supported: '已支持', testing: '验证中', contradicted: '已反驳', insufficient: '证据不足' }[value] || value)
const relayLabel = value => ({ draft: 'RemediationBundle 待 Return', dispatched: '已返回开发现场', acknowledged: 'AI 已确认', consumed: 'AI 正在修复', returned: '补丁已返回' }[value] || value)

watch(() => props.finding?.id, () => { tab.value = 'chain' })
</script>

<style scoped>
.finding-peek {
  position: absolute;
  z-index: 22;
  top: 12px;
  right: 12px;
  bottom: 60px;
  display: grid;
  width: min(424px, calc(100% - 24px));
  grid-template-rows: 48px minmax(0, 1fr) 52px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-lg);
  background: var(--float-glass);
  box-shadow: var(--shadow-float), var(--inset-hairline);
  overflow: hidden;
  backdrop-filter: blur(20px);
  animation: peek-enter 260ms cubic-bezier(0.2, 0.72, 0.2, 1) both;
}

@keyframes peek-enter {
  from { opacity: 0; transform: translateX(12px) scale(0.992); }
  to { opacity: 1; transform: translateX(0) scale(1); }
}

.peek-head,
.peek-actions,
.peek-id,
.peek-meta,
.section-line,
.relay-summary {
  display: flex;
  align-items: center;
}

.peek-head {
  justify-content: space-between;
  gap: 8px;
  padding: 0 10px 0 13px;
  border-bottom: 1px solid var(--line);
}

.peek-id { min-width: 0; gap: 7px; }
.peek-id code { padding: 3px 8px; border: 1px solid var(--line); border-radius: 8px; background: var(--canvas-soft); color: var(--ink); font-size: 13px; font-weight: 700; }
.peek-id > span:last-child { overflow: hidden; color: var(--ink-muted); font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
.severity-dot { width: 8px; height: 8px; flex: 0 0 8px; border-radius: 50%; }
.severity-dot.critical,
.severity-dot.high { background: var(--critical); box-shadow: 0 0 8px color-mix(in srgb, var(--critical) 60%, transparent); }
.severity-dot.medium { background: var(--warning); }
.severity-dot.low { background: var(--verified); }
.peek-head button { display: grid; width: 28px; height: 28px; place-items: center; border-radius: var(--radius-sm); background: transparent; color: var(--ink-muted); cursor: pointer; }
.peek-head button:hover { background: var(--surface-hover); color: var(--ink); }

.peek-scroll { min-height: 0; overflow-y: auto; }
.peek-title { padding: 18px; border-bottom: 1px solid var(--line); }
.peek-badges { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
.peek-title h2 { margin: 11px 0 9px; font-size: 22px; font-weight: 750; line-height: 1.35; text-wrap: pretty; }
.peek-title p { margin-bottom: 14px; color: var(--ink-secondary); font-size: 14px; line-height: 1.7; }
.peek-meta { gap: 13px; flex-wrap: wrap; color: var(--ink-muted); font-size: 12px; }
.peek-meta span { display: inline-flex; align-items: center; gap: 5px; }

.peek-tabs { display: grid; height: 46px; grid-template-columns: repeat(3, 1fr); border-bottom: 1px solid var(--line); }
.peek-tabs button { position: relative; background: transparent; color: var(--ink-muted); cursor: pointer; font-size: 13px; font-weight: 650; transition: color var(--motion-fast), background var(--motion-fast); }
.peek-tabs button:hover { background: var(--row-hover); color: var(--ink-secondary); }
.peek-tabs button.active { color: var(--ink); }
.peek-tabs button.active::after { position: absolute; right: 12px; bottom: -1px; left: 12px; height: 2px; border-radius: 2px; background: var(--grad-accent); box-shadow: 0 0 8px color-mix(in srgb, var(--focus) 45%, transparent); content: ""; }

.peek-section { padding: 16px; }
.chain-list { display: grid; }
.chain-step { position: relative; display: grid; grid-template-columns: 30px minmax(0, 1fr) auto; gap: 10px; padding-bottom: 19px; }
.chain-step:not(:last-child)::before { position: absolute; top: 28px; bottom: 0; left: 13px; width: 1px; background: linear-gradient(180deg, var(--line-strong), var(--line)); content: ""; }
.chain-node { z-index: 1; display: grid; width: 28px; height: 28px; place-items: center; border: 1px solid var(--line-strong); border-radius: 50%; background: var(--surface); color: var(--ink-muted); font-family: var(--font-mono); font-size: 11px; }
.chain-node.supported { border-color: rgba(86,197,150,.45); background: var(--verified-soft); color: var(--verified); }
.chain-node.testing { border-color: rgba(124,156,255,.5); background: var(--focus-soft); color: var(--focus); }
.chain-step strong { color: var(--ink); font-family: var(--font-display); font-size: 14px; font-weight: 700; }
.chain-step p { margin: 4px 0 0; color: var(--ink-muted); font-size: 12px; line-height: 1.6; }
.claim-mark { height: 24px; padding: 0 8px; border-radius: 11px; background: var(--surface-hover); color: var(--ink-muted); font-size: 11px; line-height: 24px; white-space: nowrap; }
.claim-mark.supported { background: var(--verified-soft); color: var(--verified); }
.claim-mark.testing { background: var(--focus-soft); color: var(--focus); }

.section-line { justify-content: space-between; margin-bottom: 10px; }
.section-line strong { font-family: var(--font-display); font-size: 14px; font-weight: 700; }
.section-line span { color: var(--focus); font-family: var(--font-mono); font-size: 12px; }
.peek-evidence { display: grid; width: 100%; min-height: 58px; grid-template-columns: 30px minmax(0, 1fr) 18px; align-items: center; gap: 9px; padding: 7px 9px; border-bottom: 1px solid var(--line); background: transparent; color: var(--ink-muted); cursor: pointer; text-align: left; }
.peek-evidence:hover { background: var(--surface-hover); color: var(--ink); }
.peek-evidence > span:nth-child(2) { display: grid; min-width: 0; }
.peek-evidence strong,
.peek-evidence small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.peek-evidence strong { color: var(--ink-secondary); font-size: 13px; }
.peek-evidence small { color: var(--ink-muted); font-size: 11px; }
.evidence-state { width: 7px; height: 7px; justify-self: center; border-radius: 50%; }
.evidence-state.bound { background: var(--verified); }
.evidence-state.collecting { background: var(--focus); animation: pulse 1.1s ease-in-out infinite; }
.evidence-state.contradicted { background: var(--critical); }

.remediation-view h3 { margin: 17px 0 7px; font-family: var(--font-display); font-size: 14px; font-weight: 700; }
.remediation-view p,
.remediation-view li { color: var(--ink-secondary); font-size: 13px; line-height: 1.65; }
.remediation-view ul { display: grid; gap: 6px; margin: 0; padding-left: 18px; }
.relay-summary { gap: 7px; padding: 11px; border: 1px solid rgba(170,140,255,.28); border-radius: var(--radius-sm); background: var(--relay-soft); color: var(--relay); font-size: 12px; }
.relay-summary span { flex: 1; }
.relay-summary code { font-size: 11px; }
.peek-primary { display: flex; width: 100%; min-height: 42px; align-items: center; justify-content: center; gap: 7px; margin-top: 15px; border-radius: var(--radius-sm); background: var(--grad-accent); box-shadow: 0 5px 16px color-mix(in srgb, var(--focus) 30%, transparent); color: #fff; cursor: pointer; font-size: 13px; font-weight: 800; text-shadow: 0 1px 2px rgba(20, 30, 60, 0.24); transition: transform var(--motion-fast), box-shadow var(--motion-fast), filter var(--motion-fast); }
.peek-primary:hover { box-shadow: 0 8px 22px color-mix(in srgb, var(--focus) 40%, transparent); filter: brightness(1.07); transform: translateY(-1px); }
.peek-primary.relay { background: linear-gradient(120deg, #9a7bff, #b79fff); box-shadow: 0 5px 16px color-mix(in srgb, var(--relay) 36%, transparent); }
.peek-primary.relay:hover { box-shadow: 0 8px 22px color-mix(in srgb, var(--relay) 46%, transparent); }
.peek-empty { padding: 24px 10px; color: var(--ink-muted); font-size: 13px; text-align: center; }

.peek-actions { justify-content: space-between; gap: 10px; padding: 0 10px 0 13px; border-top: 1px solid var(--line); }
.peek-actions button { display: flex; align-items: center; gap: 6px; min-height: 36px; padding: 0 10px; border-radius: var(--radius-sm); background: transparent; color: var(--focus); cursor: pointer; font-size: 12.5px; font-weight: 650; }
.peek-actions button:hover { background: var(--focus-soft); }

@media (max-width: 760px) {
  .finding-peek { top: 6px; right: 6px; bottom: 54px; left: 6px; width: auto; }
}
</style>
