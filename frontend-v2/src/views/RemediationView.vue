<template>
  <section class="view-page remediation-page">
    <div class="page-wrap compact-wrap">
      <header class="page-head">
        <div><span class="page-kicker">REMEDIATE / RETURN / RETEST</span><h1>返回与复测</h1><p>把稳定 RemediationBundle 返回开发现场，并用正向与反向控制完成闭环。</p></div>
        <span class="source-chip demo">V2 Return schema · adapter pending</span>
      </header>

      <div class="remediation-layout">
        <aside class="bundle-index">
          <header><span>整改包</span><b>{{ platform.bundles.length }}</b></header>
          <button v-for="item in platform.bundles" :key="item.id" type="button" :class="{ active: selectedId === item.id }" @click="selectedId = item.id">
            <span class="severity-bar" :class="item.severity"></span><span><code>{{ item.id }}</code><strong>{{ item.title }}</strong><small>{{ item.findingId }} · {{ relayLabel(item.state) }}</small></span><ChevronRight :size="15" />
          </button>
        </aside>

        <article v-if="bundle" class="bundle-editor">
          <header class="bundle-head">
            <div><span><code>{{ bundle.id }}</code><span class="severity-chip" :class="bundle.severity">{{ severityLabel(bundle.severity) }}</span><span class="status-chip" :class="bundle.proposalOnly ? 'candidate' : 'confirmed'">{{ bundle.proposalOnly ? '整改建议' : '已验证' }}</span></span><h2>{{ bundle.title }}</h2></div>
            <button class="button relay" type="button" :disabled="bundle.state !== 'draft'" @click="platform.dispatchBundle(bundle.id)"><Reply :size="14" />{{ bundle.state === 'draft' ? 'Return to Claude Code' : relayLabel(bundle.state) }}</button>
          </header>

          <section class="relay-track">
            <div v-for="(step, index) in bundle.relay" :key="step.state" :class="{ done: step.done, current: step.state === bundle.state }">
              <span><Check v-if="step.done" :size="13" /><b v-else>{{ index + 1 }}</b></span><strong>{{ step.label }}</strong><small>{{ step.time }}</small>
            </div>
          </section>

          <div class="bundle-grid">
            <section class="bundle-section prompt-section"><header><span>AI PATCH PROMPT</span><button type="button" title="复制" @click="copy(bundle.aiPatchPrompt)"><Copy :size="14" /></button></header><p>{{ bundle.aiPatchPrompt }}</p></section>
            <section class="bundle-section"><header><span>不可修改范围</span></header><ul><li v-for="item in bundle.constraints" :key="item"><LockKeyhole :size="13" />{{ item }}</li></ul></section>
            <section class="bundle-section"><header><span>验收条件</span></header><ul><li v-for="item in bundle.acceptance" :key="item"><CircleCheck :size="13" />{{ item }}</li></ul></section>
            <section class="bundle-section return-bundle"><header><span>RETURN PROTOCOL</span><div class="segmented return-format"><button v-for="item in formats" :key="item.id" :class="{ active: format === item.id }" @click="format = item.id">{{ item.label }}</button></div></header><pre>{{ returnPreview }}</pre></section>
          </div>

          <section v-if="bundle.patch" class="patch-retest">
            <header><div><span>PATCH RETURNED</span><h3>补丁已返回，等待定向复测</h3></div><button class="button primary" type="button" @click="runRetest"><Play :size="14" />运行复测</button></header>
            <div class="diff-grid"><pre class="patch-code">{{ bundle.patch }}</pre><div class="retest-assertions"><span>复用原始验证条件</span><div v-for="item in bundle.acceptance" :key="item"><CircleDashed :size="14" /><span>{{ item }}</span><small>pending</small></div></div></div>
          </section>
          <section v-else class="patch-waiting"><GitPullRequestArrow :size="23" /><div><strong>等待补丁返回</strong><p>Relay 接收补丁后，会在此处显示变更摘要、验收条件和修复前后证据。</p></div></section>
        </article>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import { Check, ChevronRight, CircleCheck, CircleDashed, Copy, GitPullRequestArrow, LockKeyhole, Play, Reply } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const selectedId = ref(platform.bundles[0]?.id || '')
const format = ref('claude')
const formats = [{ id: 'claude', label: 'Claude Code' }, { id: 'markdown', label: 'Markdown' }, { id: 'json', label: 'JSON' }]
const bundle = computed(() => platform.bundles.find(item => item.id === selectedId.value) || platform.bundles[0] || null)
const severityLabel = value => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[value] || value)
const relayLabel = value => ({ draft: '待 Return', dispatched: '已返回开发现场', acknowledged: 'AI 已确认', consumed: '修复中', returned: '补丁已返回' }[value] || value)
const returnPreview = computed(() => {
  if (!bundle.value) return ''
  const finding = platform.selectedFinding(bundle.value.findingId)
  const refs = platform.findingEvidence(bundle.value.findingId).map(item => `artifact://${platform.selectedRun.id}/${item.id}`)
  if (format.value === 'json') return JSON.stringify({ finding: { id: finding?.id, title: finding?.title, severity: finding?.severity, verification_status: bundle.value.verification, verification_level: finding?.verificationLevel }, evidence_refs: refs, remediation: { proposal_only: bundle.value.proposalOnly, ai_patch_prompt: bundle.value.aiPatchPrompt, patch_constraints: bundle.value.constraints, acceptance_criteria: bundle.value.acceptance }, return_target: 'claude_code', retest_required: true }, null, 2)
  if (format.value === 'markdown') return `## ${finding?.id} ${finding?.title}\n- Verification: ${bundle.value.verification} / L${finding?.verificationLevel || 1}\n- Proposal only: ${bundle.value.proposalOnly}\n- Evidence: ${refs.join(', ')}\n- Constraints: ${bundle.value.constraints.join('; ')}\n- Acceptance: ${bundle.value.acceptance.join('; ')}`
  return `SECURITY RETURN · ${platform.selectedRun.id}\nFinding: ${finding?.id} · ${finding?.title}\nVerification: ${bundle.value.verification} / L${finding?.verificationLevel || 1}\nProposal only: ${bundle.value.proposalOnly}\nEvidence refs: ${refs.join(', ')}\nPatch instruction: ${bundle.value.aiPatchPrompt}\nNext action: apply patch, preserve constraints, run targeted retest.`
})
const copy = async value => { await navigator.clipboard.writeText(value); platform.notify('整改提示已复制。', 'success') }
const runRetest = () => platform.notify('已创建定向复测计划。当前后端尚未提供 Retest API，因此未提交远端任务。', 'warning', 'Retest adapter')
</script>

<style scoped>
.return-bundle { grid-column: 1 / -1; }
.return-bundle header { align-items: center; }
.return-format { flex-wrap: nowrap; }
.return-bundle pre { max-height: 260px; margin: 0; padding: 13px; overflow: auto; background: var(--code-bg); color: var(--code-ink); font-size: 12px; line-height: 1.7; white-space: pre-wrap; }
@media (max-width: 760px) {
  .return-bundle header { align-items: flex-start; flex-direction: column; gap: 8px; }
}
</style>
