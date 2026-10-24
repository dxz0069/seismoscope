<template>
  <section class="view-page evidence-page">
    <div class="page-wrap compact-wrap">
      <header class="page-head">
        <div><span class="page-kicker">EVIDENCE BUNDLE / ARTIFACT MANIFEST</span><h1>验证证据</h1><p>原始 Artifact、Claim 引用和 ValidationSession 等级保持可追溯。</p></div>
        <div class="head-actions"><span class="source-chip demo">派生视图</span><button class="button" type="button" @click="downloadActive"><Download :size="14" />下载原文</button></div>
      </header>

      <div class="evidence-layout">
        <aside class="artifact-index">
          <div class="artifact-search"><Search :size="14" /><input v-model="query" placeholder="搜索证据" /></div>
          <div class="artifact-types">
            <button v-for="item in typeOptions" :key="item.value" type="button" :class="{ active: type === item.value }" @click="type = item.value"><component :is="item.icon" :size="14" />{{ item.label }}<b>{{ typeCount(item.value) }}</b></button>
          </div>
          <div class="artifact-list">
            <button v-for="item in filtered" :key="item.id" type="button" :class="{ active: activeId === item.id }" @click="activeId = item.id">
              <component :is="iconFor(item.type)" :size="16" /><span><strong>{{ item.title }}</strong><small>{{ item.id }} · {{ item.subtitle }}</small></span><i :class="item.status"></i>
            </button>
          </div>
        </aside>

        <article v-if="active" class="artifact-reader">
          <header>
            <div><span>{{ active.type.toUpperCase() }} / {{ active.id }}</span><h2>{{ active.title }}</h2></div>
            <span class="status-chip" :class="active.status">{{ evidenceStatus(active.status) }}</span>
          </header>
          <div class="artifact-origin">
            <span><Clock3 :size="13" />{{ active.capturedAt }}</span><span><Link2 :size="13" />{{ active.findingId }}</span><code>{{ active.hash }}</code>
          </div>
          <pre>{{ active.content }}</pre>
        </article>

        <aside v-if="activeFinding" class="artifact-context">
          <div class="context-label">LINKED CLAIM</div>
          <div class="context-badges"><span class="severity-chip" :class="activeFinding.severity">{{ severityLabel(activeFinding.severity) }}</span><span class="verification-level">L{{ activeFinding.verificationLevel || 1 }}</span></div>
          <h3>{{ activeFinding.title }}</h3>
          <p>{{ activeFinding.summary }}</p>
          <div class="context-route">
            <span><CircleDot :size="13" />{{ activeFinding.sourceNode }}</span><ArrowDown :size="13" /><span><ShieldAlert :size="13" />{{ activeFinding.sinkNode }}</span>
          </div>
          <div class="context-claims">
            <span>ValidationSession</span><strong>L{{ activeFinding.verificationLevel || 1 }} · {{ verificationLabel(activeFinding.verificationLevel) }}</strong><small>{{ linkedEvidence.length }} 个 Artifact · {{ Math.round((activeFinding.confidence || 0) * 100) }}% 结论置信度</small>
          </div>
          <router-link class="button" to="/findings"><ArrowUpRight :size="14" />打开 Finding</router-link>
        </aside>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed, markRaw, ref, watch } from 'vue'
import { ArrowDown, ArrowUpRight, Braces, CircleDot, Clock3, Code2, Download, FileJson, FlaskConical, GitBranch, Link2, Monitor, Network, ScrollText, Search, ShieldAlert } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const query = ref('')
const type = ref('all')
const activeId = ref(platform.evidence[0]?.id || '')
const iconMap = { code: markRaw(Code2), network: markRaw(Network), fuzz: markRaw(FlaskConical), browser: markRaw(Monitor), dom: markRaw(Braces), trace: markRaw(GitBranch), config: markRaw(FileJson), log: markRaw(ScrollText) }
const typeOptions = [{ value: 'all', label: '全部', icon: markRaw(ScrollText) }, { value: 'code', label: '代码', icon: markRaw(Code2) }, { value: 'network', label: '网络', icon: markRaw(Network) }, { value: 'browser', label: '浏览器', icon: markRaw(Monitor) }, { value: 'fuzz', label: 'Fuzz', icon: markRaw(FlaskConical) }, { value: 'trace', label: '轨迹', icon: markRaw(GitBranch) }]
const filtered = computed(() => platform.evidence.filter(item => (!query.value || `${item.title} ${item.id} ${item.subtitle}`.toLowerCase().includes(query.value.toLowerCase())) && (type.value === 'all' || item.type === type.value)))
const active = computed(() => platform.evidence.find(item => item.id === activeId.value) || filtered.value[0] || null)
const activeFinding = computed(() => platform.selectedFinding(active.value?.findingId))
const linkedEvidence = computed(() => platform.findingEvidence(active.value?.findingId))
watch(filtered, items => { if (items.length && !items.some(item => item.id === activeId.value)) activeId.value = items[0].id })
const iconFor = value => iconMap[value] || markRaw(ScrollText)
const typeCount = value => value === 'all' ? platform.evidence.length : platform.evidence.filter(item => item.type === value).length
const severityLabel = value => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[value] || value)
const verificationLabel = value => ({ 1: '静态证据', 2: 'Surface 一致性', 3: '沙箱证明', 4: '浏览器 / 服务证据', 5: '修复后复测' }[value] || '未分级')
const evidenceStatus = value => ({ bound: '已绑定结论', collecting: '采集中', contradicted: '反向证据' }[value] || value)
const downloadActive = () => {
  if (!active.value) return
  const blob = new Blob([active.value.content], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `${active.value.id}.txt`
  link.click()
  URL.revokeObjectURL(url)
  platform.notify('证据原文已生成下载。', 'success')
}
</script>
