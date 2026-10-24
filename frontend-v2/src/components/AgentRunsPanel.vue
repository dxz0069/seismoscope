<template>
  <section class="foundation-panel">
    <header class="foundation-toolbar"><div class="foundation-metrics"><span><b>{{ runs.length }}</b>运行</span><span><i class="failed"></i>{{ compromisedCount }} 已攻破</span><span><i class="completed"></i>{{ resistedCount }} 已抵抗</span><span><i class="running"></i>{{ processingCount }} 执行中</span></div><div class="head-actions"><button class="icon-button" title="导出 CSV" @click="platform.exportAgentRuns"><Download :size="15" /></button><button class="button" @click="openRun(true)"><Layers3 :size="14" />批量回归</button><button class="button primary" @click="openRun(false)"><Play :size="14" />新建运行</button></div></header>
    <div class="run-ledger"><article v-for="item in runs" :key="item.run_id" class="agent-run-row"><span class="verdict-mark" :class="verdictClass(item)"><ShieldX v-if="verdictClass(item) === 'compromised'" :size="17" /><ShieldCheck v-else-if="verdictClass(item) === 'resisted'" :size="17" /><LoaderCircle v-else :size="17" /></span><div class="run-ledger-title"><span><code>{{ item.run_id }}</code><span class="status-chip" :class="item.status">{{ statusLabel(item.status) }}</span></span><strong>{{ item.target_name || targetName(item.target_id) }} × {{ item.scenario_title || scenarioName(item.scenario_id) }}</strong><small>{{ item.campaign_name || 'uncategorized' }} · {{ modeLabel(item.execution_mode) }} · {{ item.created_at || '-' }}</small></div><div class="run-score"><strong>{{ item.score ?? '—' }}</strong><span>安全评分</span></div><div class="run-verdict"><span>{{ verdictLabel(item) }}</span><small>{{ item.risk_level || item.scenario_severity || '-' }}</small></div><button class="icon-button danger-icon" title="删除运行" @click="remove(item)"><Trash2 :size="14" /></button></article><div v-if="!runs.length" class="empty-panel"><div><FlaskConical :size="28" /><strong>暂无验证运行</strong><span>选择目标和场景创建一次 Agent 安全验证。</span></div></div></div>

    <div v-if="runOpen" class="modal-backdrop" @click.self="runOpen = false"><section class="modal-panel run-editor"><header class="modal-head"><div><span class="page-kicker">{{ batchMode ? 'REGRESSION BATCH' : 'AGENT VERIFICATION' }}</span><h2>{{ batchMode ? '创建批量回归' : '创建验证运行' }}</h2></div><button class="icon-button" @click="runOpen = false"><X :size="16" /></button></header><form @submit.prevent="createRun"><div class="modal-body form-grid"><template v-if="!batchMode"><label class="form-field"><span>智能体目标</span><select v-model.number="runForm.target_id" class="select" required><option disabled :value="0">选择目标</option><option v-for="item in platform.targets.filter(v => v.is_active)" :key="item.id" :value="item.id">{{ item.name }}</option></select></label><label class="form-field"><span>攻击场景</span><select v-model.number="runForm.scenario_id" class="select" required><option disabled :value="0">选择场景</option><option v-for="item in platform.scenarios.filter(v => v.is_active)" :key="item.id" :value="item.id">{{ item.title }}</option></select></label><label class="form-field"><span>执行模式</span><select v-model="runForm.execution_mode" class="select"><option value="simulation">模拟评估</option><option value="manual_trace">真实轨迹</option></select></label></template><template v-else><fieldset class="check-field"><legend>目标</legend><label v-for="item in platform.targets.filter(v => v.is_active)" :key="item.id"><input v-model="targetIds" type="checkbox" :value="item.id" />{{ item.name }}</label></fieldset><fieldset class="check-field"><legend>场景</legend><label v-for="item in platform.scenarios.filter(v => v.is_active)" :key="item.id"><input v-model="scenarioIds" type="checkbox" :value="item.id" />{{ item.title }}</label></fieldset></template><label class="form-field"><span>Campaign</span><input v-model="runForm.campaign_name" class="input" placeholder="payment-baseline" /></label><label class="form-field"><span>Baseline label</span><input v-model="runForm.baseline_label" class="input" placeholder="before-fix" /></label><template v-if="!batchMode && runForm.execution_mode === 'manual_trace'"><label class="form-field"><span>轨迹格式</span><select v-model="runForm.trace_format_hint" class="select"><option value="auto">自动识别</option><option value="json">JSON</option><option value="jsonl">JSONL</option><option value="text">文本</option></select></label><label class="form-field full"><span>Operator Trace</span><textarea v-model="runForm.operator_trace_raw" class="textarea trace-textarea" required placeholder="粘贴真实 Agent 轨迹"></textarea></label><div class="trace-preview-action full"><button class="button" type="button" @click="previewTrace"><ScanSearch :size="14" />解析预览</button><span v-if="tracePreview">{{ tracePreview.event_count }} 条事件 · {{ Object.keys(tracePreview.role_breakdown || {}).length }} 个角色</span></div><pre v-if="tracePreview" class="artifact-code full">{{ JSON.stringify(tracePreview.sample_events || [], null, 2) }}</pre></template></div><footer class="modal-foot"><button class="button" type="button" @click="runOpen = false">取消</button><button class="button primary" type="submit"><Play :size="14" />{{ batchMode ? '启动批量回归' : '启动验证' }}</button></footer></form></section></div>
  </section>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'
import { Download, FlaskConical, Layers3, LoaderCircle, Play, ScanSearch, ShieldCheck, ShieldX, Trash2, X } from 'lucide-vue-next'
import { api } from '../services/api'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const runOpen = ref(false)
const batchMode = ref(false)
const targetIds = ref([])
const scenarioIds = ref([])
const tracePreview = ref(null)
const fresh = () => ({ target_id: 0, scenario_id: 0, campaign_name: '', baseline_label: '', execution_mode: 'simulation', operator_trace_raw: '', trace_format_hint: 'auto' })
const runForm = reactive(fresh())
const runs = computed(() => platform.agentRuns || [])
const compromisedCount = computed(() => runs.value.filter(item => verdictClass(item) === 'compromised').length)
const resistedCount = computed(() => runs.value.filter(item => verdictClass(item) === 'resisted').length)
const processingCount = computed(() => runs.value.filter(item => ['processing', 'pending'].includes(item.status)).length)
const openRun = batch => { Object.assign(runForm, fresh()); targetIds.value = []; scenarioIds.value = []; tracePreview.value = null; batchMode.value = batch; runOpen.value = true }
const createRun = async () => {
  const payload = batchMode.value ? { target_ids: targetIds.value, scenario_ids: scenarioIds.value, active_only: !targetIds.value.length && !scenarioIds.value.length, campaign_name: runForm.campaign_name || null, baseline_label: runForm.baseline_label || null } : { ...runForm, campaign_name: runForm.campaign_name || null, baseline_label: runForm.baseline_label || null }
  try { await platform.createAgentRun(payload, batchMode.value); runOpen.value = false } catch (error) { platform.notify(error.userMessage || error.message, 'error', '运行创建失败') }
}
const previewTrace = async () => { try { tracePreview.value = await api.parseAgentTrace({ raw_text: runForm.operator_trace_raw, format_hint: runForm.trace_format_hint }) } catch (error) { platform.notify(error.userMessage || error.message, 'error', '轨迹解析失败') } }
const remove = async item => { if (window.confirm(`删除验证运行 ${item.run_id}？`)) await platform.deleteAgentRun(item.run_id) }
const verdictClass = item => item.result || item.verdict || (item.status === 'completed' ? 'resisted' : 'processing')
const verdictLabel = item => ({ compromised: '已攻破', resisted: '已抵抗', inconclusive: '无法判定', processing: '评估中' }[verdictClass(item)] || verdictClass(item))
const statusLabel = value => ({ processing: '执行中', completed: '已完成', failed: '失败', pending: '等待中' }[value] || value)
const modeLabel = value => ({ simulation: '模拟', manual_trace: '真实轨迹', trace: '真实轨迹' }[value] || value || '模拟')
const targetName = id => platform.targets.find(item => item.id === id)?.name || `Target ${id}`
const scenarioName = id => platform.scenarios.find(item => item.id === id)?.title || `Scenario ${id}`
</script>
