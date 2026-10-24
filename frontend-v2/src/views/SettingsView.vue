<template>
  <section class="view-page settings-page">
    <div class="page-wrap settings-wrap">
      <header class="page-head">
        <div><span class="page-kicker">POLICY / WORKFLOW GATES</span><h1>模型与策略</h1><p>配置模型角色、权限边界、人工确认和 Finding 闭环条件。</p></div>
        <span class="source-chip" :class="platform.sources.configs || 'demo'">{{ platform.sources.configs === 'live' ? 'FastAPI' : '演示数据' }}</span>
      </header>

      <div class="settings-layout">
        <nav class="settings-nav">
          <button v-for="item in tabs" :key="item.id" type="button" :class="{ active: activeTab === item.id }" @click="activeTab = item.id"><component :is="item.icon" :size="16" /><span><strong>{{ item.label }}</strong><small>{{ item.description }}</small></span><ChevronRight :size="14" /></button>
        </nav>

        <main class="settings-content">
          <template v-if="activeTab === 'models'">
            <header class="settings-section-head"><div><h2>模型配置</h2><p>聊天模型负责审查与验证，Embedding 模型负责代码定位与知识检索。</p></div><button class="button primary" type="button" @click="openCreate"><Plus :size="14" />新增模型</button></header>
            <div class="model-list">
              <article v-for="item in platform.configs" :key="item.id" class="model-row">
                <div class="model-mark" :class="item.model_type"><BrainCircuit v-if="item.model_type === 'chat'" :size="19" /><Binary v-else :size="19" /></div>
                <div class="model-name"><span><strong>{{ item.model_name }}</strong><span class="status-chip" :class="item.is_active ? 'active' : 'draft'">{{ item.is_active ? 'Active' : 'Inactive' }}</span></span><small>{{ providerLabel(item.provider) }} · {{ item.model_type }} · {{ maskUrl(item.api_base) }}</small><p>{{ item.description || '未填写用途说明。' }}</p></div>
                <div class="model-params"><span>Temperature <b>{{ item.temperature }}</b></span><span>Max tokens <b>{{ item.max_tokens }}</b></span><span>Top P <b>{{ item.top_p }}</b></span></div>
                <div class="inline-actions"><button class="icon-button" title="测试模型连接" :disabled="testingModelId === item.id" @click="testConnection(item)"><RefreshCw v-if="testingModelId === item.id" class="spin" :size="14" /><Wifi v-else :size="14" /></button><button class="icon-button" title="编辑" @click="openEdit(item)"><Pencil :size="14" /></button><button class="icon-button" :title="item.is_active ? '停用' : '启用'" @click="platform.toggleConfig(item)"><Power :size="14" /></button><button class="icon-button danger-icon" title="删除" @click="remove(item)"><Trash2 :size="14" /></button></div>
              </article>
            </div>
          </template>

          <template v-else-if="activeTab === 'policy'">
            <header class="settings-section-head"><div><h2>Permission / Closure Policy</h2><p>权限决定工具能否执行，Closure Gates 决定 Finding 能否关闭。</p></div><button class="button primary" type="button" @click="savePolicy"><Save :size="14" />保存本地策略</button></header>
            <div class="policy-matrix">
              <div class="policy-row policy-header"><span>能力</span><span>读取</span><span>写入</span><span>网络</span><span>Shell</span></div>
              <div v-for="row in policyRows" :key="row.id" class="policy-row"><span><component :is="row.icon" :size="15" /><span><strong>{{ row.label }}</strong><small>{{ row.scope }}</small></span></span><select v-for="operation in operations" :key="operation" v-model="row[operation]" :aria-label="`${row.label} ${operation}`"><option value="allow">允许</option><option value="approval">需审批</option><option value="deny">拒绝</option></select></div>
            </div>
            <section class="guard-settings"><header><div><ShieldCheck :size="17" /><span><strong>ReasoningGuard</strong><small>在结论与证据不一致时阻止闭环</small></span></div><label class="switch"><input v-model="guardEnabled" type="checkbox" /><span></span></label></header><div><label><input v-model="guardRules" type="checkbox" value="evidence_mismatch" />证据与结论不匹配</label><label><input v-model="guardRules" type="checkbox" value="closure_state_conflict" />闭环状态冲突</label><label><input v-model="guardRules" type="checkbox" value="reward_hacking" />目标偏移</label></div></section>
            <section class="closure-settings"><header><div><BadgeCheck :size="17" /><span><strong>Closure Gates</strong><small>满足证据、Return 与 Retest 条件后才能关闭</small></span></div><label class="level-select">最低等级<select v-model.number="minimumLevel" class="select"><option :value="2">L2</option><option :value="3">L3</option><option :value="4">L4</option><option :value="5">L5</option></select></label></header><div><label><input v-model="closureRules" type="checkbox" value="artifact_refs" />Evidence refs 已绑定</label><label><input v-model="closureRules" type="checkbox" value="human_confirmation" />敏感修复已确认</label><label><input v-model="closureRules" type="checkbox" value="return_delivered" />Return 已交付</label><label><input v-model="closureRules" type="checkbox" value="positive_negative_retest" />正反向复测通过</label></div></section>
          </template>

          <template v-else>
            <header class="settings-section-head"><div><h2>运行时适配</h2><p>当前 FastAPI 能力与设计文档目标之间的接入状态。</p></div><button class="button" type="button" @click="platform.initialize(true)"><RefreshCw :size="14" />重新检测</button></header>
            <div class="adapter-list">
              <div v-for="item in adapters" :key="item.name"><span class="adapter-light" :class="item.status"></span><span><strong>{{ item.name }}</strong><small>{{ item.description }}</small></span><code>{{ item.endpoint }}</code><span class="status-chip" :class="item.status === 'live' ? 'active' : 'pending'">{{ item.status === 'live' ? '已接入' : '待接入' }}</span></div>
            </div>
          </template>
        </main>
      </div>
    </div>

    <div v-if="editorOpen" class="modal-backdrop" @click.self="editorOpen = false">
      <section class="modal-panel model-editor">
        <header class="modal-head"><div><span class="page-kicker">MODEL ADAPTER</span><h2>{{ form.id ? '编辑模型配置' : '新增模型配置' }}</h2></div><button class="icon-button" @click="editorOpen = false"><X :size="16" /></button></header>
        <form @submit.prevent="saveModel">
          <div class="modal-body form-grid">
            <label class="form-field"><span>模型角色</span><select v-model="form.model_type" class="select"><option value="chat">Chat / 审查验证</option><option value="embedding">Embedding / 检索</option></select></label>
            <label class="form-field"><span>Provider</span><select v-model="form.provider" class="select"><option value="openai">OpenAI</option><option value="openai_compatible">OpenAI Compatible</option><option value="anthropic">Anthropic</option><option value="auto">Auto</option></select></label>
            <label class="form-field full"><span>API Base</span><input v-model="form.api_base" class="input" type="url" required placeholder="https://api.example.com/v1" /></label>
            <label class="form-field"><span>模型名称</span><input v-model="form.model_name" class="input" required placeholder="gpt-5.1" /></label>
            <label class="form-field"><span>API Key</span><input v-model="form.api_key" class="input" type="password" required autocomplete="new-password" placeholder="仅提交到 FastAPI，不写入前端" /></label>
            <label class="form-field"><span>Temperature</span><input v-model.number="form.temperature" class="input" type="number" min="0" max="2" step="0.1" /></label>
            <label class="form-field"><span>Max tokens</span><input v-model.number="form.max_tokens" class="input" type="number" min="1" /></label>
            <label class="form-field"><span>Top P</span><input v-model.number="form.top_p" class="input" type="number" min="0" max="1" step="0.1" /></label>
            <label class="form-field"><span>状态</span><select v-model.number="form.is_active" class="select"><option :value="1">启用</option><option :value="0">停用</option></select></label>
            <label class="form-field full"><span>用途说明</span><textarea v-model="form.description" class="textarea"></textarea></label>
          </div>
          <footer class="modal-foot"><button class="button" type="button" @click="editorOpen = false">取消</button><button class="button primary" type="submit" :disabled="saving"><Save :size="14" />保存配置</button></footer>
        </form>
      </section>
    </div>
  </section>
</template>

<script setup>
import { BadgeCheck, Binary, Bot, BrainCircuit, ChevronRight, Container, Globe2, Network, Pencil, Plus, Power, RefreshCw, Save, ShieldCheck, Trash2, Wifi, Wrench, X } from 'lucide-vue-next'
import { markRaw, onMounted, reactive, ref } from 'vue'
import { usePlatformStore } from '../stores/platform'
import { api } from '../services/api'

const platform = usePlatformStore()
const activeTab = ref('models')
const editorOpen = ref(false)
const saving = ref(false)
const testingModelId = ref('')
const guardEnabled = ref(true)
const guardRules = ref(['evidence_mismatch', 'closure_state_conflict'])
const minimumLevel = ref(4)
const closureRules = ref(['artifact_refs', 'human_confirmation', 'return_delivered', 'positive_negative_retest'])
const tabs = [{ id: 'models', label: '模型配置', description: '审查、验证与检索', icon: markRaw(BrainCircuit) }, { id: 'policy', label: '权限与闭环', description: '工具边界和 Closure Gates', icon: markRaw(ShieldCheck) }, { id: 'runtime', label: '核心适配', description: 'Harness 与现有 FastAPI', icon: markRaw(Container) }]
const operations = ['read', 'write', 'network', 'shell']
const policyRows = reactive([
  { id: 'browser', label: 'Browser Executor', scope: '隔离浏览器', icon: markRaw(Globe2), read: 'allow', write: 'approval', network: 'approval', shell: 'deny' },
  { id: 'agent', label: 'Agent Harness', scope: '工具与轨迹', icon: markRaw(Bot), read: 'allow', write: 'approval', network: 'approval', shell: 'deny' },
  { id: 'mcp', label: 'MCP Server', scope: '远端工具', icon: markRaw(Wrench), read: 'allow', write: 'approval', network: 'approval', shell: 'deny' },
  { id: 'source', label: 'Source Auditor', scope: '项目代码', icon: markRaw(Network), read: 'allow', write: 'deny', network: 'deny', shell: 'approval' }
])
const adapters = [
  { name: 'Health Check / Report', description: '体检创建、运行、报告读取', endpoint: '/api/ai-health-checks', status: 'live' },
  { name: 'Source Audit', description: '采集、审计、任务恢复', endpoint: '/api/process-task', status: 'live' },
  { name: 'Agent Security Lab', description: '目标、场景、轨迹与批量回归', endpoint: '/api/agent-test-runs', status: 'live' },
  { name: 'RunSession / Checkpoint', description: 'JSONL 或 SQLite 本地会话状态', endpoint: 'core/session', status: 'planned' },
  { name: 'RuntimeSurfaceGraph', description: '稳定节点、边与 RiskChain 绑定', endpoint: 'core/surface', status: 'planned' },
  { name: 'Evidence / Validation', description: 'EvidenceBundle 与 L1–L5 验证', endpoint: 'core/verification', status: 'planned' },
  { name: 'Return / Retest', description: 'RemediationBundle 返回与闭环', endpoint: 'core/remediation + skill', status: 'planned' }
]
const fresh = () => ({ model_type: 'chat', provider: 'openai_compatible', api_base: '', api_key: '', model_name: '', temperature: 0.2, max_tokens: 4096, top_p: 0.9, frequency_penalty: 0, presence_penalty: 0, is_active: 1, description: '' })
const form = reactive(fresh())
const resetForm = value => { Object.keys(form).forEach(key => delete form[key]); Object.assign(form, value) }
const openCreate = () => { resetForm(fresh()); editorOpen.value = true }
const openEdit = item => { resetForm({ ...item, api_key: '' }); editorOpen.value = true }
const saveModel = async () => { saving.value = true; try { const payload = { ...form }; if (form.id && !payload.api_key) delete payload.api_key; await platform.saveConfig(payload); editorOpen.value = false } finally { saving.value = false } }
const testConnection = async item => {
  if (platform.connection !== 'live') {
    platform.notify('请先连接本地 FastAPI，再测试模型连接。', 'error', '模型连接')
    return
  }
  testingModelId.value = item.id
  try {
    const result = await api.testModelConfigConnection(item.id)
    platform.notify(result.message, result.status === 'connected' ? 'success' : 'error', '模型连接')
  } catch (error) {
    platform.notify(error.userMessage || error.message || '模型连接测试失败。', 'error', '模型连接')
  } finally {
    testingModelId.value = ''
  }
}
const remove = async item => { if (window.confirm(`删除模型配置“${item.model_name}”？`)) await platform.deleteConfig(item.id) }
const providerLabel = value => ({ openai: 'OpenAI', openai_compatible: 'OpenAI compatible', anthropic: 'Anthropic', auto: 'Auto' }[value] || value)
const maskUrl = value => { try { return new URL(value).host } catch { return value || '-' } }
const savePolicy = () => { localStorage.setItem('vibesec-policy', JSON.stringify({ rows: policyRows, guardEnabled: guardEnabled.value, guardRules: guardRules.value, minimumLevel: minimumLevel.value, closureRules: closureRules.value })); platform.notify('V2 权限与闭环策略已保存在当前浏览器。后端 core/policy 接入后可同步执行。', 'success') }
onMounted(() => {
  platform.refreshModelConfigs().catch(error => {
    platform.notify(error.userMessage || error.message || 'Unable to load model configurations', 'error', 'Models')
  })
})
</script>

<style scoped>
.closure-settings { margin: 20px; border: 1px solid var(--line); }
.closure-settings > header { display: flex; min-height: 66px; align-items: center; justify-content: space-between; gap: 12px; padding: 0 14px; border-bottom: 1px solid var(--line); }
.closure-settings > header > div { display: flex; align-items: center; gap: 9px; }
.closure-settings header span { display: grid; }
.closure-settings header strong { font-size: 13px; }
.closure-settings header small { color: var(--ink-muted); font-size: 12px; }
.closure-settings > div { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px 18px; padding: 14px; }
.closure-settings > div label { display: flex; align-items: center; gap: 7px; color: var(--ink-secondary); font-size: 12px; }
.closure-settings input { accent-color: var(--focus); }
.spin { animation: settings-spin 0.8s linear infinite; }
@keyframes settings-spin { to { transform: rotate(360deg); } }
.level-select { display: flex; align-items: center; gap: 8px; color: var(--ink-muted); font-size: 12px; }
.level-select .select { width: 72px; min-height: 34px; }
@media (max-width: 760px) {
  .closure-settings > header { align-items: flex-start; flex-direction: column; padding: 12px 14px; }
  .closure-settings > div { grid-template-columns: 1fr; }
}
</style>
