<template>
  <section class="foundation-panel">
    <header class="foundation-toolbar">
      <div class="foundation-metrics"><span><b>{{ tasks.length }}</b>总任务</span><span><i class="running"></i>{{ runningCount }} 执行中</span><span><i class="completed"></i>{{ completedCount }} 已完成</span><span><i class="failed"></i>{{ failedCount }} 失败</span></div>
      <div class="head-actions"><select v-model="status" class="select toolbar-select"><option value="">全部状态</option><option value="processing">执行中</option><option value="completed">已完成</option><option value="failed">失败</option><option value="pending">等待中</option></select><button class="button primary" type="button" @click="createOpen = true"><Plus :size="14" />新建源码任务</button></div>
    </header>
    <div class="data-surface foundation-table">
      <div class="data-table-wrap"><table class="data-table"><thead><tr><th>任务</th><th>来源</th><th>状态</th><th>进度</th><th>创建时间</th><th>最后更新</th><th></th></tr></thead><tbody><tr v-for="task in filtered" :key="task.task_id"><td><code>{{ task.task_id }}</code></td><td><span class="task-source"><UploadCloud v-if="task.task_type === 'upload'" :size="14" /><Globe2 v-else :size="14" />{{ task.task_type === 'upload' ? '文件上传' : '网页采集' }}</span></td><td><span class="status-chip" :class="task.status">{{ statusLabel(task.status) }}</span></td><td><span class="table-progress"><i :style="{ width: `${task.progress || 0}%` }"></i><b>{{ task.progress || 0 }}%</b></span></td><td>{{ task.create_time || '-' }}</td><td>{{ task.updated_at || '-' }}</td><td><div class="inline-actions"><button v-if="task.status === 'completed'" class="icon-button" title="查看审计结果" @click="openResult(task)"><FileSearch :size="14" /></button><button v-if="['failed','paused','pending'].includes(task.status)" class="icon-button" title="恢复任务" @click="platform.resumeTask(task.task_id)"><Play :size="14" /></button><button class="icon-button danger-icon" title="删除" @click="remove(task)"><Trash2 :size="14" /></button></div></td></tr></tbody></table></div>
      <div v-if="!filtered.length" class="empty-panel"><div><FileCode2 :size="28" /><strong>暂无源码任务</strong><span>通过网页采集或文件上传创建第一个审计任务。</span></div></div>
    </div>

    <div v-if="createOpen" class="modal-backdrop" @click.self="createOpen = false">
      <section class="modal-panel source-task-editor">
        <header class="modal-head"><div><span class="page-kicker">SOURCE ACQUISITION</span><h2>新建源码任务</h2></div><button class="icon-button" @click="createOpen = false"><X :size="16" /></button></header>
        <div class="modal-body">
          <div class="segmented source-mode"><button type="button" :class="{ active: mode === 'crawler' }" @click="mode = 'crawler'"><Globe2 :size="14" />网页采集</button><button type="button" :class="{ active: mode === 'upload' }" @click="mode = 'upload'"><UploadCloud :size="14" />文件上传</button></div>
          <form class="source-form" @submit.prevent="createTask">
            <template v-if="mode === 'crawler'"><label class="form-field"><span>目标 URL</span><input v-model="url" class="input" type="url" required placeholder="https://example.com" /></label><label class="form-field"><span>采集深度</span><input v-model.number="depth" class="input" type="number" min="1" max="8" /></label><div class="form-note"><Route :size="16" /><span>系统采集页面源码、脚本和依赖后自动进入漏洞审计。</span></div></template>
            <template v-else><label class="upload-drop"><input ref="uploadInput" type="file" multiple @change="files = [...$event.target.files]" /><UploadCloud :size="24" /><strong>选择源码文件</strong><span>{{ files.length ? `已选择 ${files.length} 个文件` : '支持文本源码与配置文件，可多选' }}</span></label></template>
            <div class="button-row form-actions"><button class="button" type="button" @click="createOpen = false">取消</button><button class="button primary" type="submit" :disabled="submitting"><Play :size="14" />创建并审计</button></div>
          </form>
        </div>
      </section>
    </div>

    <div v-if="resultOpen" class="modal-backdrop" @click.self="resultOpen = false">
      <section class="modal-panel task-result-modal"><header class="modal-head"><div><code>{{ currentTask?.task_id }}</code><h2>源码审计结果</h2></div><button class="icon-button" @click="resultOpen = false"><X :size="16" /></button></header><div class="modal-body"><pre class="artifact-code">{{ resultText }}</pre></div></section>
    </div>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import { FileCode2, FileSearch, Globe2, Play, Plus, Route, Trash2, UploadCloud, X } from 'lucide-vue-next'
import { api } from '../services/api'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const status = ref('')
const createOpen = ref(false)
const resultOpen = ref(false)
const currentTask = ref(null)
const resultText = ref('')
const mode = ref('crawler')
const url = ref('')
const depth = ref(2)
const files = ref([])
const submitting = ref(false)
const tasks = computed(() => platform.tasks || [])
const filtered = computed(() => tasks.value.filter(item => !status.value || item.status === status.value))
const runningCount = computed(() => tasks.value.filter(item => item.status === 'processing').length)
const completedCount = computed(() => tasks.value.filter(item => item.status === 'completed').length)
const failedCount = computed(() => tasks.value.filter(item => item.status === 'failed').length)
const statusLabel = value => ({ processing: '执行中', completed: '已完成', failed: '失败', pending: '等待中', paused: '已暂停' }[value] || value)
const readFile = file => new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = reject; reader.readAsText(file) })
const createTask = async () => {
  if (mode.value === 'upload' && !files.value.length) return platform.notify('请选择至少一个源码文件。', 'warning')
  submitting.value = true
  try {
    let payload
    if (mode.value === 'crawler') payload = { command: 'crawler', params: { url: url.value, depth: depth.value } }
    else {
      const rows = await Promise.all(files.value.map(async file => ({ success: true, filename: file.name, content: await readFile(file), file_type: file.name.split('.').pop()?.toLowerCase() || 'text', file_size: file.size })))
      payload = { command: 'upload', params: { upload_results: { results: rows } } }
    }
    await platform.createTask(payload)
    createOpen.value = false
  } catch (error) { platform.notify(error.userMessage || error.message, 'error', '创建失败') } finally { submitting.value = false }
}
const openResult = async task => {
  currentTask.value = task
  resultOpen.value = true
  resultText.value = '正在读取审计结果...'
  try { resultText.value = JSON.stringify(await api.getAuditResult(task.task_id), null, 2) } catch (error) { resultText.value = `读取失败：${error.userMessage || error.message}` }
}
const remove = async task => { if (window.confirm(`删除源码任务 ${task.task_id}？`)) await platform.deleteTask(task.task_id) }
</script>

