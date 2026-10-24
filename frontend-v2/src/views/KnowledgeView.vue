<template>
  <section class="view-page knowledge-page">
    <div class="page-wrap">
      <header class="page-head">
        <div><span class="page-kicker">PROGRESSIVE DISCLOSURE</span><h1>安全知识库</h1><p>审查 Agent 按需加载的漏洞模式、判定依据和修复约束。</p></div>
        <div class="head-actions">
          <span class="source-chip" :class="platform.sources.knowledge || 'demo'">{{ platform.sources.knowledge === 'live' ? 'FastAPI' : '演示数据' }}</span>
          <input ref="fileInput" class="visually-hidden" type="file" accept=".csv,text/csv" @change="importCsv" />
          <button class="icon-button" type="button" title="导入 CSV" @click="fileInput?.click()"><Upload :size="15" /></button>
          <button class="icon-button" type="button" title="导出 CSV" @click="platform.exportKnowledge"><Download :size="15" /></button>
          <button class="button primary" type="button" @click="openCreate"><Plus :size="15" />新建条目</button>
        </div>
      </header>

      <div class="resource-toolbar">
        <div class="resource-search"><Search :size="15" /><input v-model="query" placeholder="搜索名称、描述、标签" /></div>
        <div class="segmented"><button v-for="item in layers" :key="item.value" type="button" :class="{ active: layer === item.value }" @click="layer = item.value">{{ item.label }}</button></div>
        <select v-model="severity" class="select toolbar-select"><option value="">全部风险</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option></select>
      </div>

      <div class="knowledge-layout">
        <aside class="knowledge-taxonomy">
          <header>知识域</header>
          <button type="button" :class="{ active: category === '' }" @click="category = ''"><Library :size="14" /><span>全部条目</span><b>{{ platform.knowledge.length }}</b></button>
          <button v-for="item in categories" :key="item.name" type="button" :class="{ active: category === item.name }" @click="category = item.name"><component :is="categoryIcon(item.name)" :size="14" /><span>{{ item.name }}</span><b>{{ item.count }}</b></button>
          <div class="taxonomy-note"><Layers3 :size="16" /><p>Layer 1 只暴露摘要；Layer 2 展示判定与缓解；Layer 3 保留完整细节供 Agent 引用。</p></div>
        </aside>

        <main class="knowledge-results">
          <header><span>{{ filtered.length }} 个条目</span><small>按引用次数排序</small></header>
          <article v-for="item in filtered" :key="item.id" class="knowledge-row">
            <div class="knowledge-marker" :class="item.severity"><BookOpen :size="16" /></div>
            <div class="knowledge-main">
              <div class="knowledge-title"><span class="severity-chip" :class="item.severity">{{ severityLabel(item.severity) }}</span><h2>{{ item.title }}</h2><span class="status-chip" :class="item.is_active ? 'active' : 'draft'">{{ item.is_active ? '启用' : '停用' }}</span></div>
              <p>{{ item.description || '未填写漏洞模式描述。' }}</p>
              <div v-if="layer !== 'summary'" class="knowledge-detail"><span>缓解策略</span><p>{{ item.mitigation || '尚未定义。' }}</p></div>
              <div v-if="layer === 'full'" class="knowledge-detail"><span>影响与常见场景</span><p>{{ item.impact || item.common_scenarios || '尚未补充。' }}</p></div>
              <div class="tag-line"><span>{{ item.category }}</span><code v-for="tag in item.tags || []" :key="tag">#{{ tag }}</code></div>
            </div>
            <div class="knowledge-meta"><span><GitFork :size="13" />{{ item.reference_count || 0 }} 引用</span><button class="icon-button" type="button" title="编辑" @click="openEdit(item)"><Pencil :size="14" /></button><button class="icon-button" type="button" :title="item.is_active ? '停用' : '启用'" @click="platform.toggleKnowledge(item)"><ToggleRight v-if="item.is_active" :size="16" /><ToggleLeft v-else :size="16" /></button><button class="icon-button danger-icon" type="button" title="删除" @click="remove(item)"><Trash2 :size="14" /></button></div>
          </article>
          <div v-if="!filtered.length" class="empty-panel"><div><SearchX :size="26" /><strong>没有匹配条目</strong><span>调整搜索条件或新建知识条目。</span></div></div>
        </main>
      </div>
    </div>

    <div v-if="editorOpen" class="modal-backdrop" @click.self="editorOpen = false">
      <section class="modal-panel knowledge-editor">
        <header class="modal-head"><div><span class="page-kicker">KNOWLEDGE ENTRY</span><h2>{{ form.id ? '编辑知识条目' : '新建知识条目' }}</h2></div><button class="icon-button" @click="editorOpen = false"><X :size="16" /></button></header>
        <form @submit.prevent="save">
          <div class="modal-body form-grid">
            <label class="form-field full"><span>名称</span><input v-model="form.title" class="input" required /></label>
            <label class="form-field"><span>知识域</span><input v-model="form.category" class="input" required placeholder="Agent Security" /></label>
            <label class="form-field"><span>风险等级</span><select v-model="form.severity" class="select"><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option></select></label>
            <label class="form-field full"><span>漏洞模式描述</span><textarea v-model="form.description" class="textarea" required></textarea></label>
            <label class="form-field full"><span>缓解策略</span><textarea v-model="form.mitigation" class="textarea"></textarea></label>
            <label class="form-field"><span>常见场景</span><textarea v-model="form.common_scenarios" class="textarea"></textarea></label>
            <label class="form-field"><span>影响</span><textarea v-model="form.impact" class="textarea"></textarea></label>
            <label class="form-field full"><span>标签（逗号分隔）</span><input v-model="tagsInput" class="input" placeholder="prompt, context, authorization" /></label>
          </div>
          <footer class="modal-foot"><button class="button" type="button" @click="editorOpen = false">取消</button><button class="button primary" type="submit" :disabled="saving"><Save :size="14" />保存条目</button></footer>
        </form>
      </section>
    </div>
  </section>
</template>

<script setup>
import { computed, markRaw, reactive, ref } from 'vue'
import { BookOpen, Bot, Download, GitFork, Globe2, Layers3, Library, Network, Pencil, Plus, Save, Search, SearchX, ShieldAlert, ToggleLeft, ToggleRight, Trash2, Upload, Wrench, X } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const fileInput = ref(null)
const query = ref('')
const category = ref('')
const severity = ref('')
const layer = ref('summary')
const editorOpen = ref(false)
const saving = ref(false)
const tagsInput = ref('')
const fresh = () => ({ title: '', category: 'Agent Security', severity: 'high', description: '', common_scenarios: '', mitigation: '', impact: '', tags: [], is_active: 1 })
const form = reactive(fresh())
const layers = [{ value: 'summary', label: '摘要' }, { value: 'decision', label: '判定与缓解' }, { value: 'full', label: '完整上下文' }]
const categories = computed(() => Object.entries(platform.knowledge.reduce((acc, item) => { acc[item.category || '未分类'] = (acc[item.category || '未分类'] || 0) + 1; return acc }, {})).map(([name, count]) => ({ name, count })))
const filtered = computed(() => platform.knowledge.filter(item => {
  const text = `${item.title} ${item.description || ''} ${(item.tags || []).join(' ')}`.toLowerCase()
  return text.includes(query.value.toLowerCase()) && (!category.value || item.category === category.value) && (!severity.value || item.severity === severity.value)
}).sort((a, b) => (b.reference_count || 0) - (a.reference_count || 0)))
const severityLabel = value => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[value] || value)
const categoryIcon = value => value.includes('Agent') ? markRaw(Bot) : value.includes('MCP') ? markRaw(Wrench) : value.includes('Web') || value.includes('Business') ? markRaw(Globe2) : value.includes('Network') ? markRaw(Network) : markRaw(ShieldAlert)
const resetForm = value => { Object.keys(form).forEach(key => delete form[key]); Object.assign(form, value); tagsInput.value = (value.tags || []).join(', ') }
const openCreate = () => { resetForm(fresh()); editorOpen.value = true }
const openEdit = item => { resetForm({ ...item }); editorOpen.value = true }
const save = async () => { saving.value = true; try { await platform.saveKnowledge({ ...form, tags: tagsInput.value.split(',').map(item => item.trim()).filter(Boolean) }); editorOpen.value = false } finally { saving.value = false } }
const remove = async item => { if (window.confirm(`删除知识条目“${item.title}”？`)) await platform.deleteKnowledge(item.id) }
const importCsv = async event => { const file = event.target.files?.[0]; if (file) await platform.importKnowledge(file); event.target.value = '' }
</script>

