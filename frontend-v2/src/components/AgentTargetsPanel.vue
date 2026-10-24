<template>
  <section class="foundation-panel">
    <header class="foundation-toolbar"><div><span class="toolbar-kicker">AGENT TARGETS</span><strong>被测智能体与工具权限边界</strong></div><button class="button primary" type="button" @click="openCreate"><Plus :size="14" />新增目标</button></header>
    <div class="target-grid">
      <article v-for="item in platform.targets" :key="item.id" class="target-row">
        <div class="target-symbol"><Bot :size="19" /></div>
        <div class="target-copy"><span><strong>{{ item.name }}</strong><span class="status-chip" :class="item.is_active ? 'active' : 'draft'">{{ item.is_active ? '启用' : '停用' }}</span></span><p>{{ item.description || '未填写目标说明。' }}</p><div class="tag-line"><code v-for="tool in item.tools || []" :key="tool">{{ tool }}</code><span v-for="skill in item.skills || []" :key="skill">{{ skill }}</span></div></div>
        <div class="target-boundary"><span>审批策略<strong>{{ item.approval_policy || '未指定' }}</strong></span><span>身份范围<strong>{{ item.identity_scope || '未指定' }}</strong></span></div>
        <div class="inline-actions"><button class="icon-button" title="编辑" @click="openEdit(item)"><Pencil :size="14" /></button><button class="icon-button" :title="item.is_active ? '停用' : '启用'" @click="platform.toggleTarget(item)"><Power :size="14" /></button><button class="icon-button danger-icon" title="删除" @click="remove(item)"><Trash2 :size="14" /></button></div>
      </article>
      <div v-if="!platform.targets.length" class="empty-panel"><div><Bot :size="28" /><strong>暂无智能体目标</strong><span>创建目标后即可绑定工具、Skill、身份范围和审批策略。</span><button class="button primary" type="button" @click="openCreate"><Plus :size="14" />新增目标</button></div></div>
    </div>

    <div v-if="editorOpen" class="modal-backdrop" @click.self="editorOpen = false"><section class="modal-panel target-editor"><header class="modal-head"><div><span class="page-kicker">AGENT TARGET</span><h2>{{ form.id ? '编辑智能体目标' : '新增智能体目标' }}</h2></div><button class="icon-button" @click="editorOpen = false"><X :size="16" /></button></header><form @submit.prevent="save"><div class="modal-body form-grid"><label class="form-field"><span>名称</span><input v-model="form.name" class="input" required /></label><label class="form-field"><span>状态</span><select v-model.number="form.is_active" class="select"><option :value="1">启用</option><option :value="0">停用</option></select></label><label class="form-field full"><span>目标说明</span><textarea v-model="form.description" class="textarea"></textarea></label><label class="form-field full"><span>系统提示</span><textarea v-model="form.system_prompt" class="textarea tall-textarea"></textarea></label><label class="form-field"><span>审批策略</span><input v-model="form.approval_policy" class="input" placeholder="write_requires_approval" /></label><label class="form-field"><span>身份边界</span><input v-model="form.identity_scope" class="input" placeholder="customer" /></label><label class="form-field"><span>工具列表</span><input v-model="toolsInput" class="input" placeholder="query_order, refund_order" /></label><label class="form-field"><span>Skill 列表</span><input v-model="skillsInput" class="input" placeholder="order-support" /></label><label class="form-field"><span>运行时上下文</span><textarea v-model="form.runtime_context" class="textarea"></textarea></label><label class="form-field"><span>记忆状态</span><textarea v-model="form.memory_state" class="textarea"></textarea></label></div><footer class="modal-foot"><button class="button" type="button" @click="editorOpen = false">取消</button><button class="button primary" type="submit"><Save :size="14" />保存目标</button></footer></form></section></div>
  </section>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { Bot, Pencil, Plus, Power, Save, Trash2, X } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const editorOpen = ref(false)
const toolsInput = ref('')
const skillsInput = ref('')
const fresh = () => ({ name: '', description: '', system_prompt: '', runtime_context: '', memory_state: '', approval_policy: '', identity_scope: '', tools: [], skills: [], is_active: 1 })
const form = reactive(fresh())
const reset = item => { Object.keys(form).forEach(key => delete form[key]); Object.assign(form, item); toolsInput.value = (item.tools || []).join(', '); skillsInput.value = (item.skills || []).join(', ') }
const openCreate = () => { reset(fresh()); editorOpen.value = true }
const openEdit = item => { reset({ ...item }); editorOpen.value = true }
const save = async () => { await platform.saveTarget({ ...form, tools: toolsInput.value.split(',').map(v => v.trim()).filter(Boolean), skills: skillsInput.value.split(',').map(v => v.trim()).filter(Boolean) }); editorOpen.value = false }
const remove = async item => { if (window.confirm(`删除智能体目标“${item.name}”？`)) await platform.deleteTarget(item.id) }
</script>
