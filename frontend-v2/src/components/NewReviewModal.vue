<template>
  <div v-if="ui.createReviewOpen" class="modal-backdrop" @click.self="close">
    <section class="modal-panel review-modal" role="dialog" aria-modal="true" aria-labelledby="new-review-title">
      <header class="modal-head">
        <div>
          <span class="modal-kicker">PROJECT AND AUDIT</span>
          <h2 id="new-review-title">新建本地审计</h2>
        </div>
        <button class="icon-button" type="button" aria-label="关闭" @click="close"><X :size="17" /></button>
      </header>
      <form @submit.prevent="submit">
        <div class="modal-body form-grid">
          <label class="form-field full">
            <span>项目名称</span>
            <input v-model.trim="form.name" class="input" required placeholder="例如：支付服务安全审计" />
          </label>
          <label class="form-field full">
            <span>本地项目路径</span>
            <input v-model.trim="form.path" class="input" required placeholder="E:\\workspace\\my-project" />
          </label>
          <label class="form-field full">
            <span>项目说明</span>
            <textarea v-model.trim="form.description" class="textarea" placeholder="可选。用于区分审计项目。"></textarea>
          </label>
          <fieldset class="coverage-field full">
            <legend>审计范围</legend>
            <label><input v-model="scope.web_vulns" type="checkbox" /><Globe2 :size="15" /><span>Web</span></label>
            <label><input v-model="scope.agent_vulns" type="checkbox" /><Bot :size="15" /><span>Agent</span></label>
            <label><input v-model="scope.secret_leaks" type="checkbox" /><KeyRound :size="15" /><span>Secrets</span></label>
            <label><input v-model="form.use_llm" type="checkbox" /><Sparkles :size="15" /><span>LLM 审查</span></label>
          </fieldset>
          <div class="review-plan full">
            <Route :size="18" />
            <div>
              <strong>创建后立即排入 Harness</strong>
              <p>项目会保存到本地 API，随后依次执行运行面建模、审计、验证和整改建议。运行面模型可在威胁模型页面单独重建。</p>
            </div>
          </div>
        </div>
        <footer class="modal-foot">
          <button class="button" type="button" @click="close">取消</button>
          <button class="button primary" type="submit" :disabled="submitting">
            <LoaderCircle v-if="submitting" :size="15" class="spin" />
            <Play v-else :size="15" />
            {{ submitting ? '正在创建' : '创建并审计' }}
          </button>
        </footer>
      </form>
    </section>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { Bot, Globe2, KeyRound, LoaderCircle, Play, Route, Sparkles, X } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'
import { useUiStore } from '../stores/ui'

const ui = useUiStore()
const platform = usePlatformStore()
const submitting = ref(false)
const form = reactive({ name: '', path: '', description: '', use_llm: false })
const scope = reactive({ web_vulns: true, agent_vulns: true, secret_leaks: true })

const close = () => {
  if (!submitting.value) ui.createReviewOpen = false
}

const submit = async () => {
  if (!form.name || !form.path) {
    platform.notify('请填写项目名称和本地路径。', 'warning', '项目参数')
    return
  }
  submitting.value = true
  try {
    await platform.createProjectAndAudit({ ...form, audit_scope: { ...scope } })
    ui.createReviewOpen = false
  } catch (error) {
    platform.notify(error.userMessage || error.message || '创建审计失败。', 'error', 'Harness')
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.review-modal { width: min(680px, 100%); }
.modal-kicker { display: block; margin-bottom: 4px; color: var(--focus); font-family: var(--font-mono); font-size: 11px; font-weight: 700; letter-spacing: .1em; }
.coverage-field.full, .review-plan.full { grid-column: 1 / -1; }
.coverage-field { display: grid; grid-template-columns: repeat(4, 1fr); gap: 7px; margin: 0; padding: 10px; border: 1px solid var(--line); border-radius: var(--radius-md); }
.coverage-field legend { padding: 0 6px; color: var(--ink-secondary); font-size: 12px; font-weight: 700; }
.coverage-field label { display: flex; min-height: 42px; align-items: center; gap: 8px; padding: 0 10px; border: 1px solid transparent; border-radius: var(--radius-sm); background: var(--canvas-soft); color: var(--ink-secondary); font-size: 13px; cursor: pointer; }
.coverage-field label:has(input:checked) { border-color: color-mix(in srgb, var(--focus) 42%, var(--line)); background: var(--focus-soft); color: var(--ink); }
.coverage-field input { accent-color: var(--focus); }
.review-plan { display: flex; align-items: flex-start; gap: 10px; padding: 13px; border: 1px solid color-mix(in srgb, var(--focus) 35%, var(--line)); border-radius: var(--radius-md); background: var(--focus-soft); color: var(--focus); }
.review-plan strong { font-size: 13.5px; }
.review-plan p { margin: 4px 0 0; color: var(--ink-secondary); font-size: 12px; line-height: 1.6; }
@media (max-width: 620px) { .coverage-field { grid-template-columns: repeat(2, 1fr); } }
</style>
