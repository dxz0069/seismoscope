<template>
  <div class="toast-host" aria-live="polite">
    <transition-group name="toast">
      <div v-for="toast in ui.toasts" :key="toast.id" class="toast-item" :class="toast.tone">
        <component :is="iconFor(toast.tone)" :size="17" />
        <div><strong v-if="toast.title">{{ toast.title }}</strong><span>{{ toast.message }}</span></div>
        <button type="button" aria-label="关闭通知" @click="ui.dismissToast(toast.id)"><X :size="15" /></button>
      </div>
    </transition-group>
  </div>
</template>

<script setup>
import { AlertCircle, CheckCircle2, Info, TriangleAlert, X } from 'lucide-vue-next'
import { useUiStore } from '../stores/ui'

const ui = useUiStore()
const iconFor = tone => ({ success: CheckCircle2, error: AlertCircle, warning: TriangleAlert, info: Info }[tone] || Info)
</script>
