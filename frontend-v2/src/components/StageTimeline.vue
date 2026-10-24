<template>
  <div class="stage-timeline" aria-label="审查阶段">
    <button v-for="(stage, index) in stages" :key="stage.id" type="button" :class="[stage.status, { active: active === stage.id }]" @click="$emit('select', stage.id)">
      <span class="stage-marker">
        <Check v-if="stage.status === 'completed'" :size="12" />
        <LoaderCircle v-else-if="stage.status === 'running'" :size="12" class="spin" />
        <span v-else-if="stage.status === 'failed'">!</span>
        <span v-else>{{ index + 1 }}</span>
      </span>
      <span class="stage-text"><strong>{{ stage.label }}</strong><small>{{ stage.description }}</small></span>
    </button>
    <span class="stage-progress" :style="{ width: `${progressPercent}%` }"></span>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Check, LoaderCircle } from 'lucide-vue-next'

const props = defineProps({
  stages: { type: Array, required: true },
  active: { type: String, required: true }
})
defineEmits(['select'])

const progressPercent = computed(() => {
  const total = props.stages.length || 1
  const done = props.stages.filter(item => item.status === 'completed').length
  const running = props.stages.some(item => item.status === 'running') ? 0.5 : 0
  return Math.min(100, ((done + running) / total) * 100)
})
</script>

<style scoped>
.stage-timeline {
  position: relative;
  display: grid;
  height: 50px;
  grid-template-columns: repeat(9, minmax(106px, 1fr));
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
  background: var(--panel-glass);
  overflow-x: auto;
}

.stage-progress {
  position: absolute;
  bottom: -1px;
  left: 0;
  z-index: 2;
  height: 2px;
  max-width: 100%;
  background: var(--grad-accent);
  box-shadow: 0 0 8px color-mix(in srgb, var(--focus) 45%, transparent);
  content: "";
  pointer-events: none;
  transition: width var(--motion-slow);
}

.stage-timeline button {
  position: relative;
  display: grid;
  min-width: 0;
  grid-template-columns: 24px minmax(0, 1fr);
  align-items: center;
  gap: 7px;
  padding: 0 9px;
  border-right: 1px solid var(--line);
  background: transparent;
  color: var(--ink-muted);
  cursor: pointer;
  text-align: left;
  transition: background var(--motion-fast), color var(--motion-fast);
}

.stage-timeline button:last-child { border-right: 0; }
.stage-timeline button:hover { background: var(--surface); }
.stage-timeline button.active { background: var(--grad-accent-soft); }
.stage-timeline button.active::after { position: absolute; right: 8px; bottom: -1px; left: 8px; z-index: 3; height: 2px; border-radius: 2px; background: var(--grad-accent); box-shadow: 0 0 8px color-mix(in srgb, var(--focus) 45%, transparent); content: ""; }

.stage-marker {
  position: relative;
  display: grid;
  width: 24px;
  height: 24px;
  place-items: center;
  border: 1px solid var(--line-strong);
  border-radius: 50%;
  background: var(--canvas-soft);
  font-family: var(--font-mono);
  font-size: 11px;
  transition: transform var(--motion-normal), border-color var(--motion-fast), background var(--motion-fast), box-shadow var(--motion-fast);
}

.stage-timeline button:hover .stage-marker { transform: scale(1.1); }

button.completed .stage-marker { border-color: rgba(86, 197, 150, 0.42); background: var(--verified-soft); color: var(--verified); }
button.running .stage-marker { border-color: rgba(124, 156, 255, 0.55); background: var(--focus-soft); box-shadow: 0 0 0 3px var(--focus-soft), 0 0 12px color-mix(in srgb, var(--focus) 35%, transparent); color: var(--focus); }
button.failed .stage-marker { border-color: color-mix(in srgb, var(--critical) 60%, var(--line)); background: var(--critical-soft); color: var(--critical); }
button.active .stage-text strong { color: var(--focus-strong); }

.stage-text { display: grid; min-width: 0; }
.stage-text strong { overflow: hidden; color: var(--ink); font-family: var(--font-display); font-size: 14px; font-weight: 700; text-overflow: ellipsis; white-space: nowrap; transition: color var(--motion-fast); }
.stage-text small { overflow: hidden; margin-top: 2px; color: var(--ink-muted); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }

@media (max-width: 760px) {
  .stage-timeline { grid-template-columns: repeat(9, 126px); }
}
</style>
