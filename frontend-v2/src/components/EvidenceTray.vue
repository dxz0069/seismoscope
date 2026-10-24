<template>
  <section class="evidence-tray" :class="{ open }">
    <button class="tray-handle" type="button" @click="$emit('toggle')">
      <span class="tray-title"><FlaskConical :size="15" /> Evidence Tray <b>{{ evidence.length }}</b></span>
      <span v-if="active" class="tray-current"><component :is="iconFor(active.type)" :size="14" />{{ active.title }}</span>
      <ChevronUp v-if="!open" :size="16" />
      <ChevronDown v-else :size="16" />
    </button>
    <div v-if="open" class="tray-body">
      <div class="evidence-index">
        <button v-for="item in evidence" :key="item.id" type="button" :class="{ active: item.id === activeId }" @click="$emit('select', item.id)">
          <component :is="iconFor(item.type)" :size="16" />
          <span><strong>{{ item.title }}</strong><small>{{ item.subtitle }}</small></span>
          <span class="evidence-state" :class="item.status"></span>
        </button>
      </div>
      <article v-if="active" class="evidence-viewer">
        <header>
          <div><span>{{ active.type }} · {{ active.id }}</span><h3>{{ active.title }}</h3></div>
          <div><span>{{ active.capturedAt }}</span><code>{{ active.hash }}</code></div>
        </header>
        <pre>{{ active.content }}</pre>
      </article>
      <div v-else class="tray-empty">选择一项证据查看原始内容。</div>
    </div>
  </section>
</template>

<script setup>
import { computed, markRaw } from 'vue'
import { Braces, ChevronDown, ChevronUp, Code2, FileJson, FlaskConical, Globe2, Monitor, Network, RadioTower, ScrollText } from 'lucide-vue-next'

const props = defineProps({
  evidence: { type: Array, default: () => [] },
  activeId: { type: String, default: '' },
  open: Boolean
})
defineEmits(['toggle', 'select'])

const active = computed(() => props.evidence.find(item => item.id === props.activeId) || props.evidence[0] || null)
const icons = {
  code: markRaw(Code2), network: markRaw(Network), fuzz: markRaw(FlaskConical), browser: markRaw(Monitor),
  dom: markRaw(Braces), trace: markRaw(RadioTower), config: markRaw(FileJson), screenshot: markRaw(Globe2), log: markRaw(ScrollText)
}
const iconFor = type => icons[type] || markRaw(ScrollText)
</script>

<style scoped>
.evidence-tray {
  position: absolute;
  z-index: 18;
  right: 0;
  bottom: 0;
  left: 0;
  height: 48px;
  border-top: 1px solid var(--line-strong);
  background: var(--tray-glass);
  box-shadow: 0 -12px 32px rgba(0, 0, 0, 0.22);
  backdrop-filter: blur(16px);
  transition: height var(--motion-normal);
}

.evidence-tray.open { height: min(330px, 48vh); }

.tray-handle {
  display: grid;
  width: 100%;
  height: 47px;
  grid-template-columns: auto minmax(0, 1fr) 24px;
  align-items: center;
  gap: 12px;
  padding: 0 14px;
  background: transparent;
  color: var(--ink-secondary);
  cursor: pointer;
  text-align: left;
  transition: background var(--motion-fast);
}

.tray-handle:hover { background: var(--row-hover); }

.tray-title,
.tray-current {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
}

.tray-title { color: var(--ink); font-family: var(--font-display); font-size: 14px; font-weight: 700; }
.tray-title b { padding: 2px 8px; border: 1px solid color-mix(in srgb, var(--focus) 32%, var(--line)); border-radius: 10px; background: var(--focus-soft); color: var(--focus); font-family: var(--font-mono); font-size: 12px; }
.tray-current { overflow: hidden; color: var(--ink-muted); font-size: 13px; text-overflow: ellipsis; white-space: nowrap; }

.tray-body {
  display: grid;
  height: calc(100% - 48px);
  grid-template-columns: 332px minmax(0, 1fr);
  border-top: 1px solid var(--line);
}

.evidence-index {
  min-height: 0;
  padding: 6px;
  border-right: 1px solid var(--line);
  overflow-y: auto;
}

.evidence-index button {
  display: grid;
  width: 100%;
  min-height: 56px;
  grid-template-columns: 30px minmax(0, 1fr) 18px;
  align-items: center;
  gap: 7px;
  padding: 5px 9px;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--ink-muted);
  cursor: pointer;
  text-align: left;
}

.evidence-index button:hover,
.evidence-index button.active { background: var(--surface-hover); color: var(--ink); }
.evidence-index button.active { box-shadow: inset 2px 0 0 var(--focus); }
.evidence-index button > span:nth-child(2) { display: grid; min-width: 0; }
.evidence-index strong,
.evidence-index small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.evidence-index strong { color: var(--ink-secondary); font-size: 13px; }
.evidence-index small { color: var(--ink-muted); font-size: 11px; }
.evidence-state { width: 7px; height: 7px; justify-self: center; border-radius: 50%; }
.evidence-state.bound { background: var(--verified); }
.evidence-state.collecting { background: var(--focus); animation: pulse 1.1s ease-in-out infinite; }
.evidence-state.contradicted { background: var(--critical); }

.evidence-viewer { min-width: 0; min-height: 0; overflow: auto; }
.evidence-viewer header { display: flex; min-height: 58px; align-items: center; justify-content: space-between; gap: 18px; padding: 9px 16px; border-bottom: 1px solid var(--line); }
.evidence-viewer header > div { display: grid; min-width: 0; }
.evidence-viewer header > div:last-child { justify-items: end; color: var(--ink-muted); font-size: 11px; }
.evidence-viewer header span { color: var(--ink-muted); font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; }
.evidence-viewer h3 { margin: 2px 0 0; font-size: 15px; font-weight: 700; }
.evidence-viewer code { font-size: 11px; }
.evidence-viewer pre { min-height: calc(100% - 58px); margin: 0; padding: 16px; overflow: auto; background: var(--code-bg); color: var(--code-ink); font-size: 13.5px; line-height: 1.72; white-space: pre-wrap; }
.tray-empty { display: grid; place-items: center; color: var(--ink-muted); }

@media (max-width: 760px) {
  .tray-current { display: none; }
  .tray-body { grid-template-columns: 1fr; }
  .evidence-index { border-right: 0; }
  .evidence-viewer { display: none; }
}
</style>
