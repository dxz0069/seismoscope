<template>
  <div class="graph-shell">
    <div ref="chartEl" class="graph-canvas" aria-label="Runtime Surface 攻击面关系图"></div>
    <div class="graph-controls">
      <button type="button" title="放大" @click="zoom(1.22)"><ZoomIn :size="16" /></button>
      <button type="button" title="缩小" @click="zoom(0.82)"><ZoomOut :size="16" /></button>
      <button type="button" title="重置视图" @click="render"><LocateFixed :size="16" /></button>
    </div>
    <div class="graph-mode">
      <button v-for="mode in modes" :key="mode.id" type="button" :class="{ active: activeMode === mode.id }" @click="activeMode = mode.id">
        <component :is="mode.icon" :size="14" />{{ mode.label }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { computed, markRaw, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { GraphChart } from 'echarts/charts'
import { TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { Focus, LocateFixed, Route, Shield, ZoomIn, ZoomOut } from 'lucide-vue-next'

echarts.use([GraphChart, TooltipComponent, CanvasRenderer])

const props = defineProps({
  graph: { type: Object, required: true },
  highlightedNodes: { type: Array, default: () => [] }
})
const emit = defineEmits(['select-node'])

const chartEl = ref(null)
const activeMode = ref('risk')
const compact = ref(false)
const lightTheme = ref(document.documentElement.dataset.theme === 'light')
let chart = null
let observer = null
let themeObserver = null

const modes = [
  { id: 'risk', label: '风险', icon: markRaw(Shield) },
  { id: 'boundary', label: '边界', icon: markRaw(Focus) },
  { id: 'flow', label: '数据流', icon: markRaw(Route) }
]

const themePalette = computed(() => lightTheme.value ? {
  categories: {
    entry: { color: '#ffffff', border: '#1c232d', text: '#171b21' },
    page: { color: '#e9f6f8', border: '#2d7e8f', text: '#20323a' },
    prompt: { color: '#f2edff', border: '#7255c5', text: '#34285a' },
    agent: { color: '#edf1ff', border: '#4167d5', text: '#25345f' },
    tool: { color: '#f4efff', border: '#7255c5', text: '#34285a' },
    mcp: { color: '#fff5df', border: '#9b6d1d', text: '#594115' },
    api: { color: '#e7f6ef', border: '#257f5b', text: '#234d3c' },
    storage: { color: '#e9f6f8', border: '#2d7e8f', text: '#20323a' },
    data: { color: '#e7f6ef', border: '#257f5b', text: '#234d3c' },
    external: { color: '#fff0ef', border: '#c64e48', text: '#662f2b' },
    finding: { color: '#fff0ef', border: '#c64e48', text: '#662f2b' },
    impact: { color: '#fff5df', border: '#9b6d1d', text: '#594115' }
  },
  risk: { critical: '#c64e48', high: '#d26743', medium: '#9b6d1d', low: '#257f5b', default: '#7b8794' },
  highlight: '#171b21', focus: '#4167d5', label: '#25313d', neutralLink: '#9ca8b4', flow: '#2d7e8f',
  tooltip: { background: '#ffffff', border: '#c2ccd6', text: '#171b21', meta: '#667382' }
} : {
  categories: {
    entry: { color: '#f0f1ec', border: '#f0f1ec', text: '#17191d' },
    page: { color: '#171a20', border: '#63c8d7', text: '#f3f4ef' },
    prompt: { color: '#171a20', border: '#aa8cff', text: '#f3f4ef' },
    agent: { color: '#1b2131', border: '#7c9cff', text: '#f3f4ef' },
    tool: { color: '#211a2f', border: '#aa8cff', text: '#f3f4ef' },
    mcp: { color: '#211e16', border: '#e2b45a', text: '#f3f4ef' },
    api: { color: '#14241e', border: '#56c596', text: '#f3f4ef' },
    storage: { color: '#151e24', border: '#63c8d7', text: '#f3f4ef' },
    data: { color: '#15211b', border: '#56c596', text: '#f3f4ef' },
    external: { color: '#251817', border: '#ff6b63', text: '#f3f4ef' },
    finding: { color: '#251817', border: '#ff6b63', text: '#f3f4ef' },
    impact: { color: '#211e16', border: '#e2b45a', text: '#f3f4ef' }
  },
  risk: { critical: '#ff6b63', high: '#ff8a65', medium: '#e2b45a', low: '#56c596', default: '#4a505c' },
  highlight: '#f3f4ef', focus: '#7c9cff', label: '#e7e9e4', neutralLink: '#424854', flow: '#63c8d7',
  tooltip: { background: '#181b21', border: '#363b45', text: '#f3f4ef', meta: '#8f96a2' }
})

const riskColor = risk => themePalette.value.risk[risk] || themePalette.value.risk.default

const formattedNodes = computed(() => props.graph.nodes.map(node => {
  const style = themePalette.value.categories[node.category] || themePalette.value.categories.page
  const highlighted = props.highlightedNodes.includes(node.id)
  return {
    ...node,
    symbolSize: compact.value ? Math.max(32, Math.round(node.symbolSize * 0.62)) : node.symbolSize,
    value: node.meta,
    itemStyle: {
      color: style.color,
      borderColor: highlighted ? themePalette.value.highlight : node.risk ? riskColor(node.risk) : style.border,
      borderWidth: highlighted ? 3 : 1.5,
      shadowBlur: highlighted ? 24 : node.risk ? 14 : 0,
      shadowColor: node.risk ? riskColor(node.risk) : themePalette.value.focus
    },
    label: {
      color: style.text,
      fontWeight: highlighted ? 700 : 600,
      fontSize: compact.value ? 9 : 11
    }
  }
}))

const render = async () => {
  await nextTick()
  if (!chartEl.value) return
  compact.value = chartEl.value.clientWidth < 600
  if (!chart) {
    chart = echarts.init(chartEl.value, null, { renderer: 'canvas' })
    chart.on('click', params => {
      if (params.dataType === 'node') emit('select-node', params.data)
    })
  }

  const palette = themePalette.value
  chart.setOption({
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: palette.tooltip.background,
      borderColor: palette.tooltip.border,
      borderWidth: 1,
      padding: 10,
      textStyle: { color: palette.tooltip.text, fontSize: 12 },
      formatter: params => params.dataType === 'node'
        ? `<strong>${params.data.name}</strong><br/><span style="color:${palette.tooltip.meta}">${params.data.meta || params.data.category}</span>`
        : `${params.data.kind || 'relation'}`
    },
    series: [{
      type: 'graph',
      layout: 'none',
      roam: true,
      draggable: true,
      scaleLimit: { min: 0.45, max: 2.8 },
      data: formattedNodes.value,
      links: props.graph.links.map(link => ({
        ...link,
        lineStyle: {
          color: link.risk ? riskColor(link.risk) : activeMode.value === 'flow' ? palette.flow : palette.neutralLink,
          width: link.risk ? 2.2 : 1.1,
          opacity: link.risk ? 0.88 : activeMode.value === 'risk' ? 0.45 : 0.72,
          curveness: 0.12,
          type: activeMode.value === 'boundary' && ['tool-call', 'request', 'network'].includes(link.kind) ? 'dashed' : 'solid'
        }
      })),
      edgeSymbol: ['none', 'arrow'],
      edgeSymbolSize: 6,
      label: {
        show: true,
        position: 'bottom',
        distance: 8,
        color: palette.label,
        fontFamily: 'Microsoft YaHei UI',
        fontSize: compact.value ? 9 : 11,
        formatter: params => params.data.name
      },
      emphasis: {
        focus: 'adjacency',
        lineStyle: { width: 3, opacity: 1 },
        label: { fontSize: 12 }
      },
      select: { itemStyle: { borderColor: palette.highlight, borderWidth: 3 } },
      selectedMode: 'single',
      animationDuration: 520,
      animationEasingUpdate: 'cubicOut'
    }]
  }, true)
}

const zoom = multiplier => {
  if (!chart) return
  const current = chart.getOption().series?.[0]?.zoom || 1
  chart.setOption({ series: [{ zoom: current * multiplier }] })
}

watch(() => [props.graph, props.highlightedNodes, activeMode.value, lightTheme.value], render, { deep: true })

onMounted(() => {
  render()
  observer = new ResizeObserver(() => chart?.resize())
  observer.observe(chartEl.value)
  themeObserver = new MutationObserver(() => {
    lightTheme.value = document.documentElement.dataset.theme === 'light'
  })
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
})

onBeforeUnmount(() => {
  observer?.disconnect()
  themeObserver?.disconnect()
  chart?.dispose()
})
</script>

<style scoped>
.graph-shell,
.graph-canvas {
  position: absolute;
  inset: 0;
}

.graph-shell {
  overflow: hidden;
  background-color: var(--graph-bg);
  background-image: linear-gradient(var(--graph-grid) 1px, transparent 1px), linear-gradient(90deg, var(--graph-grid) 1px, transparent 1px);
  background-size: 32px 32px;
}

.graph-canvas { z-index: 1; }

.graph-controls,
.graph-mode {
  position: absolute;
  z-index: 4;
  display: flex;
  padding: 3px;
  border: 1px solid var(--line);
  border-radius: var(--radius-md);
  background: var(--float-glass);
  box-shadow: var(--shadow-md), var(--inset-hairline);
  backdrop-filter: blur(12px);
}

.graph-controls {
  right: 14px;
  bottom: 64px;
  flex-direction: column;
}

.graph-mode {
  top: 14px;
  left: 50%;
  gap: 2px;
  transform: translateX(-50%);
  transition: opacity var(--motion-fast), transform var(--motion-normal);
}

.graph-controls button,
.graph-mode button {
  display: inline-flex;
  min-height: 30px;
  align-items: center;
  justify-content: center;
  gap: 6px;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--ink-muted);
  cursor: pointer;
  font-size: 12px;
  transition: transform var(--motion-fast), background var(--motion-fast), color var(--motion-fast), box-shadow var(--motion-fast);
}

.graph-controls button { width: 30px; }
.graph-mode button { padding: 0 10px; }
.graph-controls button:hover,
.graph-mode button:hover { background: var(--surface-hover); color: var(--ink); }
.graph-mode button.active { background: var(--focus-soft); box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--focus) 32%, transparent); color: var(--ink); font-weight: 700; }
.graph-controls button:active,
.graph-mode button:active { transform: scale(0.92); }
.graph-mode button.active svg { color: var(--focus); transform: rotate(-5deg); }

@media (min-width: 761px) and (max-width: 1100px) {
  .graph-mode {
    right: 14px;
    left: auto;
    transform: none;
  }
}

@media (max-width: 760px) {
  .graph-mode { top: 7px; right: auto; left: 62px; transform: none; }
  .graph-mode button { min-height: 32px; padding: 0 8px; font-size: 10px; }
  :global(.workspace-canvas:not(.signals-collapsed)) .graph-mode { visibility: hidden; opacity: 0 !important; pointer-events: none; transform: translateY(-4px); }
}
</style>
