<template>
  <section class="runtime-graph" aria-label="运行面建模图">
    <div ref="chartEl" class="runtime-graph__canvas"></div>
    <div class="runtime-graph__toolbar" role="group" aria-label="图视图控制">
      <div class="runtime-graph__planes">
        <button
          v-for="view in views"
          :key="view.id"
          type="button"
          :class="{ active: activeView === view.id }"
          :title="view.title"
          @click="activeView = view.id"
        >
          <component :is="view.icon" :size="14" />
          <span>{{ view.label }}</span>
        </button>
      </div>
      <label v-if="activeView === 'source_trace'" class="runtime-graph__toggle" title="显示没有安全关系边的源码实体">
        <input v-model="showIsolated" type="checkbox" />
        <span>孤立节点</span>
      </label>
      <label class="runtime-graph__toggle" title="仅显示选中风险路径中的实体">
        <input v-model="focusPath" type="checkbox" :disabled="!activeRiskPath" />
        <span>路径聚焦</span>
      </label>
    </div>
    <div class="runtime-graph__controls">
      <button type="button" title="放大" aria-label="放大" @click="zoom(1.2)"><ZoomIn :size="16" /></button>
      <button type="button" title="缩小" aria-label="缩小" @click="zoom(.84)"><ZoomOut :size="16" /></button>
      <button type="button" title="重置视图" aria-label="重置视图" @click="resetLayout"><LocateFixed :size="16" /></button>
    </div>
    <div class="runtime-graph__summary">
      <span><b>{{ graphState.nodes.length }}</b> {{ activeView === 'source_trace' ? '源码节点' : '风险实体' }}</span>
      <span><b>{{ graphState.edges.length }}</b> 关系</span>
      <span v-if="activeGraph.collapsed_implementation_node_count"><b>{{ activeGraph.collapsed_implementation_node_count }}</b> 个实现节点已聚合</span>
      <span v-if="activeView === 'source_trace' && !showIsolated && graphState.hiddenIsolated"><b>{{ graphState.hiddenIsolated }}</b> 个孤立节点已隐藏</span>
      <span v-if="graphState.hiddenByFocus"><b>{{ graphState.hiddenByFocus }}</b> 个路径外节点已隐藏</span>
      <span v-if="graphState.hiddenByLimit"><b>{{ graphState.hiddenByLimit }}</b> 个低优先级节点已聚合</span>
      <template v-if="activeView !== 'source_trace'">
        <span class="runtime-graph__legend"><i class="risk"></i>红色边框：待验证风险相关</span>
        <span class="runtime-graph__legend"><i class="flow"></i>箭头：静态代码关系</span>
      </template>
    </div>
  </section>
</template>

<script setup>
import { computed, markRaw, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { GraphChart } from 'echarts/charts'
import { TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { Boxes, Database, Fingerprint, LocateFixed, Route, ShieldCheck, ShieldEllipsis, Sparkles, ZoomIn, ZoomOut } from 'lucide-vue-next'

echarts.use([GraphChart, TooltipComponent, CanvasRenderer])

const props = defineProps({
  visualization: { type: Object, required: true },
  selectedPathId: { type: String, default: '' }
})
const emit = defineEmits(['select-node'])

const chartEl = ref(null)
const activeView = ref('risk_overview')
const showIsolated = ref(false)
const focusPath = ref(false)
const lightTheme = ref(document.documentElement.dataset.theme === 'light')
let chart = null
let observer = null
let themeObserver = null
const draggedPositions = new Map()

const views = [
  { id: 'risk_overview', label: '风险概览', title: '默认决策视图：只显示被建模的风险实体与路径', icon: markRaw(Boxes) },
  { id: 'ai_agent', label: '智能面', title: '提示词、模型、记忆、自动化工作流与可调用能力', icon: markRaw(Sparkles) },
  { id: 'data', label: '数据面', title: '外部输入、应用入口与敏感数据流', icon: markRaw(Route) },
  { id: 'authority', label: '权限面', title: '信任边界、授权、审批与特权能力', icon: markRaw(ShieldCheck) },
  { id: 'source_trace', label: '源码追溯', title: '高级视图：按源码实体追溯风险证据', icon: markRaw(Fingerprint) }
]

const palette = computed(() => lightTheme.value ? {
  text: '#17202a', muted: '#5f6c7c', neutralEdge: '#8795a5', grid: '#edf1f6', tooltip: '#ffffff', tooltipBorder: '#c4ced9'
} : {
  text: '#eef2f6', muted: '#a6b0bc', neutralEdge: '#647181', grid: '#1d2430', tooltip: '#151b23', tooltipBorder: '#394454'
})

const sourceTrace = computed(() => ({
  ...props.visualization,
  id: 'source-trace',
  title: '源码追溯',
  collapsed_implementation_node_count: 0,
  source_node_count: Array.isArray(props.visualization.nodes) ? props.visualization.nodes.length : 0,
  source_edge_count: Array.isArray(props.visualization.edges) ? props.visualization.edges.length : 0
}))
const activeGraph = computed(() => {
  if (activeView.value === 'source_trace') return sourceTrace.value
  return props.visualization.projections?.[activeView.value] || sourceTrace.value
})
const activeRiskPath = computed(() => (activeGraph.value.risk_paths || []).find(item => item.id === props.selectedPathId) || null)
const actionableRiskIds = computed(() => new Set((activeGraph.value.risk_paths || [])
  .filter(path => !['refuted', 'mitigated', 'resolved'].includes(String(path.status || '').toLowerCase()))
  .map(path => String(path.id))))
const maxRenderNodes = computed(() => activeView.value === 'source_trace' ? 120 : 40)

const graphState = computed(() => {
  const rawNodes = Array.isArray(activeGraph.value.nodes) ? activeGraph.value.nodes : []
  const rawEdges = Array.isArray(activeGraph.value.edges) ? activeGraph.value.edges : []
  const connected = new Set(rawEdges.flatMap(edge => [edge.source, edge.target]))
  const pathNodes = new Set(activeRiskPath.value?.path_node_ids || [])
  const pathEdges = new Set()
  const selectedPathNodes = activeRiskPath.value?.path_node_ids || []
  for (let index = 0; index < selectedPathNodes.length - 1; index += 1) {
    pathEdges.add(`${selectedPathNodes[index]}:${selectedPathNodes[index + 1]}`)
  }
  const allCandidates = rawNodes.filter(node => showIsolated.value || connected.has(node.id) || pathNodes.has(node.id))
  const candidates = focusPath.value && pathNodes.size
    ? allCandidates.filter(node => pathNodes.has(node.id))
    : allCandidates
  const degree = new Map(candidates.map(node => [node.id, 0]))
  for (const edge of rawEdges) {
    if (degree.has(edge.source)) degree.set(edge.source, degree.get(edge.source) + 1)
    if (degree.has(edge.target)) degree.set(edge.target, degree.get(edge.target) + 1)
  }
  const selectedNodes = candidates.filter(node => pathNodes.has(node.id))
  const selectedIds = new Set(selectedNodes.map(node => node.id))
  const remainingSlots = Math.max(0, maxRenderNodes.value - selectedNodes.length)
  const rankedCandidates = candidates
    .filter(node => !selectedIds.has(node.id))
    .sort((left, right) => {
      const leftRisk = left.risk_hypothesis_ids?.length ? 1 : 0
      const rightRisk = right.risk_hypothesis_ids?.length ? 1 : 0
      if (rightRisk !== leftRisk) return rightRisk - leftRisk
      const degreeDifference = (degree.get(right.id) || 0) - (degree.get(left.id) || 0)
      if (degreeDifference) return degreeDifference
      return String(left.label || left.id).localeCompare(String(right.label || right.id))
    })
  const visibleNodes = candidates.length > maxRenderNodes.value
    ? [...selectedNodes, ...rankedCandidates.slice(0, remainingSlots)]
    : candidates
  const allowed = new Set(visibleNodes.map(node => node.id))
  const edges = rawEdges.filter(edge => allowed.has(edge.source) && allowed.has(edge.target))
  return {
    nodes: visibleNodes,
    edges,
    pathNodes,
    pathEdges,
    hiddenIsolated: Math.max(0, rawNodes.length - allCandidates.length),
    hiddenByFocus: Math.max(0, allCandidates.length - candidates.length),
    hiddenByLimit: Math.max(0, candidates.length - visibleNodes.length)
  }
})

const nodeShape = type => {
  if (['external_input', 'application_entry', 'ai_context', 'agent_workflow', 'capability', 'control_boundary', 'sensitive_asset'].includes(type)) return 'roundRect'
  if (['external_actor', 'external_content'].includes(type)) return 'diamond'
  if (['entry_point', 'workflow'].includes(type)) return 'roundRect'
  if (['trust_boundary', 'permission'].includes(type)) return 'rect'
  if (['storage_asset', 'browser_sink', 'privileged_asset'].includes(type)) return 'pin'
  return 'circle'
}

const relationLabel = relation => {
  const value = String(relation || '').toLowerCase()
  const labels = {
    reads: '读取', writes: '写入', accesses: '访问', invokes: '调用', can_invoke: '可调用',
    supplies_data: '提供数据', influences_instruction: '影响指令', influences: '影响',
    delegates_authority: '委托权限', crosses_boundary: '跨越边界', persists_to: '持久化',
    loads_from: '加载', authenticates_as: '身份认证', renders: '渲染输出',
    semantic_flow: '运行面关联', flows: '数据流', risk_path: '风险路径'
  }
  const parts = value.split(',').map(part => part.trim()).filter(Boolean)
  return parts.map(part => labels[part] || part).join(' / ') || '运行面关联'
}

const nodeTypeLabel = type => ({
  external_input: '外部与不可信输入', application_entry: '应用入口', ai_context: '智能上下文',
  agent_workflow: '自动化代理与工作流', capability: '工具与执行能力',
  control_boundary: '授权与审批边界', sensitive_asset: '敏感资产与输出',
  external_actor: '外部访问者', external_content: '外部内容', entry_point: '应用入口',
  workflow: '工作流', trust_boundary: '信任边界', permission: '权限控制',
  storage_asset: '存储资产', browser_sink: '浏览器输出', privileged_asset: '特权操作',
  code_block: '源码实现'
}[String(type || '')] || '运行面实体')

const evidenceLabel = level => ({
  verified: '已验证', runtime_observed: '受控运行观察', static_observed: '静态代码观察',
  declared: '项目声明', inferred: '语义推断', unknown: '待补充证据'
}[String(level || '').toLowerCase()] || '待补充证据')

const shortLabel = value => {
  const label = String(value || '')
  return label.length > 28 ? `${label.slice(0, 25)}...` : label
}

const escapeHtml = value => String(value ?? '').replace(/[&<>'"]/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
}[character]))

const nodeLayers = computed(() => {
  const nodes = graphState.value.nodes
  const nodeIds = new Set(nodes.map(node => node.id))
  if (nodes.some(node => Boolean(node.attributes?.semantic_role))) {
    return new Map(nodes.map(node => [node.id, Number.isFinite(Number(node.layer)) ? Number(node.layer) : 0]))
  }
  const outgoing = new Map(nodes.map(node => [node.id, []]))
  const inDegree = new Map(nodes.map(node => [node.id, 0]))
  const layers = new Map()

  for (const edge of graphState.value.edges) {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) continue
    outgoing.get(edge.source).push(edge.target)
    inDegree.set(edge.target, inDegree.get(edge.target) + 1)
  }

  const queue = nodes.filter(node => inDegree.get(node.id) === 0).map(node => node.id)
  queue.forEach(id => layers.set(id, 0))

  // Longest-path layering keeps input, boundary, interface, and execution entities legible.
  for (let index = 0; index < queue.length; index += 1) {
    const source = queue[index]
    const sourceLayer = layers.get(source) || 0
    for (const target of outgoing.get(source) || []) {
      layers.set(target, Math.max(layers.get(target) || 0, sourceLayer + 1))
      inDegree.set(target, inDegree.get(target) - 1)
      if (inDegree.get(target) === 0) queue.push(target)
    }
  }

  let fallbackLayer = Math.max(0, ...layers.values()) + 1
  for (const node of nodes) {
    if (!layers.has(node.id)) {
      layers.set(node.id, fallbackLayer)
      fallbackLayer += 1
    }
  }
  return layers
})

const positionedNodes = (width = 920, height = 620) => {
  const groups = new Map()
  for (const node of graphState.value.nodes) {
    const layer = nodeLayers.value.get(node.id) || 0
    if (!groups.has(layer)) groups.set(layer, [])
    groups.get(layer).push(node)
  }
  const maxLayer = Math.max(0, ...groups.keys())
  const semanticGraph = graphState.value.nodes.some(node => Boolean(node.attributes?.semantic_role))
  const horizontalPadding = semanticGraph ? Math.min(150, Math.max(120, width * .19)) : Math.min(128, Math.max(74, width * .13))
  const verticalTop = 84
  const verticalBottom = Math.max(verticalTop + 80, height - 98)
  const denseGraph = graphState.value.nodes.length > 80
  const labelsVisible = graphState.value.nodes.length <= 26
  const gridColumns = Math.max(12, Math.ceil(Math.sqrt(graphState.value.nodes.length * 1.7)))
  const gridRows = Math.max(1, Math.ceil(graphState.value.nodes.length / gridColumns))
  const semanticPositions = new Map()
  if (semanticGraph) {
    const ordered = [...graphState.value.nodes].sort((left, right) => {
      const layerDifference = (Number(left.layer) || 0) - (Number(right.layer) || 0)
      return layerDifference || String(left.label || left.id).localeCompare(String(right.label || right.id))
    })
    const columns = ordered.length <= 2 ? ordered.length : 2
    const rows = Math.max(1, Math.ceil(ordered.length / columns))
    ordered.forEach((node, index) => {
      const column = index % columns
      const row = Math.floor(index / columns)
      semanticPositions.set(node.id, {
        x: width * ((column + 1) / (columns + 1)),
        y: verticalTop + ((row + 1) / (rows + 1)) * (verticalBottom - verticalTop)
      })
    })
  }
  return graphState.value.nodes.map((node, nodeIndex) => {
    const layer = nodeLayers.value.get(node.id) || 0
    const group = groups.get(layer) || []
    const index = group.findIndex(item => item.id === node.id)
    const layeredPosition = {
      x: maxLayer === 0
        ? width / 2
        : horizontalPadding + (layer / maxLayer) * (width - horizontalPadding * 2),
      y: verticalTop + ((index + 1) / (group.length + 1)) * (verticalBottom - verticalTop)
    }
    const gridPosition = {
      x: horizontalPadding + (((nodeIndex % gridColumns) + .5) / gridColumns) * (width - horizontalPadding * 2),
      y: verticalTop + ((Math.floor(nodeIndex / gridColumns) + .5) / gridRows) * (verticalBottom - verticalTop)
    }
    const automaticPosition = semanticPositions.get(node.id) || (denseGraph ? gridPosition : layeredPosition)
    const position = draggedPositions.get(node.id) || automaticPosition
    const risk = (node.risk_hypothesis_ids || []).some(id => actionableRiskIds.value.has(String(id)))
    const selected = graphState.value.pathNodes.has(node.id)
    const selectedResolvedPath = selected && activeRiskPath.value
      && !actionableRiskIds.value.has(String(activeRiskPath.value.id))
    const evidenceLevel = node.evidence?.level || 'unknown'
    const color = node.style?.color || '#64748b'
    const semantic = Boolean(node.attributes?.semantic_role)
    const memberCount = Number(node.attributes?.represented_node_count || 0)
    return {
      ...node,
      name: node.label,
      __sourceLabel: node.label,
      x: position.x,
      y: position.y,
      symbol: nodeShape(node.type),
      symbolSize: semantic ? [168, 66] : selected ? 50 : denseGraph ? (risk ? 22 : 16) : risk ? 42 : 34,
      itemStyle: {
        color: semantic ? (lightTheme.value ? '#ffffff' : '#1c232d') : color,
        borderColor: selectedResolvedPath ? '#12b76a' : risk ? '#f97066' : evidenceLevel === 'verified' ? '#12b76a' : semantic ? (lightTheme.value ? '#a7b4c4' : '#64748b') : color,
        borderWidth: semantic ? 2.2 : selected || risk || evidenceLevel === 'verified' ? 3 : 1.4,
        shadowBlur: selected || risk ? 14 : 0,
        shadowColor: selectedResolvedPath ? '#12b76a' : risk ? '#f04438' : color
      },
      label: {
        show: semantic || labelsVisible || selected,
        position: semantic ? 'inside' : 'bottom',
        formatter: semantic
          ? `{title|${shortLabel(node.label)}}\n{meta|${memberCount} 个已建模实体}`
          : shortLabel(node.label),
        color: palette.value.text,
        fontSize: 11,
        fontWeight: selected ? 700 : 500,
        lineHeight: 18,
        rich: semantic ? {
          title: { color: palette.value.text, fontSize: 12, fontWeight: 700, lineHeight: 20, align: 'center' },
          meta: { color: palette.value.muted, fontSize: 10, lineHeight: 16, align: 'center' }
        } : undefined
      },
      __evidenceLevel: evidenceLevel
    }
  })
}

const saveDraggedPositions = () => {
  if (!chart) return
  const data = chart.getModel().getSeriesByIndex(0)?.getData()
  if (!data) return
  graphState.value.nodes.forEach((node, index) => {
    const position = data.getItemLayout(index)
    if (Array.isArray(position)) draggedPositions.set(node.id, { x: position[0], y: position[1] })
  })
}

const render = async () => {
  await nextTick()
  if (!chartEl.value) return
  if (!chart) {
    chart = echarts.init(chartEl.value, null, { renderer: 'canvas' })
    chart.on('click', params => {
      if (params.dataType === 'node') {
        emit('select-node', {
          ...params.data,
          label: params.data.__sourceLabel || params.data.name || 'unnamed entity'
        })
      }
    })
    chart.getZr().on('mouseup', saveDraggedPositions)
  }
  const currentPalette = palette.value
  chart.setOption({
    animationDuration: 360,
    animationEasingUpdate: 'cubicOut',
    tooltip: {
      trigger: 'item',
      confine: true,
      backgroundColor: currentPalette.tooltip,
      borderColor: currentPalette.tooltipBorder,
      borderWidth: 1,
      padding: 10,
      textStyle: { color: currentPalette.text, fontSize: 12 },
      formatter: params => {
        if (params.dataType !== 'node') return escapeHtml(relationLabel(params.data?.relation))
        const node = params.data
        const label = node.__sourceLabel || node.name || '未命名实体'
        const provenance = node.attributes?.provenance || {}
        const location = provenance.file_path
          ? `${provenance.file_path}:${provenance.line_start || '?'}`
          : node.attributes?.represented_node_count
            ? `已聚合 ${node.attributes.represented_node_count} 个源码实体`
            : '暂无源码位置'
        return `<strong>${escapeHtml(label)}</strong><br/><span style="color:${currentPalette.muted}">${escapeHtml(nodeTypeLabel(node.type))} | ${escapeHtml(location)}</span><br/><span style="color:${currentPalette.muted}">证据：${escapeHtml(evidenceLabel(node.__evidenceLevel))}</span>`
      }
    },
    series: [{
      type: 'graph',
      layout: 'none',
      roam: true,
      draggable: true,
      cursor: 'move',
      // ECharts fits the data extent to the canvas before applying graph zoom.
      // Keep aggregate role cards inside the narrow workbench by default; users
      // can still drag them and use the zoom controls for source inspection.
      zoom: graphState.value.nodes.some(node => Boolean(node.attributes?.semantic_role)) ? .64 : 1,
      scaleLimit: { min: 0.15, max: 3.5 },
      data: positionedNodes(chart.getWidth(), chart.getHeight()),
      links: graphState.value.edges.map(edge => {
        const selected = graphState.value.pathEdges.has(`${edge.source}:${edge.target}`)
        const risk = selected || (edge.risk_hypothesis_ids || [])
          .some(id => actionableRiskIds.value.has(String(id)))
        return {
          ...edge,
          lineStyle: {
            color: selected ? '#f04438' : edge.style?.color || (risk ? '#f97066' : currentPalette.neutralEdge),
            width: selected ? 4 : risk ? 2.5 : 1.1,
            opacity: selected || risk ? .95 : .48,
            type: edge.semantic_relation === 'crosses' ? 'dashed' : 'solid',
            curveness: .08
          }
        }
      }),
      edgeSymbol: ['none', 'arrow'],
      edgeSymbolSize: 7,
      lineStyle: { opacity: .5 },
      edgeLabel: {
        show: activeView.value !== 'source_trace',
        position: 'middle',
        color: currentPalette.muted,
        fontSize: 10,
        padding: [3, 6],
        borderRadius: 2,
        backgroundColor: currentPalette.tooltip,
        formatter: params => relationLabel(params.data?.relation)
      },
      label: { position: 'bottom', distance: 7 },
      emphasis: {
        focus: 'adjacency',
        lineStyle: { width: 3, opacity: 1 },
        label: { show: true, fontSize: 12 }
      }
    }]
  }, true)
}

const zoom = multiplier => {
  if (!chart) return
  const current = chart.getOption().series?.[0]?.zoom || 1
  chart.setOption({ series: [{ zoom: current * multiplier }] })
}

const resetLayout = () => {
  draggedPositions.clear()
  render()
}

watch(() => [props.visualization, props.selectedPathId, activeView.value, showIsolated.value, focusPath.value, lightTheme.value], render, { deep: true })
watch(() => props.visualization.fingerprint, () => {
  draggedPositions.clear()
  activeView.value = props.visualization.default_view || 'risk_overview'
  focusPath.value = false
})

onMounted(() => {
  render()
  observer = new ResizeObserver(() => {
    chart?.resize()
    // Semantic coordinates depend on the canvas size, not only chart scaling.
    render()
  })
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
.runtime-graph { position: relative; height: 100%; min-height: 0; overflow: hidden; background-color: var(--graph-bg); background-image: linear-gradient(var(--graph-grid) 1px, transparent 1px), linear-gradient(90deg, var(--graph-grid) 1px, transparent 1px); background-size: 32px 32px; }
.runtime-graph__canvas { position: absolute; inset: 0; cursor: grab; }
.runtime-graph__canvas:active { cursor: grabbing; }
.runtime-graph__toolbar, .runtime-graph__controls, .runtime-graph__summary { position: absolute; z-index: 2; border: 1px solid var(--line); background: var(--float-glass); box-shadow: var(--shadow-sm); backdrop-filter: blur(12px); }
.runtime-graph__toolbar { top: 14px; left: 14px; display: flex; align-items: center; gap: 10px; padding: 4px; }
.runtime-graph__planes { display: flex; align-items: center; gap: 2px; }
.runtime-graph__planes button, .runtime-graph__controls button { display: inline-flex; align-items: center; justify-content: center; gap: 5px; min-height: 30px; border: 0; background: transparent; color: var(--ink-muted); cursor: pointer; font-size: 12px; }
.runtime-graph__planes button { padding: 0 8px; }
.runtime-graph__planes button:hover, .runtime-graph__planes button.active, .runtime-graph__controls button:hover { background: var(--focus-soft); color: var(--ink); }
.runtime-graph__planes button.active svg { color: var(--focus); }
.runtime-graph__toggle { display: inline-flex; align-items: center; gap: 6px; min-height: 30px; padding: 0 8px; border-left: 1px solid var(--line); color: var(--ink-secondary); font-size: 12px; cursor: pointer; }
.runtime-graph__toggle input { accent-color: var(--focus); }
.runtime-graph__controls { right: 14px; bottom: 14px; display: grid; padding: 3px; }
.runtime-graph__controls button { width: 32px; }
.runtime-graph__summary { right: 54px; bottom: 14px; left: 14px; display: flex; flex-wrap: wrap; gap: 5px 12px; max-width: calc(100% - 80px); padding: 7px 10px; color: var(--ink-muted); font-family: var(--font-mono); font-size: 11px; line-height: 1.35; }
.runtime-graph__summary b { color: var(--ink); font-weight: 700; }
.runtime-graph__legend { display: inline-flex; align-items: center; gap: 5px; }
.runtime-graph__legend i { width: 14px; height: 7px; border-radius: 2px; }
.runtime-graph__legend i.risk { border: 2px solid #f04438; background: transparent; }
.runtime-graph__legend i.flow { height: 2px; border-radius: 0; background: var(--focus); }
@media (max-width: 840px) { .runtime-graph { min-height: 540px; } .runtime-graph__toolbar { right: 8px; left: 8px; flex-wrap: wrap; } .runtime-graph__planes { overflow-x: auto; max-width: 100%; } .runtime-graph__toggle { border-left: 0; } .runtime-graph__planes button span { display: none; } .runtime-graph__summary { right: 8px; bottom: 8px; left: 8px; flex-wrap: wrap; } .runtime-graph__controls { right: 8px; bottom: 62px; } }
</style>
