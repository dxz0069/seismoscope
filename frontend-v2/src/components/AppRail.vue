<template>
  <aside class="app-rail" :class="{ expanded: ui.railExpanded, 'mobile-open': ui.mobileNavOpen }">
    <div class="rail-brand">
      <router-link to="/workspace" class="brand-symbol" aria-label="VibeSec 审查工作区">
        <span class="brand-icon-frame"><ScanLine :size="21" :stroke-width="1.9" /></span>
      </router-link>
      <div class="brand-name"><strong>Vibe Sec</strong><span>Security Harness</span></div>
      <button class="rail-collapse" type="button" :aria-label="ui.mobileNavOpen ? '关闭导航' : ui.railExpanded ? '收起导航' : '展开导航'" @click="toggleRail">
        <X v-if="ui.mobileNavOpen" :size="16" />
        <PanelLeftClose v-else-if="ui.railExpanded" :size="16" />
        <PanelLeftOpen v-else :size="16" />
      </button>
    </div>

    <nav class="rail-nav" aria-label="主导航">
      <div class="rail-group">
        <span class="rail-section-label">WORKFLOW</span>
        <router-link v-for="item in primary" :key="item.to" :to="item.to" class="rail-link">
          <span class="rail-icon"><component :is="item.icon" :size="18" /></span>
          <span class="rail-link-label"><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span>
          <span v-if="item.count" class="rail-count">{{ item.count }}</span>
          <span class="rail-tooltip"><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span>
        </router-link>
      </div>
      <div class="rail-divider"></div>
      <div class="rail-group">
        <span class="rail-section-label">PLATFORM</span>
        <router-link v-for="item in resources" :key="item.to" :to="item.to" class="rail-link">
          <span class="rail-icon"><component :is="item.icon" :size="18" /></span>
          <span class="rail-link-label"><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span>
          <span class="rail-tooltip"><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span>
        </router-link>
      </div>
    </nav>

    <div class="rail-foot">
      <button class="connection-pill" type="button" @click="platform.initialize(true)">
        <span class="connection-orbit"><span class="connection-light" :class="platform.connection"></span></span>
        <span class="rail-link-label"><strong>{{ platform.connectionMessage }}</strong><small>点击重新检测</small></span>
        <RefreshCw class="connection-refresh" :size="14" />
      </button>
      <router-link to="/settings" class="rail-link">
        <span class="rail-icon"><Settings :size="18" /></span>
        <span class="rail-link-label"><strong>系统设置</strong><small>模型 / Policy</small></span>
        <span class="rail-tooltip"><strong>系统设置</strong><small>模型 / Policy</small></span>
      </router-link>
    </div>
  </aside>
  <Transition name="nav-scrim">
    <button v-if="ui.mobileNavOpen" class="nav-scrim" type="button" aria-label="关闭导航" @click="ui.mobileNavOpen = false"></button>
  </Transition>
</template>

<script setup>
import { computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import {
  Bot,
  BrainCircuit,
  Container,
  FileSearch,
  FlaskConical,
  Library,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  RefreshCw,
  RotateCcw,
  Radar,
  ScanLine,
  Settings,
  ShieldCheck,
  X
} from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'
import { useUiStore } from '../stores/ui'

const ui = useUiStore()
const platform = usePlatformStore()
const route = useRoute()

const primary = computed(() => [
  { to: '/workspace', label: 'Harness 工作区', hint: 'Workflow / Surface', icon: Network },
  { to: '/audit-engine', label: '审计引擎', hint: 'Agent tasks / Contracts', icon: BrainCircuit },
  { to: '/findings', label: '风险发现', hint: 'RiskChain / L1–L5', icon: FileSearch, count: platform.findings.length },
  { to: '/evidence', label: '验证证据', hint: 'Artifacts / Claims', icon: FlaskConical, count: platform.evidence.length },
  { to: '/remediation', label: '返回与复测', hint: 'Return / Retest', icon: RotateCcw, count: platform.bundles.length }
])

const resources = [
  { to: '/threat-model', label: '威胁模型', hint: 'Hypotheses / Coverage', icon: Radar },
  { to: '/tool-fabric', label: '工具织网', hint: 'Scanners / Container', icon: Container },
  { to: '/knowledge', label: '安全知识库', hint: 'Rules / References', icon: Library },
  { to: '/foundation', label: '运行与检查点', hint: 'Session / Events', icon: ShieldCheck },
  { to: '/integrations', label: 'Skill / CLI', hint: 'Triggers / Contract', icon: Bot }
]

const toggleRail = () => {
  if (window.matchMedia('(max-width: 760px)').matches) ui.mobileNavOpen = false
  else ui.toggleRail()
}

watch(() => route.fullPath, () => { ui.mobileNavOpen = false })
</script>
