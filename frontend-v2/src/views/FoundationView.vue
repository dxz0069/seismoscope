<template>
  <section class="view-page foundation-page">
    <div class="page-wrap foundation-wrap">
      <header class="page-head foundation-head">
        <div><span class="page-kicker">LOCAL HARNESS + AGENT RUNTIME</span><h1>运行与检查点</h1><p>查看确定性 RunSession、父子任务状态、事件、检查点和现有 FastAPI 执行适配。</p></div>
        <span class="source-chip" :class="platform.connection === 'live' ? 'live' : 'demo'">{{ platform.connectionMessage }}</span>
      </header>
      <nav class="foundation-tabs">
        <button v-for="item in tabs" :key="item.id" type="button" :class="{ active: activeTab === item.id }" @click="activeTab = item.id"><component :is="item.icon" :size="16" /><span>{{ item.label }}</span><b>{{ item.count() }}</b></button>
      </nav>
      <HarnessSessionsPanel v-if="activeTab === 'sessions'" />
      <SourceTasksPanel v-else-if="activeTab === 'tasks'" />
      <AgentTargetsPanel v-else-if="activeTab === 'targets'" />
      <AgentScenariosPanel v-else-if="activeTab === 'scenarios'" />
      <AgentRunsPanel v-else />
    </div>
  </section>
</template>

<script setup>
import { computed, markRaw, ref } from 'vue'
import { Bot, FileCode2, FlaskConical, History, Swords } from 'lucide-vue-next'
import AgentRunsPanel from '../components/AgentRunsPanel.vue'
import AgentScenariosPanel from '../components/AgentScenariosPanel.vue'
import AgentTargetsPanel from '../components/AgentTargetsPanel.vue'
import HarnessSessionsPanel from '../components/HarnessSessionsPanel.vue'
import SourceTasksPanel from '../components/SourceTasksPanel.vue'
import { usePlatformStore } from '../stores/platform'

const platform = usePlatformStore()
const activeTab = ref('sessions')
const tabs = computed(() => [
  { id: 'sessions', label: '运行会话', icon: markRaw(History), count: () => platform.runs.length },
  { id: 'tasks', label: '源码适配', icon: markRaw(FileCode2), count: () => platform.tasks.length },
  { id: 'targets', label: 'Agent 目标', icon: markRaw(Bot), count: () => platform.targets.length },
  { id: 'scenarios', label: '攻击场景', icon: markRaw(Swords), count: () => platform.scenarios.length },
  { id: 'runs', label: '验证运行', icon: markRaw(FlaskConical), count: () => platform.agentRuns.length }
])
</script>
