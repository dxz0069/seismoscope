<template>
  <div v-if="ui.commandOpen" class="command-backdrop" @click.self="ui.commandOpen = false">
    <section class="command-panel" role="dialog" aria-modal="true" aria-label="全局搜索">
      <div class="command-input">
        <Search :size="18" />
        <input ref="inputRef" v-model="query" type="search" placeholder="搜索任务、Finding、证据或页面…" @keydown.esc="ui.commandOpen = false" />
        <kbd>Esc</kbd>
      </div>
      <div class="command-results">
        <p class="command-heading">跳转</p>
        <button v-for="item in filteredNavigation" :key="item.to" type="button" @click="navigate(item.to)">
          <component :is="item.icon" :size="17" /><span>{{ item.label }}</span><ArrowUpRight :size="14" />
        </button>
        <template v-if="filteredFindings.length">
          <p class="command-heading">风险发现</p>
          <button v-for="finding in filteredFindings" :key="finding.id" type="button" @click="navigate('/findings', finding.id)">
            <span class="command-severity" :class="finding.severity"></span>
            <span><strong>{{ finding.id }}</strong> {{ finding.title }}</span>
            <ArrowUpRight :size="14" />
          </button>
        </template>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowUpRight, BrainCircuit, Container, FileSearch, FlaskConical, Library, Network, Radar, Search, Settings } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'
import { useUiStore } from '../stores/ui'

const ui = useUiStore()
const platform = usePlatformStore()
const router = useRouter()
const query = ref('')
const inputRef = ref(null)

const navigation = [
  { to: '/workspace', label: '审查工作区', icon: Network },
  { to: '/audit-engine', label: 'Agentic Audit Engine', icon: BrainCircuit },
  { to: '/threat-model', label: '运行时威胁模型', icon: Radar },
  { to: '/tool-fabric', label: '安全工具织网', icon: Container },
  { to: '/findings', label: '风险发现', icon: FileSearch },
  { to: '/evidence', label: '验证证据', icon: FlaskConical },
  { to: '/knowledge', label: '安全知识库', icon: Library },
  { to: '/settings', label: '系统设置', icon: Settings }
]

const normalized = computed(() => query.value.trim().toLowerCase())
const filteredNavigation = computed(() => navigation.filter(item => !normalized.value || item.label.toLowerCase().includes(normalized.value)))
const filteredFindings = computed(() => platform.findings.filter(item => !normalized.value || `${item.id} ${item.title} ${item.category}`.toLowerCase().includes(normalized.value)).slice(0, 5))

const navigate = async (to, findingId) => {
  ui.commandOpen = false
  await router.push({ path: to, query: findingId ? { finding: findingId } : {} })
}

watch(() => ui.commandOpen, async open => {
  if (open) {
    query.value = ''
    await nextTick()
    inputRef.value?.focus()
  }
})
</script>
