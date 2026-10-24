<template>
  <header class="top-bar">
    <div class="top-left">
      <button class="icon-control mobile-menu" type="button" aria-label="打开导航" @click="ui.mobileNavOpen = true">
        <Menu :size="19" />
      </button>
      <div class="page-identity">
        <span>{{ route.meta.title }}</span>
        <template v-if="route.name === 'workspace'">
          <ChevronRight :size="13" />
          <span class="run-crumb">{{ platform.selectedRun.id }}</span>
        </template>
      </div>
    </div>

    <div class="top-actions">
      <button class="command-trigger" type="button" @click="ui.commandOpen = true">
        <Search :size="16" />
        <span>搜索任务、风险与证据</span>
        <kbd>Ctrl K</kbd>
      </button>
      <button
        class="icon-control theme-toggle"
        type="button"
        :aria-label="ui.theme === 'dark' ? '切换到白天模式' : '切换到夜晚模式'"
        :title="ui.theme === 'dark' ? '切换到白天模式' : '切换到夜晚模式'"
        @click="ui.toggleTheme($event)"
      >
        <Transition name="theme-icon" mode="out-in">
          <Sun v-if="ui.theme === 'dark'" :key="'sun'" :size="17" />
          <Moon v-else :key="'moon'" :size="17" />
        </Transition>
      </button>
      <span class="source-indicator" :class="platform.selectedRun.source">
        <Database :size="14" />{{ platform.selectedRun.source === 'live' ? 'Live' : 'Demo' }}
      </span>
      <button class="primary-command" type="button" @click="openNewReview">
        <Plus :size="17" /><span>新建审查</span>
      </button>
    </div>
  </header>
</template>

<script setup>
import { onBeforeUnmount, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ChevronRight, Database, Menu, Moon, Plus, Search, Sun } from 'lucide-vue-next'
import { usePlatformStore } from '../stores/platform'
import { useUiStore } from '../stores/ui'

const ui = useUiStore()
const platform = usePlatformStore()
const route = useRoute()
const router = useRouter()

const openNewReview = async () => {
  if (route.name !== 'workspace') await router.push('/workspace')
  ui.createReviewOpen = true
}

const onKeydown = event => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault()
    ui.commandOpen = true
  }
}

onMounted(() => window.addEventListener('keydown', onKeydown))
onBeforeUnmount(() => window.removeEventListener('keydown', onKeydown))
</script>
