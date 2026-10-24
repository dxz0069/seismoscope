<template>
  <div class="app-root" :class="{ 'rail-expanded': ui.railExpanded }">
    <AppRail />
    <div class="app-stage">
      <TopBar />
      <main class="route-stage">
        <router-view v-slot="{ Component, route }">
          <Transition name="route-shift" mode="out-in">
            <component :is="Component" :key="route.path" />
          </Transition>
        </router-view>
      </main>
    </div>
    <ToastHost />
    <CommandPalette />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import AppRail from './components/AppRail.vue'
import CommandPalette from './components/CommandPalette.vue'
import ToastHost from './components/ToastHost.vue'
import TopBar from './components/TopBar.vue'
import { usePlatformStore } from './stores/platform'
import { useUiStore } from './stores/ui'

const platform = usePlatformStore()
const ui = useUiStore()

onMounted(() => {
  ui.initializeTheme()
  platform.initialize()
})
</script>
