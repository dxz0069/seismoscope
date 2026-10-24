import { defineStore } from 'pinia'

let nextToastId = 1

export const useUiStore = defineStore('ui', {
  state: () => ({
    theme: document.documentElement.dataset.theme || 'dark',
    railExpanded: window.localStorage.getItem('vibesec-rail')
      ? window.localStorage.getItem('vibesec-rail') === 'expanded'
      : window.matchMedia('(min-width: 1200px)').matches,
    commandOpen: false,
    createReviewOpen: false,
    mobileNavOpen: false,
    toasts: []
  }),
  actions: {
    initializeTheme() {
      document.documentElement.dataset.theme = this.theme
    },
    toggleRail() {
      this.railExpanded = !this.railExpanded
      window.localStorage.setItem('vibesec-rail', this.railExpanded ? 'expanded' : 'collapsed')
    },
    toggleTheme(event) {
      const root = document.documentElement
      const nextTheme = this.theme === 'dark' ? 'light' : 'dark'
      const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

      root.style.setProperty('--theme-x', `${event?.clientX ?? window.innerWidth - 48}px`)
      root.style.setProperty('--theme-y', `${event?.clientY ?? 28}px`)

      const apply = () => {
        this.theme = nextTheme
        root.dataset.theme = nextTheme
        window.localStorage.setItem('vibesec-theme', nextTheme)
      }

      if (!reduceMotion && document.startViewTransition) document.startViewTransition(apply)
      else apply()
    },
    toast(message, tone = 'info', title = '') {
      const id = nextToastId++
      this.toasts.push({ id, message, tone, title })
      window.setTimeout(() => this.dismissToast(id), 3600)
      return id
    },
    dismissToast(id) {
      this.toasts = this.toasts.filter(item => item.id !== id)
    }
  }
})
