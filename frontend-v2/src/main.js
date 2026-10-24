import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './styles/tokens.css'
import './styles/global.css'
import './styles/shell.css'
import './styles/components.css'
import './styles/views.css'

const savedTheme = window.localStorage.getItem('vibesec-theme')
const preferredTheme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
document.documentElement.dataset.theme = savedTheme === 'light' || savedTheme === 'dark' ? savedTheme : preferredTheme

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.mount('#app')
