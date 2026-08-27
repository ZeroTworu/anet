import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import 'vuetify/styles'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import '@mdi/font/css/materialdesignicons.css'
import { createVuetify, type ThemeDefinition } from 'vuetify'

// Общая гамма панели: тёмный уголь с зелёным подтоном (не чистый чёрный)
// и один акцент — эмеральд. Оттенки согласованы с App.vue.
const dark: ThemeDefinition = {
  dark: true,
  colors: {
    background: '#0F1211',
    surface: '#1E2221',
    'surface-variant': '#232827',
    'on-surface': '#E8EBEA',
    'on-background': '#E8EBEA',
    'on-surface-variant': '#9AA5A0',
    outline: '#3A403E',
    'outline-variant': '#2A2F2E',
    primary: '#2BB894',
    'primary-darken-1': '#249E7E',
    'on-primary': '#FFFFFF',
    secondary: '#2A2F2E',
    'on-secondary': '#E8EBEA',
    success: '#2BB894',
    warning: '#D9A441',
    error: '#E5756F',
    info: '#4FBF9B',
  },
}

const vuetify = createVuetify({
  components,
  directives,
  theme: {
    defaultTheme: 'dark',
    themes: { dark },
  },
  defaults: {
    VTextField: { variant: 'filled' },
    VTextarea: { variant: 'filled' },
    VSelect: { variant: 'filled' },
    VAutocomplete: { variant: 'filled' },
    VCombobox: { variant: 'filled' },
  },
})

createApp(App).use(router).use(vuetify).mount('#app')
