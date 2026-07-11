<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { NConfigProvider, darkTheme } from 'naive-ui'

const route = useRoute()
const router = useRouter()

const logout = () => {
  localStorage.removeItem('token')
  router.push('/')
}
</script>

<template>
  <!-- Обертываем всё приложение в темную тему Naive UI -->
  <n-config-provider :theme="darkTheme">
    <div class="app-wrapper">
      <!-- HEADER только если НЕ login -->
      <n-layout-header v-if="!route.meta.isAuth" bordered class="app-header">
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 24px;">
          <span class="logo">ANet Admin Console</span>
          <n-button type="error" ghost @click="logout" size="small"> Logout </n-button>
        </div>
      </n-layout-header>

      <div class="main-content">
        <router-view />
      </div>
    </div>
  </n-config-provider>
</template>

<style>
/* Глобальный жесткий сброс стилей для всей страницы */
body {
  background-color: #050505 !important;
  margin: 0;
  padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  color: #e2e8f0;
}

/* Обертка всего приложения */
.app-wrapper {
  min-height: 100vh;
  background-color: #050505; /* Абсолютно черный фон */
}

/* Консольный хедер */
.app-header {
  background-color: #0a0a0a !important;
  border-bottom: 1px solid #1a1a1a !important; /* Тонкая темная граница */
}

.logo {
  font-weight: 700;
  font-size: 16px;
  color: #18a058; /* Наш фирменный зеленый */
  letter-spacing: 0.8px;
  font-family: monospace;
}

/* Стилизация полосы прокрутки под темный стиль */
::-webkit-scrollbar {
  width: 8px;
}
::-webkit-scrollbar-track {
  background: #050505;
}
::-webkit-scrollbar-thumb {
  background: #222;
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
  background: #333;
}
</style>