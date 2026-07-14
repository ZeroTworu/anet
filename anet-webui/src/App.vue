<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import {
  NConfigProvider,
  NMessageProvider,
  NDialogProvider,
  NNotificationProvider,
  darkTheme
} from 'naive-ui'

const route = useRoute()
const router = useRouter()

const logout = () => {
  localStorage.removeItem('token')
  router.push('/')
}
</script>

<template>
  <!-- Обертываем все глобальные провайдеры Naive UI на самый верх -->
  <n-config-provider :theme="darkTheme">
    <n-message-provider>
      <n-dialog-provider>
        <n-notification-provider>
          <div class="app-wrapper">
            <!-- HEADER только если НЕ login -->
            <n-layout-header v-if="!route.meta.isAuth" bordered class="app-header">
              <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 24px;">
                <span class="logo" @click="router.push('/users')" style="cursor: pointer;">ANet Auth Console</span>

                <!-- ВКЛАДКИ НАВИГАЦИИ -->
                <n-space size="large">
                  <n-button text :type="route.path === '/users' ? 'primary' : 'default'" @click="router.push('/users')">
                    👥 Users
                  </n-button>
                  <n-button text :type="route.path === '/servers' ? 'primary' : 'default'" @click="router.push('/servers')">
                    🖥️ Servers
                  </n-button>
                </n-space>

                <n-button type="error" ghost @click="logout" size="small"> Logout </n-button>
              </div>
            </n-layout-header>

            <div class="main-content">
              <router-view />
            </div>
          </div>
        </n-notification-provider>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<style>
body {
  background-color: #050505 !important;
  margin: 0;
  padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  color: #e2e8f0;
}

.app-wrapper {
  min-height: 100vh;
  background-color: #050505;
}

.app-header {
  background-color: #0a0a0a !important;
  border-bottom: 1px solid #1a1a1a !important;
}

.logo {
  font-weight: 700;
  font-size: 16px;
  color: #18a058;
  letter-spacing: 0.8px;
  font-family: monospace;
}

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
