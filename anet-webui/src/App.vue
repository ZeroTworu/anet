<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()
const mobileOpen = ref(false)
const snackbar = ref({ open: false, message: '', color: 'info' })
const pageTitle = computed(() => String(route.meta.title || 'ANet'))
const navigation = [
  { label: 'Overview', path: '/overview', icon: '◫', group: 'Overview' },
  { label: 'Users', path: '/users', icon: '◎', group: 'Management' },
  { label: 'Nodes', path: '/servers', icon: '◇', group: 'Management' },
  { label: 'Node Pools', path: '/pools', icon: '⑂', group: 'Management' },
  { label: 'Route Maps', path: '/route-maps', icon: '⌘', group: 'Management' },
  { label: 'Traffic', path: '/statistics', icon: '⌁', group: 'Observability' },
]
const groups = computed(() => [...new Set(navigation.map(item => item.group))])

watch(() => route.path, () => { mobileOpen.value = false })

const onMessage = (event: Event) => {
  const detail = (event as CustomEvent<{ kind: string; message: string }>).detail
  snackbar.value = { open: true, message: detail.message, color: detail.kind }
}

onMounted(() => window.addEventListener('anet:message', onMessage))
onBeforeUnmount(() => window.removeEventListener('anet:message', onMessage))

const logout = () => {
  localStorage.removeItem('token')
  router.push('/')
}
</script>

<template>
  <v-app>
    <v-main>
          <router-view v-if="route.meta.isAuth" class="auth-surface" />

          <div v-else class="admin-shell">
            <button v-if="mobileOpen" class="sidebar-backdrop" aria-label="Закрыть меню" @click="mobileOpen = false" />
            <aside :class="['sidebar', { open: mobileOpen }]">
              <button class="brand" @click="router.push('/overview')">
                <span class="brand-mark">A</span>
                <span><strong>ANet</strong><small>CONTROL PLANE</small></span>
              </button>

              <nav class="navigation">
                <section v-for="group in groups" :key="group" class="nav-group">
                  <span class="group-label">{{ group }}</span>
                  <button
                      v-for="item in navigation.filter(entry => entry.group === group)"
                      :key="item.path"
                      :class="['nav-item', { active: route.path === item.path }]"
                      @click="router.push(item.path)"
                  >
                    <span class="nav-icon">{{ item.icon }}</span>
                    <span>{{ item.label }}</span>
                  </button>
                </section>
              </nav>

              <div class="sidebar-footer">
                <div class="control-status"><i /><span><strong>Control plane</strong><small>connected</small></span></div>
                <button class="logout" @click="logout">Sign out</button>
              </div>
            </aside>

            <section class="workspace">
              <header class="workspace-header">
                <button class="mobile-menu" aria-label="Открыть меню" @click="mobileOpen = true">☰</button>
                <div><span class="breadcrumb">ANet /</span><strong>{{ pageTitle }}</strong></div>
                <div class="header-status"><i />Live</div>
              </header>
              <div class="workspace-content"><router-view /></div>
            </section>
          </div>
    </v-main>
    <v-snackbar v-model="snackbar.open" :color="snackbar.color" :timeout="4000">
      {{ snackbar.message }}
    </v-snackbar>
  </v-app>
</template>

<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
html, body, #app { min-height: 100%; margin: 0; }
body { background: #07090d; color: #e5e9f0; font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
button, input, textarea { font: inherit; }
.auth-surface { min-height: 100vh; padding-top: 1px; background: radial-gradient(circle at 50% 15%, rgba(24,160,88,.1), transparent 35%), #07090d; }
.admin-shell { display: flex; min-height: 100vh; background: #07090d; }
.sidebar { position: fixed; z-index: 30; inset: 0 auto 0 0; display: flex; width: 246px; flex-direction: column; border-right: 1px solid #1c222d; background: #0b0e13; }
.brand { display: flex; align-items: center; gap: 11px; height: 72px; padding: 0 20px; color: inherit; border: 0; border-bottom: 1px solid #171c25; background: transparent; text-align: left; cursor: pointer; }
.brand-mark { display: grid; width: 34px; height: 34px; place-items: center; color: #07110b; border-radius: 9px; background: #36ad6a; font-family: monospace; font-size: 19px; font-weight: 900; box-shadow: 0 0 20px rgba(54,173,106,.18); }
.brand > span:last-child { display: flex; flex-direction: column; }
.brand strong { font-size: 16px; letter-spacing: .03em; }
.brand small { margin-top: 2px; color: #667285; font-family: monospace; font-size: 9px; letter-spacing: .14em; }
.navigation { flex: 1; overflow-y: auto; padding: 14px 11px; }
.nav-group { margin-bottom: 18px; }
.group-label { display: block; padding: 8px 10px; color: #566173; font-size: 10px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
.nav-item { display: flex; width: 100%; align-items: center; gap: 11px; margin: 2px 0; padding: 10px 11px; color: #99a4b5; border: 1px solid transparent; border-radius: 7px; background: transparent; text-align: left; cursor: pointer; transition: .14s ease; }
.nav-item:hover { color: #e9edf3; background: #121720; }
.nav-item.active { color: #e9fff1; border-color: rgba(54,173,106,.16); background: rgba(54,173,106,.1); }
.nav-icon { width: 20px; color: #6e7b8f; font-family: monospace; font-size: 18px; text-align: center; }
.nav-item.active .nav-icon { color: #36ad6a; }
.sidebar-footer { padding: 14px; border-top: 1px solid #171c25; }
.control-status { display: flex; align-items: center; gap: 9px; padding: 8px; }
.control-status i, .header-status i { width: 7px; height: 7px; border-radius: 50%; background: #36ad6a; box-shadow: 0 0 8px #36ad6a; }
.control-status span { display: flex; flex-direction: column; }
.control-status strong { font-size: 11px; }
.control-status small { color: #667285; font-size: 10px; }
.logout { width: 100%; margin-top: 7px; padding: 8px; color: #8d98a9; border: 1px solid #222a36; border-radius: 6px; background: transparent; cursor: pointer; }
.logout:hover { color: #f2a6b4; border-color: rgba(208,48,80,.45); }
.workspace { width: calc(100% - 246px); min-width: 0; margin-left: 246px; }
.workspace-header { position: sticky; z-index: 20; top: 0; display: flex; height: 58px; align-items: center; justify-content: space-between; padding: 0 25px; border-bottom: 1px solid #1b212b; background: rgba(9,12,17,.9); backdrop-filter: blur(14px); }
.workspace-header strong { margin-left: 6px; font-size: 13px; }
.breadcrumb { color: #657185; font-size: 12px; }
.header-status { display: flex; align-items: center; gap: 7px; color: #788598; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
.workspace-content { min-height: calc(100vh - 58px); }
.mobile-menu { display: none; color: #b8c1cf; border: 0; background: transparent; font-size: 20px; cursor: pointer; }
.sidebar-backdrop { display: none; }
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: #080b0f; }
::-webkit-scrollbar-thumb { border-radius: 5px; background: #252c37; }
@media (max-width: 800px) {
  .sidebar { transform: translateX(-100%); transition: transform .2s ease; }
  .sidebar.open { transform: translateX(0); }
  .sidebar-backdrop { position: fixed; z-index: 25; inset: 0; display: block; border: 0; background: rgba(0,0,0,.62); }
  .workspace { width: 100%; margin-left: 0; }
  .workspace-header { padding: 0 16px; }
  .mobile-menu { display: block; }
}
</style>
