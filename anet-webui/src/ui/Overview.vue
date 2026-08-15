<script setup lang="ts">
// Сводная панель control plane: состояние нод, пользователи, pools,
// route maps и суммарный трафик обновляются одним периодическим срезом.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { GetServers } from '@/api/servers'
import { GetUsers } from '@/api/users'
import { GetPools } from '@/api/pools'
import { GetRouteMaps } from '@/api/route-maps'
import { GetNodeTrafficStats } from '@/api/statistics'
import type { Server } from '@/models/server'
import type { NodeTrafficStat } from '@/models/statistics'

const router = useRouter()
const servers = ref<Server[]>([])
const traffic = ref<NodeTrafficStat[]>([])
const userCount = ref(0)
const poolCount = ref(0)
const routeMapCount = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)
let refreshTimer: number | undefined

const onlineNodes = computed(() => servers.value.filter(node => node.runtime?.status === 'online'))
const offlineNodes = computed(() => servers.value.filter(node => node.runtime?.status !== 'online'))
const activeConnections = computed(() => servers.value.reduce((sum, node) => sum + (node.runtime?.active_connections || 0), 0))
const totalTraffic = computed(() => traffic.value.reduce((sum, node) => sum + node.rx_bytes + node.tx_bytes, 0))
const acceptingNodes = computed(() => onlineNodes.value.filter(node => node.runtime?.accepting_connections).length)

const formatBytes = (bytes: number) => {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let unit = 0
  while (bytes >= 1024 && unit < units.length - 1) { bytes /= 1024; unit++ }
  return `${bytes.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

const load = async () => {
  loading.value = true
  error.value = null
  try {
    const [nodeList, users, pools, maps, trafficStats] = await Promise.all([
      GetServers(), GetUsers(0, 1), GetPools(), GetRouteMaps(), GetNodeTrafficStats(),
    ])
    servers.value = nodeList
    userCount.value = users.total
    poolCount.value = pools.length
    routeMapCount.value = maps.length
    traffic.value = trafficStats
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : 'Не удалось загрузить обзор'
  } finally { loading.value = false }
}

onMounted(() => {
  load()
  refreshTimer = window.setInterval(load, 15_000)
})
onBeforeUnmount(() => { if (refreshTimer !== undefined) clearInterval(refreshTimer) })
</script>

<template>
  <main class="overview-page">
    <n-space justify="space-between" align="center" class="hero">
      <div><h1>Infrastructure overview</h1><p>Состояние control plane и VPN-узлов в реальном времени</p></div>
      <n-button :loading="loading" @click="load">Обновить</n-button>
    </n-space>
    <n-alert v-if="error" type="error" closable class="error-alert" @close="error = null">{{ error }}</n-alert>

    <n-grid cols="1 s:2 l:4" responsive="screen" :x-gap="16" :y-gap="16">
      <n-grid-item>
        <n-card class="metric-card" @click="router.push('/servers')">
          <span class="metric-label">Nodes online</span>
          <strong>{{ onlineNodes.length }}<small>/ {{ servers.length }}</small></strong>
          <span :class="offlineNodes.length ? 'metric-warning' : 'metric-ok'">{{ offlineNodes.length ? `${offlineNodes.length} требуют внимания` : 'Все узлы доступны' }}</span>
        </n-card>
      </n-grid-item>
      <n-grid-item>
        <n-card class="metric-card" @click="router.push('/users')">
          <span class="metric-label">Users</span><strong>{{ userCount }}</strong>
          <span>{{ activeConnections }} активных соединений</span>
        </n-card>
      </n-grid-item>
      <n-grid-item>
        <n-card class="metric-card" @click="router.push('/statistics')">
          <span class="metric-label">Lifetime traffic</span><strong>{{ formatBytes(totalTraffic) }}</strong>
          <span>Полезные данные туннеля</span>
        </n-card>
      </n-grid-item>
      <n-grid-item>
        <n-card class="metric-card" @click="router.push('/pools')">
          <span class="metric-label">Control policies</span><strong>{{ poolCount + routeMapCount }}</strong>
          <span>{{ poolCount }} pools · {{ routeMapCount }} route maps</span>
        </n-card>
      </n-grid-item>
    </n-grid>

    <n-grid cols="1 l:3" responsive="screen" :x-gap="18" :y-gap="18" class="details-grid">
      <n-grid-item span="1 l:2">
        <n-card title="Node health">
          <template #header-extra><span class="subtle">{{ acceptingNodes }} принимают подключения</span></template>
          <div class="node-list">
            <button v-for="node in servers" :key="node.id" class="node-row" @click="router.push('/servers')">
              <span :class="['health-dot', node.runtime?.status === 'online' ? 'online' : 'offline']" />
              <span class="node-identity"><strong>{{ node.name }}</strong><small>{{ node.address }}</small></span>
              <span class="node-state">
                <b>{{ node.runtime?.active_connections || 0 }}</b><small>connections</small>
              </span>
              <n-tag :type="node.runtime?.accepting_connections ? 'success' : 'warning'" size="small">
                {{ !node.runtime ? 'NO DATA' : node.runtime.accepting_connections ? 'OPEN' : 'CLOSED' }}
              </n-tag>
            </button>
            <n-empty v-if="servers.length === 0" description="Узлы не зарегистрированы" />
          </div>
        </n-card>
      </n-grid-item>
      <n-grid-item>
        <n-card title="Quick actions">
          <n-space vertical class="quick-actions">
            <n-button block secondary @click="router.push('/servers')">Добавить или настроить узел</n-button>
            <n-button block secondary @click="router.push('/users')">Создать пользователя</n-button>
            <n-button block secondary @click="router.push('/pools')">Настроить балансировку</n-button>
            <n-button block secondary @click="router.push('/route-maps')">Создать route map</n-button>
          </n-space>
        </n-card>
      </n-grid-item>
    </n-grid>
  </main>
</template>

<style scoped>
.overview-page { max-width: 1440px; margin: 0 auto; padding: 28px; }
.hero { margin-bottom: 24px; }
.hero h1 { margin: 0 0 5px; font-size: 25px; }
.hero p, .subtle { margin: 0; color: #7f8b9f; font-size: 13px; }
.error-alert { margin-bottom: 18px; }
.metric-card { cursor: pointer; height: 148px; transition: transform .15s ease, border-color .15s ease; }
.metric-card:hover { transform: translateY(-2px); border-color: rgba(24,160,88,.55); }
.metric-card :deep(.n-card__content) { display: flex; height: 100%; box-sizing: border-box; flex-direction: column; }
.metric-label { color: #8b98ab; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
.metric-card strong { margin: 10px 0 auto; font-size: 30px; }
.metric-card strong small { color: #697586; font-size: 15px; }
.metric-card span:last-child { color: #7f8b9f; font-size: 12px; }
.metric-card .metric-warning { color: #dca54c !important; }
.metric-card .metric-ok { color: #36ad6a !important; }
.details-grid { margin-top: 20px; }
.node-list { display: flex; flex-direction: column; gap: 4px; }
.node-row { display: grid; grid-template-columns: 12px 1fr auto auto; gap: 14px; align-items: center; width: 100%; padding: 12px 8px; color: inherit; border: 0; border-bottom: 1px solid rgba(255,255,255,.06); background: transparent; text-align: left; cursor: pointer; }
.node-row:hover { background: rgba(255,255,255,.025); }
.health-dot { width: 8px; height: 8px; border-radius: 50%; }
.health-dot.online { background: #36ad6a; box-shadow: 0 0 9px rgba(54,173,106,.7); }
.health-dot.offline { background: #d03050; }
.node-identity, .node-state { display: flex; flex-direction: column; }
.node-identity small, .node-state small { color: #768397; font-size: 11px; }
.node-state { min-width: 75px; text-align: right; }
.quick-actions { width: 100%; }
@media (max-width: 640px) { .overview-page { padding: 18px; } .node-row { grid-template-columns: 12px 1fr auto; } .node-state { display: none; } }
</style>
