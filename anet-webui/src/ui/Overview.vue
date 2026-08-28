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
    <div class="d-flex align-center justify-space-between hero">
      <div><h1>Infrastructure overview</h1><p>Состояние control plane и VPN-узлов в реальном времени</p></div>
      <v-btn :loading="loading" @click="load">Обновить</v-btn>
    </div>
    <v-alert v-if="error" type="error" closable class="error-alert" @click:close="error = null">{{ error }}</v-alert>

    <v-row>
      <v-col cols="12" sm="6" lg="3">
        <v-card class="metric-card" @click="router.push('/servers')">
          <v-card-text class="metric-content">
            <span class="metric-label">Nodes online</span>
            <strong>{{ onlineNodes.length }}<small>/ {{ servers.length }}</small></strong>
            <span :class="offlineNodes.length ? 'metric-warning' : 'metric-ok'">{{ offlineNodes.length ? `${offlineNodes.length} требуют внимания` : 'Все узлы доступны' }}</span>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" sm="6" lg="3">
        <v-card class="metric-card" @click="router.push('/users')">
          <v-card-text class="metric-content">
            <span class="metric-label">Users</span><strong>{{ userCount }}</strong>
            <span>{{ activeConnections }} активных соединений</span>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" sm="6" lg="3">
        <v-card class="metric-card" @click="router.push('/statistics')">
          <v-card-text class="metric-content">
            <span class="metric-label">Lifetime traffic</span><strong>{{ formatBytes(totalTraffic) }}</strong>
            <span>Полезные данные туннеля</span>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" sm="6" lg="3">
        <v-card class="metric-card" @click="router.push('/pools')">
          <v-card-text class="metric-content">
            <span class="metric-label">Control policies</span><strong>{{ poolCount + routeMapCount }}</strong>
            <span>{{ poolCount }} pools · {{ routeMapCount }} route maps</span>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="details-grid">
      <v-col cols="12" lg="8">
        <v-card title="Node health">
          <v-card-text>
            <span class="subtle">{{ acceptingNodes }} принимают подключения</span>
            <div class="node-list">
              <button v-for="node in servers" :key="node.id" class="node-row" @click="router.push('/servers')">
                <span :class="['health-dot', node.runtime?.status === 'online' ? 'online' : 'offline']" />
                <span class="node-identity"><strong>{{ node.name }}</strong><small>{{ node.address }}</small></span>
                <span class="node-state">
                  <b>{{ node.runtime?.active_connections || 0 }}</b><small>connections</small>
                </span>
                <v-chip :color="node.runtime?.accepting_connections ? 'success' : 'warning'" size="small">
                  {{ !node.runtime ? 'NO DATA' : node.runtime.accepting_connections ? 'OPEN' : 'CLOSED' }}
                </v-chip>
              </button>
              <v-empty-state v-if="servers.length === 0" text="Узлы не зарегистрированы" />
            </div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" lg="4">
        <v-card title="Quick actions">
          <v-card-text>
            <div class="quick-actions">
              <v-btn block variant="tonal" @click="router.push('/servers')">Добавить или настроить узел</v-btn>
              <v-btn block variant="tonal" @click="router.push('/users')">Создать пользователя</v-btn>
              <v-btn block variant="tonal" @click="router.push('/pools')">Настроить балансировку</v-btn>
              <v-btn block variant="tonal" @click="router.push('/route-maps')">Создать route map</v-btn>
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </main>
</template>

<style scoped>
.overview-page { max-width: 1440px; margin: 0 auto; padding: 28px; }
.hero { margin-bottom: 24px; }
.hero h1 { margin: 0 0 5px; font-size: 25px; }
.hero p, .subtle { margin: 0; color: #9aa5a0; font-size: 13px; }
.error-alert { margin-bottom: 18px; }
.metric-card { cursor: pointer; height: 148px; transition: transform .15s ease, border-color .15s ease; }
.metric-card:hover { transform: translateY(-2px); border-color: rgba(43,184,148,.55); }
.metric-content { display: flex; height: 100%; box-sizing: border-box; flex-direction: column; }
.metric-label { color: #9aa5a0; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
.metric-card strong { margin: 10px 0 auto; font-size: 30px; }
.metric-card strong small { color: #6e7975; font-size: 15px; }
.metric-card span:last-child { color: #7a857f; font-size: 12px; }
.metric-card .metric-warning { color: #d9a441 !important; }
.metric-card .metric-ok { color: #2bb894 !important; }
.details-grid { margin-top: 20px; }
.node-list { display: flex; flex-direction: column; gap: 4px; }
.node-row { display: grid; grid-template-columns: 12px 1fr auto auto; gap: 14px; align-items: center; width: 100%; padding: 12px 8px; color: inherit; border: 0; border-bottom: 1px solid rgba(255,255,255,.06); background: transparent; text-align: left; cursor: pointer; }
.node-row:hover { background: rgba(255,255,255,.025); }
.health-dot { width: 8px; height: 8px; border-radius: 50%; }
.health-dot.online { background: #2bb894; box-shadow: 0 0 9px rgba(43,184,148,.7); }
.health-dot.offline { background: #e5756f; }
.node-identity, .node-state { display: flex; flex-direction: column; }
.node-identity small, .node-state small { color: #7a857f; font-size: 11px; }
.node-state { min-width: 75px; text-align: right; }
.quick-actions { display: flex; flex-direction: column; gap: 10px; width: 100%; }
@media (max-width: 640px) { .overview-page { padding: 18px; } .node-row { grid-template-columns: 12px 1fr auto; } .node-state { display: none; } }
</style>
