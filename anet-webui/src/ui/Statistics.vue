<script setup lang="ts">
// Экран наблюдаемости получает независимые срезы по нодам, пользователям
// и почасовую историю, которую control plane собирает из cumulative counters.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { GetNodeTrafficStats, GetTrafficHistory, GetUserTrafficStats } from '@/api/statistics'
import type { NodeTrafficStat, TrafficHistoryPoint, UserTrafficStat } from '@/models/statistics'

const nodes = ref<NodeTrafficStat[]>([])
const users = ref<UserTrafficStat[]>([])
const history = ref<TrafficHistoryPoint[]>([])
const loading = ref(false)
let refreshTimer: number | undefined

const totalRx = computed(() => nodes.value.reduce((sum, item) => sum + item.rx_bytes, 0))
const totalTx = computed(() => nodes.value.reduce((sum, item) => sum + item.tx_bytes, 0))
const chartMax = computed(() => Math.max(1, ...history.value.flatMap(item => [item.rx_bytes, item.tx_bytes])))
const chartPoints = (field: 'rx_bytes' | 'tx_bytes') => history.value.map((item, index) => {
  const x = history.value.length <= 1 ? 500 : 40 + index * (920 / (history.value.length - 1))
  const y = 220 - item[field] / chartMax.value * 180
  return `${x},${y}`
}).join(' ')
const chartLabels = computed(() => history.value.filter((_, index) => index % 6 === 0 || index === history.value.length - 1))

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** unit).toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`
}

const load = async () => {
  loading.value = true
  try {
    const [nodeStats, userStats, trafficHistory] = await Promise.all([
      GetNodeTrafficStats(),
      GetUserTrafficStats(),
      GetTrafficHistory(24),
    ])
    nodes.value = nodeStats.sort((a, b) => b.rx_bytes + b.tx_bytes - a.rx_bytes - a.tx_bytes)
    users.value = userStats
    history.value = trafficHistory
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  refreshTimer = window.setInterval(load, 15_000)
})

onBeforeUnmount(() => {
  if (refreshTimer !== undefined) window.clearInterval(refreshTimer)
})
</script>

<template>
  <main class="statistics-page">
    <div justify="space-between" align="center" class="page-title">
      <div>
        <h2>Traffic</h2>
        <span>Полезный трафик внутри VPN-туннеля</span>
      </div>
      <v-btn :loading="loading" @click="load">Обновить</v-btn>
    </div>

    <v-row :cols="3" :x-gap="16" responsive="screen" item-responsive>
      <v-col span="3 m:1"><div label="Получено узлами" :modelValue="formatBytes(totalRx)" /></v-col>
      <v-col span="3 m:1"><div label="Отправлено клиентам" :modelValue="formatBytes(totalTx)" /></v-col>
      <v-col span="3 m:1"><div label="Всего" :modelValue="formatBytes(totalRx + totalTx)" /></v-col>
    </v-row>

    <v-card title="Последние 24 часа" class="history-card">

        <div>
          <span class="legend rx">RX</span>
          <span class="legend tx">TX</span>
        </div>

      <div class="chart-wrap">
        <svg viewBox="0 0 1000 260" role="img" aria-label="График трафика за 24 часа">
          <line v-for="y in [40, 100, 160, 220]" :key="y" x1="40" :y1="y" x2="960" :y2="y" class="grid-line" />
          <polyline :points="chartPoints('rx_bytes')" class="traffic-line rx-line" />
          <polyline :points="chartPoints('tx_bytes')" class="traffic-line tx-line" />
          <text
              v-for="(point, index) in chartLabels"
              :key="point.bucket_start"
              :x="40 + history.indexOf(point) * (920 / Math.max(1, history.length - 1))"
              y="248"
              :text-anchor="index === 0 ? 'start' : index === chartLabels.length - 1 ? 'end' : 'middle'"
              class="axis-label"
          >{{ new Date(point.bucket_start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }}</text>
        </svg>
      </div>
    </v-card>

    <div class="position-relative">
      <div type="line" animated class="traffic-tabs">
        <div name="nodes" tab="По узлам">
          <v-table :single-line="false" striped="odd">
            <thead><tr><th>Узел</th><th>RX</th><th>TX</th><th>Всего</th></tr></thead>
            <tbody>
              <tr v-for="node in nodes" :key="node.node_id">
                <td>{{ node.name }}</td>
                <td class="metric">{{ formatBytes(node.rx_bytes) }}</td>
                <td class="metric">{{ formatBytes(node.tx_bytes) }}</td>
                <td class="metric total">{{ formatBytes(node.rx_bytes + node.tx_bytes) }}</td>
              </tr>
            </tbody>
          </v-table>
          <v-empty-state v-if="nodes.length === 0" description="Нет данных по узлам" />
        </div>

        <div name="users" tab="По пользователям">
          <v-table :single-line="false" striped="odd">
            <thead><tr><th>Пользователь</th><th>Fingerprint</th><th>RX</th><th>TX</th><th>Всего</th></tr></thead>
            <tbody>
              <tr v-for="user in users" :key="user.fingerprint">
                <td>{{ user.uid || 'Локальный клиент' }}</td>
                <td class="fingerprint">{{ user.fingerprint }}</td>
                <td class="metric">{{ formatBytes(user.rx_bytes) }}</td>
                <td class="metric">{{ formatBytes(user.tx_bytes) }}</td>
                <td class="metric total">{{ formatBytes(user.rx_bytes + user.tx_bytes) }}</td>
              </tr>
            </tbody>
          </v-table>
          <v-empty-state v-if="users.length === 0" description="Нет данных по пользователям" />
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
.statistics-page { max-width: 1200px; margin: 0 auto; padding: 24px; }
.page-title { margin-bottom: 24px; }
.page-title h2 { margin: 0 0 4px; font-size: 22px; }
.page-title span { color: #94a3b8; font-size: 13px; }
.traffic-tabs { margin-top: 28px; }
.history-card { margin-top: 20px; }
.chart-wrap { width: 100%; min-height: 220px; }
.chart-wrap svg { display: block; width: 100%; height: auto; }
.grid-line { stroke: rgba(148, 163, 184, 0.15); stroke-width: 1; }
.traffic-line { fill: none; stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; }
.rx-line { stroke: #18a058; }
.tx-line { stroke: #f0a020; }
.axis-label { fill: #94a3b8; font-size: 12px; }
.legend { font-size: 12px; font-weight: 700; }
.legend.rx { color: #18a058; }
.legend.tx { color: #f0a020; }
.metric, .fingerprint { font-family: 'Fira Code', monospace; }
.fingerprint { color: #94a3b8; font-size: 12px; }
.total { font-weight: 700; }
</style>
