<script setup lang="ts">
// Экран наблюдаемости получает независимые срезы по нодам, пользователям
// и почасовую историю, которую control plane собирает из cumulative counters.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { GetNodeTrafficStats, GetTrafficHistory, GetUserTrafficStats, GetActiveConnections } from '@/api/statistics'
import type { NodeTrafficStat, TrafficHistoryPoint, UserTrafficStat, ActiveConnection } from '@/models/statistics'

const nodes = ref<NodeTrafficStat[]>([])
const users = ref<UserTrafficStat[]>([])
const activeConnections = ref<ActiveConnection[]>([])
const history = ref<TrafficHistoryPoint[]>([])
const activeTab = ref('nodes')
const loading = ref(false)
const searchQuery = ref('')
let refreshTimer: number | undefined

const totalRx = computed(() => nodes.value.reduce((sum, item) => sum + item.rx_bytes, 0))
const totalTx = computed(() => nodes.value.reduce((sum, item) => sum + item.tx_bytes, 0))

// Извлекаем чистые массивы байт для графиков
const rxValues = computed(() => history.value.map(item => item.rx_bytes))
const txValues = computed(() => history.value.map(item => item.tx_bytes))

// Вычисляем абсолютный пик трафика для корректного масштабирования обеих линий
const chartMax = computed(() => {
  const maxRx = Math.max(...rxValues.value, 0)
  const maxTx = Math.max(...txValues.value, 0)
  return Math.max(maxRx, maxTx, 1) // Исключаем деление на ноль
})

// Форматируем метки по локальной таймзоне пользователя
const chartLabelsFormatted = computed(() => {
  return history.value.map((item, index) => {
    // Выводим только каждую 4-ю метку и последнюю точку для избежания наложения текста
    if (index % 4 === 0 || index === history.value.length - 1) {
      const date = new Date(item.bucket_start)
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
    return ''
  })
})

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** unit).toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`
}

// Конфигурация колонок и вычисляемые данные для таблицы узлов
const nodeHeaders = [
  { title: 'Узел', key: 'name', align: 'start' as const },
  { title: 'RX', key: 'rx_bytes', align: 'end' as const },
  { title: 'TX', key: 'tx_bytes', align: 'end' as const },
  { title: 'Всего', key: 'total_bytes', align: 'end' as const },
]
const mappedNodes = computed(() => {
  return nodes.value.map(node => ({
    ...node,
    total_bytes: node.rx_bytes + node.tx_bytes,
  }))
})

// Конфигурация колонок и вычисляемые данные для таблицы пользователей
const userHeaders = [
  { title: 'Пользователь', key: 'username_display', align: 'start' as const },
  { title: 'RX', key: 'rx_bytes', align: 'end' as const },
  { title: 'TX', key: 'tx_bytes', align: 'end' as const },
  { title: 'Всего', key: 'total_bytes', align: 'end' as const },
]
const mappedUsers = computed(() => {
  return users.value.map(user => ({
    ...user,
    username_display: user.uid || 'Локальный клиент',
    total_bytes: user.rx_bytes + user.tx_bytes,
  }))
})

// Конфигурация колонок для таблицы активных подключений
const connectionHeaders = [
  { title: 'Пользователь', key: 'username', align: 'start' as const },
  { title: 'Сервер', key: 'server_name', align: 'start' as const },
  { title: 'RX (Сессия)', key: 'rx_bytes', align: 'end' as const },
  { title: 'TX (Сессия)', key: 'tx_bytes', align: 'end' as const },
  { title: 'Количество сессий', key: 'connection_count', align: 'end' as const },
]

const load = async () => {
  loading.value = true
  try {
    const [nodeStats, userStats, connStats, trafficHistory] = await Promise.all([
      GetNodeTrafficStats(),
      GetUserTrafficStats(),
      GetActiveConnections(),
      GetTrafficHistory(24),
    ])
    nodes.value = nodeStats.sort((a, b) => b.rx_bytes + b.tx_bytes - a.rx_bytes - a.tx_bytes)
    users.value = userStats
    activeConnections.value = connStats
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
    <div class="d-flex align-center justify-space-between page-title">
      <div>
        <h2>Traffic</h2>
        <span>Полезный трафик внутри VPN-туннеля</span>
      </div>
      <v-btn :loading="loading" @click="load">Обновить</v-btn>
    </div>

    <v-row class="mt-2">
      <v-col cols="12" md="4">
        <v-card class="pa-4">
          <div class="text-caption text-medium-emphasis">Получено узлами</div>
          <div class="text-h6 font-weight-bold">{{ formatBytes(totalRx) }}</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="4">
        <v-card class="pa-4">
          <div class="text-caption text-medium-emphasis">Отправлено клиентам</div>
          <div class="text-h6 font-weight-bold">{{ formatBytes(totalTx) }}</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="4">
        <v-card class="pa-4">
          <div class="text-caption text-medium-emphasis">Всего</div>
          <div class="text-h6 font-weight-bold">{{ formatBytes(totalRx + totalTx) }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-card class="history-card">
      <template #title>
        <div class="d-flex align-center ga-4">
          <span>Последние 24 часа</span>
          <span class="legend rx">RX</span>
          <span class="legend tx">TX</span>
        </div>
      </template>
      <v-card-text>
        <div class="chart-wrap mt-2">
          <!-- Обертка с абсолютным позиционированием для наложения графиков -->
          <v-sheet color="transparent" class="position-relative" style="height: 180px;">
            <!-- График RX с временной шкалой -->
            <v-sparkline
                :model-value="rxValues"
                :labels="chartLabelsFormatted"
                :min="0"
                :max="chartMax"
                color="primary"
                line-width="2"
                padding="16"
                smooth="8"
                stroke-linecap="round"
                auto-draw
                style="height: 100%; width: 100%;"
            />
            <!-- График TX без подписей для избежания наложения текста -->
            <v-sparkline
                :model-value="txValues"
                :min="0"
                :max="chartMax"
                color="warning"
                line-width="2"
                padding="16"
                smooth="8"
                stroke-linecap="round"
                auto-draw
                style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none;"
            />
          </v-sheet>
        </div>
      </v-card-text>
    </v-card>

    <v-card class="traffic-tabs">
      <div class="d-flex flex-wrap align-center justify-space-between px-4 pt-2 border-b">
        <v-tabs v-model="activeTab" color="primary">
          <v-tab value="nodes">По узлам</v-tab>
          <v-tab value="users">По пользователям</v-tab>
          <v-tab value="connections">Активные подключения</v-tab>
        </v-tabs>
        <v-text-field
            v-model="searchQuery"
            prepend-inner-icon="mdi-magnify"
            label="Поиск по таблице..."
            variant="outlined"
            density="compact"
            hide-details
            single-line
            style="max-width: 300px"
            class="my-2"
        />
      </div>

      <v-tabs-window v-model="activeTab">
        <v-tabs-window-item value="nodes">
          <v-data-table
              :headers="nodeHeaders"
              :items="mappedNodes"
              :search="searchQuery"
              :loading="loading"
              :items-per-page="10"
              :items-per-page-options="[10, 20, 50]"
              items-per-page-text="Строк на странице"
              loading-text="Загрузка статистики узлов…"
              no-data-text="Нет данных"
              hover
          >
            <template #item.rx_bytes="{ value }">
              <span class="metric">{{ formatBytes(value) }}</span>
            </template>
            <template #item.tx_bytes="{ value }">
              <span class="metric">{{ formatBytes(value) }}</span>
            </template>
            <template #item.total_bytes="{ value }">
              <span class="metric total">{{ formatBytes(value) }}</span>
            </template>
          </v-data-table>
        </v-tabs-window-item>

        <v-tabs-window-item value="users">
          <v-data-table
              :headers="userHeaders"
              :items="mappedUsers"
              :search="searchQuery"
              :loading="loading"
              :items-per-page="10"
              :items-per-page-options="[10, 20, 50]"
              items-per-page-text="Строк на странице"
              loading-text="Загрузка статистики пользователей…"
              no-data-text="Нет данных"
              hover
          >
            <template #item.rx_bytes="{ value }">
              <span class="metric">{{ formatBytes(value) }}</span>
            </template>
            <template #item.tx_bytes="{ value }">
              <span class="metric">{{ formatBytes(value) }}</span>
            </template>
            <template #item.total_bytes="{ value }">
              <span class="metric total">{{ formatBytes(value) }}</span>
            </template>
          </v-data-table>
        </v-tabs-window-item>

        <v-tabs-window-item value="connections">
          <v-data-table
              :headers="connectionHeaders"
              :items="activeConnections"
              :search="searchQuery"
              :loading="loading"
              :items-per-page="10"
              :items-per-page-options="[10, 20, 50]"
              items-per-page-text="Строк на странице"
              loading-text="Загрузка списка активных сессий…"
              no-data-text="Нет активных подключений"
              hover
          >
            <template #item.rx_bytes="{ value }">
              <span class="metric">{{ formatBytes(value) }}</span>
            </template>
            <template #item.tx_bytes="{ value }">
              <span class="metric">{{ formatBytes(value) }}</span>
            </template>
            <template #item.connection_count="{ value }">
              <span class="metric total">{{ value }}</span>
            </template>
          </v-data-table>
        </v-tabs-window-item>
      </v-tabs-window>
    </v-card>
  </main>
</template>

<style scoped>
.statistics-page { max-width: 1200px; margin: 0 auto; padding: 24px; }
.page-title { margin-bottom: 16px; }
.page-title h2 { margin: 0 0 4px; font-size: 22px; }
.page-title span { color: #9aa5a0; font-size: 13px; }
.traffic-tabs { margin-top: 24px; }
.history-card { margin-top: 20px; }
.chart-wrap { width: 100%; min-height: 220px; }
.grid-line { stroke: rgba(154, 165, 160, 0.15); stroke-width: 1; }
.legend { font-size: 12px; font-weight: 700; }
.legend.rx { color: #2bb894; }
.legend.tx { color: #d9a441; }
.metric { font-family: 'Fira Code', monospace; }
.total { font-weight: 700; }

/* Кастомные стили для масштабируемых шрифтов v-sparkline */
:deep(.v-sparkline text) {
  fill: #9aa5a0;
  font-size: 11px;
}
</style>
