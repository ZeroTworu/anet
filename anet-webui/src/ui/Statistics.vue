<script setup lang="ts">
// Экран наблюдаемости получает независимые срезы по нодам, пользователям
// и почасовую историю, которую control plane собирает из cumulative counters.
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api } from '@/api/client' // <-- Базовый клиент
import { useAppMessage } from '@/composables/useAppMessage' // <-- Система алертов
import { GetNodeTrafficStats, GetTrafficHistory, GetUserTrafficStats, GetActiveConnections } from '@/api/statistics'
import type { NodeTrafficStat, TrafficHistoryPoint, UserTrafficStat, ActiveConnection } from '@/models/statistics'

// Инициализируем таймер пустым значением
let refreshTimer: any = null

const nodes = ref<NodeTrafficStat[]>([])
const users = ref<UserTrafficStat[]>([])
const activeConnections = ref<ActiveConnection[]>([])
const history = ref<TrafficHistoryPoint[]>([])
const activeTab = ref('nodes')
const loading = ref(false)
const searchQuery = ref('')

const message = useAppMessage()

// Контейнер графика и состояние наведения
const containerRef = ref<HTMLElement | null>(null)
const hoveredIdx = ref<number | null>(null)

// Выбранный временной диапазон (в часах): 6, 12, 24 или 72 (3 дня)
const selectedRange = ref(24)

// Выбранный протокол (фильтр типа транспорта)
const selectedProtocol = ref('all')

// Активный фильтр трафика (что выведено на графике)
const selectedFilter = ref<{
  type: 'node' | 'user' | 'connection' | null
  id: string | null
  serverId?: string
  userId?: string
  fingerprint?: string
  name: string | null
}>({
  type: null,
  id: null,
  name: null
})

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

// Равномерно распределяем 5 временных меток по горизонтали во избежание наложений
const chartLabelsFiltered = computed(() => {
  if (history.value.length === 0) return []

  const totalPoints = history.value.length
  const indices = [
    0,
    Math.floor(totalPoints * 0.25),
    Math.floor(totalPoints * 0.5),
    Math.floor(totalPoints * 0.75),
    totalPoints - 1
  ]

  return indices.map(idx => {
    const item = history.value[idx]
    if (!item) return { time: '' }
    const date = new Date(item.bucket_start)

    // Если выбран масштаб более суток (например, 3 дня), добавляем дату
    if (selectedRange.value > 24) {
      return {
        time: date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
            date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    }

    return {
      time: date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  })
})

// Вычисление точной вертикальной координаты (%) с учетом внутреннего padding графика
const getVerticalPercent = (val: number) => {
  const height = 180
  const padding = 1
  const availableHeight = height - (padding * 2)
  const yPixels = height - padding - (val / chartMax.value) * availableHeight
  return (yPixels / height) * 100
}

// Вычисление точной горизонтальной координаты (%) с учетом внутреннего padding графика
const getHorizontalPercent = (idx: number) => {
  if (history.value.length <= 1) return 50
  const width = 1000
  const padding = 8
  const availableWidth = width - (padding * 2)
  const xPixels = padding + (idx / (history.value.length - 1)) * availableWidth
  return (xPixels / width) * 100
}

// Вычисление индекса точки при движении мыши по контейнеру (нативный трекинг)
const onMouseMove = (event: MouseEvent) => {
  if (!containerRef.value || history.value.length === 0) return

  const rect = containerRef.value.getBoundingClientRect()
  const x = event.clientX - rect.left
  const width = rect.width

  // Учитываем внутренний отступ графика (8px при ширине виртуальной сетки 1000px)
  const paddingPx = (8 / 1000) * width
  const usableWidth = width - (paddingPx * 2)

  // Рассчитываем положение внутри полезной ширины
  const xInside = x - paddingPx
  const relativeX = Math.max(0, Math.min(1, xInside / usableWidth))

  // Находим ближайший шаг времени
  hoveredIdx.value = Math.round(relativeX * (history.value.length - 1))
}

// Реактивные данные для отображения в тултипе при наведении
const hoveredData = computed(() => {
  if (hoveredIdx.value === null) return null

  const item = history.value[hoveredIdx.value]
  if (!item) return null // Сужение типа (Type Guard)

  const date = new Date(item.bucket_start)

  const dateStr = date.toLocaleDateString('ru-RU', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    weekday: 'short'
  })
  const timeStr = date.toLocaleTimeString('ru-RU', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })

  return {
    timeLabel: `${dateStr} • ${timeStr}`,
    rx: item.rx_bytes,
    tx: item.tx_bytes,
    total: item.rx_bytes + item.tx_bytes,
    xPercent: getHorizontalPercent(hoveredIdx.value),
    rxYPercent: getVerticalPercent(item.rx_bytes),
    txYPercent: getVerticalPercent(item.tx_bytes),
  }
})

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** unit).toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`
}

// Подгрузка исключительно истории трафика (чтобы не перезагружать таблицы)
const loadHistoryOnly = async () => {
  try {
    history.value = await GetTrafficHistory(
        selectedRange.value,
        selectedFilter.value.serverId,
        selectedFilter.value.userId,
        selectedFilter.value.fingerprint,
        selectedProtocol.value === 'all' ? undefined : selectedProtocol.value
    )
  } catch (e) {
    console.error('Failed to load traffic history:', e)
  }
}

const load = async () => {
  loading.value = true
  try {
    const [nodeStats, userStats, connStats] = await Promise.all([
      GetNodeTrafficStats(),
      GetUserTrafficStats(),
      GetActiveConnections(),
    ])
    nodes.value = nodeStats.sort((a, b) => b.rx_bytes + b.tx_bytes - a.rx_bytes - a.tx_bytes)
    users.value = userStats
    activeConnections.value = connStats

    await loadHistoryOnly()
  } finally {
    loading.value = false
  }
}

// Сброс активного фильтра в исходное состояние (Общий трафик)
const resetFilter = () => {
  selectedFilter.value = { type: null, id: null, name: null }
}

// Логика выбора элементов из таблиц
const selectNode = (item: NodeTrafficStat) => {
  if (selectedFilter.value.type === 'node' && selectedFilter.value.id === item.node_id) {
    resetFilter()
  } else {
    selectedFilter.value = {
      type: 'node',
      id: item.node_id,
      serverId: item.node_id,
      name: item.name
    }
  }
}

const selectUser = (item: UserTrafficStat) => {
  const id = item.user_id || item.fingerprint
  if (selectedFilter.value.type === 'user' && selectedFilter.value.id === id) {
    resetFilter()
  } else {
    selectedFilter.value = {
      type: 'user',
      id,
      userId: item.user_id || undefined,
      fingerprint: !item.user_id ? item.fingerprint : undefined,
      name: item.uid || 'Локальный клиент'
    }
  }
}

const selectConnection = (item: ActiveConnection) => {
  const id = `${item.user_id}-${item.server_id}`
  if (selectedFilter.value.type === 'connection' && selectedFilter.value.id === id) {
    resetFilter()
  } else {
    selectedFilter.value = {
      type: 'connection',
      id,
      serverId: item.server_id,
      userId: item.user_id,
      name: `${item.username} на ${item.server_name}`
    }
  }
}

// Хелперы кликов по строкам таблиц
const onNodeRowClick = (_event: any, row: { item: NodeTrafficStat }) => {
  selectNode(row.item)
}

const onUserRowClick = (_event: any, row: { item: UserTrafficStat }) => {
  selectUser(row.item)
}

const onConnectionRowClick = (_event: any, row: { item: ActiveConnection }) => {
  selectConnection(row.item)
}

// Отключить принудительно (Disconnect)
const disconnectConnection = async (item: ActiveConnection) => {
  if (!confirm(`Принудительно разорвать VPN-сессию пользователя «${item.username}» на сервере «${item.server_name}»?`)) return
  try {
    // ВЫЗОВ POST МЕТОДА С ПЕРЕДАЧЕЙ СЕРВЕРНЫХ ID И FINGERPRINT В ТЕЛЕ ЗАПРОСА
    await api<void>(`/statistics/active-connections/disconnect`, {
      method: 'POST',
      data: {
        server_id: item.server_id,
        fingerprint: item.fingerprint
      }
    })
    message.success('Команда отключения поставлена в очередь ноды. Сессия будет сброшена в течение 15 секунд.')
    await load()
  } catch (e) {
    message.error('Не удалось отправить команду отключения на сервер')
  }
}

// Определение CSS-класса для подсветки выбранной строки таблицы
const getRowProps = (data: { item: any }) => {
  const item = data.item
  const isSelected =
      (selectedFilter.value.type === 'node' && selectedFilter.value.id === item.node_id) ||
      (selectedFilter.value.type === 'user' && selectedFilter.value.id === (item.user_id || item.fingerprint)) ||
      (selectedFilter.value.type === 'connection' && selectedFilter.value.id === `${item.user_id}-${item.server_id}`);

  return isSelected ? { class: 'selected-row' } : {}
}

// Наблюдаем за изменением зума, фильтра или выбранного протокола для обновления только графика
watch([selectedRange, selectedFilter, selectedProtocol], () => {
  loadHistoryOnly()
})

onMounted(() => {
  load()
  refreshTimer = window.setInterval(load, 15_000)
})

onBeforeUnmount(() => {
  if (refreshTimer !== null) {
    window.clearInterval(refreshTimer)
  }
})

// Конфигурация колонок и вычисляемые данные для таблицы узлов
const nodeHeaders = [
  { title: 'Узел', key: 'name', sortable: true },
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
  { title: 'Пользователь', key: 'username_display', sortable: true },
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
  { title: 'Пользователь', key: 'username', sortable: true },
  { title: 'Сервер', key: 'server_name', sortable: true },
  { title: 'RX (Сессия)', key: 'rx_bytes', align: 'end' as const },
  { title: 'TX (Сессия)', key: 'tx_bytes', align: 'end' as const },
  { title: 'Количество сессий', key: 'connection_count', align: 'end' as const },
  { title: 'Протокол', key: 'protocol', align: 'center' as const },
  { title: 'Исключить', key: 'actions', sortable: false, align: 'center' as const }, // <-- Добавлена колонка действий
]
</script>

<template>
  <v-container max-width="1200" class="statistics-page py-6">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-6">
      <v-list-item
          class="px-0"
          subtitle="Полезный трафик внутри VPN-туннеля"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Traffic</h1>
        </template>
      </v-list-item>
      <v-btn :loading="loading" @click="load">Обновить</v-btn>
    </div>

    <v-row>
      <v-col cols="12" md="4">
        <v-card class="pa-4" border flat>
          <div class="text-caption text-medium-emphasis">Получено узлами</div>
          <div class="text-h6 font-weight-bold">{{ formatBytes(totalRx) }}</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="4">
        <v-card class="pa-4" border flat>
          <div class="text-caption text-medium-emphasis">Отправлено клиентам</div>
          <div class="text-h6 font-weight-bold">{{ formatBytes(totalTx) }}</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="4">
        <v-card class="pa-4" border flat>
          <div class="text-caption text-medium-emphasis">Всего</div>
          <div class="text-h6 font-weight-bold">{{ formatBytes(totalRx + totalTx) }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-card class="history-card" border flat>
      <template #title>
        <div class="d-flex align-center justify-space-between flex-wrap ga-4">
          <div class="d-flex align-center ga-4">
            <span>{{ selectedFilter.type ? `Трафик: ${selectedFilter.name}` : 'Общий трафик' }}</span>
            <span class="legend rx">RX</span>
            <span class="legend tx">TX</span>
            <v-chip
                v-if="selectedFilter.type"
                size="small"
                color="error"
                variant="tonal"
                closable
                @click:close="resetFilter"
                class="ml-2"
            >
              Сбросить фильтр
            </v-chip>
          </div>

          <div class="d-flex align-center ga-3 flex-wrap">
            <v-btn-toggle
                v-model="selectedProtocol"
                mandatory
                color="primary"
                density="compact"
                variant="outlined"
            >
              <v-btn value="all">Все</v-btn>
              <v-btn value="quic">QUIC</v-btn>
              <v-btn value="ws">WS(S)</v-btn>
              <v-btn value="ssh">SSH</v-btn>
              <v-btn value="vnc">VNC</v-btn>
              <v-btn value="ahttp">AHTTP</v-btn>
            </v-btn-toggle>

            <v-btn-toggle
                v-model="selectedRange"
                mandatory
                color="primary"
                density="compact"
                variant="outlined"
            >
              <v-btn :value="6">6ч</v-btn>
              <v-btn :value="12">12ч</v-btn>
              <v-btn :value="24">24ч</v-btn>
              <v-btn :value="72">3д</v-btn>
            </v-btn-toggle>
          </div>
        </div>
      </template>
      <v-card-text>
        <div class="chart-wrap mt-4">
          <div class="d-flex">
            <div class="d-flex flex-column justify-space-between pr-3 text-caption text-medium-emphasis text-right font-mono" style="width: 85px; height: 180px; border-right: 1px solid rgba(255,255,255,0.08); padding-bottom: 8px;">
              <span>{{ formatBytes(chartMax) }}</span>
              <span>{{ formatBytes(chartMax / 2) }}</span>
              <span>0 B</span>
            </div>

            <div
                ref="containerRef"
                class="flex-grow-1 position-relative"
                @mousemove="onMouseMove"
                @mouseleave="hoveredIdx = null"
            >
              <v-sheet v-if="history.length > 0" color="transparent" style="height: 180px;">
                <v-sparkline
                    :model-value="rxValues"
                    :min="0"
                    :max="chartMax"
                    color="primary"
                    line-width="2"
                    padding="8"
                    :smooth="0"
                    stroke-linecap="round"
                    auto-draw
                    style="height: 100%; width: 100%; cursor: crosshair;"
                />
                <v-sparkline
                    :model-value="txValues"
                    :min="0"
                    :max="chartMax"
                    color="warning"
                    line-width="2"
                    padding="8"
                    :smooth="0"
                    stroke-linecap="round"
                    auto-draw
                    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none;"
                />

                <template v-if="hoveredData">
                  <div
                      class="hover-line"
                      :style="{ left: `${hoveredData.xPercent}%` }"
                  ></div>

                  <div
                      class="hover-marker rx-marker"
                      :style="{
                      left: `${hoveredData.xPercent}%`,
                      top: `${hoveredData.rxYPercent}%`
                    }"
                  ></div>

                  <div
                      class="hover-marker tx-marker"
                      :style="{
                      left: `${hoveredData.xPercent}%`,
                      top: `${hoveredData.txYPercent}%`
                    }"
                  ></div>

                  <v-card
                      class="hover-tooltip-card pa-3 text-caption"
                      elevation="12"
                      border
                      :style="{
                      left: hoveredData.xPercent > 50 ? 'auto' : `${hoveredData.xPercent + 2}%`,
                      right: hoveredData.xPercent > 50 ? `${100 - hoveredData.xPercent + 2}%` : 'auto',
                      top: '15px'
                    }"
                  >
                    <div class="font-weight-bold mb-2">{{ hoveredData.timeLabel }}</div>

                    <div class="d-flex align-center justify-space-between mb-1" style="min-width: 240px;">
                      <div class="d-flex align-center ga-2">
                        <span class="legend rx-dot" />
                        <span>RX (Получено)</span>
                      </div>
                      <span class="font-mono">{{ formatBytes(hoveredData.rx) }}</span>
                    </div>

                    <div class="d-flex align-center justify-space-between mb-2">
                      <div class="d-flex align-center ga-2">
                        <span class="legend tx-dot" />
                        <span>TX (Отправлено)</span>
                      </div>
                      <span class="font-mono">{{ formatBytes(hoveredData.tx) }}</span>
                    </div>

                    <v-divider class="my-1" />

                    <div class="d-flex align-center justify-space-between font-weight-bold mt-1">
                      <span>Сумма</span>
                      <span class="font-mono">{{ formatBytes(hoveredData.total) }}</span>
                    </div>
                  </v-card>
                </template>
              </v-sheet>
              <v-sheet v-else color="transparent" class="d-flex align-center justify-center" style="height: 180px;">
                <span class="text-caption text-medium-emphasis">Загрузка данных графика...</span>
              </v-sheet>

              <div class="d-flex justify-space-between px-2 pt-2 text-caption text-medium-emphasis font-mono">
                <span v-for="(label, idx) in chartLabelsFiltered" :key="idx">
                  {{ label.time }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </v-card-text>
    </v-card>

    <v-card class="traffic-tabs" border flat>
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
              :row-props="getRowProps"
              :items-per-page="10"
              :items-per-page-options="[10, 20, 50]"
              items-per-page-text="Строк на странице"
              loading-text="Загрузка статистики узлов…"
              no-data-text="Нет данных"
              hover
              @click:row="onNodeRowClick"
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
              :row-props="getRowProps"
              :items-per-page="10"
              :items-per-page-options="[10, 20, 50]"
              items-per-page-text="Строк на странице"
              loading-text="Загрузка статистики пользователей…"
              no-data-text="Нет данных"
              hover
              @click:row="onUserRowClick"
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
              :row-props="getRowProps"
              :items-per-page="10"
              :items-per-page-options="[10, 20, 50]"
              items-per-page-text="Строк на странице"
              loading-text="Загрузка списка активных сессий…"
              no-data-text="Нет активных подключений"
              hover
              @click:row="onConnectionRowClick"
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
            <template #item.protocol="{ value }">
              <v-chip size="small" variant="tonal" class="text-uppercase" color="info">
                {{ value }}
              </v-chip>
            </template>
            <!-- Слот принудительного разрыва сессии -->
            <template #item.actions="{ item }">
              <v-btn
                  icon="mdi-close-circle-outline"
                  variant="text"
                  color="error"
                  size="small"
                  @click.stop="disconnectConnection(item)"
              />
            </template>
          </v-data-table>
        </v-tabs-window-item>
      </v-tabs-window>
    </v-card>
  </v-container>
</template>

<style scoped>
.statistics-page { max-width: 1200px; margin: 0 auto; }
.traffic-tabs { margin-top: 24px; }
.history-card { margin-top: 20px; }
.chart-wrap { width: 100%; min-height: 220px; }
.legend { font-size: 12px; font-weight: 700; }
.legend.rx { color: #2bb894; }
.legend.tx { color: #d9a441; }
.metric { font-family: 'Fira Code', monospace; }
.font-mono { font-family: 'Fira Code', monospace; }
.total { font-weight: 700; }

:deep(.v-sparkline text) {
  fill: #9aa5a0;
  font-size: 11px;
}

.hover-line {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background-color: rgba(229, 117, 111, 0.45);
  pointer-events: none;
  z-index: 2;
}

.hover-marker {
  position: absolute;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  border: 2px solid #1e2221;
  transform: translate(-50%, -50%);
  pointer-events: none;
  z-index: 3;
}
.rx-marker {
  background-color: #2bb894;
  box-shadow: 0 0 8px rgba(43, 184, 148, 0.85);
}
.tx-marker {
  background-color: #d9a441;
  box-shadow: 0 0 8px rgba(217, 164, 65, 0.85);
}

.hover-tooltip-card {
  position: absolute;
  background-color: rgba(30, 34, 33, 0.95) !important;
  backdrop-filter: blur(4px);
  z-index: 10;
  pointer-events: none;
  border-color: rgba(255, 255, 255, 0.08) !important;
}

.rx-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: #2bb894;
}
.tx-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: #d9a441;
}

:deep(.selected-row) {
  background-color: rgba(43, 184, 148, 0.15) !important;
}
</style>
